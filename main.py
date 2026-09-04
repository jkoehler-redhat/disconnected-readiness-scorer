#!/usr/bin/env python3
"""Disconnected Readiness Scorer — orchestrator.

Runs all (or selected) rules against a target repo and produces
an aggregate READY / NOT READY score.
"""

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import date
from fnmatch import fnmatch
from pathlib import Path

import jsonschema
import yaml

from rules.common import ArchAnalyzerResult, ConfigError, Finding, RuleResult, Severity
from rules.operator_manifest import build_module_manifest, detect_module
from rules.production_scope import compute_production_scope

SEVERITY_ORDER = {"blocker": 0, "info": 1}


class ArchAnalyzerError(Exception):
    """Raised when arch-analyzer binary is missing or fails."""


CENTRAL_CONFIG_PATH = "config/config.yaml"
_EXPIRY_WARNING_DAYS = 14

REFERENCE_DOC_BASE = (
    "https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/docs/references"
)

RULE_REGISTRY = {
    "csv": {
        "module": "rules.image_manifest_complete",
        "name": "image-manifest-complete",
        "needs_manifest": True,
        "display_name": "Image manifest completeness",
        "remediation": (
            "Register all container images used by this component in the "
            "operator manifest. For repos using the env-var pattern, add a "
            "RELATED_IMAGE_* environment variable to the operator deployment. "
            "For repos using the params.env pattern, add a key to params.env "
            "and wire it through kustomize."
        ),
        "reference_doc": f"{REFERENCE_DOC_BASE}/image-manifest-complete.md",
    },
    "tags": {
        "module": "rules.no_image_tags",
        "name": "no-image-tags",
        "needs_manifest": True,
        "display_name": "No mutable image tags",
        "remediation": (
            "Replace all mutable image tags (:latest, :v1.2, etc.) with "
            "immutable @sha256: digest references. Mutable tags can resolve "
            "to different images over time and cannot be pre-pulled reliably "
            "for disconnected deployments."
        ),
        "reference_doc": f"{REFERENCE_DOC_BASE}/no-image-tags.md",
    },
    "egress": {
        "module": "rules.no_runtime_egress",
        "name": "no-runtime-egress",
        "display_name": "No runtime external calls",
        "remediation": (
            "Remove hardcoded external URLs from source code and manifests, "
            "or make them configurable via environment variables or "
            "configuration files. In a disconnected cluster, any outbound "
            "network call to an external service will fail."
        ),
        "reference_doc": f"{REFERENCE_DOC_BASE}/no-runtime-egress.md",
    },
    "python": {
        "module": "rules.python_imports",
        "name": "python-imports-bundled",
        "display_name": "Python imports bundled",
        "remediation": (
            "Ensure all Python package dependencies are included in the "
            "offline-bundled package set or vendored into the container "
            "image at build time. Runtime pip install calls will fail "
            "without network access."
        ),
        "reference_doc": f"{REFERENCE_DOC_BASE}/python-imports-bundled.md",
    },
    "params_env": {
        "module": "rules.params_env",
        "name": "params-env-wiring",
        "needs_manifest": True,
        "display_name": "Params.env wiring",
        "remediation": (
            "Complete the params.env wiring chain: every image reference "
            "must flow from params.env through a kustomize configMapGenerator "
            "into the rendered manifests. Check for hardcoded images not "
            "sourced from params.env, unwired params.env keys, and orphan "
            "Go os.Getenv calls."
        ),
        "reference_doc": f"{REFERENCE_DOC_BASE}/params-env-wiring.md",
    },
    "manifest": {
        "module": "rules.operator_manifest",
        "name": "operator-manifest",
        "is_manifest_rule": True,
        # No display_name/remediation/reference_doc — manifest rules don't produce maturity evaluations
    },
}

# Reverse lookup: canonical rule name → registry entry
_RULE_BY_NAME: dict[str, dict] = {v["name"]: v for v in RULE_REGISTRY.values()}

VALID_RULE_NAMES = frozenset(v["name"] for v in RULE_REGISTRY.values())
VALID_RULE_NAMES_SORTED = sorted(VALID_RULE_NAMES)
ANY_RULE = "*"

DEFAULT_RULES = [k for k, v in RULE_REGISTRY.items() if not v.get("is_manifest_rule")]


def _load_yaml_file(config_path):
    """Load a YAML file, raising if the path doesn't exist."""
    if not Path(config_path).exists():
        raise ValueError(f"Config file not found: {config_path}")
    try:
        text = Path(config_path).read_text()
    except OSError as exc:
        raise ValueError(f"Cannot read {config_path}: {exc}") from exc
    try:
        return yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse {config_path}: {exc}") from exc


_SCHEMA_PATH = Path(__file__).parent / "schemas" / "config.schema.json"


def _validate_config_schema(raw, config_path):
    """Validate config dict against schemas/config.schema.json."""
    try:
        schema = json.loads(_SCHEMA_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read config schema {_SCHEMA_PATH}: {exc}") from exc
    try:
        jsonschema.validate(raw, schema)
    except jsonschema.ValidationError as exc:
        raise ValueError(f"{config_path}: schema validation error: {exc.message}") from exc


def load_central_config(config_path):
    raw = _load_yaml_file(config_path)
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} must be a YAML mapping, got {type(raw).__name__}")
    for exc in raw.get("exceptions") or []:
        if isinstance(exc, dict) and isinstance(exc.get("expires"), date):
            exc["expires"] = exc["expires"].isoformat()
    _validate_config_schema(raw, config_path)
    exceptions = raw.get("exceptions") or []
    _validate_exceptions(exceptions, config_path)
    for exc in exceptions:
        expires = exc.get("expires")
        if expires is not None:
            exc["expires"] = date.fromisoformat(expires)
    return {
        "exceptions": exceptions,
        "docker_contexts": raw.get("docker_contexts") or {},
        "known_non_image_prefixes": raw.get("known_non_image_prefixes") or [],
        "params_env_filenames": raw.get("params_env_filenames") or {},
    }


def _validate_exceptions(exceptions, config_path):
    """Validate exception entries have required fields and valid rule names."""
    for i, exc in enumerate(exceptions):
        if not isinstance(exc, dict):
            raise ValueError(
                f"Exception entry {i + 1} in {config_path} "
                f"must be a mapping, got {type(exc).__name__}"
            )
        rules = exc.get("rules")
        if not rules:
            raise ValueError(
                f"Exception entry {i + 1} in {config_path} is missing required 'rules' field"
            )
        _validate_rules_field(rules, i, config_path)
        if not exc.get("reason"):
            raise ValueError(
                f"Exception entry {i + 1} (rules={rules!r}) "
                f"in {config_path} is missing required 'reason' field"
            )
        if not any(exc.get(field) for field in ("paths", "images", "message")):
            raise ValueError(
                f"Exception entry {i + 1} (rules={rules!r}) in {config_path} "
                "must include at least one of 'paths', 'images', or 'message'"
            )
        expires = exc.get("expires")
        if expires is not None and not isinstance(expires, str | date):
            raise ValueError(
                f"Exception entry {i + 1} (rules={rules!r}) "
                f"in {config_path}: 'expires' must be a YYYY-MM-DD date string, "
                f"got {type(expires).__name__}"
            )
        if isinstance(expires, str):
            try:
                date.fromisoformat(expires)
            except ValueError:
                raise ValueError(
                    f"Exception entry {i + 1} (rules={rules!r}) "
                    f"in {config_path}: invalid 'expires' date '{expires}', "
                    f"expected YYYY-MM-DD format"
                ) from None


def _validate_rules_field(rules, entry_index, config_path):
    """Validate semantic rules for the 'rules' field of an exception entry.

    Structural validation (type, non-empty, item types) is handled by the
    JSON schema.  This function validates business constraints the schema
    cannot express: rule name existence and wildcard placement.
    """
    label = f"Exception entry {entry_index + 1} in {config_path}"
    valid_names = VALID_RULE_NAMES_SORTED
    if isinstance(rules, str):
        if rules != ANY_RULE and rules not in VALID_RULE_NAMES:
            raise ValueError(f"{label}: unknown rule name '{rules}'. Valid names: {valid_names}")
    elif isinstance(rules, list):
        for item in rules:
            if item == ANY_RULE:
                raise ValueError(
                    f"{label}: wildcard '{ANY_RULE}' is not allowed inside a list. "
                    f'Use rules: "{ANY_RULE}" as a string instead'
                )
            if item not in VALID_RULE_NAMES:
                raise ValueError(f"{label}: unknown rule name '{item}'. Valid names: {valid_names}")


def _path_matches(filepath: str, pattern: str) -> bool:
    """Match a file path against a glob pattern.

    Handles ``**/X`` patterns by also matching ``X`` at the root level
    (fnmatch does not expand ``**`` as a recursive wildcard).
    Patterns ending with ``/**`` also match the directory itself (without
    trailing content), so ``**/config/scorecard/**`` matches both
    ``config/scorecard`` and ``config/scorecard/foo.yaml``.
    Also matches against the filename alone for suffix patterns like ``*_test.go``.
    """
    if fnmatch(filepath, pattern):
        return True
    if pattern.startswith("**/") and fnmatch(filepath, pattern[3:]):
        return True
    if pattern.endswith("/**"):
        dir_pattern = pattern[:-3]
        if fnmatch(filepath, dir_pattern):
            return True
        if dir_pattern.startswith("**/") and fnmatch(filepath, dir_pattern[3:]):
            return True
    return fnmatch(filepath.rsplit("/", 1)[-1], pattern)


def _normalize_rules(rules_value):
    """Normalize a validated 'rules' field to a frozenset of rule names.

    Expects ``rules_value`` to be ``str`` or ``list[str]``, as enforced
    by the JSON schema and ``_validate_rules_field()``.  The wildcard
    ``ANY_RULE`` is preserved so callers can check ``ANY_RULE in result``.
    """
    if not rules_value:
        return frozenset()
    if isinstance(rules_value, str):
        return frozenset([rules_value])
    return frozenset(rules_value)


def _rules_display_str(rules_value):
    """Convert a rules field value to a human-readable display string."""
    if isinstance(rules_value, list):
        return ", ".join(rules_value)
    return str(rules_value) if rules_value else ""


def apply_exceptions(results, exceptions, repo_name, *, today=None):
    """Downgrade blocker findings that match configured exceptions to info severity.

    Returns a list of hit counts, one per exception entry (parallel to exceptions list).
    """
    hits = [0] * len(exceptions)
    if today is None:
        today = date.today()
    exc_with_rules = [(exc, _normalize_rules(exc.get("rules", ""))) for exc in exceptions]
    for result in results:
        for finding in result.findings:
            if finding.severity != "blocker":
                continue
            for i, (exc, exc_rules) in enumerate(exc_with_rules):
                exc_expires = exc.get("expires")
                if exc_expires and exc_expires < today:
                    continue
                if ANY_RULE not in exc_rules and result.rule not in exc_rules:
                    continue
                exc_repo = exc.get("repo")
                if exc_repo:
                    if "/" in exc_repo:
                        if exc_repo != repo_name:
                            continue
                    else:
                        if exc_repo != repo_name.rsplit("/", 1)[-1]:
                            continue
                exc_paths = exc.get("paths") or []
                if exc_paths and not any(_path_matches(finding.file, p) for p in exc_paths):
                    continue
                exc_images = exc.get("images") or []
                if exc_images and not any(fnmatch(finding.image, pat) for pat in exc_images):
                    continue
                exc_message = exc.get("message")
                if exc_message and not fnmatch(finding.message, exc_message):
                    continue
                reason = exc.get("reason", "configured exception")
                finding.message += f" [Exception: {reason}]"
                finding.severity = Severity.INFO
                hits[i] += 1
                break
        if not any(f.severity == "blocker" for f in result.findings):
            result.passed = True
    return hits


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Score a repo's disconnected / air-gapped readiness.",
    )
    parser.add_argument(
        "repo_root",
        nargs="?",
        default=".",
        help="Path to the target repository (default: current directory)",
    )
    parser.add_argument(
        "--rules",
        default="all",
        help="Comma-separated rule aliases, 'all', or empty (default: all). "
        "'all' or empty runs every registered rule. "
        f"Available: {', '.join(RULE_REGISTRY)}",
    )
    parser.add_argument(
        "--report",
        default="markdown",
        help="Output format: 'markdown', 'json', or comma-separated "
        "'json,markdown' for dual output (default: markdown).",
    )
    parser.add_argument(
        "--operator-path",
        help="Path to a pre-cloned opendatahub-operator. "
        "If omitted, clones to a temporary directory when needed.",
    )
    parser.add_argument(
        "--output",
        "-o",
        nargs="*",
        help="Write report(s) to file(s). With dual --report, provide "
        "one -o per format in the same order.",
    )
    parser.add_argument(
        "--config",
        help=f"Path to central config.yaml (default: {CENTRAL_CONFIG_PATH}).",
    )
    parser.add_argument(
        "--no-production-scope",
        action="store_true",
        help="Disable production-scope analysis (Dockerfile + go list). "
        "All files are scanned at full severity.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed diagnostic output to stderr (per-step timing, "
        "file scan progress, production scope decisions, config loading). "
        "When used with --report json, includes files_checked per rule.",
    )
    parser.add_argument(
        "--arch-analyzer",
        default=str(Path(__file__).parent / "bin" / "arch-analyzer"),
        help="Path to arch-analyzer binary (default: bin/arch-analyzer).",
    )
    parser.add_argument(
        "--list-expiring",
        action="store_true",
        help="List expired and soon-to-expire exceptions and exit. "
        "Exit code 0 if none, 2 if any found.",
    )
    parser.add_argument(
        "--audit-exceptions",
        action="store_true",
        help="Analyze exception entries for overly broad scope and exit. "
        "Exit code 0 if no warnings, 2 if any found.",
    )
    parser.add_argument(
        "--module-mode",
        action="store_true",
        default=False,
        help="Validate the repo as a standalone module. Uses the module's own "
        "RELATED_IMAGE_* definitions (from *-module/ subdirs or pkg/**/images.go) "
        "as the authority instead of the opendatahub-operator manifest. "
        "Skips operator clone entirely. Takes precedence over --operator-path.",
    )
    return parser.parse_args(argv)


def resolve_rules(rules_arg):
    if not rules_arg or rules_arg == "all":
        return list(DEFAULT_RULES)
    keys = [k.strip() for k in rules_arg.split(",")]
    for k in keys:
        if k not in RULE_REGISTRY:
            raise SystemExit(f"Unknown rule '{k}'. Available: {', '.join(RULE_REGISTRY)}")
    return keys


def load_manifest(operator_path):
    mod = importlib.import_module("rules.operator_manifest")
    target = Path(operator_path)
    if not (target / ".git").exists():
        print("  Cloning opendatahub-operator (shallow)...", file=sys.stderr)
        try:
            mod.clone_operator(target)
        except Exception as exc:
            raise SystemExit(
                f"Failed to clone opendatahub-operator: {exc}\n"
                f"Use --operator-path to provide a pre-cloned copy."
            ) from exc
    manifest = mod.build_manifest(str(target))
    env_vars = set()
    for e in manifest.images:
        env_vars.add(e.env_var)
        if e.manifest_key:
            env_vars.add(e.manifest_key)
    return manifest, env_vars


def adapt_manifest_result(manifest):
    # passed stays True: manifest issues are informational/warning only,
    # not blockers — the csv rule handles actual disconnected-readiness failures.
    result = RuleResult(rule="operator-manifest")
    all_vars = sorted({e.env_var for e in manifest.images})
    result.findings.append(
        Finding(
            severity="info",
            file="",
            line=0,
            image="",
            message=f"Parsed {len(all_vars)} RELATED_IMAGE vars "
            f"across {len(manifest.components)} components.",
        )
    )
    if manifest.known_issues:
        for issue in manifest.known_issues:
            result.findings.append(
                Finding(
                    severity="info",
                    file="",
                    line=0,
                    image="",
                    message=f"Known issue in operator manifest: {issue}",
                )
            )
    return result


def compute_score(results):
    if any(not r.passed for r in results):
        return "NOT READY"
    return "READY"


def print_summary(score, results, log_file=None):
    out = log_file or sys.stderr
    print(f"\nDisconnected Readiness Score: {score}\n", file=out)
    for r in results:
        blockers = sum(1 for f in r.findings if f.severity == "blocker")

        if blockers:
            tag = "FAIL"
            summary_msg = f"{blockers} blocker(s)"
        else:
            tag = "PASS"
            summary_msg = "All checks passed"

        print(f"  {tag:<9} {r.rule:<25} {summary_msg}", file=out)

    total_blockers = sum(1 for r in results for f in r.findings if f.severity == "blocker")
    total_passed = sum(1 for r in results if r.passed)
    print(f"\nBlockers: {total_blockers} | Passed: {total_passed}", file=out)


def render_json(
    score,
    results,
    repo_name,
    verbose=False,
    exceptions=None,
    exception_hits=None,
    today=None,
    git_sha=None,
):
    snippets = _build_exception_snippets(results)
    rules_data = []
    for r in results:
        rule_entry = {
            "name": r.rule,
            "passed": r.passed,
            "blockers": sum(1 for f in r.findings if f.severity == "blocker"),
            "infos": sum(1 for f in r.findings if f.severity == "info"),
            "findings": [
                {
                    "severity": f.severity,
                    "file": f.file,
                    "line": f.line,
                    "image": f.image,
                    "message": f.message,
                }
                for f in sorted(r.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            ],
        }
        reg = _RULE_BY_NAME.get(r.rule, {})
        if reg.get("display_name"):
            rule_entry["display_name"] = reg["display_name"]
        if reg.get("remediation"):
            rule_entry["remediation"] = reg["remediation"]
        if reg.get("reference_doc"):
            rule_entry["reference_doc"] = reg["reference_doc"]
        if verbose and r.files_checked:
            rule_entry["files_checked"] = sorted(set(r.files_checked))
            if r.scan_filters:
                rule_entry["scan_filters"] = r.scan_filters
        rules_data.append(rule_entry)
    data = {
        "repo": repo_name,
        "date": date.today().isoformat(),
        "score": score,
        "rules": rules_data,
    }
    if git_sha:
        data["git_sha"] = git_sha
    if exceptions and exception_hits:
        data["exceptions"] = [
            {
                "rules": sorted(_normalize_rules(exc.get("rules", ""))),
                "reason": exc.get("reason", ""),
                **({"repo": exc["repo"]} if exc.get("repo") else {}),
                **({"expires": exc["expires"].isoformat()} if exc.get("expires") else {}),
                "hits": exception_hits[i],
            }
            for i, exc in enumerate(exceptions)
        ]
        expiring = _find_expiring_exceptions(exceptions, exception_hits, today=today)
        if expiring:
            data["expiring_exceptions"] = [
                {
                    "rules": sorted(_normalize_rules(exc.get("rules", ""))),
                    "reason": exc.get("reason", ""),
                    **({"repo": exc["repo"]} if exc.get("repo") else {}),
                    "expires": exc["expires"].isoformat(),
                    "days_remaining": days_remaining,
                    "hits": hits,
                }
                for exc, days_remaining, hits in expiring
            ]
        expired = _find_expired_exceptions(exceptions, today=today)
        if expired:
            data["expired_exceptions"] = [
                {
                    "rules": sorted(_normalize_rules(exc.get("rules", ""))),
                    "reason": exc.get("reason", ""),
                    **({"repo": exc["repo"]} if exc.get("repo") else {}),
                    "expires": exc["expires"].isoformat(),
                    "days_since_expiry": days_since,
                }
                for exc, days_since in expired
            ]
        _today = today if today is not None else date.today()
        unused = [
            {
                "rules": sorted(_normalize_rules(exc.get("rules", ""))),
                "reason": exc.get("reason", ""),
                **({"repo": exc["repo"]} if exc.get("repo") else {}),
            }
            for i, exc in enumerate(exceptions)
            if i < len(exception_hits)
            and exception_hits[i] == 0
            and exc.get("repo")
            and _repo_matches(exc.get("repo"), repo_name)
            and not (isinstance(exc.get("expires"), date) and exc["expires"] < _today)
        ]
        if unused:
            data["unused_exceptions"] = unused
    if snippets:
        data["false_positive_help"] = {
            "exception_snippets": snippets,
        }
    return json.dumps(data, indent=2)


def _render_template_simple(template_str, context):
    """Minimal Jinja2-compatible renderer for the report template.

    Handles {{ var }}, {{ var | upper }}, and {% for x in y %}...{% endfor %}.
    """

    def resolve(expr, local_ctx):
        expr = expr.strip()
        filt = None
        if "|" in expr:
            expr, filt = expr.rsplit("|", 1)
            expr = expr.strip()
            filt = filt.strip()
        parts = expr.split(".")
        val = local_ctx
        for p in parts:
            val = val.get(p, "") if isinstance(val, dict) else getattr(val, p, "")
        val = str(val)
        if filt == "upper":
            val = val.upper()
        return val

    for_pattern = re.compile(
        r"\{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%\}(.*?)\{%\s*endfor\s*%\}",
        re.DOTALL,
    )

    def expand_for(m):
        var_name = m.group(1)
        collection_name = m.group(2)
        body = m.group(3).strip("\n")
        if re.search(r"\{%\s*for\s+", body):
            raise ValueError(
                "Nested {% for %} blocks are not supported by the built-in template renderer."
            )
        collection = context.get(collection_name, [])
        pieces = []
        for item in collection:
            local = {**context, var_name: item}

            def replace_var(mv, local_context=local):
                return resolve(mv.group(1), local_context)

            rendered = re.sub(
                r"\{\{\s*(.+?)\s*\}\}",
                replace_var,
                body,
            )
            pieces.append(rendered)
        return "\n".join(pieces)

    output = for_pattern.sub(expand_for, template_str)
    return re.sub(
        r"\{\{\s*(.+?)\s*\}\}",
        lambda mv: resolve(mv.group(1), context),
        output,
    )


def _escape_md_cell(value):
    """Escape a string for use inside a Markdown table cell."""
    s = str(value).replace("|", "\\|").replace("\n", " ")
    return s.replace("<", "&lt;").replace(">", "&gt;")


def _build_exception_snippets(results):
    """Build pre-filled exception YAML entries from blocker findings."""
    snippets = []
    for r in results:
        for f in r.findings:
            if f.severity != "blocker":
                continue
            snippet = {"rules": r.rule, "file": f.file, "line": f.line}
            if f.image:
                snippet["image"] = f.image
            if f.message:
                snippet["message"] = f.message
            snippets.append(snippet)
    return snippets


def _build_false_positive_section(snippets):
    """Build the Reporting False Positives markdown section from blocker snippets."""
    if not snippets:
        return ""

    count = len(snippets)
    noun = "finding" if count == 1 else "findings"
    readme_url = (
        "https://github.com/opendatahub-io/disconnected-readiness-scorer#reporting-false-positives"
    )
    lines = [
        "## Reporting False Positives",
        "",
        f"{count} blocker {noun} above may be false positives.",
        "To unblock your PR, add an exception to the central config file.",
        f"See [{readme_url}]({readme_url}) for the format and required fields.",
        "",
    ]

    return "\n".join(lines)


def _build_exceptions_section(exceptions, exception_hits):
    """Build the Applied Exceptions markdown section."""
    if not exceptions or not exception_hits:
        return ""
    applied = [
        (exc, exception_hits[i]) for i, exc in enumerate(exceptions) if exception_hits[i] > 0
    ]
    if not applied:
        return ""
    has_expires = any(exc.get("expires") for exc, _ in applied)
    lines = [
        "## Applied Exceptions",
        "",
    ]
    if has_expires:
        lines.append("| Rules | Repo | Reason | Expires | Hits |")
        lines.append("|-------|------|--------|---------|------|")
    else:
        lines.append("| Rules | Repo | Reason | Hits |")
        lines.append("|-------|------|--------|------|")
    for exc, hits in applied:
        rules_cell = _escape_md_cell(_rules_display_str(exc.get("rules", "")))
        repo = _escape_md_cell(exc.get("repo", ""))
        reason = _escape_md_cell(exc.get("reason", ""))
        if has_expires:
            exp = exc.get("expires")
            expires = _escape_md_cell(exp.isoformat() if exp else "")
            lines.append(f"| {rules_cell} | {repo} | {reason} | {expires} | {hits} |")
        else:
            lines.append(f"| {rules_cell} | {repo} | {reason} | {hits} |")
    lines.append("")
    return "\n".join(lines)


def _find_expiring_exceptions(exceptions, exception_hits, *, today=None):
    """Find exceptions that will expire within the warning window.

    Returns a list of (exception_dict, days_remaining, hits) tuples.
    Excludes already-expired exceptions.
    """
    if today is None:
        today = date.today()
    expiring = []
    for i, exc in enumerate(exceptions):
        exc_expires = exc.get("expires")
        if not isinstance(exc_expires, date):
            continue
        days_remaining = (exc_expires - today).days
        if 0 <= days_remaining <= _EXPIRY_WARNING_DAYS:
            hits = exception_hits[i] if exception_hits and i < len(exception_hits) else 0
            expiring.append((exc, days_remaining, hits))
    return expiring


def _find_expired_exceptions(exceptions, *, today=None):
    """Find exceptions whose expires date is in the past.

    Returns a list of (exception_dict, days_since_expiry) tuples.
    """
    if today is None:
        today = date.today()
    expired = []
    for exc in exceptions:
        exc_expires = exc.get("expires")
        if not isinstance(exc_expires, date):
            continue
        if exc_expires < today:
            days_since = (today - exc_expires).days
            expired.append((exc, days_since))
    return expired


def _audit_exceptions(exceptions):
    """Analyze exceptions for overly broad scope.

    Returns a list of audit finding dicts with keys:
      - index: 0-based position in the exceptions list
      - level: "warning" or "info"
      - reason: human-readable explanation
      - exception: the original exception dict
    """
    findings = []
    for i, exc in enumerate(exceptions):
        rules = exc.get("rules", "")
        is_wildcard = rules == ANY_RULE
        has_repo = bool(exc.get("repo"))
        has_message = bool(exc.get("message"))
        has_images = bool(exc.get("images"))
        has_paths = bool(exc.get("paths"))

        if is_wildcard and has_repo and not has_message and not has_images:
            findings.append(
                {
                    "index": i,
                    "level": "warning",
                    "reason": (
                        f"Repo-specific exception for '{exc.get('repo')}' uses "
                        f'rules: "*" — consider listing specific rule names'
                    ),
                    "exception": exc,
                }
            )
        elif is_wildcard and not has_repo:
            findings.append(
                {
                    "index": i,
                    "level": "info",
                    "reason": "Universal wildcard exception (expected for test/CI/build dirs)",
                    "exception": exc,
                }
            )

        if has_repo and has_paths and not has_message and not has_images:
            paths = exc.get("paths", [])
            has_broad_glob = any("**" in p or p.endswith("*") for p in paths)
            if has_broad_glob:
                findings.append(
                    {
                        "index": i,
                        "level": "warning",
                        "reason": (
                            f"Repo-specific exception for '{exc.get('repo')}' has "
                            f"only broad path globs — consider adding message or "
                            f"images filter for finer granularity"
                        ),
                        "exception": exc,
                    }
                )

    return findings


def _repo_matches(exc_repo, repo_name):
    """Check whether an exception's repo field matches the scanned repo name."""
    if not exc_repo:
        return False
    if "/" in exc_repo:
        return exc_repo == repo_name
    return exc_repo == repo_name.rsplit("/", 1)[-1]


def _build_unused_exceptions_section(exceptions, exception_hits, repo_name="", *, today=None):
    """Build markdown section listing repo-scoped exceptions that matched zero findings."""
    if not exceptions or not exception_hits:
        return ""
    if today is None:
        today = date.today()
    unused = [
        exc
        for i, exc in enumerate(exceptions)
        if i < len(exception_hits)
        and exception_hits[i] == 0
        and exc.get("repo")
        and _repo_matches(exc.get("repo"), repo_name)
        and not (isinstance(exc.get("expires"), date) and exc["expires"] < today)
    ]
    if not unused:
        return ""
    lines = [
        "## Unused Exceptions",
        "",
        f"{len(unused)} exception(s) matched zero findings in this scan "
        "(may be stale or only relevant to other repos).",
        "",
        "| Rules | Repo | Reason |",
        "|-------|------|--------|",
    ]
    for exc in unused:
        rules_cell = _escape_md_cell(_rules_display_str(exc.get("rules", "")))
        repo = _escape_md_cell(exc.get("repo", ""))
        reason = _escape_md_cell(exc.get("reason", ""))
        lines.append(f"| {rules_cell} | {repo} | {reason} |")
    lines.append("")
    return "\n".join(lines)


def _build_expiring_exceptions_section(exceptions, exception_hits, *, today=None):
    """Build markdown section warning about soon-to-expire exceptions."""
    expiring = _find_expiring_exceptions(exceptions, exception_hits, today=today)
    if not expiring:
        return ""
    lines = [
        "## Expiring Exceptions",
        "",
        f"The following {len(expiring)} exception(s) will expire "
        f"within {_EXPIRY_WARNING_DAYS} days.",
        "Update the `expires` date in `config/config.yaml` to renew, "
        "or remediate the underlying findings.",
        "",
        "| Rules | Repo | Reason | Expires | Days Left | Hits |",
        "|-------|------|--------|---------|-----------|------|",
    ]
    for exc, days_remaining, hits in expiring:
        rules_cell = _escape_md_cell(_rules_display_str(exc.get("rules", "")))
        repo = _escape_md_cell(exc.get("repo", ""))
        reason = _escape_md_cell(exc.get("reason", ""))
        expires = exc["expires"].isoformat()
        lines.append(
            f"| {rules_cell} | {repo} | {reason} | {expires} | {days_remaining} | {hits} |"
        )
    lines.append("")
    return "\n".join(lines)


def _build_expired_exceptions_section(exceptions, *, today=None):
    """Build markdown section listing already-expired exceptions."""
    expired = _find_expired_exceptions(exceptions, today=today)
    if not expired:
        return ""
    lines = [
        "## Expired Exceptions",
        "",
        f"The following {len(expired)} exception(s) have expired and are "
        "**no longer applied** — matching findings have reverted to blocker "
        "severity. Renew the `expires` date or remove the exception from "
        "`config/config.yaml`.",
        "",
        "| Rules | Repo | Reason | Expired On | Days Ago |",
        "|-------|------|--------|------------|----------|",
    ]
    for exc, days_since in expired:
        rules_cell = _escape_md_cell(_rules_display_str(exc.get("rules", "")))
        repo = _escape_md_cell(exc.get("repo", ""))
        reason = _escape_md_cell(exc.get("reason", ""))
        expires = exc["expires"].isoformat()
        lines.append(f"| {rules_cell} | {repo} | {reason} | {expires} | {days_since} |")
    lines.append("")
    return "\n".join(lines)


def render_markdown(score, results, repo_name, exceptions=None, exception_hits=None, today=None):
    template_path = Path(__file__).parent / "templates" / "report.md"
    try:
        template_str = template_path.read_text()
    except OSError:
        return f"# Disconnected Readiness Report\n\n**Score:** {score}\n"

    blocker_rows = []
    for r in results:
        for f in r.findings:
            if f.severity == "blocker":
                blocker_rows.append(
                    {
                        "rule": _escape_md_cell(r.rule),
                        "file": _escape_md_cell(f.file),
                        "line": f.line if f.line else "",
                        "message": _escape_md_cell(f.message),
                    }
                )

    context = {
        "repo_name": repo_name,
        "date": date.today().isoformat(),
        "score": score,
        "rules": [
            {
                "name": r.rule,
                "result": "PASS" if r.passed else "FAIL",
                "blockers": sum(1 for f in r.findings if f.severity == "blocker"),
            }
            for r in results
        ],
        "blockers": blocker_rows,
        "exceptions_section": _build_exceptions_section(exceptions, exception_hits),
        "expiring_exceptions_section": _build_expiring_exceptions_section(
            exceptions or [], exception_hits or [], today=today
        ),
        "expired_exceptions_section": _build_expired_exceptions_section(
            exceptions or [], today=today
        ),
        "unused_exceptions_section": _build_unused_exceptions_section(
            exceptions or [], exception_hits or [], repo_name, today=today
        ),
        "false_positive_section": _build_false_positive_section(_build_exception_snippets(results)),
    }

    try:
        import jinja2

        env = jinja2.Environment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
        tmpl = env.from_string(template_str)
        return tmpl.render(**context)
    except ImportError:
        return _render_template_simple(template_str, context)


def _get_repo_name(repo_root):
    """Derive org/name from git remote, fall back to directory basename."""
    try:
        url = subprocess.check_output(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        url = re.sub(r"\.git$", "", url)
        # Normalize SSH git@host:org/repo → org/repo
        ssh_match = re.match(r"[^@]+@[^:]+:(.+)", url)
        if ssh_match:
            url = ssh_match.group(1)
        parts = url.rstrip("/").rsplit("/", 2)
        if len(parts) >= 2:
            return f"{parts[-2]}/{parts[-1]}"
    except (subprocess.CalledProcessError, OSError):
        pass
    return os.path.basename(repo_root)


def _get_git_head_sha(repo_root):
    """Return the HEAD commit SHA, or None if not a git repo."""
    try:
        return subprocess.check_output(
            ["git", "-C", repo_root, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        ).strip()
    except (subprocess.CalledProcessError, OSError):
        return None


def _run_arch_analyzer(arch_analyzer_bin: str, target_dir: str) -> ArchAnalyzerResult:
    """Extract arch-analyzer JSON for a directory.

    Always runs arch-analyzer fresh — never trusts pre-existing JSON
    in the target repo (supply chain safety).
    Raises ArchAnalyzerError if binary missing or extraction fails.
    """
    json_path = os.path.join(target_dir, "component-architecture.json")

    if os.path.lexists(json_path):
        try:
            os.remove(json_path)
        except OSError as exc:
            raise ArchAnalyzerError(f"Failed to remove stale {json_path}: {exc}") from exc

    if not os.path.isfile(arch_analyzer_bin):
        raise ArchAnalyzerError(
            f"arch-analyzer binary not found at {arch_analyzer_bin}.\n"
            f"Install with: make install-arch-analyzer"
        )

    try:
        subprocess.run(
            [arch_analyzer_bin, "extract", ".", "--extractors", "docker,kustomize"],
            cwd=target_dir,
            capture_output=True,
            timeout=300,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        stderr_msg = e.stderr.decode(errors="replace") if e.stderr else str(e)
        raise ArchAnalyzerError(f"arch-analyzer failed on {target_dir}:\n{stderr_msg}") from e
    except (subprocess.TimeoutExpired, OSError) as e:
        raise ArchAnalyzerError(f"arch-analyzer failed on {target_dir}: {e}") from e

    if not os.path.isfile(json_path):
        raise ArchAnalyzerError(f"arch-analyzer did not generate {json_path}")

    try:
        with open(json_path) as f:
            return ArchAnalyzerResult.from_dict(json.load(f))
    except (json.JSONDecodeError, OSError) as e:
        raise ArchAnalyzerError(f"Failed to parse {json_path}: {e}") from e


def _run(
    args,
    operator_path,
    *,
    manifest=None,
    manifest_env_vars=None,
    operator_arch_data=None,
    log_stream=None,
    central_cfg=None,
):
    """Run all selected rules on a repo and produce reports.

    Optional keyword args allow callers (e.g. run_all.py) to pass
    pre-computed operator data to avoid redundant work across repos.
    *log_stream* overrides sys.stderr for diagnostic output (thread-safe).
    *central_cfg*, if provided, skips this function's own config load —
    used by main() to load+validate the config exactly once for all CLI modes.
    """
    repo_root = os.path.abspath(args.repo_root)
    repo_name = _get_repo_name(repo_root)
    selected = resolve_rules(args.rules)
    verbose = getattr(args, "verbose", False)
    arch_analyzer_bin = getattr(args, "arch_analyzer", "")
    _stderr = log_stream or sys.stderr

    def _vlog(msg):
        if verbose:
            print(f"  [verbose] {msg}", file=_stderr)

    t_total = time.monotonic()

    _vlog(f"Repo: {repo_name} at {repo_root}")
    _vlog(f"Selected rules: {selected}")

    # --- Central config (loaded once, used for exceptions + detect_params_env) ---
    if central_cfg is None:
        _central_config_path = args.config or str(Path(__file__).parent / CENTRAL_CONFIG_PATH)
        central_cfg = load_central_config(_central_config_path)
    docker_contexts = central_cfg.get("docker_contexts", {}).get(repo_name, {})
    if not docker_contexts:
        docker_contexts = central_cfg.get("docker_contexts", {}).get(repo_name.split("/")[-1], {})
    non_image_prefixes = central_cfg.get("known_non_image_prefixes", [])
    _pef_map = central_cfg.get("params_env_filenames", {})
    params_env_extra = _pef_map.get(repo_name) or _pef_map.get(repo_name.split("/")[-1]) or []
    module_mode = getattr(args, "module_mode", False)
    if not module_mode and detect_module(Path(repo_root)):
        _vlog("Auto-detected module layout; switching to module mode")
        module_mode = True

    need_manifest = "manifest" in selected
    image_pattern = None
    for key in selected:
        if not RULE_REGISTRY[key].get("needs_manifest"):
            continue
        mod = importlib.import_module(RULE_REGISTRY[key]["module"])
        if hasattr(mod, "detect_image_pattern"):
            if image_pattern is None:
                image_pattern = mod.detect_image_pattern(Path(repo_root))
            if image_pattern == "env_var":
                _vlog(f"rule {key}: detected env_var pattern, manifest needed")
                need_manifest = True
                break
        elif hasattr(mod, "detect_params_env"):
            if mod.detect_params_env(Path(repo_root), extra_filenames=params_env_extra):
                _vlog(f"rule {key}: detected params.env pattern, manifest needed")
                need_manifest = True
                break

    if module_mode:
        t0 = time.monotonic()
        _vlog("Module mode: building manifest from module source, skipping operator clone")
        manifest_obj = build_module_manifest(repo_root)
        manifest_env_vars = {e.env_var for e in manifest_obj.images}
        manifest = manifest_obj
        _vlog(f"load_manifest: {time.monotonic() - t0:.1f}s")
    elif need_manifest and manifest is None:
        t0 = time.monotonic()
        manifest, manifest_env_vars = load_manifest(operator_path)
        _vlog(f"load_manifest: {time.monotonic() - t0:.1f}s")

    # --- Run arch-analyzer (REQUIRED) ---
    t0 = time.monotonic()
    if operator_arch_data is None:
        operator_arch_data = _run_arch_analyzer(arch_analyzer_bin, operator_path)
        if operator_arch_data:
            print("  Loaded operator architecture data", file=_stderr)
    component_arch_data = _run_arch_analyzer(arch_analyzer_bin, repo_root)
    if component_arch_data:
        print("  Loaded component architecture data", file=_stderr)
    _vlog(f"arch_analyzer: {time.monotonic() - t0:.1f}s")

    # --- Production scope ---
    prod_scope = None
    if not getattr(args, "no_production_scope", False):
        t0 = time.monotonic()
        manifest_source_folders = None
        overlay_paths = None
        repo_basename = os.path.basename(repo_root)
        op_manifest_mod = importlib.import_module("rules.operator_manifest")

        # Parse manifest entries once (both source_folders and component_keys)
        source_folders_map, component_keys_map = op_manifest_mod.parse_manifest_entries(
            operator_path
        )
        manifest_source_folders = source_folders_map.get(repo_basename)
        if manifest_source_folders:
            print(
                f"  Operator mapping: {repo_basename} → {manifest_source_folders}",
                file=_stderr,
            )

        # Determine overlay paths
        if operator_arch_data:
            component_key = component_keys_map.get(repo_basename)
            if component_key:
                raw_overlays = op_manifest_mod.parse_overlay_paths_from_arch_data(
                    operator_arch_data,
                    component_key,
                )
                if raw_overlays and manifest_source_folders:
                    overlay_paths = [
                        os.path.join(sf, ov)
                        for sf in manifest_source_folders
                        for ov in raw_overlays
                    ]
                elif raw_overlays:
                    overlay_paths = raw_overlays
                if overlay_paths:
                    print(
                        f"  Overlay paths ({component_key}): {overlay_paths}",
                        file=_stderr,
                    )

        prod_scope = compute_production_scope(
            Path(repo_root),
            manifest_source_folders=manifest_source_folders,
            overlay_paths=overlay_paths,
            arch_data=component_arch_data,
            docker_contexts=docker_contexts or None,
        )
        _vlog(f"production_scope: {time.monotonic() - t0:.1f}s")
        if prod_scope:
            parts = []
            if prod_scope.production_dirs:
                parts.append(f"{len(prod_scope.production_dirs)} dirs")
            if prod_scope.manifest_files:
                parts.append(f"{len(prod_scope.manifest_files)} manifest files")
            print(
                f"  Production scope: {prod_scope.method} ({', '.join(parts)})",
                file=_stderr,
            )

    results = []
    for key in selected:
        entry = RULE_REGISTRY[key]
        mod = importlib.import_module(entry["module"])

        if entry.get("is_manifest_rule"):
            t0 = time.monotonic()
            if manifest is None:
                manifest, manifest_env_vars = load_manifest(operator_path)
            results.append(adapt_manifest_result(manifest))
            _vlog(f"rule {key}: {time.monotonic() - t0:.1f}s")
            continue

        kwargs = {}
        if entry.get("needs_manifest") and manifest_env_vars is not None:
            kwargs["manifest_env_vars"] = manifest_env_vars
        if module_mode:
            kwargs["module_mode"] = True
        if prod_scope is not None:
            kwargs["production_scope"] = prod_scope
        if component_arch_data:
            kwargs["arch_data"] = component_arch_data
        if non_image_prefixes:
            kwargs["non_image_prefixes"] = non_image_prefixes
        if key == "params_env" and params_env_extra:
            kwargs["extra_filenames"] = params_env_extra
        t0 = time.monotonic()
        result = mod.run(repo_root, **kwargs)
        _vlog(f"rule {key}: {time.monotonic() - t0:.1f}s")
        results.append(result)

    exceptions = central_cfg["exceptions"]
    today = date.today()
    exception_hits = (
        apply_exceptions(results, exceptions, repo_name, today=today) if exceptions else []
    )

    score = compute_score(results)
    print_summary(score, results, log_file=_stderr)

    formats = [f.strip() for f in args.report.split(",")]
    _valid_formats = {"json", "markdown"}
    for fmt in formats:
        if fmt not in _valid_formats:
            raise SystemExit(f"Unknown report format '{fmt}'. Valid: {', '.join(_valid_formats)}")

    outputs = args.output or []

    if outputs and len(outputs) != len(formats):
        raise SystemExit(
            f"Mismatch: {len(formats)} report format(s) but {len(outputs)} output path(s). "
            f"Provide one -o per --report format, in the same order."
        )

    git_sha = _get_git_head_sha(repo_root)

    exc_args = {"exceptions": exceptions, "exception_hits": exception_hits, "today": today}

    for i, fmt in enumerate(formats):
        if fmt == "json":
            report = render_json(
                score, results, repo_name, verbose=verbose, git_sha=git_sha, **exc_args
            )
        else:
            report = render_markdown(score, results, repo_name, **exc_args)

        if outputs:
            Path(outputs[i]).write_text(report + "\n")
            print(f"\nReport written to {outputs[i]}", file=_stderr)
        else:
            print(report)

    _vlog(f"total: {time.monotonic() - t_total:.1f}s")
    return 0 if score != "NOT READY" else 1


def main(argv=None):
    args = parse_args(argv)

    # Loaded once here, before any CLI mode branches, so every mode that needs
    # central_cfg (list-expiring, audit-exceptions, scan) fails the same way on
    # an invalid --config instead of each mode guarding this call independently.
    config_path = args.config or str(Path(__file__).parent / CENTRAL_CONFIG_PATH)
    try:
        central_cfg = load_central_config(config_path)
    except (ConfigError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.list_expiring:
        exceptions = central_cfg["exceptions"]
        dummy_hits = [0] * len(exceptions)
        today = date.today()
        expired = _find_expired_exceptions(exceptions, today=today)
        expiring = _find_expiring_exceptions(exceptions, dummy_hits, today=today)
        found = False
        if expired:
            found = True
            print(f"{len(expired)} expired exception(s) — no longer applied:\n")
            print(f"{'Rules':<25} {'Repo':<30} {'Expired On':<12} {'Days Ago':<10} Reason")
            print("-" * 100)
            for exc, days_since in expired:
                rules_value = _rules_display_str(exc.get("rules", ""))
                print(
                    f"{rules_value:<25} "
                    f"{exc.get('repo', ''):<30} "
                    f"{exc['expires'].isoformat():<12} {days_since:<10} "
                    f"{exc.get('reason', '')}"
                )
            print()
        if expiring:
            found = True
            print(f"{len(expiring)} exception(s) expiring within {_EXPIRY_WARNING_DAYS} days:\n")
            print(f"{'Rules':<25} {'Repo':<30} {'Expires':<12} {'Days Left':<10} Reason")
            print("-" * 100)
            for exc, days_remaining, _ in expiring:
                rules_value = _rules_display_str(exc.get("rules", ""))
                print(
                    f"{rules_value:<25} "
                    f"{exc.get('repo', ''):<30} "
                    f"{exc['expires'].isoformat():<12} {days_remaining:<10} "
                    f"{exc.get('reason', '')}"
                )
        if not found:
            print("No expired or expiring exceptions found.")
            return 0
        return 2

    if args.audit_exceptions:
        exceptions = central_cfg["exceptions"]
        audit_findings = _audit_exceptions(exceptions)
        warnings = [f for f in audit_findings if f["level"] == "warning"]
        infos = [f for f in audit_findings if f["level"] == "info"]
        if warnings:
            print(f"{len(warnings)} warning(s) — exceptions with overly broad scope:\n")
            print(f"{'#':<4} {'Rules':<30} {'Repo':<25} Reason")
            print("-" * 100)
            for finding in warnings:
                exc = finding["exception"]
                rules_value = _rules_display_str(exc.get("rules", ""))
                print(
                    f"{finding['index'] + 1:<4} "
                    f"{rules_value:<30} "
                    f"{exc.get('repo', ''):<25} "
                    f"{finding['reason']}"
                )
            print()
        if infos:
            print(
                f"{len(infos)} info(s) — universal wildcard exceptions "
                f"(expected for test/CI/build dirs):\n"
            )
            print(f"{'#':<4} {'Paths (first)':<50} Reason")
            print("-" * 80)
            for finding in infos:
                exc = finding["exception"]
                paths = exc.get("paths", [])
                first_path = paths[0] if paths else "(no paths)"
                print(f"{finding['index'] + 1:<4} {first_path:<50} {exc.get('reason', '')}")
        if not audit_findings:
            print("No audit findings — all exceptions are well-scoped.")
            return 0
        return 2 if warnings else 0

    try:
        if args.operator_path:
            return _run(args, args.operator_path, central_cfg=central_cfg)

        with tempfile.TemporaryDirectory(prefix="odh-operator-") as tmp_dir:
            return _run(args, tmp_dir, central_cfg=central_cfg)
    except (ArchAnalyzerError, ConfigError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

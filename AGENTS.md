# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A Claude Code skill (plugin) that scores a repository's readiness for disconnected / air-gapped OpenShift deployments. It is invoked as `/disconnected-score` from any RHOAI component repo. The skill definition lives in `skills/disconnected-score/SKILL.md`.

## Dependencies

Managed via `pyproject.toml` + [uv](https://docs.astral.sh/uv/):

```bash
uv sync --extra dev          # install all dev dependencies
pre-commit install           # install git hooks (runs ruff on commit)
```

Runtime deps: `pyyaml` (required). Optional: `jinja2` (for Jinja2-based report rendering, falls back to built-in renderer).

## Testing

```bash
python -m pytest tests/ -v                                 # all tests
python -m pytest tests/test_image_manifest_complete.py -v        # single test file
python -m pytest tests/test_main.py::TestParseArgs -v      # single test class
python -m pytest tests/ -v --cov=. --cov-report=term       # with coverage
```

CI runs on Python 3.12 (`.github/workflows/ci.yml`). Codecov enforces 80% patch coverage.

Tests use `tmp_path` fixtures to create disposable repo layouts (Go files, YAML manifests, etc.) and assert on `RuleResult` / `Finding` fields. No external network calls or fixtures needed.

## Running the Orchestrator

`main.py` runs all (or selected) rules and produces the aggregate score:

```bash
python3 main.py /path/to/target/repo                     # all default rules
python3 main.py . --rules csv,tags                        # subset of rules
python3 main.py . --report json                           # JSON output
python3 main.py . --operator-path /tmp/opendatahub-operator  # pre-cloned operator
python3 main.py . --module-mode                           # validate as standalone module (no operator clone)
python3 main.py . --verbose                               # diagnostics + timing + files_checked in JSON
```

Rule aliases: `csv`, `tags`, `egress`, `python`, `params_env`, `manifest`. Exit code is 0 for READY, 1 for NOT READY.

**Module mode** (`--module-mode`): for repos that define their own `RELATED_IMAGE_*` set (modularized components with `*-module/` subdirectories or `pkg/**/images.go`). The scorer uses the module's own image definitions as the authority instead of cloning the operator. Auto-detected via `detect_module()`; the flag makes the selection explicit and takes precedence over `--operator-path`.

## Running Rules Individually

Each rule is a standalone Python script with a `run(repo_root: str) -> RuleResult` entry point. Run any rule directly:

```bash
python3 rules/image_manifest_complete.py /path/to/target/repo
python3 rules/no_image_tags.py .
python3 rules/no_runtime_egress.py .
python3 rules/python_imports.py .
python3 rules/operator_manifest.py /tmp/opendatahub-operator
```

All rules output JSON to stdout with `rule`, `passed`, and `findings` fields.

## Architecture

**Orchestrator (`main.py`):** CLI entry point that imports rules as modules, runs them, computes the aggregate score, and renders output (console summary + markdown or JSON report). Handles the operator manifest lifecycle — only clones when a `needs_manifest`-flagged rule (`csv`, `params_env`, or `tags`) detects a pattern needing cross-referencing, or when `manifest` is explicitly selected. Supports `--config` to load exception rules that downgrade matching findings to info severity. Computes production scope once via `production_scope.compute_production_scope()` and passes it to all rules. Use `--no-production-scope` to disable. Supports `--verbose` / `-v` for detailed diagnostic output (per-step timing, file scan progress, config loading, production scope decisions). When combined with `--report json`, includes `files_checked` per rule in the JSON output. `ArchAnalyzerError` is raised when the arch-analyzer binary is missing or fails, caught in `main()` for clean error reporting.

**Shared types (`rules/common.py`):** `Finding`, `RuleResult`, `ProductionScope`, `Severity` enum, and `ConfigError` exception used by all rules, plus `get_tracked_files()`, `is_file_in_production_scope()`, `is_yaml_in_production_scope()`, `downgrade_non_production_overlay()`, `detect_image_pattern()`, and the `RELATED_IMAGE_PATTERN` regex. `detect_image_pattern()` and `RELATED_IMAGE_PATTERN` are genuinely shared — both `image_manifest_complete.py` and `no_image_tags.py` need them — everything else specific to `RELATED_IMAGE_*` handling (`extract_related_image_vars()`, the file/directory-level var lookup) lives privately in `image_manifest_complete.py`, since `no_image_tags.py` uses a different, stricter mechanism of its own (see its bullet below) rather than sharing that lookup. The `Severity` enum (`blocker`/`info`) validates severity strings at `Finding` construction time via `__post_init__` — invalid severities raise `ValueError`. `ConfigError` is raised when a config file exists but cannot be read or parsed. Each rule uses a dual-import pattern: `try: from rules.common import ...` / `except ModuleNotFoundError: from common import ...` so standalone execution (`python3 rules/foo.py .`) works without the package being installed. The catch is deliberately narrow (`ModuleNotFoundError` only, not `ImportError`) to avoid masking other import errors such as misspelled symbols or circular imports. Tests import via the package path (`from rules.common import ...`).

**Rule engine pattern:** Every rule module under `rules/` exports a `run(repo_root) -> RuleResult` function. `RuleResult` is a dataclass with `rule` (name), `passed` (bool), and `findings` (list of `Finding`). Each `Finding` has `severity` (blocker/info), `file`, `line`, `image`, and `message`. Severity is binary: blocker (will/may break disconnected) or info (excluded file, configurable pattern, or informational).

**Rules:**

- `image_manifest_complete.py` — Auto-detects whether the target repo uses `RELATED_IMAGE_*` env vars (opendatahub-operator pattern) or static CSV `relatedImages`, then checks image completeness against the detected pattern. Accepts optional `manifest_env_vars` parameter — when provided by the orchestrator, cross-references the target repo's env vars against the authoritative manifest (operator manifest in normal mode; the module's own definitions in module mode). Accepts `module_mode=True` to skip the operator-stale-var check (vars defined by the module are valid by definition) and adjust finding messages to reference the "module manifest" rather than "operator manifest". Filters scanned files to git-tracked only.
- `params_env.py` — Validates repos using the `params.env` + kustomize pattern. Requires kustomize binary. Validates the full wiring chain: params.env → kustomize configMap → rendered manifest → Go os.Getenv. Detects hardcoded images not sourced from params.env (blocker), unwired params.env keys (blocker), and orphan Go os.Getenv calls (blocker). Accepts optional `manifest_env_vars` for operator manifest cross-referencing.
- `params_env_utils.py` — Utility functions for params.env + kustomize validation, adapted from `verify-params-env-images.py`. Handles params.env parsing, overlay discovery, kustomize build, probe-based hardcoded image detection, configMapKeyRef wiring, and Go env var cross-referencing. Used by `params_env.py`.
- `operator_manifest.py` — Parses the opendatahub-operator source to build the authoritative image manifest via `build_manifest()`. Returns a `Manifest` dataclass (not RuleResult); the orchestrator adapts it via `adapt_manifest_result()`. When no `--operator-path` is provided, `main.py` uses `tempfile.TemporaryDirectory(prefix="odh-operator-")` and clones the operator repo there. Also extracts overlay paths from operator Go source (`parse_component_overlay_paths()`) to determine which kustomize overlays are actually deployed per platform — used by `params_env` to filter out non-production overlays. In module mode, `detect_module(repo_root)` detects `*-module/` subdirectories or `pkg/**/images.go` containing `RELATED_IMAGE_*`, and `build_module_manifest(repo_root)` builds an equivalent `Manifest` from the module's own Go source — same type, no operator clone needed.
- `no_image_tags.py` — Enforces `@sha256:` digest refs; rejects mutable tags. Detects three patterns: qualified images (`registry/org/name:tag`), `oci://` URIs without digest pin, and unqualified k8s images (`image: name:tag` in YAML `image:` fields). Source code and manifest files produce blocker severity. For `.yaml`/`.yml`, tagged matches on lines belonging to OpenAPI-style documentation fields (`description`, `example`, `examples`) are downgraded to info with `[documentation field]` via `documentation_field_lines()` (see `rules/yaml_documentation_fields.py`); real `image:` / schema `default:` fields remain blockers. `_emit_finding()` routes both the qualified-image and k8s-unqualified-image match branches in `scan_file()` through the same classification/downgrade/emit pipeline so the two can't drift out of sync. Skips directories managed by params.env + kustomize. Filters to git-tracked files only. HTTP/HTTPS URLs are excluded from image detection. Skips `package.json` files to avoid false positives from npm package references. Accepts optional `manifest_env_vars` — when provided, a blocker is downgraded to info only when a confirmed `RELATED_IMAGE_*` var is textually inside the same balanced-paren block as the image in source files, or on the same line in non-source files (YAML, params.env, JSON, TOML), in the same file — see "Manifest cross-referencing" below for why this is stricter than `image_manifest_complete.py`'s own lookup.
- `yaml_documentation_fields.py` — `documentation_field_lines()`: returns the 1-based line numbers belonging to a `description`/`example`/`examples` subtree, used by `no_image_tags.py` to downgrade sample text in schemas. Schema keywords (`default`/`enum`/`const`) never inherit docs status from an ancestor docs key (so a CRD property named `description` cannot launder its defaults). Walks PyYAML's `yaml.parse()` event stream so each alias stays a distinct site from its anchor; see the module docstring for the full threat model. Detection is line-granular: a real `image:` sharing a flow-style line with a docs key is also downgraded (rare in block-style k8s YAML).
- `no_runtime_egress.py` — Detects outbound HTTP calls in Go/Python/TS/shell source and inline shell commands embedded in YAML manifests (`.yaml`/`.yml`). Distinguishes hardcoded URLs (blocker) from configurable ones (info). Also detects HuggingFace model downloads (`hf download`, `huggingface-cli download`) as always-blocker. YAML scanning catches `curl`/`wget` calls embedded in Kubernetes CronJob/Job/Pod `command:` or `args:` fields. Filters to git-tracked files only.
- `python_imports.py` — Validates Python deps against the known-bundled list. Checks requirements files, `setup.py`, `pyproject.toml`, and runtime `pip install` calls.

**Manifest cross-referencing:** When the orchestrator runs, it detects the target repo's image pattern. If env_var or params_env, it clones the opendatahub-operator, builds the authoritative manifest via `operator_manifest.build_manifest()`, and passes the env var set to `image_manifest_complete.run()` and `no_image_tags.run()`. For env_var: (A) image ref uses a RELATED_IMAGE var not in the manifest → blocker, (B) repo defines a var not in the manifest → blocker, (C) manifest vars not referenced in repo → info. For params_env: validates that RELATED_IMAGE vars mapped from params.env keys exist in the operator manifest. For `no_image_tags`: a blocker is downgraded to info only when a confirmed `RELATED_IMAGE_*` var sits inside the same balanced-paren block as the image (source files) or on the same line (non-source files) — no whole-file and no cross-file matching. This is deliberately stricter than `image_manifest_complete.py`'s own same-line → whole-file → sibling-`.go`-file lookup, which stays as-is: reusing that coarser lookup for `no_image_tags` was found, by review, to produce false negatives (an unrelated var anywhere in the file or in a sibling file being treated as "covering" an unrelated image), since downgrading a `no-image-tags` finding cancels a different rule's independently-detected tag-mutability defect outright, not just an internal annotation. The two rules intentionally do not share this decision logic — `no_image_tags.py`'s balanced-paren block detection is private to that module.

**Production scope (`rules/production_scope.py`):** Reduces false positives by narrowing scanning to production source directories. Uses arch-analyzer's `dockerfiles[].copy_instructions[].original_sources` to identify which directories are COPYed into Docker images. Returns a `ProductionScope` with `production_dirs` (set of resolved directory paths). Rules skip files outside `production_dirs` (no findings emitted). Applies to ALL file types (Go, Python, YAML, shell, etc). Returns `None` (full scan) when arch_data has no original_sources.

**Exclusion logic:** Test-path exclusion is handled centrally by `config/config.yaml`, not by individual rules. The exceptions mechanism downgrades matching blocker findings to info severity based on file path globs, covering test directories, CI config, build files, and lint rules. Rules emit findings at their natural severity; the orchestrator applies exceptions post-hoc. Exceptions may have an optional `expires` date (ISO 8601 `YYYY-MM-DD`); expired exceptions are skipped in `apply_exceptions()`, and exceptions expiring within 14 days are flagged in the report output. Use `--list-expiring` to list soon-to-expire exceptions without running a scan. Use `--audit-exceptions` to analyze exception scope quality (detects overly broad repo-specific wildcards and missing message/images filters). After a scan, unused exceptions (zero hits) are reported in both markdown and JSON output.

**Central config (`config/config.yaml`):** Single unified YAML with exception rules that apply to all scanned repos. Loaded by the orchestrator via `--config` or defaults to `config/config.yaml`. A missing config file — whether the default path or an explicitly passed `--config` path — is a hard error (`ValueError`), never a silent "no exceptions" fallback. JSON schema at `schemas/config.schema.json`. In the reusable GH Actions workflow (`.github/workflows/disconnected-readiness-check.yml`), this file is always fetched fresh from `main` via `--config`, independent of the pinned scorer code version — see [docs/VERSIONING.md](docs/VERSIONING.md#what-pinning-does-and-does-not-cover). Each exception entry has a `rules` field that accepts a single rule name string, a list of rule names, or `"*"` for all rules. Rule names are validated against `RULE_REGISTRY` at load time. The wildcard `"*"` is only allowed as a standalone string, not inside a list. Prefer naming specific rules over using `"*"` — the wildcard should only be used when the excepted path genuinely cannot produce valid findings for any rule (e.g. test directories, CI config, build files). For repo-specific exceptions, consider which rules the path could realistically violate and list only those — overly broad wildcards can silently hide real issues that a more targeted exception would have caught. Pattern matching uses glob (fnmatch), not regex — glob covers current use cases. A `re:` prefix syntax is the planned extension point if regex becomes necessary.

**Configuration:** All configuration is managed centrally through `config/config.yaml`. No per-repository configuration files are supported. Repo-specific exceptions use the `repo` field in the central config to scope them to a single component.

**Report rendering:** `templates/report.md` uses Jinja2-style `{{ }}` placeholders. The orchestrator tries `import jinja2` first; falls back to a built-in micro-renderer that handles `{{ var }}`, `{{ var | upper }}`, and `{% for %}` blocks.

**Maturity report (`maturity_report.py`):** Transforms per-repo JSON reports (from `run_all.py`) into the `ExternalBatchReport` wire format consumed by the component-maturity system. Reads `.github/config/repo_mappings.json` (vendored from the software catalog) to map repos to component-maturity catalog IDs via `jira_component.lower().replace(" ", "-")`. Repos sharing a Jira component are merged into one evaluation set. Supports path-scoped mappings: entries with a `path` field route findings from that subdirectory to the specified component using longest-prefix match, with the pathless entry as default. Accepts `--repo-mappings` to override the vendored file. Outputs `disconnected-readiness-report.json`, uploaded as a GitHub Actions artifact by `readiness-summary.yml`. See `docs/component-maturity-integration.md` for the full data flow and artifact contract. Rule definitions include `remediation` text and `reference_doc` URLs pointing to `docs/references/<rule-id>.md`. **The `docs/references/` files are consumed standalone by the component-maturity system** — they must be fully self-contained with only absolute links and no assumptions about surrounding repo context. Always use absolute URLs (e.g. `https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/...`) when linking to other files in this repo.

## Severity Levels

| Severity | Meaning                                                                    |
|----------|----------------------------------------------------------------------------|
| blocker  | Will or may break disconnected — must be fixed or granted an exception     |
| info     | Excluded file, configurable pattern, or informational — does not block     |

## Code Quality

Python code quality is managed via [ruff](https://docs.astral.sh/ruff/), a fast Python linter and formatter.

```bash
# Lint and auto-fix violations
uv run ruff check .                  # Check for violations
uv run ruff check . --fix            # Auto-fix safe violations
uv run ruff format .                 # Format code

# Check without modifying
uv run ruff check . --no-fix         # Lint only (no fixes)
uv run ruff format --check .         # Verify formatting (CI mode)
```

**Configuration:** Located in `ruff.toml`. Targets Python 3.12+ with comprehensive rule set including:
- Core style (E/W/F/I): pycodestyle errors, warnings, Pyflakes, isort
- Modern Python (UP): Type hint modernization (List[T] → list[T], Optional[T] → T | None)
- Code quality (B/C4/PIE/RET/SIM): bugbear, comprehensions, simplification, returns

CI runs `ruff check` and `ruff format --check` before tests. PRs are blocked on style violations. Install pre-commit hooks with `pre-commit install` for local enforcement.

**VS Code integration:** Install the [Ruff extension](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff) for real-time linting and formatting.

## Post-Change Checklist

After modifying rules, config, or architecture, update `README.md` and `AGENTS.md` to reflect the changes. Both files document rule behavior, config options, exceptions, and architecture — they must stay in sync with the code. When modifying rule behavior, also update the corresponding `docs/references/<rule-id>.md` — these are the primary per-rule docs surfaced by the component-maturity system. Remember: `docs/references/` files must use only absolute links (they are consumed standalone outside this repo).

When modifying a function, verify it has test coverage before declaring the change complete. If the function is untested, add tests for the changed behavior — do not rely on the absence of test failures as proof of correctness.

## Key Design Decisions

- The `image_manifest_complete` rule detects the image management pattern (env var vs static CSV) automatically rather than requiring config. Threshold: 5+ `RELATED_IMAGE_*` occurrences in Go source → env var pattern.
- `operator_manifest.py` shells out to `git clone --depth 1` (list form, no shell) to fetch the operator source. When no `--operator-path` is given, the orchestrator uses `tempfile.TemporaryDirectory()` for automatic cleanup. The repo URL is hardcoded to the upstream operator; it is never user-supplied.
- Optional `yaml` import: rules that parse YAML skip their checks if PyYAML is not installed.

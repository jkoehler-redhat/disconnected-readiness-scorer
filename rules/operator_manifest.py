#!/usr/bin/env python3
"""Parse the opendatahub-operator to extract the authoritative image manifest.

This is the foundation rule — it reads the operator source code to build
the definitive list of RELATED_IMAGE_* env vars, which component each
belongs to, and which Go file defines it. This manifest is the source of
truth for what images must be mirrorable in disconnected environments.
"""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

try:
    from rules.common import ArchAnalyzerResult, Finding, RuleResult
except ModuleNotFoundError:
    from common import ArchAnalyzerResult, Finding, RuleResult

RELATED_IMAGE_PATTERN = re.compile(r'"(RELATED_IMAGE_[A-Z0-9_]+)"')
IMAGE_MAP_PATTERN = re.compile(r'"([^"]+)":\s*"(RELATED_IMAGE_[A-Z0-9_]+)"')
KNOWN_ISSUES_PATTERN = re.compile(r"- image:\s*(RELATED_IMAGE_[A-Z0-9_]+)")

OPERATOR_REPO_NAME = "opendatahub-io/opendatahub-operator"
OPERATOR_REPO = f"https://github.com/{OPERATOR_REPO_NAME}.git"
COMPONENTS_PATH = "internal/controller/components"

# Minimal skip set for the operator repo (no .tox/.devcontainer present).
SKIP_DIRS = {".git", "vendor", "node_modules", "__pycache__"}
TEST_SUFFIXES = {"_test.go", "_int_test.go", "_internal_test.go"}


@dataclass
class ImageEntry:
    env_var: str
    component: str
    manifest_key: str
    source_file: str
    source_line: int


@dataclass
class Manifest:
    images: list = field(default_factory=list)
    components: dict = field(default_factory=dict)
    known_issues: list = field(default_factory=list)


_MANIFEST_ENTRY_RE = re.compile(r'\["([^"]*)"\]\s*=\s*"([^:]+):([^:]+):([^:]+):([^"]+)"')


def parse_manifest_entries(operator_path: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Parse get_all_manifests.sh → (repo→source_folders, repo→component_key).

    Parses ODH_COMPONENT_MANIFESTS, ODH_COMPONENT_CHARTS, and ODH_CCM_CHARTS arrays
    in a single pass (regex matches entry format, not array name).
    Returns tuple of:
    - repo→source_folders: e.g. ``{'kserve': ['config'], 'odh-dashboard': ['manifests']}``
    - repo→component_key: e.g. ``{'kserve': 'kserve', 'kubeflow': 'workbenches/kf-notebook-controller'}``
    """
    script = Path(operator_path) / "get_all_manifests.sh"
    if not script.is_file():
        return {}, {}

    try:
        content = script.read_text()
    except (OSError, UnicodeDecodeError):
        return {}, {}

    source_folders: dict[str, list[str]] = {}
    component_keys: dict[str, str] = {}

    for match in _MANIFEST_ENTRY_RE.finditer(content):
        component_key = match.group(1)
        repo_name = match.group(3)
        source_folder = match.group(5)

        source_folders.setdefault(repo_name, [])
        if source_folder not in source_folders[repo_name]:
            source_folders[repo_name].append(source_folder)

        component_keys.setdefault(repo_name, component_key)

    return source_folders, component_keys


_COMPONENT_DIR_MAP = {
    "maas": "modelsasservice",
}

_SKIP_OVERLAY_COMPONENTS = {"operator"}


def _get_component_dir(component_key: str) -> str:
    """Map component key to operator component directory name."""
    if "/" in component_key:
        return component_key.split("/")[0]
    return _COMPONENT_DIR_MAP.get(component_key, component_key)


def parse_overlay_paths_from_arch_data(
    arch_data: ArchAnalyzerResult,
    component_key: str,
) -> list[str]:
    """Extract deployed overlay paths from arch-analyzer kustomize_components.

    Reads ``overlay_paths`` from the operator's component-architecture.json
    ``kustomize_components`` section.
    Returns a deduplicated list of paths.
    """
    if component_key in _SKIP_OVERLAY_COMPONENTS:
        return []

    dir_name = _get_component_dir(component_key)

    for comp in arch_data.kustomize_components:
        parts = comp.support_file.split("/")
        if "components" not in parts:
            continue
        idx = parts.index("components")
        if idx + 1 >= len(parts) or parts[idx + 1] != dir_name:
            continue

        if not comp.overlay_paths:
            return []

        result: list[str] = []
        for path in comp.overlay_paths:
            path = path.strip("/")
            if path and path not in result:
                result.append(path)
        return result

    return []


def clone_operator(target_dir: Path) -> Path:
    """Clone the operator repo if not already present."""
    if target_dir.exists() and (target_dir / ".git").exists():
        return target_dir
    subprocess.run(
        ["git", "clone", "--depth", "1", OPERATOR_REPO, str(target_dir)],
        capture_output=True,
        check=True,
    )
    return target_dir


def parse_component_images(component_dir: Path, component_name: str) -> list[ImageEntry]:
    """Parse a component's Go files for RELATED_IMAGE mappings."""
    entries = []

    for go_file in component_dir.rglob("*.go"):
        if any(go_file.name.endswith(s) for s in TEST_SUFFIXES):
            continue

        try:
            lines = go_file.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for i, line in enumerate(lines, 1):
            map_match = IMAGE_MAP_PATTERN.search(line)
            if map_match:
                entries.append(
                    ImageEntry(
                        env_var=map_match.group(2),
                        component=component_name,
                        manifest_key=map_match.group(1),
                        source_file=str(go_file),
                        source_line=i,
                    )
                )
                continue

            for match in RELATED_IMAGE_PATTERN.finditer(line):
                env_var = match.group(1)
                if env_var == "RELATED_IMAGE_*":
                    continue
                if not any(e.env_var == env_var and e.component == component_name for e in entries):
                    entries.append(
                        ImageEntry(
                            env_var=env_var,
                            component=component_name,
                            manifest_key="",
                            source_file=str(go_file),
                            source_line=i,
                        )
                    )

    return entries


def _is_module_dir_name(name: str) -> bool:
    n = name.lower()
    return n.endswith(("-module", "_module"))


def _dir_has_related_images(directory: Path) -> bool:
    for go_file in directory.rglob("*.go"):
        if any(go_file.name.endswith(s) for s in TEST_SUFFIXES):
            continue
        if any(d in go_file.parts for d in SKIP_DIRS):
            continue
        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if RELATED_IMAGE_PATTERN.search(content):
            return True
    return False


def detect_module(repo_root: str | Path) -> bool:
    """Return True if repo_root contains a module with RELATED_IMAGE_* definitions.

    Detects two layouts:
    - Subdirectory named ``*-module`` or ``*_module`` containing RELATED_IMAGE_* Go source.
    - Whole-repo-is-module: ``pkg/**/images.go`` at root level with RELATED_IMAGE_*.

    Known gap: standalone module operators that place RELATED_IMAGE_* directly
    in ``cmd/`` or ``internal/`` without a ``*-module/`` subdir or
    ``pkg/**/images.go`` are not auto-detected (e.g. mcp-lifecycle-module-operator).
    Use ``--module-mode`` explicitly for those repos.
    """
    root = Path(repo_root)
    for d in root.iterdir():
        if d.is_dir() and _is_module_dir_name(d.name) and _dir_has_related_images(d):
            return True
    pkg_dir = root / "pkg"
    if pkg_dir.is_dir():
        for go_file in pkg_dir.rglob("images.go"):
            try:
                content = go_file.read_text()
            except (OSError, UnicodeDecodeError):
                continue
            if RELATED_IMAGE_PATTERN.search(content):
                return True
    return False


def build_module_manifest(repo_root: str | Path) -> Manifest:
    """Build image manifest from a module's own RELATED_IMAGE_* definitions.

    Scans ``*-module`` / ``*_module`` subdirectories; falls back to the repo root
    when none are found (whole-repo-is-module layout).  Reuses
    :func:`parse_component_images` so the returned :class:`Manifest` is identical
    in structure to the one produced by :func:`build_manifest`.
    """
    root = Path(repo_root)
    manifest = Manifest()

    module_dirs = [
        d
        for d in sorted(root.iterdir())
        if d.is_dir() and _is_module_dir_name(d.name) and _dir_has_related_images(d)
    ]

    if not module_dirs:
        module_dirs = [root]

    for module_dir in module_dirs:
        component_name = module_dir.name
        entries = parse_component_images(module_dir, component_name)
        manifest.images.extend(entries)
        if entries:
            manifest.components[component_name] = {
                "image_count": len(entries),
                "env_vars": sorted({e.env_var for e in entries}),
            }

    return manifest


def parse_known_issues(operator_root: Path) -> list[str]:
    """Parse component-params-env.yaml for known issues."""
    params_file = operator_root / "component-params-env.yaml"
    known_issues = []

    if not params_file.exists():
        return known_issues

    try:
        content = params_file.read_text()
    except (OSError, UnicodeDecodeError):
        return known_issues

    in_known_issues = False

    for line in content.splitlines():
        stripped = line.strip()

        if stripped.startswith("# known_issues:"):
            in_known_issues = True
            continue
        if stripped.startswith("#") and not stripped.startswith("# -"):
            in_known_issues = False

        if in_known_issues:
            match = KNOWN_ISSUES_PATTERN.match(stripped)
            if match:
                known_issues.append(match.group(1))

    return known_issues


def build_manifest(operator_root: str | Path) -> Manifest:
    """Build the complete image manifest from the operator source."""
    root = Path(operator_root)
    manifest = Manifest()

    components_dir = root / COMPONENTS_PATH
    if not components_dir.exists():
        return manifest

    for component_dir in sorted(components_dir.iterdir()):
        if not component_dir.is_dir():
            continue
        if component_dir.name.startswith(".") or component_dir.name == "registry":
            continue

        component_name = component_dir.name
        entries = parse_component_images(component_dir, component_name)
        manifest.images.extend(entries)

        if entries:
            manifest.components[component_name] = {
                "image_count": len(entries),
                "env_vars": sorted({e.env_var for e in entries}),
            }

    # Also scan top-level files for RELATED_IMAGE refs not in components
    for go_file in root.rglob("*.go"):
        if COMPONENTS_PATH in str(go_file):
            continue
        if any(d in go_file.parts for d in SKIP_DIRS):
            continue
        if any(go_file.name.endswith(s) for s in TEST_SUFFIXES):
            continue

        try:
            lines = go_file.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for i, line in enumerate(lines, 1):
            for match in RELATED_IMAGE_PATTERN.finditer(line):
                env_var = match.group(1)
                if env_var == "RELATED_IMAGE_*":
                    continue
                if not any(e.env_var == env_var for e in manifest.images):
                    manifest.images.append(
                        ImageEntry(
                            env_var=env_var,
                            component="operator-core",
                            manifest_key="",
                            source_file=str(go_file),
                            source_line=i,
                        )
                    )

    manifest.known_issues = parse_known_issues(root)

    return manifest


def run(operator_path: str) -> RuleResult:
    """Run the manifest builder and return a RuleResult."""
    manifest = build_manifest(operator_path)
    all_env_vars = sorted({e.env_var for e in manifest.images})

    result = RuleResult(rule="operator-manifest")
    result.findings.append(
        Finding(
            severity="info",
            file="",
            line=0,
            image="",
            message=f"Operator manifest: {len(all_env_vars)} unique RELATED_IMAGE env vars "
            f"across {len(manifest.components)} components.",
        )
    )
    for issue in manifest.known_issues:
        result.findings.append(
            Finding(
                severity="info",
                file="component-params-env.yaml",
                line=0,
                image=issue,
                message=f"Known issue in operator manifest: {issue}",
            )
        )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: operator_manifest.py <path-to-operator-repo>", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[1]
    r = run(path)
    print(
        json.dumps(
            {
                "rule": r.rule,
                "passed": r.passed,
                "findings": [
                    {
                        "severity": f.severity,
                        "file": f.file,
                        "line": f.line,
                        "image": f.image,
                        "message": f.message,
                    }
                    for f in r.findings
                ],
            },
            indent=2,
        )
    )

[![codecov](https://codecov.io/gh/opendatahub-io/disconnected-readiness-scorer/graph/badge.svg?token=XE1XU6SQPB)](https://codecov.io/gh/opendatahub-io/disconnected-readiness-scorer)

# Disconnected Readiness Scorer

Score a repository's readiness for deployment in disconnected / air-gapped OpenShift environments.

## Why this exists

Disconnected and air-gapped deployments are a core requirement for many Red Hat OpenShift AI customers — particularly in government, financial services, and regulated industries where clusters have no outbound internet access. Analysis of ~96 open JIRA issues across RHAIRFE, RHAISTRAT, and RHOAIENG revealed that **75% of disconnected failures fall into four patterns detectable by static analysis before code is merged**:

| Pattern | % of Issues | Rule |
|---------|-------------|------|
| Missing images from manifests | ~30% | `image-manifest-complete` |
| Hardcoded external dependencies | ~25% | `python-imports` |
| Image tags instead of digests | ~10% | `no-image-tags` |
| Runtime external URL calls | ~10% | `no-runtime-egress` |

Today, none of these are checked automatically — failures are only discovered during manual disconnected testing, often weeks or months after the breaking change was merged. This scanner catches them at PR time.

## Quick start

**Prerequisites:** Install arch-analyzer first: `make install-arch-analyzer`

### As a Claude Code skill

```bash
/disconnected-score
```

Run from the root of any RHOAI component repository. The skill definition is in [SKILL.md](SKILL.md).

### As a CLI tool

```bash
python3 main.py /path/to/target/repo                        # all default rules
python3 main.py /path/to/target/repo --rules csv,tags        # subset of rules
python3 main.py /path/to/target/repo --report json           # JSON output
python3 main.py /path/to/target/repo --operator-path /tmp/opendatahub-operator  # pre-cloned operator
python3 main.py /path/to/target/repo --module-mode           # validate as standalone module (no operator clone)
python3 main.py /path/to/target/repo --config /path/to/config.yaml              # custom central config
python3 main.py /path/to/target/repo --arch-analyzer /path/to/arch-analyzer     # custom arch-analyzer binary
python3 main.py /path/to/target/repo --verbose                                 # diagnostics + timing + files_checked in JSON
python3 main.py --list-expiring                                                # list exceptions expiring within 14 days
python3 main.py --audit-exceptions                                             # analyze exception scope quality
```

Exit code is `0` for READY, `1` for NOT READY. `--list-expiring` exits with `2` if any expired or expiring exceptions exist. `--audit-exceptions` exits with `2` if warnings are found, `0` for info-only or no findings.

### Individual rules

Each rule is a standalone script:

```bash
python3 rules/image_manifest_complete.py /path/to/target/repo
python3 rules/params_env.py /path/to/target/repo
python3 rules/no_image_tags.py /path/to/target/repo
python3 rules/no_runtime_egress.py /path/to/target/repo
python3 rules/python_imports.py /path/to/target/repo
python3 rules/operator_manifest.py /path/to/opendatahub-operator
```

All rules output JSON to stdout with `rule`, `passed`, and `findings` fields.

## Output

```
Disconnected Readiness Score: NOT READY

  FAIL     image-manifest-complete   2 blocker(s)
  PASS     no-image-tags             All checks passed
  PASS     no-runtime-egress         All checks passed
  PASS     python-imports-bundled    All checks passed

Blockers: 2 | Passed: 3
```

Reports are also generated as markdown (default) or JSON (`--report json`). Write to a file with `--output report.md`.

## Rules

For detailed technical documentation of each rule — detection logic, regex patterns, severity heuristics, cross-rule data flow, and the orchestrator execution sequence — see [docs/rules-reference.md](docs/rules-reference.md).

| Alias        | Rule                      | What it checks                                                                         |
| ------------ | ------------------------- | -------------------------------------------------------------------------------------- |
| `csv`        | `image-manifest-complete` | Every container image ref is accounted for in the disconnected manifest                 |
| `tags`       | `no-image-tags`           | All image refs use `@sha256:` digests, not mutable tags                                |
| `egress`     | `no-runtime-egress`       | No hardcoded outbound HTTP calls in runtime code (Go, Python, TS, shell, YAML)         |
| `python`     | `python-imports-bundled`  | Python deps are available from bundled/internal mirrors; no runtime `pip install`       |
| `params_env` | `params-env-wiring`       | Full `params.env` → kustomize → rendered manifest → Go `os.Getenv` wiring is valid     |
| `manifest`   | `operator-manifest`       | Builds the authoritative RELATED_IMAGE manifest from the opendatahub-operator source   |

**Network access:** `csv`, `tags`, and `params_env` clone the `opendatahub-operator` repo (shallow) whenever the target repo is detected as using the `RELATED_IMAGE_*` env var pattern, to cross-reference image env vars against the authoritative manifest. Use `--operator-path` to point at a pre-cloned copy and avoid the clone (e.g. for fully offline runs).

**Module mode:** For repos that ship their own `RELATED_IMAGE_*` image manifest (modularized components with a `*-module/` subdirectory or `pkg/**/images.go`), use `--module-mode`. The scorer validates the module's own image set as the authority — no operator clone needed. Module repos are auto-detected; `--module-mode` makes the selection explicit and takes precedence over `--operator-path`.

**Production scope** (not a rule): Uses arch-analyzer to identify production code directories. Files outside production scope are skipped (no findings emitted). Disabled with `--no-production-scope`.

[arch-analyzer](https://github.com/ugiordan/architecture-analyzer) is **required** (`make install-arch-analyzer`). It runs on both the operator and target component repos to extract Dockerfile COPY sources, kustomize overlay paths, and production scope data.

## Scoring

| Score | Meaning |
|-------|---------|
| **READY** | All rules pass — no blocker findings |
| **NOT READY** | One or more blocker-level findings |

Severity levels for individual findings:

| Severity | Meaning |
|----------|---------|
| `blocker` | Will or may break disconnected — must be fixed or granted an exception |
| `info` | Excluded file, configurable pattern, or informational — does not block |

## Exception System

All policy-based exclusions (test dirs, CI dirs, build files, etc.) are configured in `config/config.yaml` rather than hardcoded in rules. Exceptions downgrade matching blocker findings to **info** severity. See [Add an exception](#add-an-exception) for the field reference.

Path patterns support `**/` prefix to match at any depth (e.g. `**/Dockerfile` matches both `Dockerfile` and `build/Dockerfile`). Patterns ending with `/**` also match the directory itself (e.g. `**/config/scorecard/**` matches both `config/scorecard` and `config/scorecard/foo.yaml`).

### Default exceptions

The default `config/config.yaml` exceptions include:

- **Test directories:** `**/test/**`, `**/*tests*/**`, `**/testdata/**`, `**/testing/**`, `**/e2e/**`, `**/mocks/**`, `**/contract-tests/**`, `**/hack/**`, `**/k8mocks/**`, `**/cypress/**`
- **Test file suffixes:** `*_test.go`, `test_*.py`, `*.test.ts`, `*.spec.ts`, `*.test.yml`, `*.test.yaml`
- **Test fixtures:** `**/recordings/**`, `**/snapshots/**`, `**/*.snap.json`
- **Test kustomize overlays:** `config/overlays/test/**`, `config/overlays/kind-tests/**`, `config/samples/**`
- **CI directories:** `.github/`, `.tekton/`, `.buildkite/`, `**/ci/**`
- **Non-production:** `**/docs/**`, `**/examples/**`, `**/samples/**`, `**/demo/**`, `**/kind-emulator/**`
- **OLM scorecard:** `**/config/scorecard/**`
- **Build files:** `**/Dockerfile`, `**/*.Dockerfile`, `**/Containerfile`
- **Lint config:** `**/semgrep.yaml`, `**/semgrep.yml`

### Custom exceptions

Override with `--config /path/to/config.yaml`:

```yaml
exceptions:
  - rules: no-runtime-egress
    repo: opendatahub-io/odh-dashboard
    paths:
      - "frontend/src/services/**"
    reason: "Frontend services call the backend BFF, not external endpoints"

  - rules:
      - image-manifest-complete
      - no-image-tags
    paths:
      - "config/scorecard/**"
    reason: "OLM scorecard config — test images, not production"

  # Time-bounded exception — expires Dec 31, 2026
  - rule: no-runtime-egress
    repo: my-component
    paths:
      - "internal/legacy_client.go"
    reason: "Legacy HTTP client — migrating to configurable URL"
    expires: "2026-12-31"
```

### Skipped directories

The following directories are always fully skipped (no findings at all): `.git`, `vendor`, `node_modules`, `__pycache__`, `.tox`, `.devcontainer`.

## Configuration

All configuration is in YAML files with JSON Schema support for IDE autocomplete. Add `# yaml-language-server: $schema=<url>` at the top of your config file.

### Central config (`config/config.yaml`)

Single unified config in the scorer repo. Contains exception rules that apply to all scanned repos.

```yaml
# yaml-language-server: $schema=../schemas/config.schema.json

exceptions:
  - rules: "*"
    paths:
      - "**/test/**"
      - "**/*tests*/**"
    reason: "Test directory — not deployed in production"
```

A missing config file — whether the default path or an explicitly passed `--config` path — is a hard error: the run fails immediately rather than silently proceeding with zero exceptions.

### Configuration

All configuration is managed centrally in `config/config.yaml`. No per-repository configuration files are supported — repo-specific exceptions use the `repo` field in the central config.

## Reporting False Positives

When the scanner flags something that is not a real disconnected issue, add an exception to unblock your PR.

### Add an exception

Exceptions are managed centrally in the scorer repository's `config/config.yaml` file. Each exception requires a scope filter so it only applies to specific findings — you cannot disable an entire rule.

| Field       | Required | Description                                                                 |
|-------------|----------|-----------------------------------------------------------------------------|
| `rules`     | yes      | Rule name string, `"*"` for all rules, or a list of rule names (see below)  |
| `paths`     | *        | List of glob patterns matched against finding file path                     |
| `images`    | *        | List of glob patterns matched against finding image ref (any match wins)    |
| `message`   | *        | Glob pattern matched against finding message (use `*text*` for substring)   |
| `reason`    | yes      | Why this is not a real disconnected issue                                   |
| `repo`      | no       | Repo name or `org/repo` — scopes exception to one component                |
| `reference` | no       | Tracking URL (GitHub Issue or Jira ticket) if this is a scanner bug         |
| `expires`   | no       | ISO 8601 date (`YYYY-MM-DD`) after which the exception is no longer honored |

\* At least one of `paths`, `images`, or `message` is required.

The `rules` field accepts three forms:

- **Single rule**: `rules: no-runtime-egress`
- **List of rules**: `rules: [no-image-tags, no-runtime-egress]`
- **Wildcard**: `rules: "*"` — matches all rules

Prefer naming specific rules over using `"*"`. The wildcard should only be used when the excepted path genuinely cannot produce valid findings for any rule (e.g. test directories, CI config, build files). For repo-specific exceptions, consider which rules the path could realistically violate and list only those — overly broad wildcards can silently hide real issues that a more targeted exception would have caught.

```yaml
exceptions:
  # Repo-specific: scoped to one component via 'repo' field
  - rules: no-runtime-egress
    repo: my-component
    paths:
      - "internal/client.go"
    reason: "Calls cluster-internal Kubernetes API at kubernetes.default.svc"
    # reference: "https://issues.redhat.com/browse/RHOAIENG-XXXXX"  # optional, for scanner bugs

  # Cross-component: applies to all repos (no 'repo' field)
  - rules: no-runtime-egress
    paths:
      - "**/internal/cluster/**"
    reason: "Internal cluster calls — not external egress"
```

Add this exception to the scorer's `config/config.yaml`. Use the `repo` field to scope it to a specific component, or omit it for a cross-component exception that applies to all repos. The scanner loads the central config automatically and downgrades matching findings to info severity.

If you think a finding is caused by a bug in the scanner (not just a repo-specific exclusion), file a Jira ticket under RHOAIENG and add the ticket URL as a `reference` in your exception entry. The AI Core Platform team triages these and either fixes the rule or confirms the exception is permanent.

### Pattern matching

Exception matching uses **glob patterns** (via Python's `fnmatch`), not regex. Glob patterns support:

- `*` — matches any sequence of characters (except `/` in paths)
- `?` — matches exactly one character
- `[abc]` — matches one character from the set
- `**/` prefix — matches at any directory depth (extended glob)
- `/**` suffix — matches directory and all contents

For `message` matching, use `*text*` for substring matching (e.g. `message: "*hardcoded*"`). Exact strings without wildcards must match the full message.

Regex support was evaluated and deferred — glob patterns cover the current use cases. If regex becomes necessary in the future, a `re:` prefix syntax (e.g. `message: "re:pattern-(a|b)"`) is the planned extension point.

### Auditing exceptions

Use `--audit-exceptions` to analyze exception quality without running a full scan:

```bash
python3 main.py --audit-exceptions
```

This reports:
- **Warnings**: repo-specific exceptions using `rules: "*"` (should list specific rules) or having only `paths` without `message`/`images` filters
- **Info**: universal wildcard exceptions (expected for test/CI/build dirs)

During a normal scan, the report also includes an **Unused Exceptions** section listing entries that matched zero findings — these may be stale or only relevant to other repos.

### Common Errors

**"at least one scope filter"** — Include `paths`, `images`, or `message` to limit the exception. Disabling an entire rule is not allowed.

**"unknown field(s)"** — Check for typos in field names. Valid fields: `rules`, `repo`, `paths`, `images`, `message`, `reason`, `reference`, `expires`.

## PR Integration

The primary use case for this tool is running it against Pull Requests in RHOAI component repositories, catching disconnected-breaking changes **before they merge** rather than weeks later during manual testing.

### GitHub Actions (recommended)

Use the reusable workflow for consistent integration across repositories:

```yaml
# .github/workflows/disconnected-readiness.yml
name: Disconnected Readiness Check

on:
  pull_request:
    branches: [main]

jobs:
  check:
    uses: opendatahub-io/disconnected-readiness-scorer/.github/workflows/disconnected-readiness-check.yml@v1
    with:
      rules: ""  # Leave empty for all default rules, or specify: "csv,tags,egress"
```

#### Versioning Strategy

This repository uses **floating major version tags** for automatic updates while maintaining security:

```yaml
# Recommended: Automatic updates within major version
uses: opendatahub-io/disconnected-readiness-scorer/.github/workflows/disconnected-readiness-check.yml@v1
```

Pinning only governs the reusable workflow file's own orchestration logic — it does not pin the scorer's Python code or `schemas/config.schema.json` (both always come from the workflow's own internal floating `v1` checkout, regardless of the caller's pin) or `config/config.yaml` (exceptions, always fetched live from `main`), so a merged exception reaches every consumer on its next run without any release. See [docs/VERSIONING.md](docs/VERSIONING.md#what-pinning-does-and-does-not-cover) for details.

**Complete Documentation:**
- **[docs/VERSIONING.md](docs/VERSIONING.md)** - Consumer strategy guide (when to use @v1 vs @v1.2.3 vs @sha)
- **[docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md)** - Release procedures and troubleshooting
- **[Releases](https://github.com/opendatahub-io/disconnected-readiness-scorer/releases)** - Version history and release notes

### Manual Setup (alternative)

If you prefer direct integration without the reusable workflow:

```yaml
name: Disconnected Readiness Check
on:
  pull_request:
    branches: [main]

jobs:
  disconnected-score:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3

      - name: Install uv
        uses: astral-sh/setup-uv@fac544c07dec837d0ccb6301d7b5580bf5edae39 # v8.2.0

      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6.2.0
        with:
          python-version: "3.12"

      - name: Checkout scorer
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          repository: opendatahub-io/disconnected-readiness-scorer
          ref: 29ae4bc3591a988c6e3f6ec72d0184c0866650fe # Pinned to specific commit for deterministic execution
          path: scorer

      - name: Install dependencies
        run: |
          cd scorer && uv sync --extra report --frozen && make install-arch-analyzer

      - name: Run disconnected readiness check
        env:
          INPUT_RULES: ${{ inputs.rules }}
        run: |
          cd scorer
          # Build arguments array with rules if specified
          ARGS=("${{ github.workspace }}" --report json,markdown -o disconnected-report.json disconnected-report.md)
          if [ -n "$INPUT_RULES" ]; then
            ARGS+=(--rules "$INPUT_RULES")
          fi
          # Run analysis and capture JSON output
          uv run main.py "${ARGS[@]}"

      - name: Store results as artifact
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: disconnected-readiness-report
          path: |
            scorer/disconnected-report.json
            scorer/disconnected-report.md
          retention-days: 1
```

The workflow exits with code `1` when blocker-level findings are present, which will fail the PR check.

### Targeted rules per repository

Not every rule applies to every repo. Use `--rules` to run only the relevant checks:

| Repository type                             | Recommended rules              |
|---------------------------------------------|--------------------------------|
| Operators using `RELATED_IMAGE_*` env vars  | `csv,tags,manifest`            |
| Modularized components (`*-module/` layout) | `csv,tags` + `--module-mode`   |
| Components using `params.env` + kustomize   | `params_env,tags,egress`       |
| Python ML components (e.g., model serving)  | `python,tags,egress`           |
| Go services / controllers                   | `csv,tags,egress`              |
| Frontend / dashboard                        | `egress`                       |

Example for a Python-heavy repo:

```yaml
      - name: Run disconnected readiness check
        run: python3 /tmp/scorer/main.py . --rules python,tags,egress
```

### PR comment reporting

To post results as a PR comment instead of just failing the check, pipe the markdown report into the GitHub CLI:

```yaml
      - name: Run disconnected readiness check
        id: score
        run: |
          python3 /tmp/scorer/main.py . --report markdown --output disconnected-report.md || true

      - name: Post PR comment
        if: github.event_name == 'pull_request'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          {
            echo "## Disconnected Readiness Report"
            echo ""
            cat disconnected-report.md
          } | gh pr comment ${{ github.event.pull_request.number }} --body-file -
```

### Running locally on a PR branch

To check a PR branch before pushing:

```bash
# From the component repo, on your PR branch
python3 /path/to/disconnected-readiness-scorer/main.py .
```

Or using the Claude Code skill from the component repo root:

```bash
/disconnected-score
```

## Jira Issue Validation

`verify_jira_issues.py` validates the scanner against known real-world Jira disconnected bugs. It clones each repo at the commit where the bug exists, runs the scorer, and outputs JSON with all findings.

```bash
python3 verify_jira_issues.py                  # JSON to stdout
python3 verify_jira_issues.py | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(f'{r[\"status\"]:5s} {r[\"jira\"]}: {r[\"summary\"]}')"
```

Each entry in `JIRA_ISSUES` specifies:

- `repo_url` / `ref` / `checkout` — the repo and commit to test against
- The script runs all rules and outputs the complete report per issue

Current coverage: 7/10 issues detected, 3 gaps identified (params.env exclusion by design, URL string literals, container runtime downloads).

## Development

### Dependencies

Dependencies are managed with [uv](https://docs.astral.sh/uv/). Install it first.

Then install all dev dependencies and git hooks:

```bash
uv sync --extra dev
make install-arch-analyzer
pre-commit install
```

**Required:** `pyyaml`, `arch-analyzer` (for production scope detection, overlay classification, and operator analysis).

**Optional:** `jinja2` (report rendering degrades gracefully without it, installed with `--extra report` or `--extra dev`).

### Running tests

```bash
uv run python -m pytest tests/ -v                                 # all tests
uv run python -m pytest tests/test_image_manifest_complete.py -v  # single file
uv run python -m pytest tests/test_main.py::TestParseArgs -v      # single class
uv run python -m pytest tests/ -v --cov=. --cov-report=term       # with coverage
```

CI runs on Python 3.12. Codecov enforces 80% patch coverage.

## License

Internal Red Hat / AI First Initiative.

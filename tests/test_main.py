"""Tests for main.py orchestrator functions."""

import io
import json
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from main import (
    RULE_REGISTRY,
    ArchAnalyzerError,
    _audit_exceptions,
    _build_exception_snippets,
    _build_exceptions_section,
    _build_expired_exceptions_section,
    _build_expiring_exceptions_section,
    _build_false_positive_section,
    _build_unused_exceptions_section,
    _find_expired_exceptions,
    _find_expiring_exceptions,
    _get_repo_name,
    _normalize_rules,
    _render_template_simple,
    _rules_display_str,
    _run,
    _run_arch_analyzer,
    _validate_config_schema,
    adapt_manifest_result,
    apply_exceptions,
    compute_score,
    load_central_config,
    main,
    parse_args,
    print_summary,
    render_json,
    render_markdown,
    resolve_rules,
)
from rules.common import Finding, RuleResult


def load_exceptions(path):
    """Test helper: load exceptions list from a config file."""
    return load_central_config(path)["exceptions"]


def _make_import_side_effect(fake_mod):
    """Return an importlib.import_module side_effect that is module-aware.

    Returns *fake_mod* for rule modules but a proper mock with
    parse_manifest_entries / parse_overlay_paths_from_arch_data for
    ``rules.operator_manifest`` so production-scope code works.
    """
    op_manifest_mock = MagicMock()
    op_manifest_mock.parse_manifest_entries.return_value = ({}, {})
    op_manifest_mock.parse_overlay_paths_from_arch_data.return_value = []

    def _side_effect(name):
        if name == "rules.operator_manifest":
            return op_manifest_mock
        return fake_mod

    return _side_effect


# --- parse_args ---


class TestParseArgs:
    def test_defaults(self):
        args = parse_args([])
        assert args.repo_root == "."
        assert args.rules == "all"
        assert args.report == "markdown"
        assert args.operator_path is None
        assert args.output is None

    def test_positional_repo(self):
        args = parse_args(["/tmp/repo"])
        assert args.repo_root == "/tmp/repo"

    def test_rules_flag(self):
        args = parse_args([".", "--rules", "csv,tags"])
        assert args.rules == "csv,tags"

    def test_report_json(self):
        args = parse_args([".", "--report", "json"])
        assert args.report == "json"

    def test_operator_path(self):
        args = parse_args([".", "--operator-path", "/tmp/op"])
        assert args.operator_path == "/tmp/op"

    def test_output_short(self):
        args = parse_args([".", "-o", "out.md"])
        assert args.output == ["out.md"]

    def test_output_dual(self):
        args = parse_args([".", "--report", "json,markdown", "-o", "r.json", "r.md"])
        assert args.report == "json,markdown"
        assert args.output == ["r.json", "r.md"]

    def test_module_mode_default_false(self):
        args = parse_args([])
        assert args.module_mode is False

    def test_module_mode_flag(self):
        args = parse_args([".", "--module-mode"])
        assert args.module_mode is True


# --- resolve_rules ---


class TestResolveRules:
    def test_all_returns_defaults(self):
        from main import DEFAULT_RULES

        result = resolve_rules("all")
        assert result == list(DEFAULT_RULES)

    def test_empty_returns_defaults(self):
        from main import DEFAULT_RULES

        assert resolve_rules("") == list(DEFAULT_RULES)

    def test_none_returns_defaults(self):
        from main import DEFAULT_RULES

        assert resolve_rules(None) == list(DEFAULT_RULES)

    def test_specific_rules(self):
        assert resolve_rules("csv,tags") == ["csv", "tags"]

    def test_single_rule(self):
        assert resolve_rules("egress") == ["egress"]

    def test_unknown_rule_exits(self):
        with pytest.raises(SystemExit, match="Unknown rule 'nope'"):
            resolve_rules("nope")

    def test_whitespace_stripped(self):
        assert resolve_rules(" csv , tags ") == ["csv", "tags"]


# --- compute_score ---


class TestComputeScore:
    def test_ready(self):
        results = [RuleResult(rule="a"), RuleResult(rule="b")]
        assert compute_score(results) == "READY"

    def test_ready_with_info(self):
        r = RuleResult(rule="a", findings=[Finding("info", "", 0, "", "ok")])
        assert compute_score([r]) == "READY"

    def test_not_ready(self):
        r = RuleResult(rule="a", passed=False, findings=[Finding("blocker", "f", 1, "img", "bad")])
        assert compute_score([r]) == "NOT READY"

    def test_not_ready_with_mixed_rules(self):
        r1 = RuleResult(rule="a", findings=[Finding("info", "", 0, "", "ok")])
        r2 = RuleResult(rule="b", passed=False)
        assert compute_score([r1, r2]) == "NOT READY"

    def test_empty_results(self):
        assert compute_score([]) == "READY"


# --- adapt_manifest_result ---


@dataclass
class FakeImageEntry:
    env_var: str
    image: str = ""


@dataclass
class FakeManifest:
    images: list = field(default_factory=list)
    components: list = field(default_factory=list)
    known_issues: list = field(default_factory=list)


class TestAdaptManifestResult:
    def test_basic(self):
        manifest = FakeManifest(
            images=[FakeImageEntry("VAR_A"), FakeImageEntry("VAR_B")],
            components=["comp1"],
        )
        result = adapt_manifest_result(manifest)
        assert result.rule == "operator-manifest"
        assert result.passed is True
        assert len(result.findings) == 1
        assert "2 RELATED_IMAGE vars" in result.findings[0].message

    def test_duplicate_env_vars_counted_unique(self):
        manifest = FakeManifest(
            images=[FakeImageEntry("VAR_A"), FakeImageEntry("VAR_A")],
            components=[],
        )
        result = adapt_manifest_result(manifest)
        assert "1 RELATED_IMAGE vars" in result.findings[0].message

    def test_known_issues_become_info(self):
        manifest = FakeManifest(
            images=[],
            components=[],
            known_issues=["stale ref", "missing var"],
        )
        result = adapt_manifest_result(manifest)
        assert len(result.findings) == 3  # 3 info findings
        assert all(f.severity == "info" for f in result.findings)
        issue_findings = [f for f in result.findings if "Known issue" in f.message]
        assert len(issue_findings) == 2
        assert "stale ref" in issue_findings[0].message


# --- print_summary ---


class TestPrintSummary:
    def test_output_to_stderr(self, capsys):
        results = [
            RuleResult(
                rule="r1",
                passed=True,
                findings=[
                    Finding("info", "", 0, "", "ok"),
                ],
            ),
            RuleResult(
                rule="r2",
                passed=False,
                findings=[
                    Finding("blocker", "f.go", 1, "img", "bad"),
                ],
            ),
        ]
        print_summary("NOT READY", results)
        err = capsys.readouterr().err
        assert "NOT READY" in err
        assert "PASS" in err
        assert "FAIL" in err

    def test_pass_tag(self, capsys):
        results = [
            RuleResult(
                rule="r1",
                findings=[
                    Finding("info", "x.py", 1, "", "informational"),
                ],
            ),
        ]
        print_summary("READY", results)
        err = capsys.readouterr().err
        assert "READY" in err
        assert "All checks passed" in err


# --- render_json ---


class TestRenderJson:
    def test_structure(self):
        results = [
            RuleResult(
                rule="a",
                passed=True,
                findings=[
                    Finding("blocker", "f.go", 10, "img", "msg"),
                    Finding("info", "g.go", 20, "", "imsg"),
                ],
            ),
        ]
        raw = render_json("NOT READY", results, "my-repo")
        data = json.loads(raw)
        assert data["repo"] == "my-repo"
        assert data["score"] == "NOT READY"
        assert len(data["rules"]) == 1
        rule = data["rules"][0]
        assert rule["name"] == "a"
        assert rule["passed"] is True
        assert rule["blockers"] == 1
        assert "warnings" not in rule
        assert len(rule["findings"]) == 2

    def test_empty_results(self):
        data = json.loads(render_json("READY", [], "repo"))
        assert data["rules"] == []
        assert data["score"] == "READY"

    def test_verbose_includes_files_checked(self):
        r = RuleResult(rule="b", passed=True)
        r.files_checked = ["src/a.go", "src/b.go", "src/a.go"]
        data = json.loads(render_json("READY", [r], "repo", verbose=True))
        rule = data["rules"][0]
        assert "files_checked" in rule
        assert rule["files_checked"] == ["src/a.go", "src/b.go"]  # sorted+deduped

    def test_non_verbose_omits_files_checked(self):
        r = RuleResult(rule="b", passed=True)
        r.files_checked = ["src/a.go"]
        data = json.loads(render_json("READY", [r], "repo", verbose=False))
        assert "files_checked" not in data["rules"][0]

    def test_verbose_omits_files_checked_when_empty(self):
        r = RuleResult(rule="c", passed=True)
        data = json.loads(render_json("READY", [r], "repo", verbose=True))
        assert "files_checked" not in data["rules"][0]


class TestRenderJsonRuleMetadata:
    def test_rule_entries_include_maturity_metadata(self):
        results = [RuleResult(rule="no-image-tags", passed=True)]
        report = json.loads(render_json("READY", results, "org/repo"))
        rule_entry = report["rules"][0]
        assert rule_entry["display_name"] == "No mutable image tags"
        assert isinstance(rule_entry["remediation"], str) and rule_entry["remediation"]
        assert rule_entry["reference_doc"].startswith("https://")
        assert "no-image-tags" in rule_entry["reference_doc"]

    def test_unknown_rule_omits_metadata_fields(self):
        results = [RuleResult(rule="unknown-rule", passed=True)]
        report = json.loads(render_json("READY", results, "org/repo"))
        rule_entry = report["rules"][0]
        assert "display_name" not in rule_entry
        assert "remediation" not in rule_entry
        assert "reference_doc" not in rule_entry


# --- _render_template_simple ---


class TestRenderTemplateSimple:
    def test_variable_substitution(self):
        result = _render_template_simple("Hello {{ name }}", {"name": "world"})
        assert result == "Hello world"

    def test_upper_filter(self):
        result = _render_template_simple("{{ x | upper }}", {"x": "abc"})
        assert result == "ABC"

    def test_for_loop(self):
        template = "{% for item in items %}[{{ item.v }}]{% endfor %}"
        ctx = {"items": [{"v": "a"}, {"v": "b"}]}
        assert _render_template_simple(template, ctx) == "[a]\n[b]"

    def test_dot_access_in_loop(self):
        template = "{% for r in rules %}{{ r.name }},{% endfor %}"
        ctx = {"rules": [{"name": "x"}, {"name": "y"}]}
        assert _render_template_simple(template, ctx) == "x,\ny,"

    def test_nested_for_raises(self):
        template = "{% for a in x %}{% for b in y %}{% endfor %}{% endfor %}"
        with pytest.raises(ValueError, match="Nested"):
            _render_template_simple(template, {"x": [1], "y": [2]})

    def test_missing_variable_returns_empty(self):
        assert _render_template_simple("{{ missing }}", {}) == ""


# --- render_markdown ---


class TestRenderMarkdown:
    def test_fallback_on_missing_template(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "main.Path", lambda *a: tmp_path / "nope" if len(a) == 1 else type(tmp_path)(*a)
        )
        result = render_markdown("READY", [], "repo")
        assert "READY" in result

    def test_uses_builtin_renderer_without_jinja(self):
        saved = sys.modules.get("jinja2")
        sys.modules["jinja2"] = None
        try:
            result = render_markdown("READY", [], "repo")
        except AttributeError:
            pytest.fail("Fallback did not catch jinja2 unavailability")
        finally:
            if saved is not None:
                sys.modules["jinja2"] = saved
            else:
                sys.modules.pop("jinja2", None)
        assert "READY" in result


# --- main (integration-level) ---


class TestMain:
    @patch("main.compute_production_scope", return_value=None)
    def test_all_pass_returns_0(self, _mock_scope):
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="test-rule", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv,tags,egress,python", "--report", "json"])
        assert exit_code == 0

    @patch("main.compute_production_scope", return_value=None)
    def test_blocker_returns_1(self, _mock_scope):
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(
            rule="test-rule",
            passed=False,
            findings=[Finding("blocker", "f.go", 1, "img", "fail")],
        )
        fake_mod.detect_image_pattern.return_value = "static_csv"

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv", "--report", "json"])
        assert exit_code == 1

    @patch("main.compute_production_scope", return_value=None)
    def test_config_flag_applies_exception_through_real_scan(self, _mock_scope, tmp_path):
        """--config must drive apply_exceptions() inside the real _run() scan path,
        not just be recognized by argparse -- see RHOAIENG-79773."""
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(
            rule="image-manifest-complete",
            passed=False,
            findings=[Finding("blocker", "f.go", 1, "img", "fail")],
        )
        fake_mod.detect_image_pattern.return_value = "static_csv"

        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "exceptions:\n"
            "  - rules: image-manifest-complete\n"
            "    message: fail\n"
            "    reason: test exception\n"
        )

        out_file = tmp_path / "report.json"
        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main(
                [
                    ".",
                    "--rules",
                    "csv",
                    "--config",
                    str(config_path),
                    "--report",
                    "json",
                    "-o",
                    str(out_file),
                ]
            )
        assert exit_code == 0
        data = json.loads(out_file.read_text())
        finding = data["rules"][0]["findings"][0]
        assert finding["severity"] == "info"
        assert "[Exception: test exception]" in finding["message"]

    @patch("main.compute_production_scope", return_value=None)
    def test_config_flag_with_unsupported_rule_fails_hard(self, _mock_scope, tmp_path):
        """A live config referencing a rule name the running code doesn't know about
        must abort the run loudly, never silently skip -- see RHOAIENG-79773."""
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="image-manifest-complete", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "exceptions:\n"
            "  - rules: rule-that-does-not-exist\n"
            "    message: fail\n"
            "    reason: test exception\n"
        )

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main(
                [".", "--rules", "csv", "--config", str(config_path), "--report", "json"]
            )
        assert exit_code == 1

    @patch("main.compute_production_scope", return_value=None)
    def test_config_flag_with_nonexistent_path_fails_hard(self, _mock_scope, tmp_path, capsys):
        """A --config path that doesn't exist must abort the run loudly, never
        silently fall back to zero exceptions -- see RHOAIENG-79773."""
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="image-manifest-complete", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        missing_config_path = tmp_path / "does-not-exist.yaml"

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main(
                [".", "--rules", "csv", "--config", str(missing_config_path), "--report", "json"]
            )
        assert exit_code == 1
        assert "Config file not found" in capsys.readouterr().err

    @patch("main.compute_production_scope", return_value=None)
    def test_run_uses_supplied_central_cfg_without_loading_from_disk(self, _mock_scope, tmp_path):
        """_run(..., central_cfg=...) must apply the caller-supplied config directly
        and never call load_central_config() itself -- this is the contract main()
        relies on to load the config exactly once for every CLI mode. Mirrors
        run_all.py's direct _run() call shape (see tests/test_run_all.py) but
        supplies a pre-built central_cfg the way main() now does."""
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(
            rule="image-manifest-complete",
            passed=False,
            findings=[Finding("blocker", "f.go", 1, "img", "fail")],
        )
        fake_mod.detect_image_pattern.return_value = "static_csv"

        supplied_central_cfg = {
            "exceptions": [
                {
                    "rules": "image-manifest-complete",
                    "message": "fail",
                    "reason": "test exception",
                }
            ],
            "docker_contexts": {},
            "known_non_image_prefixes": [],
            "params_env_filenames": {},
        }

        args = SimpleNamespace(
            repo_root=str(tmp_path),
            rules="csv",
            report="json",
            output=[str(tmp_path / "report.json")],
            operator_path=None,
            config=None,
            repo_config=None,
            no_production_scope=False,
            verbose=False,
            arch_analyzer="",
        )

        with (
            patch("main.load_central_config", side_effect=AssertionError("must not be called")),
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = _run(
                args,
                None,
                central_cfg=supplied_central_cfg,
                log_stream=io.StringIO(),
            )
        assert exit_code == 0
        data = json.loads((tmp_path / "report.json").read_text())
        finding = data["rules"][0]["findings"][0]
        assert finding["severity"] == "info"
        assert "[Exception: test exception]" in finding["message"]

    @patch("main.compute_production_scope", return_value=None)
    def test_output_flag_writes_file(self, _mock_scope, tmp_path):
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="r", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        out_file = tmp_path / "report.json"
        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv", "--report", "json", "-o", str(out_file)])
        assert exit_code == 0
        content = out_file.read_text()
        data = json.loads(content.strip())
        assert data["score"] == "READY"

    @patch("main.compute_production_scope", return_value=None)
    def test_manifest_rule_triggers_adapt(self, _mock_scope):
        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])
        fake_mod = MagicMock()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, set())) as mock_load,
            patch(
                "main.adapt_manifest_result", return_value=RuleResult(rule="operator-manifest")
            ) as mock_adapt,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "manifest", "--report", "json"])
            assert exit_code == 0
            mock_load.assert_called_once()
            mock_adapt.assert_called_once_with(fake_manifest)

    @patch("main.compute_production_scope", return_value=None)
    def test_env_var_pattern_triggers_manifest_load(self, _mock_scope):
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "env_var"
        fake_mod.run.return_value = RuleResult(rule="csv", passed=True)

        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, set())) as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv", "--report", "json"])
            assert exit_code == 0
            mock_load.assert_called_once()

    @patch("main.compute_production_scope", return_value=None)
    def test_env_var_pattern_triggers_manifest_load_for_tags(self, _mock_scope):
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "env_var"
        fake_mod.run.return_value = RuleResult(rule="tags", passed=True)

        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, set())) as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "tags", "--report", "json"])
            assert exit_code == 0
            mock_load.assert_called_once()

    @patch("main.compute_production_scope", return_value=None)
    def test_manifest_env_vars_passed_to_no_image_tags(self, _mock_scope):
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "env_var"
        fake_mod.run.return_value = RuleResult(rule="tags", passed=True)

        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])
        env_vars = {"RELATED_IMAGE_FOO"}

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, env_vars)),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "tags", "--report", "json"])
            assert exit_code == 0
            call_kwargs = fake_mod.run.call_args
            assert call_kwargs[1].get("manifest_env_vars") == env_vars

    @patch("main.compute_production_scope", return_value=None)
    def test_manifest_env_vars_not_passed_to_egress(self, _mock_scope):
        """manifest_env_vars must be threaded only to needs_manifest-flagged
        rules (csv), never to unrelated rules (egress) -- verified with two
        independently configured mocks, not a single mock shared across
        both registry entries."""
        csv_mod = MagicMock()
        csv_mod.detect_image_pattern.return_value = "env_var"
        csv_mod.run.return_value = RuleResult(rule="csv", passed=True)

        egress_mod = MagicMock()
        egress_mod.run.return_value = RuleResult(rule="egress", passed=True)

        op_manifest_mock = MagicMock()
        op_manifest_mock.parse_manifest_entries.return_value = ({}, {})
        op_manifest_mock.parse_overlay_paths_from_arch_data.return_value = []

        def _side_effect(name):
            if name == "rules.operator_manifest":
                return op_manifest_mock
            if name == "rules.no_runtime_egress":
                return egress_mod
            return csv_mod

        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])
        env_vars = {"RELATED_IMAGE_FOO"}

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, env_vars)),
            patch("importlib.import_module", side_effect=_side_effect),
        ):
            exit_code = main([".", "--rules", "csv,egress", "--report", "json"])
            assert exit_code == 0
            egress_mod.run.assert_called_once()
            assert "manifest_env_vars" not in egress_mod.run.call_args.kwargs
            csv_mod.run.assert_called_once()
            assert csv_mod.run.call_args.kwargs.get("manifest_env_vars") == env_vars

    @patch("main.compute_production_scope", return_value=None)
    def test_detect_image_pattern_called_once_for_static_csv_repo(self, _mock_scope):
        """Regression: when the repo pattern is not env_var, detect_image_pattern
        must not be called again for a second needs_manifest rule -- the
        answer cannot change between calls against the same repo_root."""
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "static_csv"
        fake_mod.run.return_value = RuleResult(rule="rule", passed=True)

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv,tags", "--report", "json"])
            assert exit_code == 0
            assert fake_mod.detect_image_pattern.call_count == 1

    @patch("main.compute_production_scope", return_value=None)
    def test_verbose_logs_which_rule_triggered_manifest_load(self, _mock_scope, capsys):
        """Regression: --verbose gives no attribution for why the manifest
        clone happened -- a tags-only run should explain which rule
        detected the pattern needing the operator manifest."""
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "env_var"
        fake_mod.run.return_value = RuleResult(rule="tags", passed=True)

        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.load_manifest", return_value=(fake_manifest, set())),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "tags", "--verbose", "--report", "json"])
            assert exit_code == 0
            err = capsys.readouterr().err
            assert "tags" in err
            assert "env_var" in err


# --- integration tests with arch-analyzer fixtures ---


class TestMainWithArchFixtures:
    """Integration tests that pass real arch-analyzer fixture data through the pipeline."""

    @patch("main.compute_production_scope", return_value=None)
    def test_arch_data_passed_to_rules(self, _mock_scope):
        from tests.conftest import load_arch_fixture

        fixture = load_arch_fixture("go_operator")
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="test-rule", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        with (
            patch("main._run_arch_analyzer", return_value=fixture),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "tags", "--report", "json"])

        assert exit_code == 0
        call_kwargs = fake_mod.run.call_args
        assert call_kwargs[1].get("arch_data") is fixture

    @patch("main.compute_production_scope")
    def test_arch_data_passed_to_production_scope(self, mock_scope):
        from tests.conftest import load_arch_fixture

        mock_scope.return_value = None
        fixture = load_arch_fixture("python_component")
        fake_mod = MagicMock()
        fake_mod.run.return_value = RuleResult(rule="test-rule", passed=True)
        fake_mod.detect_image_pattern.return_value = "static_csv"

        with (
            patch("main._run_arch_analyzer", return_value=fixture),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            main([".", "--rules", "tags", "--report", "json"])

        scope_call = mock_scope.call_args
        assert scope_call[1].get("arch_data") is fixture


# --- load_exceptions ---


class TestLoadExceptions:
    def test_load_from_file(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text(
            "exceptions:\n"
            "  - rules: no-runtime-egress\n"
            "    paths:\n"
            '      - "src/main.go"\n'
            '    reason: "internal proxy"\n'
        )
        result = load_exceptions(str(exc_file))
        assert len(result) == 1
        assert result[0]["rules"] == "no-runtime-egress"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ValueError, match="Config file not found"):
            load_exceptions(str(tmp_path / "nope.yaml"))

    def test_empty_exceptions_returns_empty(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text("exceptions: []\n")
        assert load_exceptions(str(exc_file)) == []

    def test_non_mapping_root_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text("- rules: no-image-tags\n  reason: test\n")
        with pytest.raises(ValueError, match="must be a YAML mapping"):
            load_exceptions(str(exc_file))

    def test_missing_reason_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text(
            'exceptions:\n  - rules: no-image-tags\n    paths:\n      - "deploy.yaml"\n'
        )
        with pytest.raises(ValueError, match="reason"):
            load_exceptions(str(exc_file))

    def test_missing_rules_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text('exceptions:\n  - paths:\n      - "deploy.yaml"\n    reason: "test"\n')
        with pytest.raises(ValueError, match="rules"):
            load_exceptions(str(exc_file))

    def test_missing_scope_filter_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text('exceptions:\n  - rules: "*"\n    reason: "no scope filter"\n')
        with pytest.raises(ValueError, match="must include at least one of"):
            load_exceptions(str(exc_file))

    def test_non_dict_entry_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text("exceptions:\n  - no-image-tags\n")
        with pytest.raises(ValueError):
            load_exceptions(str(exc_file))

    def test_malformed_yaml_raises(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text('exceptions:\n  - rules: "missing close quote\n')
        with pytest.raises(ValueError, match="Failed to parse"):
            load_exceptions(str(exc_file))

    def test_unreadable_file_raises(self, tmp_path):
        exc_dir = tmp_path / "exceptions.yaml"
        exc_dir.mkdir()
        with pytest.raises(ValueError, match="Cannot read"):
            load_exceptions(str(exc_dir))

    def test_list_form_rules(self, tmp_path):
        exc_file = tmp_path / "exceptions.yaml"
        exc_file.write_text(
            "exceptions:\n"
            "  - rules:\n"
            "      - no-image-tags\n"
            "      - no-runtime-egress\n"
            "    paths:\n"
            '      - "install/*"\n'
            '    reason: "historical snapshots"\n'
        )
        result = load_exceptions(str(exc_file))
        assert len(result) == 1
        assert result[0]["rules"] == ["no-image-tags", "no-runtime-egress"]
        assert result[0]["paths"] == ["install/*"]


# --- _get_repo_name ---


class TestGetRepoName:
    def test_https_remote(self, tmp_path):
        subprocess_run = patch(
            "main.subprocess.check_output",
            return_value="https://github.com/org-a/my-repo.git\n",
        )
        with subprocess_run:
            assert _get_repo_name(str(tmp_path)) == "org-a/my-repo"

    def test_ssh_remote(self, tmp_path):
        subprocess_run = patch(
            "main.subprocess.check_output",
            return_value="git@github.com:org-a/my-repo.git\n",
        )
        with subprocess_run:
            assert _get_repo_name(str(tmp_path)) == "org-a/my-repo"

    def test_no_remote_falls_back_to_basename(self, tmp_path):
        from subprocess import CalledProcessError

        subprocess_run = patch(
            "main.subprocess.check_output",
            side_effect=CalledProcessError(1, "git"),
        )
        with subprocess_run:
            assert _get_repo_name(str(tmp_path)) == tmp_path.name


# --- apply_exceptions ---


class TestApplyExceptions:
    def test_matching_rule_downgrades_blocker(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "deploy.yaml", 10, "img:latest", "bad tag")],
            )
        ]
        exceptions = [{"rules": "no-image-tags", "reason": "known false positive"}]
        apply_exceptions(results, exceptions, "my-repo")
        assert results[0].findings[0].severity == "info"
        assert "[Exception:" in results[0].findings[0].message
        assert results[0].passed is True

    def test_info_findings_not_targeted(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                findings=[Finding("info", "main.go", 5, "", "configurable URL")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "reason": "internal only"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_non_matching_rule_keeps_severity(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "f.yaml", 1, "img", "bad")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "reason": "wrong rule"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"
        assert results[0].passed is False

    def test_path_glob_matching(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding("blocker", "src/main.go", 1, "img", "bad"),
                    Finding("blocker", "deploy/app.yaml", 2, "img2", "also bad"),
                ],
            )
        ]
        exceptions = [{"rules": "no-image-tags", "paths": ["src/*.go"], "reason": "source ok"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "blocker"
        assert results[0].passed is False

    def test_doublestar_suffix_matches_bare_dir(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding("blocker", "config/scorecard", 1, "img", "bad"),
                    Finding("blocker", "config/scorecard/foo.yaml", 2, "img2", "bad"),
                    Finding("blocker", "config/manager/deploy.yaml", 3, "img3", "bad"),
                ],
            )
        ]
        exceptions = [{"rules": "*", "paths": ["**/config/scorecard/**"], "reason": "test"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "info"
        assert results[0].findings[2].severity == "blocker"

    def test_repo_filter_matches(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "f.go", 1, "", "egress")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "repo": "org/my-repo", "reason": "ok"}]
        apply_exceptions(results, exceptions, "org/my-repo")
        assert results[0].findings[0].severity == "info"

    def test_repo_filter_no_match(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "f.go", 1, "", "egress")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "repo": "other-repo", "reason": "ok"}]
        apply_exceptions(results, exceptions, "my-repo")
        assert results[0].findings[0].severity == "blocker"

    def test_repo_filter_short_exception_matches_full_repo_name(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "f.go", 1, "", "egress")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "repo": "my-repo", "reason": "ok"}]
        apply_exceptions(results, exceptions, "org/my-repo")
        assert results[0].findings[0].severity == "info"

    def test_repo_filter_different_org_same_name_no_match(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "f.go", 1, "", "egress")],
            )
        ]
        exceptions = [{"rules": "no-runtime-egress", "repo": "org-a/foo", "reason": "ok"}]
        apply_exceptions(results, exceptions, "org-b/foo")
        assert results[0].findings[0].severity == "blocker"

    def test_passed_recomputed_after_downgrade(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "a.go", 1, "", "b1"),
                    Finding("blocker", "b.go", 2, "", "b2"),
                ],
            )
        ]
        exceptions = [
            {"rules": "r", "paths": ["a.go"], "reason": "ok"},
            {"rules": "r", "paths": ["b.go"], "reason": "ok"},
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].passed is True

    def test_no_exceptions_noop(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        apply_exceptions(results, [], "repo")
        assert results[0].findings[0].severity == "blocker"
        assert results[0].passed is False

    def test_list_of_rules(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "install/v1/k.yaml", 1, "img", "bad")],
            ),
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "install/v1/s.sh", 5, "", "curl")],
            ),
        ]
        exceptions = [
            {
                "rules": ["no-image-tags", "no-runtime-egress"],
                "paths": ["install/*"],
                "reason": "historical snapshots",
            }
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[0].passed is True
        assert results[1].findings[0].severity == "info"
        assert results[1].passed is True

    def test_list_of_rules_partial_match(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "f.yaml", 1, "img", "bad")],
            ),
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[Finding("blocker", "f.go", 5, "", "curl")],
            ),
        ]
        exceptions = [
            {
                "rules": ["no-image-tags"],
                "reason": "only tags",
            }
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[1].findings[0].severity == "blocker"

    def test_message_glob_matching(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "f.go", 1, "", "http.Get with hardcoded external URL")
                ],
            )
        ]
        exceptions = [{"rules": "r", "message": "*hardcoded*", "reason": "ok"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_message_exact_no_glob_does_not_substring_match(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "f.go", 1, "", "http.Get with hardcoded external URL")
                ],
            )
        ]
        exceptions = [{"rules": "r", "message": "http", "reason": "ok"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"

    def test_images_list_matches(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "f.yaml", 1, "repo/REPLACE_IMAGE:tag", "tagged image")
                ],
            )
        ]
        exceptions = [{"rules": "*", "images": ["*/REPLACE_IMAGE:*"], "reason": "placeholder"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[0].passed is True

    def test_images_list_no_match_stays_blocker(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f.yaml", 1, "quay.io/org/real:tag", "tagged image")],
            )
        ]
        exceptions = [{"rules": "*", "images": ["*/REPLACE_IMAGE:*"], "reason": "placeholder"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"

    def test_images_list_any_pattern_matches(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "f.yaml", 1, "quay.io/org/app:replace", "tagged image")
                ],
            )
        ]
        exceptions = [
            {"rules": "*", "images": ["*/REPLACE_IMAGE:*", "*:replace"], "reason": "placeholder"}
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_images_and_paths_both_must_match(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "prod/f.yaml", 1, "repo/REPLACE_IMAGE:tag", "tagged")],
            )
        ]
        exceptions = [
            {
                "rules": "*",
                "images": ["*/REPLACE_IMAGE:*"],
                "paths": ["test/**"],
                "reason": "placeholder",
            }
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"

    def test_test_yaml_file_pattern(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding("blocker", "docker-compose.test.yml", 5, "nginx:latest", "mutable tag"),
                    Finding(
                        "blocker", "docker-compose.test.yaml", 10, "redis:latest", "mutable tag"
                    ),
                    Finding("blocker", "docker-compose.yml", 3, "postgres:latest", "mutable tag"),
                ],
            )
        ]
        exceptions = [
            {"rules": "*", "paths": ["*.test.yml", "*.test.yaml"], "reason": "Test/mock file"},
        ]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "info"
        assert results[0].findings[2].severity == "blocker"
        assert results[0].passed is False

    # --- rhoai-mcp: loaded from production config/config.yaml ---

    @pytest.fixture()
    def rhoai_mcp_exceptions(self):
        cfg_path = str(Path(__file__).parent.parent / "config" / "config.yaml")
        all_exc = load_exceptions(cfg_path)
        exc = [e for e in all_exc if isinstance(e, dict) and e.get("repo") == "rhoai-mcp"]
        assert len(exc) == 5, f"expected 5 rhoai-mcp exception groups, got {len(exc)}"
        return exc

    @pytest.mark.parametrize("rule", ["no-image-tags", "image-manifest-complete"])
    def test_rhoai_mcp_mock_k8s_matched(self, rhoai_mcp_exceptions, rule):
        results = [
            RuleResult(
                rule=rule,
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/mock_k8s/cluster_state.py",
                        183,
                        "quay.io/modh/odh-minimal-notebook:v2-2024a",
                        "tagged image",
                    ),
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/mock_k8s/cluster_state.py",
                        378,
                        "quay.io/modh/vllm:latest",
                        "tagged image",
                    ),
                    # evals/mock_k8s — same mock fixtures, different path
                    Finding(
                        "blocker",
                        "evals/mock_k8s/cluster_state.py",
                        183,
                        "quay.io/modh/odh-minimal-notebook:v2-2024a",
                        "tagged image",
                    ),
                    # wrong image org — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/mock_k8s/cluster_state.py",
                        50,
                        "quay.io/prod-org/real-app:v1",
                        "tagged image",
                    ),
                    # right image, wrong path — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/serving/tools.py",
                        42,
                        "quay.io/modh/vllm:latest",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "info"
        assert results[0].findings[2].severity == "info"
        assert results[0].findings[3].severity == "blocker"
        assert results[0].findings[4].severity == "blocker"

    @pytest.mark.parametrize("rule", ["no-image-tags", "image-manifest-complete"])
    def test_rhoai_mcp_notebooks_matched(self, rhoai_mcp_exceptions, rule):
        results = [
            RuleResult(
                rule=rule,
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/notebooks/client.py",
                        101,
                        "image-registry.openshift-image-registry.svc:5000/redhat-ods-applications/jupyter-datascience-notebook:2024.1",
                        "tagged image",
                    ),
                    # different registry — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/notebooks/client.py",
                        50,
                        "quay.io/prod-org/production-notebook:v3",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "blocker"

    @pytest.mark.parametrize("rule", ["no-image-tags", "image-manifest-complete"])
    def test_rhoai_mcp_training_matched(self, rhoai_mcp_exceptions, rule):
        results = [
            RuleResult(
                rule=rule,
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/training/tools/runtimes.py",
                        179,
                        "quay.io/modh/training:latest",
                        "tagged image",
                    ),
                    # different org — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/training/tools/runtimes.py",
                        99,
                        "registry.redhat.io/prod/serving-runtime:v2",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "blocker"

    @pytest.mark.parametrize("rule", ["no-image-tags", "image-manifest-complete"])
    def test_rhoai_mcp_inference_docstring_matched(self, rhoai_mcp_exceptions, rule):
        results = [
            RuleResult(
                rule=rule,
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/inference/tools.py",
                        118,
                        "oci://quay.io/org/image:tag",
                        "OCI URI uses tag",
                    ),
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/inference/tools.py",
                        118,
                        "registry.redhat.io/image:tag",
                        "tagged image",
                    ),
                    # unrelated image — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/inference/tools.py",
                        200,
                        "quay.io/prod-org/real-model:v1",
                        "tagged image",
                    ),
                    # sibling name image-prod — stays blocker ([:@] constraint)
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/inference/tools.py",
                        130,
                        "oci://quay.io/org/image-prod:v2",
                        "OCI URI uses tag",
                    ),
                    # sibling name image-builder — stays blocker ([:@] constraint)
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/domains/inference/tools.py",
                        135,
                        "registry.redhat.io/image-builder:latest",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "info"
        assert results[0].findings[2].severity == "blocker"
        assert results[0].findings[3].severity == "blocker"
        assert results[0].findings[4].severity == "blocker"

    @pytest.mark.parametrize("rule", ["no-image-tags", "image-manifest-complete"])
    def test_rhoai_mcp_storage_helper_matched(self, rhoai_mcp_exceptions, rule):
        results = [
            RuleResult(
                rule=rule,
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/composites/training/storage.py",
                        55,
                        "registry.access.redhat.com/ubi9/ubi:latest",
                        "tagged image",
                    ),
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/composites/training/storage.py",
                        60,
                        "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
                        "tagged image",
                    ),
                    # different registry path — stays blocker
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/composites/training/storage.py",
                        70,
                        "quay.io/some-org/ubi9:v1",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "info"
        assert results[0].findings[1].severity == "info"
        assert results[0].findings[2].severity == "blocker"

    def test_rhoai_mcp_wrong_repo_keeps_all_blockers(self, rhoai_mcp_exceptions):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/mock_k8s/cluster_state.py",
                        10,
                        "quay.io/modh/notebook:latest",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "some-other-repo")
        assert results[0].findings[0].severity == "blocker"

    def test_rhoai_mcp_unrelated_rule_not_excepted(self, rhoai_mcp_exceptions):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/rhoai_mcp/mock_k8s/cluster_state.py",
                        10,
                        "quay.io/modh/notebook:latest",
                        "egress call",
                    ),
                ],
            )
        ]
        apply_exceptions(results, rhoai_mcp_exceptions, "rhoai-mcp")
        assert results[0].findings[0].severity == "blocker"

    # --- garak: loaded from production config/config.yaml ---

    @pytest.fixture()
    def garak_exceptions(self):
        cfg_path = str(Path(__file__).parent.parent / "config" / "config.yaml")
        all_exc = load_exceptions(cfg_path)
        exc = [
            e
            for e in all_exc
            if isinstance(e, dict) and e.get("repo") == "llama-stack-provider-trustyai-garak"
        ]
        assert len(exc) == 1
        return exc

    def test_garak_digest_pinned_image_matched(self, garak_exceptions):
        results = [
            RuleResult(
                rule="image-manifest-complete",
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/llama_stack_provider_trustyai_garak/constants.py",
                        6,
                        "quay.io/trustyai/trustyai-garak-lls-provider-dsp@sha256:c960230103493b8dece955012b0a34105c185dd4ac5a3034460b50efa8303084",
                        "hardcoded image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, garak_exceptions, "llama-stack-provider-trustyai-garak")
        assert results[0].findings[0].severity == "info"

    def test_garak_tagged_image_not_matched(self, garak_exceptions):
        results = [
            RuleResult(
                rule="image-manifest-complete",
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/llama_stack_provider_trustyai_garak/constants.py",
                        6,
                        "quay.io/trustyai/trustyai-garak-lls-provider-dsp:latest",
                        "tagged image",
                    ),
                    Finding(
                        "blocker",
                        "src/llama_stack_provider_trustyai_garak/constants.py",
                        6,
                        "quay.io/trustyai/trustyai-garak-lls-provider-dsp:v1.2.3",
                        "tagged image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, garak_exceptions, "llama-stack-provider-trustyai-garak")
        assert results[0].findings[0].severity == "blocker"
        assert results[0].findings[1].severity == "blocker"

    def test_garak_sibling_image_not_matched(self, garak_exceptions):
        results = [
            RuleResult(
                rule="image-manifest-complete",
                passed=False,
                findings=[
                    Finding(
                        "blocker",
                        "src/llama_stack_provider_trustyai_garak/constants.py",
                        6,
                        "quay.io/trustyai/trustyai-garak-lls-provider-dsp-extra@sha256:" + "b" * 64,
                        "hardcoded image",
                    ),
                ],
            )
        ]
        apply_exceptions(results, garak_exceptions, "llama-stack-provider-trustyai-garak")
        assert results[0].findings[0].severity == "blocker"


# --- report sorting ---


class TestReportSorting:
    def test_markdown_blockers_section(self):
        results = [
            RuleResult(
                rule="r1",
                passed=False,
                findings=[
                    Finding("info", "i.go", 1, "", "info msg"),
                    Finding("blocker", "b.go", 2, "img", "block msg"),
                ],
            ),
        ]
        output = render_markdown("NOT READY", results, "repo")
        assert "## Blockers" in output
        assert "block msg" in output
        assert "## Warnings" not in output

    def test_json_findings_sorted_by_severity(self):
        results = [
            RuleResult(
                rule="r",
                findings=[
                    Finding("info", "i.go", 1, "", "info"),
                    Finding("blocker", "b.go", 2, "", "blocker"),
                ],
            ),
        ]
        data = json.loads(render_json("NOT READY", results, "repo"))
        severities = [f["severity"] for f in data["rules"][0]["findings"]]
        assert severities == ["blocker", "info"]

    def test_fallback_renderer_two_for_loops(self):
        template = (
            "{% for b in blockers %}B:{{ b.msg }}{% endfor %}"
            "{% for i in infos %}I:{{ i.msg }}{% endfor %}"
        )
        ctx = {
            "blockers": [{"msg": "b1"}],
            "infos": [{"msg": "i1"}, {"msg": "i2"}],
        }
        result = _render_template_simple(template, ctx)
        assert result == "B:b1I:i1\nI:i2"


# --- parse_args exceptions flag ---


class TestParseArgsExceptions:
    def test_exceptions_flag(self, tmp_path):
        exc_path = tmp_path / "exc.yaml"
        args = parse_args([".", "--config", str(exc_path)])
        assert args.config == str(exc_path)

    def test_exceptions_default_none(self):
        args = parse_args(["."])
        assert args.config is None


# --- central exception loading ---


class TestLoadCentralConfig:
    def test_missing_file_raises(self, tmp_path):
        from main import load_central_config

        with pytest.raises(ValueError, match="Config file not found"):
            load_central_config(str(tmp_path / "nope.yaml"))

    def test_present_file_has_all_keys(self, tmp_path):
        from main import load_central_config

        f = tmp_path / "config.yaml"
        f.write_text("exceptions: []\n")
        cfg = load_central_config(str(f))
        assert cfg["docker_contexts"] == {}
        assert cfg["known_non_image_prefixes"] == []
        assert cfg["params_env_filenames"] == {}

    def test_loads_docker_contexts(self, tmp_path):
        from main import load_central_config

        f = tmp_path / "config.yaml"
        f.write_text("docker_contexts:\n  myrepo:\n    Dockerfile: src/\n")
        cfg = load_central_config(str(f))
        assert cfg["docker_contexts"] == {"myrepo": {"Dockerfile": "src/"}}

    def test_loads_known_non_image_prefixes(self, tmp_path):
        from main import load_central_config

        f = tmp_path / "config.yaml"
        f.write_text("known_non_image_prefixes:\n  - ghcr.io/foo/bar\n")
        cfg = load_central_config(str(f))
        assert "ghcr.io/foo/bar" in cfg["known_non_image_prefixes"]

    def test_loads_params_env_filenames(self, tmp_path):
        from main import load_central_config

        f = tmp_path / "config.yaml"
        f.write_text("params_env_filenames:\n  myrepo:\n    - params-latest.env\n")
        cfg = load_central_config(str(f))
        assert cfg["params_env_filenames"] == {"myrepo": ["params-latest.env"]}


class TestArchAnalyzerError:
    def test_is_exception(self):
        from main import ArchAnalyzerError

        err = ArchAnalyzerError("binary missing")
        assert isinstance(err, Exception)
        assert "binary missing" in str(err)


class TestValidateConfigSchema:
    def test_valid_config_passes(self):
        _validate_config_schema({"exceptions": []}, "test.yaml")

    def test_invalid_config_raises(self):
        with pytest.raises(ValueError, match="schema validation error"):
            _validate_config_schema({"exceptions": "not_a_list"}, "test.yaml")

    def test_missing_schema_file_raises(self, monkeypatch):
        import main
        from rules.common import ConfigError

        monkeypatch.setattr(main, "_SCHEMA_PATH", Path("/nonexistent/schema.json"))
        with pytest.raises(ConfigError, match="Cannot read config schema"):
            _validate_config_schema({"anything": True}, "test.yaml")


class TestRunArchAnalyzer:
    def test_deletes_existing_json_before_run(self, tmp_path, monkeypatch):
        """Pre-existing JSON is deleted (supply chain safety), binary must exist."""
        (tmp_path / "component-architecture.json").write_text('{"old": true}')
        with pytest.raises(ArchAnalyzerError, match="not found"):
            _run_arch_analyzer("nonexistent-bin", str(tmp_path))
        assert not (tmp_path / "component-architecture.json").exists()

    def test_binary_not_found_raises(self, tmp_path):
        with pytest.raises(ArchAnalyzerError, match="not found"):
            _run_arch_analyzer(str(tmp_path / "no-such-bin"), str(tmp_path))

    def test_subprocess_failure_raises(self, tmp_path, monkeypatch):
        import subprocess

        bin_path = tmp_path / "fake-bin"
        bin_path.touch()
        monkeypatch.setattr(
            "main.subprocess.run",
            MagicMock(side_effect=subprocess.CalledProcessError(1, "cmd", stderr=b"fail")),
        )
        with pytest.raises(ArchAnalyzerError, match="failed"):
            _run_arch_analyzer(str(bin_path), str(tmp_path))

    def test_timeout_raises(self, tmp_path, monkeypatch):
        import subprocess

        bin_path = tmp_path / "fake-bin"
        bin_path.touch()
        monkeypatch.setattr(
            "main.subprocess.run",
            MagicMock(side_effect=subprocess.TimeoutExpired("cmd", 300)),
        )
        with pytest.raises(ArchAnalyzerError, match="failed"):
            _run_arch_analyzer(str(bin_path), str(tmp_path))

    def test_missing_output_after_run_raises(self, tmp_path, monkeypatch):
        bin_path = tmp_path / "fake-bin"
        bin_path.touch()
        monkeypatch.setattr("main.subprocess.run", MagicMock())
        with pytest.raises(ArchAnalyzerError, match="did not generate"):
            _run_arch_analyzer(str(bin_path), str(tmp_path))

    def test_invalid_json_raises(self, tmp_path, monkeypatch):
        bin_path = tmp_path / "fake-bin"
        bin_path.touch()

        def fake_run(*args, **kwargs):
            (tmp_path / "component-architecture.json").write_text("not json{{{")

        monkeypatch.setattr("main.subprocess.run", fake_run)
        with pytest.raises(ArchAnalyzerError, match="Failed to parse"):
            _run_arch_analyzer(str(bin_path), str(tmp_path))


class TestApplyExceptionsHits:
    def test_returns_hit_counts(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f.go", 1, "", "msg")],
            )
        ]
        exceptions = [
            {"rules": "r", "reason": "ok"},
            {"rules": "other", "reason": "unused"},
        ]
        hits = apply_exceptions(results, exceptions, "repo")
        assert hits == [1, 0]

    def test_empty_exceptions_returns_empty(self):
        results = [RuleResult(rule="r", findings=[Finding("blocker", "f", 1, "", "m")])]
        hits = apply_exceptions(results, [], "repo")
        assert hits == []

    def test_wildcard_rule_counts(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[
                    Finding("blocker", "a.go", 1, "", "m1"),
                    Finding("blocker", "b.go", 2, "", "m2"),
                    Finding("blocker", "c.go", 3, "", "m3"),
                ],
            )
        ]
        exceptions = [{"rules": "*", "reason": "all ok"}]
        hits = apply_exceptions(results, exceptions, "repo")
        assert hits == [3]


# --- rules field validation ---


def _write_exception(tmp_path, rules_value):
    """Write a minimal exception config and return the path string."""
    exc_file = tmp_path / "config.yaml"
    if isinstance(rules_value, list):
        items = "\n".join(f"      - {v}" for v in rules_value)
        rules_block = f"rules:\n{items}"
    else:
        rules_block = f"rules: {rules_value}"
    exc_file.write_text(
        f'exceptions:\n  - {rules_block}\n    paths:\n      - "**/*.yaml"\n    reason: "ok"\n'
    )
    return str(exc_file)


class TestRulesFieldValidation:
    def test_valid_rules_accepted(self, tmp_path):
        cases = [
            ("single-rule", "no-image-tags", "no-image-tags"),
            ("wildcard", '"*"', "*"),
            (
                "list",
                ["no-image-tags", "no-runtime-egress"],
                ["no-image-tags", "no-runtime-egress"],
            ),
        ]
        for name, rules_value, expected in cases:
            d = tmp_path / name
            d.mkdir()
            result = load_exceptions(_write_exception(d, rules_value))
            assert result[0]["rules"] == expected, name

    def test_invalid_rules_rejected(self, tmp_path):
        cases = [
            ("invalid-string", "nonexistent", "unknown rule name 'nonexistent'"),
            ("invalid-in-list", ["no-image-tags", "bogus"], "unknown rule name 'bogus'"),
            ("wildcard-in-list", ['"*"'], r"wildcard.*not allowed inside a list"),
            ("wildcard-mixed", ["no-image-tags", '"*"'], r"wildcard.*not allowed inside a list"),
            ("empty-string", '""', "schema validation error"),
            ("empty-list", "[]", "schema validation error"),
            ("integer", "42", "schema validation error"),
            ("non-string-item", [42], "schema validation error"),
            ("duplicates", ["no-image-tags", "no-image-tags"], "schema validation error"),
        ]
        for name, rules_value, error_pattern in cases:
            d = tmp_path / name
            d.mkdir()
            with pytest.raises(ValueError, match=error_pattern):
                load_exceptions(_write_exception(d, rules_value))


# --- normalize rules ---


class TestNormalizeRules:
    def test_string_returns_frozenset(self):
        assert _normalize_rules("no-image-tags") == frozenset(["no-image-tags"])

    def test_wildcard_preserved(self):
        result = _normalize_rules("*")
        assert "*" in result
        assert result == frozenset(["*"])

    def test_list_returns_frozenset(self):
        assert _normalize_rules(["a", "b"]) == frozenset(["a", "b"])

    def test_empty_string_returns_empty(self):
        assert _normalize_rules("") == frozenset()

    def test_none_returns_empty(self):
        assert _normalize_rules(None) == frozenset()

    def test_empty_list_returns_empty(self):
        assert _normalize_rules([]) == frozenset()

    def test_return_type_is_frozenset(self):
        assert isinstance(_normalize_rules("x"), frozenset)
        assert isinstance(_normalize_rules(["x"]), frozenset)
        assert isinstance(_normalize_rules(""), frozenset)


class TestRulesDisplayStr:
    def test_string_passthrough(self):
        assert _rules_display_str("no-image-tags") == "no-image-tags"

    def test_list_joined(self):
        assert (
            _rules_display_str(["no-image-tags", "no-runtime-egress"])
            == "no-image-tags, no-runtime-egress"
        )

    def test_single_item_list(self):
        assert _rules_display_str(["no-image-tags"]) == "no-image-tags"

    def test_empty_string_returns_empty(self):
        assert _rules_display_str("") == ""

    def test_none_returns_empty(self):
        assert _rules_display_str(None) == ""

    def test_empty_list_returns_empty(self):
        assert _rules_display_str([]) == ""

    def test_wildcard(self):
        assert _rules_display_str("*") == "*"


# --- exception rendering ---


class TestBuildExceptionsSection:
    def test_string_rules_value(self):
        exceptions = [{"rules": "no-image-tags", "reason": "ok"}]
        section = _build_exceptions_section(exceptions, [3])
        assert "## Applied Exceptions" in section
        assert "| Rules |" in section
        assert "| no-image-tags |" in section
        assert "| 3 |" in section

    def test_list_rules_joined(self):
        exceptions = [{"rules": ["no-image-tags", "no-runtime-egress"], "reason": "ok"}]
        section = _build_exceptions_section(exceptions, [2])
        assert "no-image-tags, no-runtime-egress" in section

    def test_wildcard_rules(self):
        exceptions = [{"rules": "*", "reason": "all"}]
        section = _build_exceptions_section(exceptions, [5])
        assert "| * |" in section

    def test_zero_hits_excluded(self):
        exceptions = [
            {"rules": "no-image-tags", "reason": "ok"},
            {"rules": "no-runtime-egress", "reason": "unused"},
        ]
        section = _build_exceptions_section(exceptions, [1, 0])
        assert "no-image-tags" in section
        assert "no-runtime-egress" not in section

    def test_empty_when_no_hits(self):
        exceptions = [{"rules": "*", "reason": "ok"}]
        assert _build_exceptions_section(exceptions, [0]) == ""

    def test_empty_when_no_exceptions(self):
        assert _build_exceptions_section([], []) == ""


class TestRenderJsonExceptions:
    def test_string_rules_normalized_to_list(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [{"rules": "no-image-tags", "reason": "ok"}]
        raw = render_json("READY", results, "repo", exceptions=exceptions, exception_hits=[1])
        data = json.loads(raw)
        assert "exceptions" in data
        assert data["exceptions"][0]["rules"] == ["no-image-tags"]
        assert data["exceptions"][0]["hits"] == 1

    def test_list_rules_sorted_in_output(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [{"rules": ["no-runtime-egress", "no-image-tags"], "reason": "ok"}]
        raw = render_json("READY", results, "repo", exceptions=exceptions, exception_hits=[2])
        data = json.loads(raw)
        assert data["exceptions"][0]["rules"] == ["no-image-tags", "no-runtime-egress"]

    def test_wildcard_normalized_to_list(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [{"rules": "*", "reason": "ok"}]
        raw = render_json("READY", results, "repo", exceptions=exceptions, exception_hits=[1])
        data = json.loads(raw)
        assert data["exceptions"][0]["rules"] == ["*"]

    def test_repo_included_when_present(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [{"rules": "*", "repo": "my-repo", "reason": "ok"}]
        raw = render_json("READY", results, "repo", exceptions=exceptions, exception_hits=[1])
        data = json.loads(raw)
        assert data["exceptions"][0]["repo"] == "my-repo"

    def test_no_exceptions_key_when_empty(self):
        results = [RuleResult(rule="r", findings=[])]
        raw = render_json("READY", results, "repo")
        data = json.loads(raw)
        assert "exceptions" not in data


# --- exception snippets and false positive section ---


class TestExceptionSnippets:
    def test_builds_snippets_from_blockers_only(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                findings=[
                    Finding("blocker", "deploy.yaml", 10, "img:latest", "mutable tag"),
                    Finding("info", "src/main.go", 5, "img:v1", "source tag"),
                    Finding("info", "test/t.go", 1, "img:dev", "test file"),
                ],
            )
        ]
        snippets = _build_exception_snippets(results)
        assert len(snippets) == 1
        assert snippets[0]["rules"] == "no-image-tags"
        assert snippets[0]["file"] == "deploy.yaml"

    def test_snippets_exclude_empty_fields(self):
        results = [
            RuleResult(
                rule="no-runtime-egress",
                findings=[
                    Finding("blocker", "client.go", 5, "", "egress call"),
                ],
            )
        ]
        snippets = _build_exception_snippets(results)
        assert "image" not in snippets[0]
        assert snippets[0]["message"] == "egress call"

    def test_empty_when_no_blockers(self):
        results = [
            RuleResult(
                rule="r",
                findings=[
                    Finding("info", "f", 1, "", "ok"),
                ],
            )
        ]
        assert _build_exception_snippets(results) == []

    def test_false_positive_section_empty_when_no_snippets(self):
        assert _build_false_positive_section([]) == ""

    def test_false_positive_section_shows_count_and_link(self):
        snippets = [
            {"rules": "r1", "file": "a.go", "line": 1, "image": "", "message": "m1"},
            {"rules": "r2", "file": "b.go", "line": 2, "image": "", "message": "m2"},
        ]
        section = _build_false_positive_section(snippets)
        assert "2 blocker findings" in section
        assert "central config file" in section
        assert "#reporting-false-positives" in section

    def test_false_positive_section_singular_for_one_blocker(self):
        snippets = [{"rules": "r", "file": "f", "line": 1, "image": "", "message": "m"}]
        section = _build_false_positive_section(snippets)
        assert "1 blocker finding" in section

    def test_markdown_report_includes_false_positive_section(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding("blocker", "deploy.yaml", 10, "img:latest", "mutable tag"),
                ],
            )
        ]
        output = render_markdown("NOT READY", results, "test-repo")
        assert "Reporting False Positives" in output
        assert "central config file" in output

    def test_markdown_report_omits_section_when_no_blockers(self):
        results = [
            RuleResult(
                rule="r",
                findings=[
                    Finding("info", "f", 1, "", "ok"),
                ],
            )
        ]
        output = render_markdown("READY", results, "repo")
        assert "Reporting False Positives" not in output

    def test_json_report_includes_false_positive_help(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[
                    Finding("blocker", "deploy.yaml", 10, "img:latest", "mutable tag"),
                ],
            )
        ]
        data = json.loads(render_json("NOT READY", results, "test-repo"))
        assert "false_positive_help" in data
        assert "exception_snippets" in data["false_positive_help"]
        assert len(data["false_positive_help"]["exception_snippets"]) == 1

    def test_json_report_omits_help_when_no_blockers(self):
        results = [
            RuleResult(
                rule="r",
                findings=[
                    Finding("info", "f", 1, "", "ok"),
                ],
            )
        ]
        data = json.loads(render_json("READY", results, "repo"))
        assert "false_positive_help" not in data


# ---------------------------------------------------------------------------
# Exception expiration — validation
# ---------------------------------------------------------------------------


class TestValidateExceptionsExpires:
    def test_valid_expires_string(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            '    reason: "temp exception"\n'
            '    expires: "2025-12-31"\n'
            "    paths:\n"
            '      - "**/*.yaml"\n'
        )
        result = load_exceptions(str(f))
        assert result[0]["expires"] == date(2025, 12, 31)

    def test_expires_bare_date_normalized(self, tmp_path):
        """YAML auto-parses bare dates as datetime.date objects."""
        f = tmp_path / "config.yaml"
        f.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    reason: temp\n"
            "    expires: 2025-12-31\n"
            "    paths:\n"
            '      - "**/*.yaml"\n'
        )
        result = load_exceptions(str(f))
        assert result[0]["expires"] == date(2025, 12, 31)
        assert isinstance(result[0]["expires"], date)

    def test_invalid_expires_format_raises(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            'exceptions:\n  - rules: no-image-tags\n    reason: "temp"\n    expires: "not-a-date"\n'
        )
        with pytest.raises(ValueError, match=r"invalid.*expires.*date"):
            load_exceptions(str(f))

    def test_expires_wrong_type_raises(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text('exceptions:\n  - rules: no-image-tags\n    reason: "temp"\n    expires: 42\n')
        with pytest.raises(ValueError, match="expires"):
            load_exceptions(str(f))

    def test_no_expires_field_passes(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text(
            'exceptions:\n  - rules: \'*\'\n    reason: "permanent"\n    paths:\n      - "**/*"\n'
        )
        result = load_exceptions(str(f))
        assert "expires" not in result[0]


# ---------------------------------------------------------------------------
# Exception expiration — enforcement
# ---------------------------------------------------------------------------


class TestApplyExceptionsExpiration:
    def test_expired_exception_not_applied(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "f.yaml", 1, "img:latest", "bad tag")],
            )
        ]
        exceptions = [{"rules": "no-image-tags", "reason": "temp", "expires": date(2020, 1, 1)}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"
        assert results[0].passed is False

    def test_future_exception_still_applied(self):
        results = [
            RuleResult(
                rule="no-image-tags",
                passed=False,
                findings=[Finding("blocker", "f.yaml", 1, "img:latest", "bad tag")],
            )
        ]
        exceptions = [{"rules": "no-image-tags", "reason": "temp", "expires": date(2099, 12, 31)}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_expires_today_still_honored(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        exceptions = [{"rules": "r", "reason": "ok", "expires": date.today()}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_expires_yesterday_not_honored(self):
        yesterday = date.today() - timedelta(days=1)
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        exceptions = [{"rules": "r", "reason": "ok", "expires": yesterday}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "blocker"

    def test_no_expires_field_is_permanent(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        exceptions = [{"rules": "r", "reason": "permanent"}]
        apply_exceptions(results, exceptions, "repo")
        assert results[0].findings[0].severity == "info"

    def test_expired_exception_hit_count_zero(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        exceptions = [{"rules": "r", "reason": "expired", "expires": date(2020, 1, 1)}]
        hits = apply_exceptions(results, exceptions, "repo")
        assert hits == [0]

    def test_mix_of_expired_and_active(self):
        results = [
            RuleResult(
                rule="r",
                passed=False,
                findings=[Finding("blocker", "f", 1, "", "msg")],
            )
        ]
        exceptions = [
            {"rules": "r", "reason": "expired", "expires": date(2020, 1, 1)},
            {"rules": "r", "reason": "active", "expires": date(2099, 12, 31)},
        ]
        hits = apply_exceptions(results, exceptions, "repo")
        assert hits == [0, 1]
        assert results[0].findings[0].severity == "info"


# ---------------------------------------------------------------------------
# Exception expiration — warnings and reports
# ---------------------------------------------------------------------------


class TestExpiringExceptionsReport:
    def test_find_expiring_exceptions(self):
        soon = date.today() + timedelta(days=7)
        exceptions = [
            {"rules": "r", "reason": "soon", "expires": soon},
            {"rules": "r2", "reason": "permanent"},
            {"rules": "r3", "reason": "expired", "expires": date(2020, 1, 1)},
        ]
        hits = [5, 3, 0]
        expiring = _find_expiring_exceptions(exceptions, hits)
        assert len(expiring) == 1
        assert expiring[0][0]["reason"] == "soon"
        assert expiring[0][1] == 7
        assert expiring[0][2] == 5

    def test_find_expiring_none_within_window(self):
        exceptions = [
            {"rules": "r", "reason": "far", "expires": date(2099, 12, 31)},
            {"rules": "r2", "reason": "permanent"},
        ]
        assert _find_expiring_exceptions(exceptions, [1, 1]) == []

    def test_expiring_section_in_markdown(self):
        soon = date.today() + timedelta(days=5)
        exceptions = [{"rules": "r", "repo": "my-repo", "reason": "temp fix", "expires": soon}]
        section = _build_expiring_exceptions_section(exceptions, [3])
        assert "Expiring Exceptions" in section
        assert "my-repo" in section
        assert "5" in section

    def test_expiring_section_empty_when_none(self):
        assert _build_expiring_exceptions_section([], []) == ""

    def test_json_report_includes_expiring_exceptions(self):
        soon = date.today() + timedelta(days=3)
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "temp", "expires": soon}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[0],
            )
        )
        assert "expiring_exceptions" in data
        assert data["expiring_exceptions"][0]["days_remaining"] == 3

    def test_json_report_no_expiring_when_none(self):
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "perm"}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[0],
            )
        )
        assert "expiring_exceptions" not in data

    def test_json_report_includes_expires_in_exceptions(self):
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "temp", "expires": date(2099, 12, 31)}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[1],
            )
        )
        assert data["exceptions"][0]["expires"] == "2099-12-31"

    def test_json_report_omits_expires_when_not_set(self):
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "perm"}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[1],
            )
        )
        assert "expires" not in data["exceptions"][0]

    def test_applied_exceptions_section_shows_expires_column(self):
        exceptions = [
            {"rules": "r", "reason": "temp", "expires": date(2025, 9, 1)},
        ]
        section = _build_exceptions_section(exceptions, [3])
        assert "Expires" in section
        assert "2025-09-01" in section

    def test_applied_exceptions_section_no_expires_column_when_none(self):
        exceptions = [{"rules": "r", "reason": "perm"}]
        section = _build_exceptions_section(exceptions, [3])
        assert "Expires" not in section


# ---------------------------------------------------------------------------
# Exception expiration — schema validation
# ---------------------------------------------------------------------------


class TestSchemaExpiresField:
    def test_expires_field_accepted_by_schema(self):
        _validate_config_schema(
            {"exceptions": [{"rules": "r", "reason": "ok", "expires": "2025-09-01"}]},
            "test.yaml",
        )

    def test_invalid_expires_type_fails_schema(self):
        with pytest.raises(ValueError, match="schema validation error"):
            _validate_config_schema(
                {"exceptions": [{"rules": "r", "reason": "ok", "expires": 123}]},
                "test.yaml",
            )


# ---------------------------------------------------------------------------
# --list-expiring CLI flag
# ---------------------------------------------------------------------------


class TestListExpiring:
    def test_list_expiring_flag_parsed(self):
        args = parse_args([".", "--list-expiring"])
        assert args.list_expiring is True

    def test_list_expiring_default_false(self):
        args = parse_args(["."])
        assert args.list_expiring is False

    def test_list_expiring_with_nonexistent_config_fails_hard(self, tmp_path, capsys):
        """--list-expiring must abort loudly on a bad --config, matching
        --audit-exceptions and the normal scan path -- see RHOAIENG-79773."""
        missing_config_path = tmp_path / "does-not-exist.yaml"

        exit_code = main([".", "--list-expiring", "--config", str(missing_config_path)])
        assert exit_code == 1
        assert "Config file not found" in capsys.readouterr().err

    def test_list_expiring_no_expiring_returns_zero(self, tmp_path, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    reason: permanent\n"
            "    paths:\n"
            '      - "**/*"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 0
        assert "No expired or expiring" in capsys.readouterr().out

    def test_list_expiring_with_expiring_returns_two(self, tmp_path, capsys):
        from datetime import date, timedelta

        soon = (date.today() + timedelta(days=5)).isoformat()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    reason: temp fix\n"
            f'    expires: "{soon}"\n'
            "    repo: my-repo\n"
            "    paths:\n"
            '      - "**/*"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 2
        out = capsys.readouterr().out
        assert "1 exception(s) expiring" in out
        assert "my-repo" in out
        assert "no-image-tags" in out

    def test_list_expiring_shows_expired(self, tmp_path, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    reason: old workaround\n"
            '    expires: "2020-01-01"\n'
            "    repo: stale-repo\n"
            "    paths:\n"
            '      - "**/*"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 2
        out = capsys.readouterr().out
        assert "1 expired exception(s)" in out
        assert "stale-repo" in out
        assert "2020-01-01" in out
        assert "no-image-tags" in out

    def test_list_expiring_shows_both_expired_and_expiring(self, tmp_path, capsys):
        from datetime import date, timedelta

        soon = (date.today() + timedelta(days=3)).isoformat()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    reason: already gone\n"
            '    expires: "2020-06-15"\n'
            "    repo: old-repo\n"
            "    paths:\n"
            '      - "**/*"\n'
            "  - rules: no-runtime-egress\n"
            "    reason: going soon\n"
            f'    expires: "{soon}"\n'
            "    repo: new-repo\n"
            "    paths:\n"
            '      - "**/*"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 2
        out = capsys.readouterr().out
        assert "1 expired exception(s)" in out
        assert "1 exception(s) expiring" in out
        assert "old-repo" in out
        assert "new-repo" in out
        assert "no-image-tags" in out
        assert "no-runtime-egress" in out

    def test_list_expiring_with_list_rules_expired(self, tmp_path, capsys):
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules:\n"
            "      - image-manifest-complete\n"
            "      - no-image-tags\n"
            "    reason: test multi-rule\n"
            '    expires: "2020-01-01"\n'
            "    repo: test-repo\n"
            "    paths:\n"
            '      - "foo/**"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 2
        out = capsys.readouterr().out
        assert "1 expired exception(s)" in out
        assert "image-manifest-complete, no-image-tags" in out
        assert "test-repo" in out

    def test_list_expiring_with_list_rules_expiring(self, tmp_path, capsys):
        from datetime import date, timedelta

        soon = (date.today() + timedelta(days=5)).isoformat()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "exceptions:\n"
            "  - rules:\n"
            "      - image-manifest-complete\n"
            "      - no-image-tags\n"
            "    reason: test multi-rule\n"
            f'    expires: "{soon}"\n'
            "    repo: test-repo\n"
            "    paths:\n"
            '      - "foo/**"\n'
        )
        rc = main([".", "--list-expiring", "--config", str(cfg)])
        assert rc == 2
        out = capsys.readouterr().out
        assert "1 exception(s) expiring" in out
        assert "image-manifest-complete, no-image-tags" in out
        assert "test-repo" in out


# ---------------------------------------------------------------------------
# Expired exceptions — helpers and reports
# ---------------------------------------------------------------------------


class TestExpiredExceptions:
    def test_find_expired_exceptions(self):
        exceptions = [
            {"rules": "r1", "reason": "old", "expires": date(2020, 1, 1)},
            {"rules": "r2", "reason": "permanent"},
            {"rules": "r3", "reason": "future", "expires": date(2099, 12, 31)},
        ]
        expired = _find_expired_exceptions(exceptions)
        assert len(expired) == 1
        assert expired[0][0]["reason"] == "old"
        assert expired[0][1] > 0  # days_since > 0

    def test_find_expired_none_when_all_active(self):
        exceptions = [
            {"rules": "r", "reason": "future", "expires": date(2099, 12, 31)},
            {"rules": "r2", "reason": "permanent"},
        ]
        assert _find_expired_exceptions(exceptions) == []

    def test_find_expired_excludes_today(self):
        exceptions = [
            {"rules": "r", "reason": "today", "expires": date.today()},
        ]
        assert _find_expired_exceptions(exceptions) == []

    def test_expired_section_in_markdown(self):
        exceptions = [
            {"rules": "r", "repo": "my-repo", "reason": "old fix", "expires": date(2020, 6, 15)}
        ]
        section = _build_expired_exceptions_section(exceptions)
        assert "Expired Exceptions" in section
        assert "no longer applied" in section
        assert "my-repo" in section
        assert "2020-06-15" in section

    def test_expired_section_empty_when_none(self):
        assert _build_expired_exceptions_section([]) == ""

    def test_json_report_includes_expired_exceptions(self):
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "old", "expires": date(2020, 1, 1)}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[0],
            )
        )
        assert "expired_exceptions" in data
        assert data["expired_exceptions"][0]["days_since_expiry"] > 0
        assert data["expired_exceptions"][0]["expires"] == "2020-01-01"

    def test_json_report_no_expired_when_none(self):
        results = [RuleResult(rule="r")]
        exceptions = [{"rules": "r", "reason": "perm"}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[0],
            )
        )
        assert "expired_exceptions" not in data


class TestRuleRegistryMetadata:
    def test_component_rules_have_maturity_fields(self):
        for alias, entry in RULE_REGISTRY.items():
            if entry.get("is_manifest_rule"):
                continue
            for key in ("display_name", "remediation", "reference_doc"):
                assert key in entry, f"Rule {alias} missing {key}"
                assert isinstance(entry[key], str) and entry[key]

    def test_component_rules_reference_doc_is_absolute(self):
        for alias, entry in RULE_REGISTRY.items():
            if entry.get("is_manifest_rule"):
                continue
            assert entry["reference_doc"].startswith("https://"), (
                f"Rule {alias} reference_doc not absolute: {entry['reference_doc']}"
            )

    def test_manifest_rules_have_no_maturity_fields(self):
        for alias, entry in RULE_REGISTRY.items():
            if entry.get("is_manifest_rule"):
                for key in ("display_name", "remediation", "reference_doc"):
                    assert key not in entry, f"Manifest rule {alias} should not have {key}"


# --- audit exceptions ---


class TestAuditExceptions:
    def test_repo_specific_wildcard_is_warning(self):
        exceptions = [
            {"rules": "*", "repo": "my-repo", "paths": ["src/**"], "reason": "test"},
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) >= 1
        assert 'rules: "*"' in warnings[0]["reason"]

    def test_universal_wildcard_is_info(self):
        exceptions = [
            {"rules": "*", "paths": ["**/test/**"], "reason": "test dirs"},
        ]
        findings = _audit_exceptions(exceptions)
        infos = [f for f in findings if f["level"] == "info"]
        assert len(infos) == 1
        assert "Universal" in infos[0]["reason"]

    def test_repo_specific_broad_paths_only_is_warning(self):
        exceptions = [
            {"rules": "no-image-tags", "repo": "my-repo", "paths": ["src/**"], "reason": "test"},
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) == 1
        assert "broad path globs" in warnings[0]["reason"]

    def test_repo_specific_narrow_paths_only_no_warning(self):
        exceptions = [
            {
                "rules": "no-image-tags",
                "repo": "my-repo",
                "paths": ["pkg/constants/constants.go"],
                "reason": "specific file",
            },
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) == 0

    def test_repo_specific_with_message_no_warning(self):
        exceptions = [
            {
                "rules": "no-image-tags",
                "repo": "my-repo",
                "paths": ["src/**"],
                "message": "*specific*",
                "reason": "test",
            },
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) == 0

    def test_repo_specific_with_images_no_warning(self):
        exceptions = [
            {
                "rules": "no-image-tags",
                "repo": "my-repo",
                "paths": ["src/**"],
                "images": ["quay.io/*"],
                "reason": "test",
            },
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) == 0

    def test_well_scoped_returns_empty(self):
        exceptions = [
            {
                "rules": "no-image-tags",
                "repo": "my-repo",
                "paths": ["src/**"],
                "message": "*tag*",
                "reason": "test",
            },
        ]
        findings = _audit_exceptions(exceptions)
        assert len(findings) == 0

    def test_empty_exceptions_returns_empty(self):
        assert _audit_exceptions([]) == []

    def test_finding_index_matches_exception_position(self):
        exceptions = [
            {"rules": "no-image-tags", "paths": ["a/**"], "message": "*x*", "reason": "ok"},
            {"rules": "*", "repo": "r", "paths": ["b/**"], "reason": "broad"},
        ]
        findings = _audit_exceptions(exceptions)
        assert findings[0]["index"] == 1

    def test_repo_specific_wildcard_plus_paths_only_produces_two_warnings(self):
        exceptions = [
            {"rules": "*", "repo": "my-repo", "paths": ["src/**"], "reason": "test"},
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning"]
        assert len(warnings) == 2

    def test_repo_specific_wildcard_with_images_no_wildcard_warning(self):
        exceptions = [
            {
                "rules": "*",
                "repo": "my-repo",
                "paths": ["config/**"],
                "images": ["REPLACE_IMAGE:*"],
                "reason": "constrained by images",
            },
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning" and 'rules: "*"' in f["reason"]]
        assert len(warnings) == 0

    def test_repo_specific_wildcard_with_message_no_wildcard_warning(self):
        exceptions = [
            {
                "rules": "*",
                "repo": "my-repo",
                "paths": ["src/**"],
                "message": "*specific*",
                "reason": "constrained by message",
            },
        ]
        findings = _audit_exceptions(exceptions)
        warnings = [f for f in findings if f["level"] == "warning" and 'rules: "*"' in f["reason"]]
        assert len(warnings) == 0


# --- unused exceptions ---


class TestUnusedExceptions:
    def test_renders_unused_exceptions_table(self):
        exceptions = [
            {"rules": "no-image-tags", "reason": "ok", "repo": "a"},
            {"rules": "*", "reason": "unused one", "repo": "foo"},
        ]
        section = _build_unused_exceptions_section(exceptions, [3, 0], "foo")
        assert "## Unused Exceptions" in section
        assert "unused one" in section
        assert "no-image-tags" not in section

    def test_empty_when_all_have_hits(self):
        exceptions = [{"rules": "*", "reason": "ok", "repo": "r"}]
        assert _build_unused_exceptions_section(exceptions, [5], "r") == ""

    def test_empty_when_no_exceptions(self):
        assert _build_unused_exceptions_section([], [], "") == ""

    def test_empty_when_no_hits_list(self):
        assert _build_unused_exceptions_section(None, None, "") == ""

    def test_list_rules_joined_in_table(self):
        exceptions = [
            {"rules": ["no-image-tags", "no-runtime-egress"], "reason": "multi", "repo": "r"},
        ]
        section = _build_unused_exceptions_section(exceptions, [0], "r")
        assert "no-image-tags, no-runtime-egress" in section

    def test_global_exceptions_excluded(self):
        exceptions = [
            {"rules": "*", "reason": "universal test dirs"},
            {"rules": "no-image-tags", "reason": "repo one", "repo": "foo"},
        ]
        section = _build_unused_exceptions_section(exceptions, [0, 0], "foo")
        assert "universal test dirs" not in section
        assert "repo one" in section

    def test_other_repo_exceptions_excluded(self):
        exceptions = [
            {"rules": "*", "reason": "for bar", "repo": "bar"},
            {"rules": "no-image-tags", "reason": "for foo", "repo": "foo"},
        ]
        section = _build_unused_exceptions_section(exceptions, [0, 0], "foo")
        assert "for bar" not in section
        assert "for foo" in section

    def test_short_repo_matches_full_name(self):
        exceptions = [
            {"rules": "*", "reason": "match", "repo": "my-repo"},
        ]
        section = _build_unused_exceptions_section(exceptions, [0], "org/my-repo")
        assert "match" in section

    def test_expired_exceptions_excluded(self):
        exceptions = [
            {"rules": "*", "reason": "expired", "repo": "foo", "expires": date(2020, 1, 1)},
            {"rules": "no-image-tags", "reason": "active unused", "repo": "foo"},
        ]
        section = _build_unused_exceptions_section(
            exceptions, [0, 0], "foo", today=date(2025, 1, 1)
        )
        assert "expired" not in section
        assert "active unused" in section

    def test_json_report_includes_unused_exceptions(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [
            {"rules": "no-image-tags", "reason": "used", "repo": "repo"},
            {"rules": "*", "reason": "unused one", "repo": "repo"},
        ]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[1, 0],
            )
        )
        assert "unused_exceptions" in data
        assert len(data["unused_exceptions"]) == 1
        assert data["unused_exceptions"][0]["reason"] == "unused one"

    def test_json_report_no_unused_when_all_hit(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [{"rules": "*", "reason": "ok", "repo": "repo"}]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[1],
            )
        )
        assert "unused_exceptions" not in data

    def test_json_report_excludes_other_repo_from_unused(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [
            {"rules": "*", "reason": "other repo", "repo": "other"},
        ]
        data = json.loads(
            render_json(
                "READY",
                results,
                "my-repo",
                exceptions=exceptions,
                exception_hits=[0],
            )
        )
        assert "unused_exceptions" not in data

    def test_json_report_excludes_global_from_unused(self):
        results = [RuleResult(rule="r", findings=[])]
        exceptions = [
            {"rules": "*", "reason": "global"},
            {"rules": "*", "reason": "also global"},
        ]
        data = json.loads(
            render_json(
                "READY",
                results,
                "repo",
                exceptions=exceptions,
                exception_hits=[0, 0],
            )
        )
        assert "unused_exceptions" not in data


# --- audit exceptions CLI ---


class TestAuditExceptionsCLI:
    def test_flag_parsed(self):
        args = parse_args([".", "--audit-exceptions"])
        assert args.audit_exceptions is True

    def test_flag_default_false(self):
        args = parse_args(["."])
        assert args.audit_exceptions is False

    def test_audit_no_warnings_returns_zero(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text(
            "exceptions:\n"
            "  - rules: no-image-tags\n"
            "    repo: my-repo\n"
            "    paths: ['src/**']\n"
            "    message: '*tag*'\n"
            "    reason: well-scoped\n"
        )
        ret = main([".", "--audit-exceptions", "--config", str(config)])
        assert ret == 0

    def test_audit_with_warnings_returns_two(self, tmp_path, capsys):
        config = tmp_path / "config.yaml"
        config.write_text(
            "exceptions:\n"
            '  - rules: "*"\n'
            "    repo: my-repo\n"
            "    paths: ['src/**']\n"
            "    reason: too broad\n"
        )
        ret = main([".", "--audit-exceptions", "--config", str(config)])
        assert ret == 2
        captured = capsys.readouterr()
        assert "warning" in captured.out.lower()


class TestModuleMode:
    """Tests for --module-mode flag and auto-detect in _run()."""

    def _fake_mod(self):
        fake_mod = MagicMock()
        fake_mod.detect_image_pattern.return_value = "env_var"
        fake_mod.run.return_value = RuleResult(rule="csv", passed=True)
        return fake_mod

    def _fake_module_manifest(self):
        entry = FakeImageEntry(env_var="RELATED_IMAGE_FOO")
        return FakeManifest(images=[entry], components=[], known_issues=[])

    @patch("main.compute_production_scope", return_value=None)
    def test_module_mode_flag_calls_build_module_manifest(self, _mock_scope):
        fake_manifest = self._fake_module_manifest()
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.build_module_manifest", return_value=fake_manifest) as mock_build,
            patch("main.load_manifest") as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv", "--report", "json", "--module-mode"])
            assert exit_code == 0
            mock_build.assert_called_once()
            mock_load.assert_not_called()

    @patch("main.compute_production_scope", return_value=None)
    def test_module_mode_does_not_clone_operator(self, _mock_scope):
        fake_manifest = self._fake_module_manifest()
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.build_module_manifest", return_value=fake_manifest),
            patch("main.load_manifest") as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            main([".", "--rules", "csv", "--report", "json", "--module-mode"])
            mock_load.assert_not_called()

    @patch("main.compute_production_scope", return_value=None)
    def test_auto_detect_switches_to_module_mode(self, _mock_scope):
        fake_manifest = self._fake_module_manifest()
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.detect_module", return_value=True),
            patch("main.build_module_manifest", return_value=fake_manifest) as mock_build,
            patch("main.load_manifest") as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            exit_code = main([".", "--rules", "csv", "--report", "json"])
            assert exit_code == 0
            mock_build.assert_called_once()
            mock_load.assert_not_called()

    @patch("main.compute_production_scope", return_value=None)
    def test_auto_detect_false_uses_operator_path(self, _mock_scope):
        fake_manifest = FakeManifest(images=[], components=[], known_issues=[])
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.detect_module", return_value=False),
            patch("main.build_module_manifest") as mock_build,
            patch("main.load_manifest", return_value=(fake_manifest, set())) as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            main([".", "--rules", "csv", "--report", "json"])
            mock_load.assert_called_once()
            mock_build.assert_not_called()

    @patch("main.compute_production_scope", return_value=None)
    def test_explicit_module_mode_skips_auto_detect(self, _mock_scope):
        """--module-mode=True must not call detect_module at all."""
        fake_manifest = self._fake_module_manifest()
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.detect_module") as mock_detect,
            patch("main.build_module_manifest", return_value=fake_manifest),
            patch("main.load_manifest"),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            main([".", "--rules", "csv", "--report", "json", "--module-mode"])
            mock_detect.assert_not_called()

    @patch("main.compute_production_scope", return_value=None)
    def test_module_manifest_env_vars_passed_to_rule(self, _mock_scope):
        entry = FakeImageEntry(env_var="RELATED_IMAGE_FOO")
        fake_manifest = FakeManifest(images=[entry], components=[], known_issues=[])
        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.build_module_manifest", return_value=fake_manifest),
            patch("main.load_manifest"),
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            main([".", "--rules", "csv", "--report", "json", "--module-mode"])
            call_kwargs = fake_mod.run.call_args
            assert "RELATED_IMAGE_FOO" in call_kwargs[1].get("manifest_env_vars", set())

    @patch("main.compute_production_scope", return_value=None)
    def test_module_mode_overrides_pre_loaded_operator_manifest(self, _mock_scope):
        """batch mode (run_all.py) passes manifest= pre-loaded; module_mode must override it."""
        operator_entry = FakeImageEntry(env_var="RELATED_IMAGE_FROM_OPERATOR")
        operator_manifest = FakeManifest(images=[operator_entry], components=[], known_issues=[])

        module_entry = FakeImageEntry(env_var="RELATED_IMAGE_FROM_MODULE")
        module_manifest = FakeManifest(images=[module_entry], components=[], known_issues=[])

        fake_mod = self._fake_mod()

        with (
            patch("main._run_arch_analyzer", return_value=None),
            patch("main.build_module_manifest", return_value=module_manifest) as mock_build,
            patch("main.load_manifest") as mock_load,
            patch("importlib.import_module", side_effect=_make_import_side_effect(fake_mod)),
        ):
            # Simulate run_all.py passing a pre-loaded operator manifest
            args = SimpleNamespace(
                repo_root=".",
                rules="csv",
                report="json",
                output=None,
                config=None,
                no_production_scope=True,
                verbose=False,
                arch_analyzer="",
                module_mode=True,
            )
            _run(
                args,
                operator_path="/tmp/fake-operator",
                manifest=operator_manifest,
                manifest_env_vars={"RELATED_IMAGE_FROM_OPERATOR"},
            )
            # Must call build_module_manifest, not use the pre-loaded operator manifest
            mock_build.assert_called_once()
            mock_load.assert_not_called()
            call_kwargs = fake_mod.run.call_args
            passed_vars = call_kwargs[1].get("manifest_env_vars", set())
            assert "RELATED_IMAGE_FROM_MODULE" in passed_vars
            assert "RELATED_IMAGE_FROM_OPERATOR" not in passed_vars

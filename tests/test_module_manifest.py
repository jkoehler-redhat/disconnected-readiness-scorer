"""Tests for module detection and manifest building in rules/operator_manifest.py."""

from rules.operator_manifest import (
    Manifest,
    _dir_has_related_images,
    _is_module_dir_name,
    build_module_manifest,
    detect_module,
)


class TestIsModuleDirName:
    def test_hyphen_module_suffix(self):
        assert _is_module_dir_name("kserve-module") is True

    def test_underscore_module_suffix(self):
        assert _is_module_dir_name("kserve_module") is True

    def test_compound_hyphen_module(self):
        assert _is_module_dir_name("trustyai-operator-module") is True

    def test_uppercase_insensitive(self):
        assert _is_module_dir_name("KServe-Module") is True

    def test_plain_module_no_suffix(self):
        assert _is_module_dir_name("modules") is False

    def test_module_prefix_not_suffix(self):
        assert _is_module_dir_name("module-utils") is False

    def test_unrelated_dir(self):
        assert _is_module_dir_name("pkg") is False

    def test_node_modules(self):
        assert _is_module_dir_name("node_modules") is False


class TestDirHasRelatedImages:
    def test_finds_related_image_in_go_file(self, tmp_path):
        (tmp_path / "images.go").write_text('"RELATED_IMAGE_FOO"')
        assert _dir_has_related_images(tmp_path) is True

    def test_returns_false_when_no_go_files(self, tmp_path):
        assert _dir_has_related_images(tmp_path) is False

    def test_returns_false_when_no_related_image(self, tmp_path):
        (tmp_path / "main.go").write_text('fmt.Println("hello")')
        assert _dir_has_related_images(tmp_path) is False

    def test_skips_test_files(self, tmp_path):
        (tmp_path / "images_test.go").write_text('"RELATED_IMAGE_FOO"')
        assert _dir_has_related_images(tmp_path) is False

    def test_skips_int_test_files(self, tmp_path):
        (tmp_path / "images_int_test.go").write_text('"RELATED_IMAGE_FOO"')
        assert _dir_has_related_images(tmp_path) is False

    def test_finds_in_subdir(self, tmp_path):
        sub = tmp_path / "pkg" / "module"
        sub.mkdir(parents=True)
        (sub / "images.go").write_text('"RELATED_IMAGE_BAR"')
        assert _dir_has_related_images(tmp_path) is True

    def test_unreadable_file_skipped(self, tmp_path):
        (tmp_path / "bad.go").write_bytes(b"\x80\x81\x82" * 100)
        assert _dir_has_related_images(tmp_path) is False

    def test_skip_dirs_not_traversed(self, tmp_path):
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "lib.go").write_text('"RELATED_IMAGE_VENDOR"')
        assert _dir_has_related_images(tmp_path) is False

    def test_wildcard_var_not_matched(self, tmp_path):
        (tmp_path / "util.go").write_text('"RELATED_IMAGE_*"')
        # wildcard is not captured by RELATED_IMAGE_PATTERN (requires [A-Z0-9_]+)
        assert _dir_has_related_images(tmp_path) is False


class TestDetectModule:
    def _make_module_dir(self, root, name, content='"RELATED_IMAGE_FOO"'):
        d = root / name
        d.mkdir()
        pkg = d / "pkg" / "mymodule"
        pkg.mkdir(parents=True)
        (pkg / "images.go").write_text(content)
        return d

    def test_detects_hyphen_module_subdir(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve-module")
        assert detect_module(tmp_path) is True

    def test_detects_underscore_module_subdir(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve_module")
        assert detect_module(tmp_path) is True

    def test_detects_compound_module_subdir(self, tmp_path):
        self._make_module_dir(tmp_path, "trustyai-operator-module")
        assert detect_module(tmp_path) is True

    def test_module_dir_without_related_images_not_detected(self, tmp_path):
        d = tmp_path / "kserve-module"
        d.mkdir()
        (d / "main.go").write_text('fmt.Println("hello")')
        assert detect_module(tmp_path) is False

    def test_no_module_dirs_returns_false(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "main.go").write_text('fmt.Println("hello")')
        assert detect_module(tmp_path) is False

    def test_empty_root_returns_false(self, tmp_path):
        assert detect_module(tmp_path) is False

    def test_whole_repo_module_via_pkg_images_go(self, tmp_path):
        pkg = tmp_path / "pkg" / "mymodule"
        pkg.mkdir(parents=True)
        (pkg / "images.go").write_text('"RELATED_IMAGE_BAR"')
        assert detect_module(tmp_path) is True

    def test_whole_repo_module_ignores_test_go_in_pkg(self, tmp_path):
        pkg = tmp_path / "pkg" / "mymodule"
        pkg.mkdir(parents=True)
        (pkg / "images_test.go").write_text('"RELATED_IMAGE_BAR"')
        # images.go not present, test file not images.go → not detected
        assert detect_module(tmp_path) is False

    def test_non_module_dir_ignored(self, tmp_path):
        d = tmp_path / "vendor"
        d.mkdir()
        (d / "images.go").write_text('"RELATED_IMAGE_FOO"')
        assert detect_module(tmp_path) is False

    def test_module_dir_test_files_not_counted(self, tmp_path):
        d = tmp_path / "kserve-module"
        d.mkdir()
        (d / "images_test.go").write_text('"RELATED_IMAGE_FOO"')
        assert detect_module(tmp_path) is False

    def test_whole_repo_unreadable_images_go_skipped(self, tmp_path):
        pkg = tmp_path / "pkg" / "mymodule"
        pkg.mkdir(parents=True)
        (pkg / "images.go").write_bytes(b"\x80\x81\x82" * 100)
        assert detect_module(tmp_path) is False


class TestBuildModuleManifest:
    def _make_module_dir(self, root, name, vars_):
        d = root / name
        d.mkdir()
        pkg = d / "pkg" / "mymodule"
        pkg.mkdir(parents=True)
        content = "\n".join(f'"image-{v.lower()}": "{v}"' for v in vars_)
        (pkg / "images.go").write_text(content)
        return d

    def test_builds_manifest_from_module_subdir(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve-module", ["RELATED_IMAGE_FOO", "RELATED_IMAGE_BAR"])
        manifest = build_module_manifest(tmp_path)
        env_vars = {e.env_var for e in manifest.images}
        assert "RELATED_IMAGE_FOO" in env_vars
        assert "RELATED_IMAGE_BAR" in env_vars

    def test_component_name_is_dir_name(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve-module", ["RELATED_IMAGE_FOO"])
        manifest = build_module_manifest(tmp_path)
        assert all(e.component == "kserve-module" for e in manifest.images)

    def test_multiple_module_dirs_all_included(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve-module", ["RELATED_IMAGE_KSERVE"])
        self._make_module_dir(tmp_path, "trustyai-operator-module", ["RELATED_IMAGE_TRUSTYAI"])
        manifest = build_module_manifest(tmp_path)
        env_vars = {e.env_var for e in manifest.images}
        assert "RELATED_IMAGE_KSERVE" in env_vars
        assert "RELATED_IMAGE_TRUSTYAI" in env_vars
        assert "kserve-module" in manifest.components
        assert "trustyai-operator-module" in manifest.components

    def test_fallback_to_root_when_no_module_subdirs(self, tmp_path):
        pkg = tmp_path / "pkg" / "mymod"
        pkg.mkdir(parents=True)
        (pkg / "images.go").write_text('"RELATED_IMAGE_ROOT"')
        manifest = build_module_manifest(tmp_path)
        env_vars = {e.env_var for e in manifest.images}
        assert "RELATED_IMAGE_ROOT" in env_vars

    def test_returns_manifest_type(self, tmp_path):
        manifest = build_module_manifest(tmp_path)
        assert isinstance(manifest, Manifest)

    def test_empty_repo_returns_empty_manifest(self, tmp_path):
        manifest = build_module_manifest(tmp_path)
        assert manifest.images == []
        assert manifest.components == {}

    def test_components_dict_populated(self, tmp_path):
        self._make_module_dir(tmp_path, "kserve-module", ["RELATED_IMAGE_FOO"])
        manifest = build_module_manifest(tmp_path)
        assert "kserve-module" in manifest.components
        assert manifest.components["kserve-module"]["image_count"] == 1
        assert "RELATED_IMAGE_FOO" in manifest.components["kserve-module"]["env_vars"]

    def test_module_dir_without_related_images_excluded(self, tmp_path):
        # dir has -module suffix but no RELATED_IMAGE_* → not counted
        d = tmp_path / "empty-module"
        d.mkdir()
        (d / "main.go").write_text('fmt.Println("hello")')
        # root also has no pkg/images.go → fallback to root → also empty
        manifest = build_module_manifest(tmp_path)
        assert manifest.images == []

    def test_known_issues_not_populated(self, tmp_path):
        # build_module_manifest does not parse component-params-env.yaml
        self._make_module_dir(tmp_path, "kserve-module", ["RELATED_IMAGE_FOO"])
        (tmp_path / "component-params-env.yaml").write_text(
            "# known_issues:\n- image: RELATED_IMAGE_BROKEN\n"
        )
        manifest = build_module_manifest(tmp_path)
        assert manifest.known_issues == []

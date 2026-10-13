from __future__ import annotations

import gzip
import io
import json
import tarfile
import tempfile
import unittest
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from scripts.validate_public_release import (
    ASSETS,
    POLICY,
    MAX_ARCHIVE,
    MAX_UNPACKED,
    GitHubRedirects,
    digest,
    archive_files,
    metadata,
    validate_directory,
    validate_public_download,
)


class PublicReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="skillforge-public-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.runtime: list[str] = policy["runtime"]
        self.files: dict[str, bytes] = {
            name: b"Synthetic public helper fixture\n" for name in self.runtime
        }
        self.files.update(
            {
                "package.json": self.json_bytes(
                    {
                        "name": "@blackoutsecure/skillforge-learner-helper",
                        "version": "1.0.2",
                        "private": True,
                        "type": "module",
                        "description": "Synthetic learner helper",
                        "engines": {"node": ">=20"},
                        "license": "SEE LICENSE IN LICENSE",
                        "bin": {"skillforge": "services/helper/src/index.mjs"},
                        "scripts": {"start": "node services/helper/src/index.mjs"},
                        "files": ["services", "shared", "scripts", "labs"],
                    }
                ),
                "README.md": b"# Synthetic learner helper\n",
                "labs/README.txt": b"No authoring content\n",
                "shared/learner-config.json": self.json_bytes({"platformUrl": ""}),
                "services/wiki-site/public/skillforge-manifest.json": self.json_bytes({"labs": []}),
            }
        )
        self.files["helper-build.json"] = self.json_bytes(
            {
                "schemaVersion": 1,
                "sourceSha": "a" * 40,
                "development": False,
                "files": [
                    {"path": name, "sha256": digest(self.files[name])} for name in self.runtime
                ],
            }
        )

    @staticmethod
    def json_bytes(value: object) -> bytes:
        return (json.dumps(value, indent=2) + "\n").encode("utf-8")

    def write_assets(
        self, extra: list[tuple[tarfile.TarInfo, bytes]] | None = None, trailing: bytes = b""
    ) -> dict[str, object]:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, data in self.files.items():
                member = tarfile.TarInfo(f"package/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            for member, data in extra or []:
                archive.addfile(member, io.BytesIO(data))
        data = gzip.compress(stream.getvalue() + trailing)
        (self.directory / "learner-helper.tgz").write_bytes(data)
        release: dict[str, object] = {
            "schemaVersion": 1,
            "component": "learner-helper",
            "version": "1.0.2",
            "tag": "learner-helper/v1.0.2",
            "source": {"repository": "blackoutsecure/bos-skillforge-labs", "commit": "a" * 40},
            "node": ">=20",
            "artifact": {"name": "learner-helper.tgz", "sha256": digest(data), "size": len(data)},
        }
        self.write_metadata(release)
        return release

    def write_metadata(self, release: dict[str, object]) -> None:
        data = self.json_bytes(release)
        (self.directory / "release.json").write_bytes(data)
        (self.directory / "SHA256SUMS").write_text(
            f"{digest((self.directory / 'learner-helper.tgz').read_bytes())}  learner-helper.tgz\n"
            f"{digest(data)}  release.json\n",
            encoding="ascii",
            newline="\n",
        )

    def validate(self) -> None:
        validate_directory(self.directory, "learner-helper/v1.0.2")

    def test_valid_exact_learner_package(self) -> None:
        self.write_assets()
        result = validate_directory(self.directory, "learner-helper/v1.0.2")
        self.assertEqual(result.version, "1.0.2")
        self.assertEqual(result.source_sha, "a" * 40)

    def test_unknown_release_assets_are_rejected(self) -> None:
        self.write_assets()
        (self.directory / "INSTRUCTOR-GUIDE.md").write_text("Synthetic forbidden asset")
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.validate()

    def test_archive_integrity_and_checksum_file_are_required(self) -> None:
        self.write_assets()
        (self.directory / "SHA256SUMS").write_text("incorrect")
        with self.assertRaisesRegex(ValueError, "SHA256SUMS"):
            self.validate()
        self.write_assets()
        with (self.directory / "learner-helper.tgz").open("ab") as archive:
            archive.write(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum or size"):
            self.validate()

    def test_unknown_traversal_duplicate_and_link_entries_are_rejected(self) -> None:
        for name, kind in [
            ("package/INSTRUCTOR-SOLUTION.sh", tarfile.REGTYPE),
            ("package/../private.txt", tarfile.REGTYPE),
            ("package/LICENSE", tarfile.REGTYPE),
            ("package/symlink", tarfile.SYMTYPE),
            ("package/hardlink", tarfile.LNKTYPE),
            ("package/device", tarfile.CHRTYPE),
        ]:
            with self.subTest(name=name, kind=kind):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "../../private"
                self.write_assets([(member, b"")])
                with self.assertRaisesRegex(ValueError, "Unapproved"):
                    self.validate()

    def test_hidden_trailing_archive_content_is_rejected(self) -> None:
        self.write_assets(trailing=b"hidden content")
        with self.assertRaisesRegex(ValueError, "trailing data"):
            self.validate()

    def test_school_configuration_and_course_content_are_not_public(self) -> None:
        for name, value in [
            ("shared/learner-config.json", {"platformUrl": "https://school.example.edu"}),
            ("services/wiki-site/public/skillforge-manifest.json", {"labs": [{"id": "private-lab"}]}),
        ]:
            with self.subTest(name=name):
                previous = self.files[name]
                self.files[name] = self.json_bytes(value)
                self.write_assets()
                with self.assertRaisesRegex(ValueError, "cannot"):
                    self.validate()
                self.files[name] = previous

    def test_development_and_source_mismatches_fail_closed(self) -> None:
        build = json.loads(self.files["helper-build.json"])
        for change in [{"development": True}, {"sourceSha": "b" * 40}, {"schemaVersion": True}]:
            self.files["helper-build.json"] = self.json_bytes({**build, **change})
            self.write_assets()
            with self.assertRaisesRegex(ValueError, "source"):
                self.validate()

    def test_source_inventory_and_private_keys_are_checked(self) -> None:
        self.files["services/helper/src/index.mjs"] += b"changed"
        self.write_assets()
        with self.assertRaisesRegex(ValueError, "source checksum"):
            self.validate()
        self.files["LICENSE"] = b"-----BEGIN PRIVATE KEY-----\nSYNTHETIC NON-KEY\n"
        self.write_assets()
        with self.assertRaisesRegex(ValueError, "Private-key"):
            self.validate()

    def test_metadata_contract_and_duplicate_keys(self) -> None:
        release = self.write_assets()
        for change in [
            {"version": "1.0.2-rc.1"},
            {"version": "01.0.2"},
            {"schemaVersion": True},
            {"component": "instructor"},
            {"extra": "forbidden"},
            {"source": {"repository": "another/repo", "commit": "a" * 40}},
            {"artifact": {"name": "learner-helper.tgz", "sha256": "b" * 64, "size": True}},
        ]:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    metadata(self.json_bytes({**release, **change}), "learner-helper/v1.0.2")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            metadata(b'{"version":"1.0.2","version":"2.0.0"}', "learner-helper/v1.0.2")

    def test_install_scripts_or_dependencies_are_not_packaged(self) -> None:
        package = json.loads(self.files["package.json"])
        for change in [
            {"dependencies": {"unapproved": "1.0.0"}},
            {"scripts": {"postinstall": "unapproved"}},
            {"private": False},
        ]:
            self.files["package.json"] = self.json_bytes({**package, **change})
            self.write_assets()
            with self.assertRaises(ValueError):
                self.validate()

    def test_anonymous_download_validates_actual_public_bytes(self) -> None:
        self.write_assets()
        requests: list[str] = []

        def fetch(url: str, maximum: int) -> bytes:
            requests.append(url)
            if url == "https://api.github.com/repos/blackoutsecure/bos-skillforge-release":
                return self.json_bytes({
                    "full_name": "blackoutsecure/bos-skillforge-release",
                    "private": False, "visibility": "public",
                })
            if "/releases/tags/" in url:
                return self.json_bytes({
                    "tag_name": "learner-helper/v1.0.2", "draft": False, "prerelease": False,
                    "assets": [{"name": name} for name in ASSETS],
                })
            return (self.directory / url.rsplit("/", 1)[1]).read_bytes()

        with patch("scripts.validate_public_release.download", side_effect=fetch):
            result = validate_public_download("learner-helper/v1.0.2")
        self.assertEqual(result.version, "1.0.2")
        self.assertEqual(len(requests), 5)
        self.assertTrue(all(url.startswith("https://") for url in requests))

    def test_private_or_missing_public_releases_never_pass(self) -> None:
        with patch(
            "scripts.validate_public_release.download",
            return_value=self.json_bytes({
                "full_name": "blackoutsecure/bos-skillforge-release",
                "private": True, "visibility": "internal",
            }),
        ):
            with self.assertRaisesRegex(ValueError, "anonymously"):
                validate_public_download("learner-helper/v1.0.2")
        with self.assertRaisesRegex(ValueError, "Only stable"):
            validate_public_download("../unapproved")

    def test_redirects_cannot_leave_github_https_download_hosts(self) -> None:
        for url in ["http://github.com/file", "https://example.com/file", "http://127.0.0.1/"]:
            with self.assertRaisesRegex(ValueError, "redirect"):
                GitHubRedirects().redirect_request(
                    urllib.request.Request("https://github.com/fixture"),
                    io.BytesIO(), 302, "Redirect", Message(), url,
                )

    def test_archive_size_limits_are_measured_at_the_boundary(self) -> None:
        release = self.write_assets()
        artifact = release["artifact"]
        assert isinstance(artifact, dict)
        accepted = {**release, "artifact": {**artifact, "size": MAX_ARCHIVE}}
        self.assertEqual(metadata(self.json_bytes(accepted), "learner-helper/v1.0.2").archive_size, MAX_ARCHIVE)
        with self.assertRaises(ValueError):
            metadata(
                self.json_bytes({**accepted, "artifact": {**artifact, "size": MAX_ARCHIVE + 1}}),
                "learner-helper/v1.0.2",
            )
        with self.assertRaisesRegex(ValueError, "32 MiB"):
            archive_files(gzip.compress(b"\0" * (MAX_UNPACKED + 1)), set(self.files))


if __name__ == "__main__":
    unittest.main()

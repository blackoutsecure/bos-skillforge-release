from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from email.message import Message
from pathlib import Path
from typing import BinaryIO

REPOSITORY = "blackoutsecure/bos-skillforge-release"
SOURCE = "blackoutsecure/bos-skillforge-labs"
ASSETS = frozenset({"learner-helper.tgz", "release.json", "SHA256SUMS"})
POLICY = Path(__file__).resolve().parents[1] / "config" / "learner-helper-files.json"
VERSION = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
MAX_ARCHIVE = 10 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


@dataclass(frozen=True)
class HelperRelease:
    version: str
    tag: str
    source_sha: str
    archive_sha256: str
    archive_size: int


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(data: bytes) -> object:
    return json.loads(data, object_pairs_hook=unique_object)


def object_fields(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Unexpected release metadata fields")
    return value


def metadata(data: bytes, tag: str) -> HelperRelease:
    if len(data) > 65536:
        raise ValueError("Release metadata exceeds 64 KiB")
    value = object_fields(
        read_json(data),
        {"schemaVersion", "component", "version", "tag", "source", "node", "artifact"},
    )
    version = value["version"]
    source = object_fields(value["source"], {"repository", "commit"})
    artifact = object_fields(value["artifact"], {"name", "sha256", "size"})
    source_sha, sha256, size = source["commit"], artifact["sha256"], artifact["size"]
    if (
        type(value["schemaVersion"]) is not int
        or value["schemaVersion"] != 1
        or value["component"] != "learner-helper"
        or not isinstance(version, str)
        or not re.fullmatch(VERSION, version)
        or value["tag"] != f"learner-helper/v{version}"
        or value["tag"] != tag
        or value["node"] != ">=20"
        or source["repository"] != SOURCE
        or not isinstance(source_sha, str)
        or not re.fullmatch(r"[a-f0-9]{40}", source_sha)
        or artifact["name"] != "learner-helper.tgz"
        or not isinstance(sha256, str)
        or not re.fullmatch(r"[a-f0-9]{64}", sha256)
        or type(size) is not int
        or not 0 < size <= MAX_ARCHIVE
    ):
        raise ValueError("Invalid stable learner-helper metadata")
    return HelperRelease(version, tag, source_sha, sha256, size)


def regular_bytes(file: Path, maximum: int) -> bytes:
    if file.is_symlink() or not file.is_file():
        raise ValueError(f"Expected a regular asset: {file.name}")
    if file.stat().st_size > maximum:
        raise ValueError(f"Asset exceeds its size limit: {file.name}")
    return file.read_bytes()


def archive_files(
    archive: bytes, allowed: set[str], prefix: str = "package/"
) -> dict[str, bytes]:
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as compressed:
        expanded = compressed.read(MAX_UNPACKED + 1)
    if len(expanded) > MAX_UNPACKED:
        raise ValueError("Helper archive exceeds 32 MiB unpacked")
    if PRIVATE_KEY.search(expanded):
        raise ValueError("Private-key material is forbidden in public assets")
    files: dict[str, bytes] = {}
    end = 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as package:
        for member in package:
            name = member.name.removeprefix(prefix)
            if (
                not member.name.startswith(prefix)
                or name not in allowed
                or name in files
                or not member.isreg()
                or member.sparse is not None
                or set(member.pax_headers) - {"path", "size", "mtime"}
                or not 0 <= member.size <= 2 * 1024 * 1024
            ):
                raise ValueError(f"Unapproved archive entry: {member.name}")
            stream = package.extractfile(member)
            if stream is None:
                raise ValueError("Unreadable helper archive member")
            with stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) != member.size:
                raise ValueError("Helper archive member length mismatch")
            files[name] = data
            end = member.offset_data + ((member.size + 511) // 512) * 512
    if set(files) != allowed or any(expanded[end:]):
        raise ValueError("Helper archive inventory or trailing data is invalid")
    return files


def validate_directory(directory: Path, tag: str) -> HelperRelease:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Public asset directory must be a regular directory")
    if {file.name for file in directory.iterdir()} != ASSETS:
        raise ValueError("Expected exactly the three approved public helper assets")
    release_bytes = regular_bytes(directory / "release.json", 65536)
    release = metadata(release_bytes, tag)
    archive = regular_bytes(directory / "learner-helper.tgz", MAX_ARCHIVE)
    if len(archive) != release.archive_size or digest(archive) != release.archive_sha256:
        raise ValueError("Helper archive checksum or size mismatch")
    sums = regular_bytes(directory / "SHA256SUMS", 1024)
    expected = (
        f"{digest(archive)}  learner-helper.tgz\n"
        f"{digest(release_bytes)}  release.json\n"
    ).encode("ascii")
    if sums != expected:
        raise ValueError("SHA256SUMS must cover exactly the archive and release metadata")
    policy = object_fields(read_json(POLICY.read_bytes()), {"runtime", "generated"})
    runtime, generated = policy["runtime"], policy["generated"]
    if not isinstance(runtime, list) or not isinstance(generated, list):
        raise ValueError("Invalid helper file policy")
    paths = runtime + generated
    if any(not isinstance(name, str) for name in paths) or len(set(paths)) != len(paths):
        raise ValueError("Invalid or duplicate helper policy paths")
    files = archive_files(archive, set(paths))
    package = object_fields(
        read_json(files["package.json"]),
        {"name", "version", "private", "type", "description", "engines", "license", "bin", "scripts", "files"},
    )
    if (
        package["name"] != "@blackoutsecure/skillforge-learner-helper"
        or package["version"] != release.version
        or package["private"] is not True
        or package["type"] != "module"
        or package["engines"] != {"node": ">=20"}
        or package["license"] != "SEE LICENSE IN LICENSE"
        or package["bin"] != {"skillforge": "services/helper/src/index.mjs"}
        or package["scripts"] != {"start": "node services/helper/src/index.mjs"}
    ):
        raise ValueError("Unexpected helper package or lifecycle scripts")
    if read_json(files["shared/learner-config.json"]) != {"platformUrl": ""}:
        raise ValueError("School configuration cannot be included in a public helper")
    if read_json(files["services/wiki-site/public/skillforge-manifest.json"]) != {"labs": []}:
        raise ValueError("Course payloads cannot be included in a public helper")
    build = object_fields(
        read_json(files["helper-build.json"]), {"schemaVersion", "sourceSha", "development", "files"}
    )
    records = build["files"]
    if (
        type(build["schemaVersion"]) is not int
        or build["schemaVersion"] != 1
        or build["development"] is not False
        or build["sourceSha"] != release.source_sha
        or not isinstance(records, list)
        or len(records) != len(runtime)
    ):
        raise ValueError("Unverified or development helper source")
    seen: set[str] = set()
    for record in records:
        entry = object_fields(record, {"path", "sha256"})
        name = entry["path"]
        if not isinstance(name, str) or name not in runtime or name in seen:
            raise ValueError("Invalid helper source inventory")
        if entry["sha256"] != digest(files[name]):
            raise ValueError(f"Helper source checksum mismatch: {name}")
        seen.add(name)
    return release


class GitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: BinaryIO,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https" or url.hostname not in {
            "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
        }:
            raise ValueError("Unexpected public GitHub download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, maximum: int) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "SkillForge-public-release-validator"}
    )
    # Deliberately anonymous: a repository token would hide public-access failures.
    with urllib.request.build_opener(GitHubRedirects()).open(request, timeout=30) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Public download exceeds its size limit")
    return data


def validate_public_download(tag: str) -> HelperRelease:
    if not re.fullmatch(f"learner-helper/v{VERSION}", tag):
        raise ValueError("Only stable learner-helper tags are approved")
    api = f"https://api.github.com/repos/{REPOSITORY}"
    repository = read_json(download(api, 1024 * 1024))
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
        or repository.get("private") is not False
        or repository.get("visibility") != "public"
    ):
        raise ValueError("Public release repository is not anonymously accessible")
    release = read_json(download(f"{api}/releases/tags/{urllib.parse.quote(tag, safe='')}", 1024 * 1024))
    if (
        not isinstance(release, dict)
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not isinstance(release.get("assets"), list)
    ):
        raise ValueError("Expected an anonymously accessible stable release")
    assets = release["assets"]
    names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
    if len(names) != len(assets) or len(names) != len(ASSETS) or set(names) != ASSETS:
        raise ValueError("Public release contains unapproved or missing assets")
    with tempfile.TemporaryDirectory(prefix="skillforge-public-release-") as temporary:
        directory = Path(temporary)
        for name in ASSETS:
            url = f"https://github.com/{REPOSITORY}/releases/download/{urllib.parse.quote(tag, safe='')}/{name}"
            limit = MAX_ARCHIVE if name.endswith(".tgz") else 65536
            (directory / name).write_bytes(download(url, limit))
        return validate_directory(directory, tag)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate approved SkillForge public release assets")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--directory", type=Path, help="Validate local assets instead of anonymous downloads")
    args = parser.parse_args(argv)
    try:
        release = (
            validate_directory(args.directory, args.tag)
            if args.directory is not None
            else validate_public_download(args.tag)
        )
    except (ValueError, OSError, EOFError, tarfile.TarError, urllib.error.URLError, zlib.error) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {release.tag}; exact learner-only inventory, checksums and reviewed source verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path

if __package__:
    from .validate_public_release import (
        REPOSITORY, SOURCE, VERSION, archive_files, digest, download,
        object_fields, read_json, regular_bytes,
    )
else:
    from validate_public_release import (
        REPOSITORY, SOURCE, VERSION, archive_files, digest, download,
        object_fields, read_json, regular_bytes,
    )

IMAGE = f"ghcr.io/{REPOSITORY}/base-ubuntu"
REGISTRY_PATH = f"{REPOSITORY}/base-ubuntu"
POLICY = Path(__file__).resolve().parents[1] / "config" / "container-base-files.json"
CONTEXT_ASSETS = frozenset({"container-context.tar.gz", "release.json", "SHA256SUMS"})
IMAGE_ASSETS = frozenset({
    "container.json", "SHA256SUMS", "sbom-amd64.cdx.json", "sbom-arm64.cdx.json",
    "provenance-amd64.sigstore.json", "provenance-arm64.sigstore.json",
    "sbom-amd64.sigstore.json", "sbom-arm64.sigstore.json", "index-provenance.sigstore.json",
})
MAX_CONTEXT = 1024 * 1024
MAX_EVIDENCE = 16 * 1024 * 1024
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
SOURCE_FILES = {
    "Dockerfile": "docker/base-ubuntu/Dockerfile",
    "scripts/self-assess.sh": "scripts/self-assess.sh",
    "LICENSE": "LICENSE",
    "NOTICE.md": "NOTICE.md",
}


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def stable_version(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(VERSION, value):
        raise ValueError("Expected a stable major.minor.patch container version")
    return value


def full_sha(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("Expected a reviewed full source SHA")
    return value


def image_digest(value: object) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise ValueError("Expected an immutable SHA-256 image digest")
    return value


def check_recipe(data: bytes) -> None:
    policy = object_fields(read_json(POLICY.read_bytes()), {"files", "aptPackages"})
    packages = policy["aptPackages"]
    if not isinstance(packages, list) or any(not isinstance(item, str) for item in packages):
        raise ValueError("Invalid reviewed base package policy")
    text = data.decode("utf-8").replace("\\\r\n", " ").replace("\\\n", " ")
    instructions = [line.strip() for line in text.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    expected_run = (
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        + " ".join(packages) + " && rm -rf /var/lib/apt/lists/*"
    )
    actual = [" ".join(line.split()) for line in instructions]
    if (
        len(actual) != 6
        or actual[0] != "FROM ubuntu:24.04"
        or actual[1] != expected_run
        or actual[2] != "COPY --chmod=0755 scripts/self-assess.sh /usr/local/bin/skillforge-assess"
        or not actual[3].startswith("LABEL org.opencontainers.image.title=")
        or actual[4] != "COPY LICENSE NOTICE.md /usr/share/doc/skillforge/"
        or actual[5] != 'CMD ["bash"]'
    ):
        raise ValueError("Base Dockerfile exceeds the reviewed generic-only recipe")


def context_metadata(data: bytes, tag: str) -> dict[str, object]:
    value = object_fields(read_json(data), {
        "schemaVersion", "component", "version", "tag", "source", "imageRepository", "artifact", "files",
    })
    version = stable_version(value["version"])
    source = object_fields(value["source"], {"repository", "commit"})
    artifact = object_fields(value["artifact"], {"name", "sha256", "size"})
    full_sha(source["commit"])
    if (
        type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
        or value["component"] != "container-base-source"
        or value["tag"] != f"container-base-source/v{version}" or value["tag"] != tag
        or source["repository"] != SOURCE or value["imageRepository"] != IMAGE
        or artifact["name"] != "container-context.tar.gz"
        or not isinstance(artifact["sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", artifact["sha256"])
        or type(artifact["size"]) is not int or not 0 < artifact["size"] <= MAX_CONTEXT
        or not isinstance(value["files"], list)
    ):
        raise ValueError("Invalid public container source metadata")
    return value


def checksums(directory: Path, names: list[str]) -> bytes:
    return "".join(
        f"{digest(regular_bytes(directory / name, MAX_EVIDENCE))}  {name}\n"
        for name in sorted(names)
    ).encode("ascii")


def validate_context(directory: Path, tag: str, extract: Path | None = None) -> dict[str, object]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Container assets must be a regular directory")
    if {file.name for file in directory.iterdir()} != CONTEXT_ASSETS:
        raise ValueError("Only the approved container source assets may be public")
    value = context_metadata(regular_bytes(directory / "release.json", 65536), tag)
    artifact = object_fields(value["artifact"], {"name", "sha256", "size"})
    archive = regular_bytes(directory / "container-context.tar.gz", MAX_CONTEXT)
    if len(archive) != artifact["size"] or digest(archive) != artifact["sha256"]:
        raise ValueError("Container context checksum or size mismatch")
    if regular_bytes(directory / "SHA256SUMS", 1024) != checksums(
        directory, ["container-context.tar.gz", "release.json"]
    ):
        raise ValueError("Container context SHA256SUMS is invalid")
    policy = object_fields(read_json(POLICY.read_bytes()), {"files", "aptPackages"})
    allowed = policy["files"]
    if not isinstance(allowed, list) or set(allowed) != set(SOURCE_FILES):
        raise ValueError("Unexpected public container file policy")
    files = archive_files(archive, set(SOURCE_FILES), prefix="container/")
    records = value["files"]
    if not isinstance(records, list) or len(records) != len(files):
        raise ValueError("Container file inventory is incomplete")
    seen: set[str] = set()
    for record in records:
        entry = object_fields(record, {"path", "sha256", "size", "mode"})
        name = entry["path"]
        if not isinstance(name, str) or name not in files or name in seen:
            raise ValueError("Unexpected or duplicate container source file")
        if (
            entry["sha256"] != digest(files[name]) or type(entry["size"]) is not int
            or entry["size"] != len(files[name])
            or entry["mode"] != (493 if name.endswith(".sh") else 420)
        ):
            raise ValueError(f"Container source integrity mismatch: {name}")
        seen.add(name)
    check_recipe(files["Dockerfile"])
    if extract is not None:
        if extract.exists() or extract.is_symlink():
            raise ValueError("Build context output must not already exist")
        extract.mkdir(parents=True)
        for name, contents in files.items():
            file = extract / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(contents)
            file.chmod(0o755 if name.endswith(".sh") else 0o644)
    return value


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=False, timeout=30
    )
    if result.returncode != 0:
        raise ValueError(f"Cannot read reviewed source: {result.stderr.decode('utf-8', errors='replace').strip()}")
    return result.stdout


def pack_context(root: Path, source_sha: str, version: str, output: Path) -> dict[str, object]:
    full_sha(source_sha)
    stable_version(version)
    if output.exists() or output.is_symlink():
        raise ValueError("Container source staging output must not already exist")
    package = read_json(git(root, "show", f"{source_sha}:package.json"))
    if not isinstance(package, dict) or package.get("version") != version:
        raise ValueError("Source package version must match the stable source release")
    files: dict[str, bytes] = {}
    for name, source in SOURCE_FILES.items():
        tree = git(root, "ls-tree", source_sha, "--", source).decode("utf-8").strip()
        if not re.fullmatch(rf"100(?:644|755) blob [a-f0-9]{{40}}\t{re.escape(source)}", tree):
            raise ValueError(f"Only regular reviewed Git blobs may be public: {source}")
        files[name] = git(root, "show", f"{source_sha}:{source}")
    check_recipe(files["Dockerfile"])
    records = []
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(f"container/{name}")
            member.size = len(data)
            member.mode = 0o755 if name.endswith(".sh") else 0o644
            archive.addfile(member, io.BytesIO(data))
            records.append({"path": name, "sha256": digest(data), "size": len(data), "mode": member.mode})
    payload = gzip.compress(stream.getvalue(), mtime=0)
    value = {
        "schemaVersion": 1, "component": "container-base-source", "version": version,
        "tag": f"container-base-source/v{version}",
        "source": {"repository": SOURCE, "commit": source_sha}, "imageRepository": IMAGE,
        "artifact": {"name": "container-context.tar.gz", "sha256": digest(payload), "size": len(payload)},
        "files": records,
    }
    output.mkdir(parents=True)
    (output / "container-context.tar.gz").write_bytes(payload)
    (output / "release.json").write_bytes(json_bytes(value))
    (output / "SHA256SUMS").write_bytes(checksums(output, ["container-context.tar.gz", "release.json"]))
    return validate_context(output, str(value["tag"]))


def github_json(path: str, token: str) -> object:
    request = urllib.request.Request(f"https://api.github.com/{path}", headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "User-Agent": "SkillForge-container-publisher", "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("GitHub response exceeds its limit")
    return read_json(data)


def require_approval(token: str, repository: str, environment: str) -> None:
    if repository != REPOSITORY or environment != "public-container-publish" or not token:
        raise ValueError("Missing public container approval context")
    value = github_json(f"repos/{repository}/environments/{environment}", token)
    if not isinstance(value, dict) or not any(
        isinstance(rule, dict) and rule.get("type") == "required_reviewers"
        and rule.get("prevent_self_review") is True and bool(rule.get("reviewers"))
        for rule in value.get("protection_rules", [])
    ):
        raise ValueError("Public container publishing requires independent reviewers and no self-review")


def require_package_visibility(token: str, bootstrap: bool) -> str:
    path = f"orgs/blackoutsecure/packages/container/{urllib.parse.quote(REGISTRY_PATH.split('/', 1)[1], safe='')}"
    try:
        value = github_json(path, token)
    except urllib.error.HTTPError as error:
        if error.code == 404 and bootstrap:
            error.close()
            return "missing"
        if error.code == 404:
            error.close()
            raise ValueError("GHCR namespace is missing; explicitly bootstrap it, then make it public") from error
        raise
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("repository"), dict)
        or value["repository"].get("full_name") != REPOSITORY
        or value.get("name") != REGISTRY_PATH.split("/", 1)[1]
        or value.get("package_type") != "container"
    ):
        raise ValueError("GHCR package is not associated with the fixed public release repository")
    visibility = value.get("visibility")
    if bootstrap and visibility == "private":
        return "private"
    if not bootstrap and visibility == "public":
        return "public"
    raise ValueError("Bootstrap is private-only; normal publication requires an explicitly PUBLIC GHCR package")


def registry_manifest(reference: str) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}|sha256:[a-f0-9]{64}", reference):
        raise ValueError("Unsafe registry reference")
    query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{REGISTRY_PATH}:pull"})
    # No GitHub credential or Docker login is used for this proof of public access.
    request = urllib.request.Request(
        f"https://ghcr.io/token?{query}", headers={"User-Agent": "SkillForge-anonymous-image-check"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        token_data = read_json(response.read(65537))
    if not isinstance(token_data, dict) or not isinstance(token_data.get("token"), str):
        raise ValueError("GHCR refused an anonymous pull token")
    request = urllib.request.Request(
        f"https://ghcr.io/v2/{REGISTRY_PATH}/manifests/{reference}", headers={
            "Authorization": f"Bearer {token_data['token']}",
            "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
            "User-Agent": "SkillForge-anonymous-image-check",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
        reported = response.headers.get("Docker-Content-Digest")
    actual = f"sha256:{digest(data)}"
    if len(data) > 1024 * 1024 or reported != actual or (reference.startswith("sha256:") and reference != actual):
        raise ValueError("Anonymous registry manifest digest mismatch")
    value = read_json(data)
    if not isinstance(value, dict):
        raise ValueError("Invalid anonymous registry manifest")
    return {"digest": actual, "manifest": value}


def verify_public_index(digest_value: str) -> dict[str, object]:
    image_digest(digest_value)
    result = registry_manifest(digest_value)
    manifest = result["manifest"]
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ValueError("Expected a multiarchitecture public image index")
    entries = manifest.get("manifests")
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError("Public base index must contain exactly two native architectures")
    architectures = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("platform"), dict):
            raise ValueError("Invalid public architecture manifest")
        platform = entry["platform"]
        if platform.get("os") != "linux" or platform.get("architecture") not in {"amd64", "arm64"}:
            raise ValueError("Unexpected public container platform")
        architectures.append(platform["architecture"])
        child = registry_manifest(image_digest(entry.get("digest")))
        if child["digest"] != entry["digest"]:
            raise ValueError("Anonymous architecture manifest mismatch")
    if sorted(architectures) != ["amd64", "arm64"]:
        raise ValueError("Duplicate or missing public architecture")
    return result


def download_context(tag: str, output: Path, extract: Path | None = None) -> dict[str, object]:
    if not re.fullmatch(f"container-base-source/v{VERSION}", tag):
        raise ValueError("Only approved container base source tags are accepted")
    if output.exists() or output.is_symlink():
        raise ValueError("Download output must not already exist")
    release = read_json(download(
        f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{urllib.parse.quote(tag, safe='')}",
        1024 * 1024,
    ))
    if (
        not isinstance(release, dict) or release.get("tag_name") != tag
        or release.get("draft") is not False or release.get("prerelease") is not False
        or not isinstance(release.get("assets"), list)
        or len(release["assets"]) != len(CONTEXT_ASSETS)
        or {item.get("name") for item in release["assets"] if isinstance(item, dict)} != CONTEXT_ASSETS
    ):
        raise ValueError("Expected a public, complete, stable container source release")
    output.mkdir(parents=True)
    for name in CONTEXT_ASSETS:
        url = f"https://github.com/{REPOSITORY}/releases/download/{urllib.parse.quote(tag, safe='')}/{name}"
        (output / name).write_bytes(download(url, MAX_CONTEXT if name.endswith(".gz") else 65536))
    return validate_context(output, tag, extract)


def assert_unused_image_tag(version: str) -> None:
    tag = f"v{stable_version(version)}"
    try:
        registry_manifest(tag)
    except urllib.error.HTTPError as error:
        if error.code == 404 and error.url == f"https://ghcr.io/v2/{REGISTRY_PATH}/manifests/{tag}":
            error.close()
            return
        raise
    raise ValueError("Immutable GHCR version tag already exists; never overwrite it")


def image_metadata(data: bytes, tag: str) -> dict[str, object]:
    value = object_fields(read_json(data), {
        "schemaVersion", "component", "version", "tag", "source", "image", "publisher",
    })
    version = stable_version(value["version"])
    source = object_fields(value["source"], {"repository", "commit", "contextTag", "contextSha256"})
    image = object_fields(value["image"], {"repository", "digest", "platforms"})
    publisher = object_fields(value["publisher"], {"repository", "commit", "runId", "runAttempt"})
    full_sha(source["commit"])
    full_sha(publisher["commit"])
    image_digest(image["digest"])
    if (
        type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
        or value["component"] != "container-base" or value["tag"] != tag
        or tag != f"container-base/v{version}"
        or source["repository"] != SOURCE or source["contextTag"] != f"container-base-source/v{version}"
        or not isinstance(source["contextSha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", source["contextSha256"])
        or image["repository"] != IMAGE or not isinstance(image["platforms"], list)
        or len(image["platforms"]) != 2 or publisher["repository"] != REPOSITORY
        or any(not isinstance(publisher[key], str) or not re.fullmatch(r"[1-9]\d*", publisher[key])
               for key in ("runId", "runAttempt"))
    ):
        raise ValueError("Invalid immutable public base image metadata")
    architectures = []
    for item in image["platforms"]:
        record = object_fields(item, {"architecture", "digest"})
        if record["architecture"] not in {"amd64", "arm64"}:
            raise ValueError("Unexpected image architecture")
        image_digest(record["digest"])
        architectures.append(record["architecture"])
    if sorted(architectures) != ["amd64", "arm64"]:
        raise ValueError("Missing or duplicate public image architecture")
    return value


def stage_image_release(
    context: Path, platforms: Path, digest_value: str, policy_sha: str, output: Path
) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise ValueError("Image release staging output must not already exist")
    raw = read_json(regular_bytes(context / "release.json", 65536))
    if not isinstance(raw, dict) or not isinstance(raw.get("tag"), str):
        raise ValueError("Missing approved source context identity")
    source = validate_context(context, raw["tag"])
    source_identity = object_fields(source["source"], {"repository", "commit"})
    artifact = object_fields(source["artifact"], {"name", "sha256", "size"})
    run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[1-9]\d*", run_id) or not re.fullmatch(r"[1-9]\d*", attempt):
        raise ValueError("Missing public build run identity")
    files: dict[str, bytes] = {}
    records = []
    for architecture in ("amd64", "arm64"):
        directory = platforms / f"container-base-platform-{architecture}"
        record = object_fields(read_json(regular_bytes(directory / "platform.json", 65536)), {
            "architecture", "repository", "digest", "sourceSha", "contextSha256", "runId", "runAttempt", "scan",
        })
        if (
            record["architecture"] != architecture or record["repository"] != IMAGE
            or record["sourceSha"] != source_identity["commit"] or record["contextSha256"] != artifact["sha256"]
            or record["runId"] != run_id or record["runAttempt"] != attempt or record["scan"] != "passed"
        ):
            raise ValueError("Platform digest is not from this exact tested/scanned public build")
        records.append({"architecture": architecture, "digest": image_digest(record["digest"])})
        for original, published in (
            ("sbom.cdx.json", f"sbom-{architecture}.cdx.json"),
            ("provenance.sigstore.json", f"provenance-{architecture}.sigstore.json"),
            ("sbom.sigstore.json", f"sbom-{architecture}.sigstore.json"),
        ):
            data = regular_bytes(directory / original, MAX_EVIDENCE)
            if not isinstance(read_json(data), dict):
                raise ValueError("Invalid public SBOM or attestation evidence")
            files[published] = data
    value = {
        "schemaVersion": 1, "component": "container-base", "version": source["version"],
        "tag": f"container-base/v{source['version']}",
        "source": {**source_identity, "contextTag": source["tag"], "contextSha256": artifact["sha256"]},
        "image": {"repository": IMAGE, "digest": image_digest(digest_value), "platforms": records},
        "publisher": {"repository": REPOSITORY, "commit": full_sha(policy_sha), "runId": run_id, "runAttempt": attempt},
    }
    image_metadata(json_bytes(value), str(value["tag"]))
    output.mkdir(parents=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
    (output / "container.json").write_bytes(json_bytes(value))
    return value


def validate_image_assets(directory: Path, tag: str) -> dict[str, object]:
    if directory.is_symlink() or not directory.is_dir() or {item.name for item in directory.iterdir()} != IMAGE_ASSETS:
        raise ValueError("Expected the exact public image metadata, SBOMs and attestation inventory")
    value = image_metadata(regular_bytes(directory / "container.json", 65536), tag)
    if regular_bytes(directory / "SHA256SUMS", 2048) != checksums(directory, sorted(IMAGE_ASSETS - {"SHA256SUMS"})):
        raise ValueError("Public image evidence checksums are invalid")
    for name in IMAGE_ASSETS - {"SHA256SUMS", "container.json"}:
        if not isinstance(read_json(regular_bytes(directory / name, MAX_EVIDENCE)), dict):
            raise ValueError("Public image evidence must be JSON")
    return value


def verify_image_release(tag: str) -> dict[str, object]:
    if not re.fullmatch(f"container-base/v{VERSION}", tag):
        raise ValueError("Only approved public base image tags are accepted")
    release = read_json(download(
        f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{urllib.parse.quote(tag, safe='')}",
        1024 * 1024,
    ))
    if (
        not isinstance(release, dict) or release.get("tag_name") != tag
        or release.get("draft") is not False or release.get("prerelease") is not False
        or not isinstance(release.get("assets"), list) or len(release["assets"]) != len(IMAGE_ASSETS)
        or {item.get("name") for item in release["assets"] if isinstance(item, dict)} != IMAGE_ASSETS
    ):
        raise ValueError("Public image release is incomplete or contains unapproved assets")
    with tempfile.TemporaryDirectory(prefix="skillforge-public-image-") as temporary:
        directory = Path(temporary)
        for name in IMAGE_ASSETS:
            url = f"https://github.com/{REPOSITORY}/releases/download/{urllib.parse.quote(tag, safe='')}/{name}"
            (directory / name).write_bytes(download(url, MAX_EVIDENCE))
        value = validate_image_assets(directory, tag)
    verify_image_record(value)
    return value


def verify_image_record(value: dict[str, object]) -> None:
    image = object_fields(value["image"], {"repository", "digest", "platforms"})
    index = verify_public_index(image_digest(image["digest"]))
    manifest = index["manifest"]
    assert isinstance(manifest, dict)
    actual = {item["platform"]["architecture"]: item["digest"] for item in manifest["manifests"]}
    expected = {item["architecture"]: item["digest"] for item in image["platforms"]}
    if actual != expected:
        raise ValueError("Public registry platform digests differ from the published release")


def existing_image_release(directory: Path) -> dict[str, object]:
    raw = read_json(regular_bytes(directory / "release.json", 65536))
    if not isinstance(raw, dict) or not isinstance(raw.get("tag"), str):
        raise ValueError("Missing source context metadata")
    context = validate_context(directory, raw["tag"])
    tag = f"container-base/v{context['version']}"
    api_url = f"https://api.github.com/repos/{REPOSITORY}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        published = verify_image_release(tag)
    except urllib.error.HTTPError as error:
        if error.code == 404 and error.url == api_url:
            error.close()
            return {"published": False}
        raise
    source = object_fields(published["source"], {"repository", "commit", "contextTag", "contextSha256"})
    context_source = object_fields(context["source"], {"repository", "commit"})
    context_artifact = object_fields(context["artifact"], {"name", "sha256", "size"})
    if source["commit"] != context_source["commit"] or source["contextSha256"] != context_artifact["sha256"]:
        raise ValueError("Existing immutable public image belongs to different reviewed sources")
    return {"published": True, "release": published}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Approved public SkillForge base container delivery")
    parser.add_argument("command", choices=[
        "pack", "validate", "download", "approval", "visibility", "verify-image",
        "unused-tag", "stage-image", "seal-image", "validate-image-assets", "verify-image-release", "existing",
    ])
    parser.add_argument("--tag", default="")
    parser.add_argument("--version", default="")
    parser.add_argument("--source-sha", default="")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--extract", type=Path)
    parser.add_argument("--digest", default="")
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--platforms", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--policy-sha", default="")
    args = parser.parse_args(argv)
    try:
        if args.command == "pack" and args.root is not None and args.directory is not None:
            result = pack_context(args.root, args.source_sha, args.version, args.directory)
        elif args.command == "validate" and args.directory is not None:
            result = validate_context(args.directory, args.tag, args.extract)
        elif args.command == "download" and args.directory is not None:
            result = download_context(args.tag, args.directory, args.extract)
        elif args.command == "approval":
            require_approval(os.environ.get("GH_TOKEN", ""), os.environ.get("GITHUB_REPOSITORY", ""), "public-container-publish")
            result = {"approval": "verified"}
        elif args.command == "visibility":
            result = {"visibility": require_package_visibility(os.environ.get("GH_TOKEN", ""), args.bootstrap)}
        elif args.command == "verify-image":
            result = verify_public_index(args.digest)
        elif args.command == "unused-tag":
            assert_unused_image_tag(args.version)
            result = {"unused": f"v{args.version}"}
        elif args.command == "stage-image" and args.directory is not None and args.platforms is not None and args.output is not None:
            result = stage_image_release(args.directory, args.platforms, args.digest, args.policy_sha, args.output)
        elif args.command == "seal-image" and args.directory is not None:
            if {item.name for item in args.directory.iterdir()} != IMAGE_ASSETS - {"SHA256SUMS"}:
                raise ValueError("Incomplete image release before checksum sealing")
            (args.directory / "SHA256SUMS").write_bytes(checksums(args.directory, sorted(IMAGE_ASSETS - {"SHA256SUMS"})))
            result = validate_image_assets(args.directory, args.tag)
            verify_image_record(result)
        elif args.command == "validate-image-assets" and args.directory is not None:
            result = validate_image_assets(args.directory, args.tag)
        elif args.command == "verify-image-release":
            result = verify_image_release(args.tag)
        elif args.command == "existing" and args.directory is not None:
            result = existing_image_release(args.directory)
        else:
            raise ValueError("Required command arguments are missing")
    except (ValueError, OSError, EOFError, tarfile.TarError, urllib.error.URLError, zlib.error, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

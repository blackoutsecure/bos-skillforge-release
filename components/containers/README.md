# Public SkillForge Containers

This public repository owns GHCR distribution for explicitly approved images:

| Image                                                                    | Registry path                                               | Public eligibility                                          |
| ------------------------------------------------------------------------ | ----------------------------------------------------------- | ----------------------------------------------------------- |
| Generic Ubuntu 24.04 base with `skillforge-assess`                       | `ghcr.io/blackoutsecure/bos-skillforge-release/base-ubuntu` | Allowlisted; activation and first live release required     |
| Course-specific learner images                                           | None here by default                                        | Private until separately approved for public redistribution |
| Instructor/authoring images, platform backend and full-source appliances | None                                                        | Not eligible for this public pipeline                       |

Do not interpret the public base as an assigned lab. It contains tools and the generic assessor, not
a catalog, rubric, instructor answer, account, school configuration or learner work. An assigned lab
still requires its reviewed digest-addressed learner release and course access.

## Release structure and use

Approved source releases produce two separately named components:

```text
container-base-source/v1.0.2
  container-context.tar.gz
  release.json
  SHA256SUMS

container-base/v1.0.2
  container.json
  SHA256SUMS
  sbom-amd64.cdx.json
  sbom-arm64.cdx.json
  provenance-amd64.sigstore.json
  provenance-arm64.sigstore.json
  sbom-amd64.sigstore.json
  sbom-arm64.sigstore.json
  index-provenance.sigstore.json
```

The source context contains exactly `Dockerfile`, `scripts/self-assess.sh`, `LICENSE` and
`NOTICE.md`, read from regular Git blobs at the reviewed source commit. Uncommitted changes,
symlinks, whole-tree `COPY`, extra build instructions/packages, instructor files and school data are
rejected. The [policy](../../config/container-base-files.json) is deny-by-default.

After a verified public image release, download `container.json` and its checksums from
[the official releases](https://github.com/blackoutsecure/bos-skillforge-release/releases). Use the
immutable digest, not `latest` or a moving architecture tag:

```powershell
$release = Get-Content .\container.json -Raw | ConvertFrom-Json
$image = "$($release.image.repository)@$($release.image.digest)"
docker pull $image
```

The version tag is `:vMAJOR.MINOR.PATCH`, but deployment and learner-image construction use
`@sha256:<digest>`. There is no automatic `latest` tag. An existing version tag is never
overwritten. Pass the digest from `container.json` as `base_image` to the internal learner-image
workflow. That does **not** change a course image's private visibility or grant course enrollment.

Both native `linux/amd64` and `linux/arm64` images are built and smoke-tested. Each exact image is
vulnerability/secret scanned before registry login; it is pushed without rebuilding. SBOMs and
GitHub build attestations accompany the platform digests and combined index. The final workflow
verifies anonymous index/child manifests, pulls both architectures with an empty Docker
configuration, then creates the public release record and rechecks its public assets.

For publisher verification, use the official repository's attestation instructions, for example:

```powershell
gh attestation verify "oci://$image" --repo blackoutsecure/bos-skillforge-release
```

Checksums alone are not publisher authentication. Keep the workflow/reviewer trust boundary.

## Credentials and public visibility

Publishing runs **here**, using the public repository's short-lived `GITHUB_TOKEN` with job-level
Packages write. Gatewall is used only in the internal source repository to upload approved source
assets; its Contents token is not repurposed as a GHCR credential. No private-source checkout token
or registry PAT is installed in this public repository.

**A public repository does not automatically make a GHCR package public.** GHCR packages start
private and inherit repository access permissions, not visibility. See GitHub's
[registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and
[package visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
documentation.

### One-time activation/bootstrap

1. Review/promote this public policy and workflows to `main`. Keep development on `dev`.
2. In the labs repository, protect `public-container-source` with independent reviewers and
   prevention of self-review; authorize its existing target-only Gatewall Contents credential.
3. Here, protect `public-container-publish` with independent reviewers, prevention of self-review
   and trusted release-tag restrictions. Approve the intended public content and redistribution
   licensing before enabling it.
4. Set `SKILLFORGE_PUBLIC_BASE_ENABLED=true` in both participating repositories only after approval.
   Publish a matching stable source release, or dispatch the source workflow with that existing tag.
5. For the first namespace only, dispatch **Public SkillForge base container** here with the
   reviewed `container-base-source/v...` tag and `bootstrap_namespace=true`. This creates a scanned
   generic package under an isolated bootstrap tag; it reports public availability as **Not
   Assessed** and creates no public image release record.
6. An organization/package administrator must set that GHCR package's visibility to **Public** in
   its package settings. Ensure `bos-skillforge-release` has workflow access; organization settings
   can disable automatic access inheritance. Do not broaden a PAT or Gatewall permission as a
   shortcut.
7. Dispatch again with `bootstrap_namespace=false`. Normal publishing refuses missing, private,
   internal, incorrectly associated or already occupied namespaces/version tags. Announce downloads
   only after anonymous pulls and durable image-release verification succeed.

GitHub Actions releases created with `GITHUB_TOKEN` do not trigger another release workflow, so the
container publisher performs final public-release validation directly. The source asset uploader's
App token does trigger the public build workflow.

An interrupted matrix may leave candidate platform tags, but cannot publish the combined release. If
an interruption leaves a version tag without a complete release record, stop and perform reviewed
recovery or publish a new version; do not overwrite a digest or move a version tag by hand. This
pipeline does not claim reproducible apt installs across dates: source context bytes are
deterministic, and the published/scanned image is retained by digest.

## Licensing and boundaries

Ubuntu and installed packages retain their own licenses and copyright notices. The included
SkillForge license governs the original SkillForge files, not every bundled OS package. The public
build overrides the old whole-image proprietary label with `NOASSERTION`, not a new license grant.
Retain upstream notices and satisfy applicable corresponding-source/redistribution obligations;
review the package inventory/SBOM before approving public distribution.

Adding another public image requires its own reviewed file/content policy and publication contract.
Do not flip the existing private learner repository to public or copy arbitrary Docker images,
volumes, attempts, registry credentials or the authoring tree here.

## Offline and live checks

```powershell
python -m unittest discover -s tests -v
python scripts\container_release.py validate --tag container-base-source/v1.0.2 --directory <source-assets>
python scripts\container_release.py verify-image-release --tag container-base/v1.0.2
```

The first two prove contract/privacy behavior offline. Only the last command and the hosted native
build/anonymous-pull workflow prove a real public container is available. No image has been
published just by adding this pipeline.

# Blackout Secure SkillForge Releases

Public distribution of explicitly approved SkillForge downloads. The internal `bos-skillforge-labs`
and `bos-skillforge-platform` repositories remain the authoring and control-plane sources. This
repository is not a mirror of either source tree.

## Organized releases

| Component                                                        | Versioned release tag                      | Public assets                                  | Status                                                           |
| ---------------------------------------------------------------- | ------------------------------------------ | ---------------------------------------------- | ---------------------------------------------------------------- |
| [Learner helper](components/learner-helper/README.md)            | `learner-helper/vMAJOR.MINOR.PATCH`        | npm archive, release metadata, checksums       | Implemented; operator activation and first live release required |
| [Public generic base container](components/containers/README.md) | `container-base/vMAJOR.MINOR.PATCH`        | GHCR image, digest record, SBOMs, attestations | Implemented; visibility bootstrap and first live build required  |
| Approved generic container sources                               | `container-base-source/vMAJOR.MINOR.PATCH` | Allowlisted Docker build context and checksums | Input to the public container publisher                          |
| Student PDFs / lesson reader                                     | Not yet approved                           | None                                           | Not Assessed                                                     |
| Learner images / sanitized appliances                            | Not yet approved                           | None                                           | Not Assessed                                                     |
| Platform API / SDK                                               | Not yet approved                           | None                                           | Not Assessed                                                     |

Large downloads belong to **GitHub Release assets**, never Git history. Separate component tags
prevent client updates from accidentally selecting a PDF, appliance or platform release. The helper
checks the highest stable helper SemVer, not GitHub's repository-wide "latest" release. Prereleases,
drafts and other components are not installed or offered as stable updates.

Only these assets are accepted for each helper release:

```text
learner-helper/v1.0.2
  learner-helper.tgz
  release.json
  SHA256SUMS
```

The [archive policy](config/learner-helper-files.json) is deny-by-default. The package has no
authoring catalog, instructor material, content generators, platform backend, school API
configuration, dependency installation scripts, shared credentials or learner data. Public
availability does not relicense anything: the original `LICENSE` and `NOTICE.md` remain inside the
archive and govern authorized use.

This repository uses the same [Blackout Secure Proprietary License](LICENSE) as the labs and
platform repositories. Public availability does not grant production-use or redistribution rights.
Third-party components retain their own licenses; this does not relicense Ubuntu or bundled
packages.

## Publication boundary

Packaging, source tests, human approval and secret scanning stay in the internal labs repository.
Its `publish-public-helper.yml` uploads only the allowlisted helper assets here, using a short-lived
Gatewall App token scoped to this repository's Contents permission. This public repository never
receives a credential that can read either internal source. No source release notes, full-source
archives or arbitrary workflow artifacts are mirrored.

The source workflows handle a published source release and successful completion of the existing
source-release workflow. The latter is necessary because a release created using `GITHUB_TOKEN` does
not trigger another `release` workflow. Manual dispatch with an existing source tag supports
retries/backfills.

Publishing stages a draft, uploads the complete inventory, then publishes it. Interrupted drafts can
be resumed only with matching identity and bytes. An existing published version is immutable:
different content fails rather than clobbering assets or moving tags.

### Public Docker/OCI images

The [container publisher](.github/workflows/publish-public-containers.yml) builds/scans native
amd64/arm64 images **in this public repository**, using only the publicly approved four-file generic
base context. Images are associated with this repository through OCI metadata and published to
`ghcr.io/blackoutsecure/bos-skillforge-release/base-ubuntu`. The source authoring repository is
never cloned here; it uploads sanitized sources through its separate approved workflow.

The public publisher uses its own job-scoped `GITHUB_TOKEN` for GHCR; it does not require a new PAT
or private-source access. GHCR packages initially remain private even when this repository is
public. Normal publication explicitly requires public package visibility and checks anonymous
manifests and actual pulls for both architectures. Namespace bootstrap is separate and reports **Not
Assessed**. See [container activation and use](components/containers/README.md) for the necessary
one-time visibility step, immutable digest references and licensing boundary.

### Operator activation

1. Review this repository's policy on `dev`, promote it to `main`, and install its workflows. A
   reviewed `main` commit must exist before the source publisher can create a public tag.
2. In the internal labs repository, configure the `public-learner-helper` environment with required
   independent reviewers, prevention of self-review, and trusted branch/tag restrictions. The source
   workflow verifies reviewer protection before publishing.
3. Authorize the existing Gatewall App for this public target with Contents write, and make its
   existing App ID variable/private-key secret available to the protected source job. Do not widen
   Gatekeeper permissions or supply private-source credentials to this public repository.
4. Enable `SKILLFORGE_PUBLIC_HELPER_ENABLED=true` only after the helper's public-distribution
   approval. Until then publication is **Not Assessed**, not a passed publish.
5. Publish a reviewed, stable `vMAJOR.MINOR.PATCH` source release whose package version matches. For
   recovery, dispatch the source workflow with that existing source tag.
6. Verify **Public download validation** here before announcing the release. It downloads
   anonymously, checks every checksum, inspects the archive without extracting it, and confirms the
   reviewed source inventory. The source App token makes the release event trigger this check.

Revalidation checks out the public release tag's own policy, not a newer policy that could
incorrectly reject an older immutable package.

No assets have been published merely by adding these files.

## Validation

Python 3.12+ and its standard library are sufficient:

```powershell
python -m unittest discover -s tests -v
python scripts\validate_public_release.py --tag learner-helper/v1.0.2 --directory <assets-directory>
python scripts\validate_public_release.py --tag learner-helper/v1.0.2
actionlint .github\workflows\ci.yml .github\workflows\publish-public-containers.yml .github\workflows\validate-public-assets.yml
```

The local command validates bytes and contracts. Only the command without `--directory` and the live
workflow prove anonymous availability. Neither checks school identity, private registry access,
Docker execution, classroom permissions or official grading.

## Further workflow migration

- Publish **reviewed student-only PDFs and the read-only lesson reader** as their own component
  after explicit approval. Never copy the combined PDF output: it also contains instructor PDFs.
- Keep authoring/runtime validation in the source repositories and transfer only reviewed sanitized
  container inputs here. The generic base is now built/scanned/published here with digest-addressed
  references, SBOMs and provenance. Existing course learner images remain private; do not change
  their registry privacy just to make a download link work.
- Build a separate sanitized learner appliance before publishing OVAs. The current full-source
  authoring appliance is not eligible, and GitHub Release asset-size limits must be checked.
- Keep platform deployment, tenant configuration, identity, evidence, grade review, Canvas passback,
  runner provisioning and authoring/lifecycle gates in their source repositories.
- Migrate the labs' legacy `launchpad.yml` caller before relying on its deployment path: its
  `bos-universal-launchpad.yml@dev` hub target returned 404 during this review. Review the new hub
  input/secret contract first; do not move secret-bearing deployments into this public repo.
- Replace the legacy authoring-repository Marketplace claims with accurate source-release messaging
  (corrected in the source workflow). An internal proprietary repository is not a public Marketplace
  listing.
- Add release attestations/signing and an operator-verified first release before advertising
  automatic update trust. Checksums alone detect corruption, not publisher authenticity.
- Onboard repository protection/security/dependency maintenance deliberately. Managed-file sync must
  preserve proprietary licensing; do not accept the hub's default Apache license blindly.

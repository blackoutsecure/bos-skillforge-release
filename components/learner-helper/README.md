# SkillForge Learner Helper Downloads

Download the **learner-helper** component from
[SkillForge Releases](https://github.com/blackoutsecure/bos-skillforge-release/releases). Select a
stable `learner-helper/vMAJOR.MINOR.PATCH` tag, not another component or a prerelease. There is no
public download until the first approved release has been published and its anonymous-download check
has passed.

## Install

Install Node.js 20+ and your institution-approved Docker engine for Linux containers first. Download
`learner-helper.tgz`, `release.json` and `SHA256SUMS` from the same release.

In PowerShell, inside the download directory:

```powershell
$sums = Get-Content .\SHA256SUMS
if ($sums.Count -ne 2) { throw "Unexpected checksum inventory" }
$seen = @()
foreach ($line in $sums) {
  if ($line -notmatch '^([a-f0-9]{64})  (learner-helper\.tgz|release\.json)$') { throw "Invalid checksum entry" }
  $expected, $file = $Matches[1], $Matches[2]
  if ($file -in $seen) { throw "Duplicate checksum entry" }
  $seen += $file
  if ((Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw "Checksum mismatch: $file" }
}
$release = Get-Content .\release.json -Raw | ConvertFrom-Json
$actual = (Get-FileHash .\learner-helper.tgz -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $release.artifact.sha256) { throw "Helper checksum mismatch" }
if ((Get-Item .\learner-helper.tgz).Length -ne $release.artifact.size) { throw "Helper size mismatch" }
npm install --global --offline --ignore-scripts .\learner-helper.tgz
skillforge
```

On Linux/macOS, verify the whole checksum file with `sha256sum --check SHA256SUMS` or
`shasum -a 256 --check SHA256SUMS`, then install with
`npm install --global --offline --ignore-scripts ./learner-helper.tgz`.

Checksum files from the same download do not independently authenticate the publisher. Use the
official repository and your institution's verified release approval.

## Configure and pair

The public helper intentionally embeds **no school API origin**. Obtain your institution's trusted
HTTPS API origin, then set it before starting the helper:

```powershell
$env:SKILLFORGE_PLATFORM_URL = "https://school-api.example.edu"
skillforge
```

Choose **Pair this device**, sign in to the school portal, and approve only the matching code on
your own device. Pairing does not provide course enrollment or private image-registry access. The
package contains no authoring catalog or instructor answers.

## Check and apply an update

Run `skillforge update-check` or choose **Check updates** in the local helper. It compares the
installed helper version against stable helper releases, checks release metadata, and reports the
download URL and archive SHA-256 when a newer version exists.

No release yet, an unverified development helper, a network failure or malformed metadata is never
reported as "up to date." Updates are notification-only: verify the new archive, stop the helper,
install it explicitly and start it again. Existing lab work is not reset by the checker.

# Verify release artifacts

Verify the source tag, complete artifact family and publisher identity before
extracting or running a release binary. Use an independently trusted, clean
source checkout, GPG, the required Go compiler, cosign and GitHub CLI. The verifier
reads archived executable metadata but never executes an archived binary.

Set `SOURCE` to that checkout's absolute path, `TAG` to the approved tag and
`FINAL_SHA` to its independently approved 40-hex commit. Set `CORE` to an absolute
directory containing only the six archives, six provenance documents and
`SHA256SUMS`; set `SIDECARS` to a separate absolute directory containing only the
13 matching `.sigstore.json` bundles. Do not derive the expected commit, signer or
compiler from the downloaded artifacts.

The workflow retains the core family as `release-verified-<commit>` and the
bundles as `release-signatures-<commit>`. A published release contains the same
26 files. A bundle is named `<core-basename>.sigstore.json`, including
`SHA256SUMS.sigstore.json`. Download all members; an individually valid archive
or checksum file is not verification of the complete family.

## Supply an independent toolchain expectation

`verify` requires `--go-version` with the complete expected embedded Go version,
including the `go` prefix. Derive it from the committed `go.mod` in `SOURCE`, not
from provenance or the verifier's runtime. The policy helper returns the numeric
version, so add the prefix:

```sh
EXPECTED_GO_VERSION="go$(/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" go-version "$SOURCE")"
```

By-hand policy commands otherwise inherit the operator's Go environment. The
commands here use the release workflow's settings: `GOENV=off`, empty
`GOEXPERIMENT`, empty `GOFLAGS`, `GOTOOLCHAIN=local` and `GOWORK=off`. Put the
approved compiler on `PATH`; `local` selects that executable, not a named SDK.
Check it before running the verification helper:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" verify-toolchain "$SOURCE" "$EXPECTED_GO_VERSION"
```

The six provenance documents and actual embedded build information of all
18 executables must agree with the expected plain compiler. A uniformly different
version is rejected even if the family agrees internally. Experiment suffixes
are compared exactly, never removed or normalized.

For a standalone consistency check, a named compiler can build the verifier
without relying on the operator's launcher:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=go1.27.4 GOWORK=off go -C "$SOURCE" run ./internal/releasecheck/cmd/releasecheck verify "$CORE" "$TAG" --go-version "$EXPECTED_GO_VERSION" --source-root "$SOURCE"
```

`--source-root` selects an absolute, existing, clean trusted checkout. Without it,
verification uses the invoking source root. The reader's commit and runtime can
differ from the expected source and compiler; record both. `--source-root` is
accepted only by `verify`; `record` and `checksums` use the invoking checkout.
Consistency checks cover source commit/tree, module graph, LICENSE, exact archive
membership, paths, bounds, build settings and hashes. They do not authenticate a
publisher and do not prove reproducible builds.

## Verify the signed source tag

The independently trusted checkout contains `release/signing-policy.asc`: the
approved primary fingerprint `D29A27D9FD847A40E42880EAA71DFD3B4DA7A79B` and its
public key. The signing key expires on 2027-01-22 at 06:06:56 UTC; maintainers must
refresh this committed public policy when extending the key. Do not substitute a
key or fingerprint supplied alongside an untrusted download.

Run the same signed-tag and source check as the release workflow:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" verify-source "$SOURCE" "$TAG" "$FINAL_SHA" "$SOURCE/release/signing-policy.asc"
```

This requires an annotated tag, its signed name matching the requested ref, a
valid signature by the approved primary key, and no expired or revoked signing
key or signature. Lightweight, unsigned and wrong-signer tags are refused.
A signing subkey is accepted only when it is part of the committed public signing policy.
Verification uses an isolated keyring containing only that policy. Tag names
contain only ASCII letters, digits, dots, plus signs and hyphens. The helper also
requires both the tag's peeled commit and the checked-out `HEAD` to equal
`FINAL_SHA`; a valid signature over another source commit does not pass.

Tag signature checking is a publication gate, not a claim of server-side signed-tag
enforcement. Production-signer acceptance and hosted identity checks require the
actual signed proof tag; local throwaway-key tests do not establish those results.

## Classify the tag and publication inputs

Classify the independently selected tag before treating it as a public release:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" release-channel "$TAG"
```

The result is `release` for `vMAJOR.MINOR.PATCH`, `prerelease` for
`vMAJOR.MINOR.PATCH-rc.N`, or `proof` for a valid `v0.0.0-test.*` tag. Public
numeric components have no leading zeros, except a component that is exactly
zero; `N` is positive and has no leading zeros. Build metadata and other public
prerelease forms are refused. All accepted tags are at most 64 bytes and must be
valid Git refs.

A proof tag exercises the build, signing and verification jobs without publishing
a GitHub Release. Its tag-specific artifacts cannot be renamed or reused for a
public version. Public release options can be inspected without publishing:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" publication-options "$SOURCE" "$TAG"
```

This refuses proof tags. For public tags it requires a non-empty regular file
`docs/releases/v0.1.0.md` in the selected source, not a symbolic link. It returns
`--verify-tag` and `--notes-file` with that path, adding `--prerelease` only for
release-candidate tags. The workflow consumes these options; it does not replace
missing notes with inline text. An absent, empty or non-regular notes file blocks
publication. This command only prints options and does not create a release.

## Authenticate every core file

With the approved compiler on `PATH` and the signed source checked, run the
workflow's complete publication verifier:

```sh
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=local GOWORK=off bash "$SOURCE/hack/release-policy.sh" verify-publication "$SOURCE" "$CORE" "$SIDECARS" "$TAG" "$EXPECTED_GO_VERSION" "$FINAL_SHA"
```

It checks exact core and sidecar membership, artifact consistency, each Sigstore
bundle and every build attestation. For an independent per-file check, set `name`
to each of the 13 core basenames in turn, including `SHA256SUMS`, and run both
commands:

```sh
cosign verify-blob --bundle "$SIDECARS/$name.sigstore.json" --certificate-identity "https://github.com/zchee/mitmproxy-go/.github/workflows/release.yaml@refs/tags/$TAG" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$CORE/$name"
```

```sh
gh attestation verify "$CORE/$name" --repo zchee/mitmproxy-go --cert-identity "https://github.com/zchee/mitmproxy-go/.github/workflows/release.yaml@refs/tags/$TAG" --cert-oidc-issuer https://token.actions.githubusercontent.com --source-ref "refs/tags/$TAG" --source-digest "$FINAL_SHA" --deny-self-hosted-runners
```

The expected certificate identity includes the actual tag and the release
workflow; the OIDC issuer is `https://token.actions.githubusercontent.com`.
Attestation verification also binds the source ref and the source commit.
Proof-tag bundles cannot authenticate a differently named public tag.
Any wrong identity, missing member, invalid signature or failed verification
stops installation. GitHub or Sigstore unavailability does not authorize a
fallback to unauthenticated archives.

Signatures authenticate the expected identity and bytes; attestations state build
provenance, not independent source review or absence of defects. Checksums alone
are not publisher authentication. Apple code signing and notarization are not
provided.

## Verify independently on another host

Transfer the same 13 core files and 13 bundles without changing their basenames.
Compare transfer hashes before and after, and independently obtain the approved
source checkout, signer policy, tag and commit on the second host. Repeat the
compiler preflight and `verify-source` there, requiring both the peeled tag and
checked-out `HEAD` to match the independently approved commit. Repeat tag
classification and the complete publication verifier above, then both per-file
commands for every core basename. Use the same
independent artifact compiler expectation, even if the second host's standalone
reader uses another compiler. Record source/tree, reader/compiler identities,
command exit statuses and raw outputs. A repeated check on the first host is not
second-host verification.

Only after every check passes, extract the intended platform's archive into a new
versioned directory. It contains LICENSE and `mitmdump`, `mitmproxy`, `mitmweb`
(`.exe` on Windows). Verify updates in a new directory before switching the
executable path; retain an older verified directory for rollback. Native
local-mode redirectors are separate installations, and cross-building is not
native platform acceptance.

## Install from source

Use an independently pinned clean checkout at the approved tag's commit, after
verifying the source tag as above. Set `GOBIN` to an absolute directory outside
the checkout. To reproduce the plain compiler string, source installs require
`GOTOOLCHAIN=go1.27.4` and an empty `GOEXPERIMENT`. Run one command for each tool:

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go -C "$SOURCE" install ./cmd/mitmdump
```

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go -C "$SOURCE" install ./cmd/mitmproxy
```

```sh
/usr/bin/env GOTOOLCHAIN=go1.27.4 GOEXPERIMENT= GOFLAGS= GOENV=off GOWORK=off GOBIN="$GOBIN" go -C "$SOURCE" install ./cmd/mitmweb
```

Unlike the workflow's preinstalled compiler selected with `GOTOOLCHAIN=local`,
these commands select the named compiler: `local` can select an unrelated
development launcher. Ordinary source builds report `0.1.0-dev`; release linker
injection is not part of these commands. A `go build` of the same command packages
is also supported. Version-suffixed
`go install github.com/zchee/mitmproxy-go/cmd/<tool>@<version>` is unsupported while
the YAML replacement remains in `go.mod`. Do not remove that replacement to
force an install; it supplies the maintained parser hook used by bounded YAML
consumers.

For each tool retain the install exit status, executable hash, complete
`--version` output and `go version -m` output. `--version` has exactly three lines:
`Mitmproxy-go: 0.1.0-dev`, `Go: <independently expected plain compiler>` and
`Platform: <expected native goos>/<expected native goarch>`. Require the
corresponding `github.com/zchee/mitmproxy-go/cmd/<tool>` main-package path, VCS
revision equal to the approved commit, `vcs.modified=false` and the pinned YAML
replacement in build information. Go derives the main-module version from the
version tags in the checkout: it is the version tag itself when one points at
the approved commit, otherwise a pseudo-version ending in the approved commit's
UTC timestamp and the first twelve hexadecimal digits of its hash, or `(devel)`
when no version-control information is stamped. Keep
the checkout clean before and after; put installed binaries and receipts outside
it.

## Withdraw a published version

Withdrawal is a maintainer action, not an automatic rollback. Set `TAG` to the
affected public version and `WITHDRAWAL_NOTES` to an absolute Markdown file
containing the explicit reason, affected scope and fixed patch version. Keep
the original artifacts, checksums, signatures and tag intact. Mark the release
prerelease and replace its notes with the reviewed withdrawal notice:

```sh
gh release edit "$TAG" --repo zchee/mitmproxy-go --prerelease --notes-file "$WITHDRAWAL_NOTES"
```

Remove that version from installation recommendations and publish the fixed patch
version through the ordinary verification process. Never move the tag or replace
its assets. Deletion requires a separate explicit decision; it cannot recall
users' downloads, Go-proxy caches or checksum-database records, and the version
must never be reused. GitHub prerelease marking does not retract a Go module
version; any needed `retract` directive belongs to the module owner and retains
its reason in release notes.

## Release approval boundary

The repository applies three tag rulesets: creation of `refs/tags/v*` is
restricted to bypass actors; published tags under `refs/tags/v*`, excluding
`refs/tags/v0.0.0-test.*`, cannot be updated or deleted and that ruleset has no
bypass actor; disposable proof tags under `refs/tags/v0.0.0-test.*` can be
updated or deleted only by bypass actors. The bypass actor for creation and
proof-tag mutation is the repository administrator role, which includes all
current and future repository administrators, not the owner alone. Rulesets are
repository settings, not part of the source tree; before relying on them,
list them with `gh api repos/zchee/mitmproxy-go/rulesets` and read each
listed ruleset's conditions, rules and bypass actors with
`gh api repos/zchee/mitmproxy-go/rulesets/<id>`.
No ruleset requires a signed tag;
the release workflow checks the tag signature.

This verification procedure authorizes no tag push, release publication or
deletion. The production-signer positive proof and hosted OIDC/signature/attestation
acceptance require the final signed proof tag. The
[release notes](../releases/v0.1.0.md) describe supported channels and residual
limits. Neither successful local verification nor deletion of a disposable proof
tag authorizes changing a public version.

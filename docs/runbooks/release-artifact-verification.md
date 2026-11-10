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
/usr/bin/env GOENV=off GOEXPERIMENT= GOFLAGS= GOTOOLCHAIN=go1.27.3 GOWORK=off go -C "$SOURCE" run ./internal/releasecheck/cmd/releasecheck verify "$CORE" "$TAG" --go-version "$EXPECTED_GO_VERSION" --source-root "$SOURCE"
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
gh attestation verify "$CORE/$name" --repo zchee/mitmproxy-go --signer-workflow zchee/mitmproxy-go/.github/workflows/release.yaml --cert-identity "https://github.com/zchee/mitmproxy-go/.github/workflows/release.yaml@refs/tags/$TAG" --cert-oidc-issuer https://token.actions.githubusercontent.com --source-ref "refs/tags/$TAG" --source-digest "$FINAL_SHA" --deny-self-hosted-runners
```

The expected certificate identity includes the actual tag and the release
workflow; the OIDC issuer is `https://token.actions.githubusercontent.com`.
Attestation verification also binds the source ref, source commit and signer
workflow. Proof-tag bundles cannot authenticate a differently named public tag.
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

## Release approval boundary

Three tag-ruleset documents are **prepared, not applied**: creation restriction
for `refs/tags/v*`, immutable public tags, and administrator-only mutation of
disposable proof tags. Their bypass actor is the repository administrator role,
which includes all current and future repository administrators, not the owner
alone. Prepared documents do not establish server-side protection. Applying each
ruleset requires separate approval and a readback of the effective configuration.

This verification procedure authorizes no tag push, release publication or
deletion. The production-signer positive proof and hosted OIDC/signature/attestation
acceptance remain pending until the final signed proof tag. Supported channels,
withdrawal instructions and the first public release's residual limits are
finalized with the remaining release documentation; neither successful local
verification nor deletion of a disposable proof tag authorizes changing a public
version.

# Verify release artifacts

Run the verifier from a trusted source checkout with the required Go toolchain.
Keep the artifact family separate from the expected source: six archives, their
six provenance documents and `SHA256SUMS` are inputs, not instructions to run.
The verifier never executes an archived binary.

## Supply an independent toolchain expectation

`verify` requires `--go-version` with the complete expected embedded Go version,
including the `go` prefix and any experiment suffix. Obtain it independently from
a trusted build receipt, operator policy or the trusted source's release-toolchain
policy. Do not copy it from the artifacts under test or the verifier's own runtime.

For a family built with plain Go 1.27.3, replace the artifact path and tag with the
family you intend to check:

```sh
go run ./internal/releasecheck/cmd/releasecheck verify /absolute/path/to/artifact-family v0.0.0-test.20261028 --go-version go1.27.3
```

The six provenance documents and the actual embedded build information of all
18 executables must agree with that expectation. A uniformly different version
is rejected even when the family agrees internally. Experiment suffixes are
compared exactly, not removed or normalized.

This proves **consistency with an independently asserted toolchain, not publisher
authenticity**. Checksums establish integrity; they are not publisher signatures
or notarization. Source commit/tree, module graph, LICENSE, archive membership,
paths, bounds and build settings are checked separately.

## Select the expected source checkout

`--source-root` optionally selects an absolute, existing, clean trusted checkout;
without it, verification uses the current source root. Select the independently
pinned source commit used for the family, not whichever checkout happens to host
the newer verifier. The artifact directory cannot select the expected source.

```sh
go run ./internal/releasecheck/cmd/releasecheck verify /absolute/path/to/artifact-family v0.0.0-test.20261028 --go-version go1.27.3 --source-root /absolute/path/to/trusted-clean-checkout
```

The reader's commit and runtime can differ from the expected source and compiler.
Record both identities with the artifact hashes and verification result. Do not
change `GOEXPERIMENT` merely to make the reader accept a family; supply the actual
expected artifact toolchain instead.

The release workflow supplies the expected version from its trusted go.mod-derived
toolchain step, not from the downloaded provenance or the verifier runtime. The
source-root selector is verification-only; it does not change recording or
checksum-generation behavior.

## Deferred release planning

A first public release needs a separate scope and approval decision; this
verification procedure authorizes no tag push, release publication or deletion.
Confirm whether the six-target, three-command artifact family is the supported
shipped set, with Windows lacking automatic native acceptance and FreeBSD remaining
cross-compile build-only. Decide who supplies the independent expected Go version
and whether the published toolchain is plain or experiment-suffixed.

Choose the archive/checksum/tag signing and macOS notarization policy, its trusted
configuration and the claims a release page may make. Toolchain consistency must
not be presented as publisher authentication. Define supported installation and
update channels, rollback/withdrawal behavior, and whether published tags may be
deleted; successful test-tag deletion does not establish that policy.

Release notes must disposition the unrepaired timing-sensitive leaves, the
HTTP/3 high-concurrency measurement and telemetry benchmark status, the diagnostics
shutdown residual and the outstanding native macOS/Windows runbook evidence.
Decide whether manual-only fuzzing remains acceptable or schedule activation is a
release prerequisite. Finally confirm the first version, prerelease/test-tag
conventions and protection rules for tag pushes.

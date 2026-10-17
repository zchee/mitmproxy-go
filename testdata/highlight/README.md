# Highlight corpus

The input corpus is fixed before token mapping or golden generation. It has
seven Rust test-literal occurrences and four real-world source excerpts.
`inputs/manifest.json` records their identities, languages, SHA256 digests,
physical line counts, original paths, full commits, Git blobs and source spans.
The two XML occurrences intentionally have identical bytes and distinct
origins. Configuration-only Rust tests are listed separately.

## Real-world sources

Each sample is exactly source lines 1–200, including original whitespace and
line endings. These are excerpts, not necessarily complete syntax trees.
Nothing is padded, repeated, or edited to improve highlighter agreement.

| Language | Source | Commit | License |
| --- | --- | --- | --- |
| CSS | [Bootstrap dist/css/bootstrap.css](https://github.com/twbs/bootstrap/blob/6e1f75f420f68e1d52733b8e407fc7c3766c9dba/dist/css/bootstrap.css) | `6e1f75f420f68e1d52733b8e407fc7c3766c9dba` | MIT |
| JavaScript | [Bootstrap js/src/modal.js](https://github.com/twbs/bootstrap/blob/6e1f75f420f68e1d52733b8e407fc7c3766c9dba/js/src/modal.js) | `6e1f75f420f68e1d52733b8e407fc7c3766c9dba` | MIT |
| XML | [Maven pom.xml](https://github.com/apache/maven/blob/8e8579a9e76f7d015ee5ec7bfcdc97d260186937/pom.xml) | `8e8579a9e76f7d015ee5ec7bfcdc97d260186937` | Apache-2.0 |
| YAML | [Kubernetes hack/golangci.yaml](https://github.com/kubernetes/kubernetes/blob/948afe5ca072329a73c8e79ed5938717a5cb3d21/hack/golangci.yaml) | `948afe5ca072329a73c8e79ed5938717a5cb3d21` | Apache-2.0 |

The small Rust source files are retained to verify literal spans. For the
real-world samples, the manifest records the immutable URL, commit, path,
source line range, full upstream file SHA256 and excerpt SHA256; the complete
external files are not vendored. License texts and Maven's NOTICE are retained
under `licenses/`.

## Oracle boundary

The oracle is the released `mitmproxy_rs==0.12.11` wheel, not execution of
Rust source commit `51fe2b7c5aa8439c162abb665db61c6669d146d6`. The retained
`highlighter-source.diff` records the measured empty highlighter/binding source
diff between `v0.12.11` and that commit. Their Cargo.lock files resolve
tree-sitter and tree-sitter-highlight to different versions.
`sources/mitmproxy-rs/lock-tables.json` retains only the seven relevant entries
per revision, including checksums; the complete lockfiles are not vendored.

`goldens.json` is the portable frozen expectation and must match a fresh
wheel generation byte-for-byte on every supported host. `provenance.json`
is runtime-specific evidence: wheel filename and digest, installed-file
manifest and digest, Python/uv versions, both source pins, lock entries,
source diff, and input origins. Validate and retain it on each host; do not
compare another platform's wheel digest with the generating platform's.
Two generations on the same host must match every generated file exactly.
See [SCHEMA.md](SCHEMA.md) for the reader contract.

`SHA256SUMS` covers this corpus separately from the root imported-fixture
manifest. Ordinary tests must never rewrite the frozen inputs or goldens.

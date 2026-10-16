# Highlight asset schema

## Inputs

`inputs/manifest.json` has `schema_version: 1` and an ordered `inputs` array.
Each entry has `id`, `kind` (`rust_literal` or `sample`), `language`, `path`
(relative to `inputs/`), SHA256 `sha256`, `physical_lines`, and `source`.
Source records identify the repository, full commit, original path, Git blob,
full-source SHA256, and inclusive one-based source line range.
Rust records also name the test function and retained source snapshot;
samples name their license and frozen excerpt SHA256 without a full copy.

All eleven identities are fixed: `css_debug`, `css_highlight`,
`javascript_debug`, `javascript_highlight`, `xml_debug`, `xml_highlight`,
`yaml_highlight`, and `{css,javascript,xml,yaml}_real_200`.
The two XML inputs have equal bytes but distinct source occurrences.
The four configuration-only tests are recorded separately, not as inputs.
Physical lines count a final unterminated line, without creating an extra line
for a trailing newline. Each real sample is exactly the first 200 physical
lines of its source at the recorded immutable URL; no text is inserted or
normalized. Full external samples and complete Cargo.lock files are not stored.

The manifest also carries both source pins, the wheel-source commit, the
seven resolved tree-sitter lock entries for each Rust revision, the empty
highlighter/binding source diff, and license-file SHA256 records. Source
snapshots and notices are outside `inputs/`, so the input directory contains
only its manifest and eleven declared input files.

## Portable golden output

`goldens.json` is UTF-8 JSON, indented by two spaces, keys sorted, ending in
one newline. Its shape is:

```json
{
  "schema_version": 1,
  "oracle": {"distribution": "mitmproxy_rs", "version": "0.12.11"},
  "languages": ["css", "javascript", "xml", "yaml", "none", "error"],
  "tags": ["name", "string", "number", "boolean", "comment", "error"],
  "cases": [
    {
      "id": "css_debug",
      "language": "css",
      "input_sha256": "<64 lowercase hexadecimal characters>",
      "physical_lines": 1,
      "reconstruction_equal": true,
      "chunks": [{"tag": "name", "text": "<unmodified oracle text>"}]
    }
  ]
}
```

The example illustrates the shape, not an actual expected chunk sequence.
`cases` follows manifest order. A chunk's `tag` is either the empty string
(unstyled Text) or one of the six public tags, all lowercase. `text` is the
exact decoded string returned by the pinned wheel, including whitespace.
Concatenating every chunk's text must exactly reproduce the source input.
There are no byte offsets; consumers derive offsets or physical lines by
walking the ordered chunks. Do not sort, merge, trim or otherwise normalize
chunks. A source-spanning chunk remains one chunk in the golden; splitting
at physical lines is solely an exemption-accounting operation.

## Generation provenance

`provenance.json` accompanies the portable output. It records the input
manifest SHA256, source pins, lock tables and their snapshot hashes, source
diff metadata, complete input source records, the exact languages/tags,
uv and Python versions, and installed `mitmproxy_rs` distribution version.

The installed distribution digest is SHA256 of canonical UTF-8 JSON for a
sorted list of `{path, sha256, size}` records covering every installed file
listed by distribution metadata, except interpreter-created `.pyc` files.
The metadata's RECORD file is included; files are never imported as code
while hashing. Paths are distribution-relative; absolute installation paths,
execution dates and output-directory names are not serialized.

A run validates both provenance and portable output before publication.
Two runs on the same runtime must produce byte-identical files. A different
platform's wheel has a different installed distribution digest; portable
chunk bytes are compared with `goldens.json`, while that run's independently
validated `provenance.json` is retained as its platform-specific receipt.

`SHA256SUMS` at this directory's root covers the frozen inputs, source
snapshots, notices and generated assets. It is separate from the root
`testdata/SHA256SUMS`, which only covers byte-exact upstream fixture trees.

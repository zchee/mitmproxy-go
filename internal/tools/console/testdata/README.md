# Console fixtures

`dumpfile-7-current.mitm` is the two-flow upstream console integration fixture,
transcoded without changing the migrated flow states by the pinned Python
FlowReader → FlowWriter (Python 3.13.14, mitmproxy 13.0.0.dev0).

- Source: `mitmproxy/mitmproxy` commit `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`,
  `test/mitmproxy/data/dumpfile-7.mitm`, Git blob
  `77243bfd9677f506d09892bf2c618d0825aa1eca`, format 11.
- Source SHA256: `1ac49aabb38255e2ea04b00bb71fecd89732220f754da4942204d4dd0ff9e55c`.
- Vendored SHA256: `327c45e457cb48e8c102a71b1bfc62706a761ddb902188e833f5117c647373b7`,
  12,492 bytes, format 21.
- Generator: Python FlowReader → FlowWriter at upstream commit
  `3368a0a06ae6195aad817a1ece1aaeb6fe0353a1`, using the versions stated above.
  A complete-state equality check verified the transcoded flows against the
  source flows. The digests above identify the source and vendored bytes.

The Go reader still supports formats 18–21; this fixture conversion does not add
legacy format-11 reader support. Upstream fixture licensing is recorded in the
repository's `testdata/UPSTREAM_LICENSE` notice.

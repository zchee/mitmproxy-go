#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["ruamel.yaml"]
# ///
"""Regenerate options/testdata/dump_defaults.yaml from upstream mitmproxy.

Usage: options/testdata/golden.py <mitmproxy checkout> <output dir>

The checkout must be at mitmproxy commit 3368a0a, the commit this port
follows. The script writes dump_defaults.yaml: the output of
optmanager.dump_defaults for the core options of mitmproxy's Options class,
the annotated YAML that "mitmdump --options" prints.
"""

import io
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])

from mitmproxy import options, optmanager  # noqa: E402

out = Path(sys.argv[2])
opts = options.Options()
buf = io.StringIO()
optmanager.dump_defaults(opts, buf)
(out / "dump_defaults.yaml").write_text(buf.getvalue())

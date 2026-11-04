#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7",
# ]
# ///
"""Print the installed mitmproxy version, then each argument on its own line."""

import sys

from mitmproxy.version import VERSION

print(VERSION)
for arg in sys.argv[1:]:
    print(arg)

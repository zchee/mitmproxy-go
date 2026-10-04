#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
# ]
# ///
"""Print the installed mitmproxy version, then each argument on its own line."""

import sys

from mitmproxy.version import VERSION

print(VERSION)
for arg in sys.argv[1:]:
    print(arg)

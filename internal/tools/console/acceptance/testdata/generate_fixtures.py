#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
# ]
# ///
"""Produce deterministic shared HTTP flow inputs for console frame checks."""

import hashlib
import sys
from pathlib import Path

import orjson
from mitmproxy import connection, flow, http, io


def main() -> None:
    """Write fixed flow states and their options/keystroke manifest.

    The sole command-line argument is an existing output directory. File write
    errors propagate to the caller; no live network or terminal is used.
    """
    output = Path(sys.argv[1])
    flows = []
    for index, path in enumerate(("/inspect", "/paused", "/unreachable"), 1):
        started = 946684800.0 + index
        item = http.HTTPFlow(
            connection.Client(
                id=f"10000000-0000-0000-0000-{index:012d}",
                peername=("127.0.0.1", 50100 + index),
                sockname=("127.0.0.1", 8080),
                timestamp_start=started,
            ),
            connection.Server(
                id=f"20000000-0000-0000-0000-{index:012d}",
                address=("example.com", 80),
            ),
        )
        item.id = f"00000000-0000-0000-0000-{index:012d}"
        item.timestamp_created = started
        item.request = http.Request.make(
            "POST" if index == 1 else "GET",
            f"http://example.com{path}",
            b"console request body\n" if index == 1 else b"",
            http.Headers(((b"host", b"example.com"), (b"content-type", b"text/plain"))),
        )
        item.request.timestamp_start = started
        item.request.timestamp_end = started + 0.025
        if index == 1:
            item.response = http.Response.make(
                200, b"console response body\n", {"content-type": "text/plain"}
            )
            item.response.timestamp_start = started + 0.1
            item.response.timestamp_end = started + 0.125
        elif index == 2:
            item.intercepted = True
        else:
            item.error = flow.Error("Connection refused", started + 0.125)
        flows.append(item)
    flow_path = output / "console.mitm"
    with flow_path.open("wb") as stream:
        writer = io.FlowWriter(stream)
        for item in flows:
            writer.add(item)
    with flow_path.open("rb") as stream:
        restored = list(io.FlowReader(stream).stream())
    assert [item.get_state() for item in restored] == [
        item.get_state() for item in flows
    ]
    manifest = {
        "format": "mitmproxy-flow-21",
        "provenance": "generated test input, not copied upstream fixture",
        "flow_sha256": hashlib.sha256(flow_path.read_bytes()).hexdigest(),
        "ids": [item.id for item in flows],
        "focus_index": 0,
        "timezone": "UTC",
        "options": [
            "console_default_contentview=raw",
            "console_palette=solarized_dark",
            "console_palette_transparent=true",
            "console_flowlist_layout=default",
            "console_layout=single",
            "console_layout_headers=true",
            "console_quickhelp_visible=true",
            "console_focus_follow=false",
            "listen_host=127.0.0.1",
            "listen_port=8080",
        ],
        "states": {
            "flowlist": "",
            "flowview": "<enter>",
            "commander": ":console.view.",
        },
        "golden_sizes": [[80, 24], [200, 50]],
        "live_python_size": [80, 24],
    }
    (output / "fixtures.json").write_bytes(
        orjson.dumps(manifest, option=orjson.OPT_INDENT_2) + b"\n"
    )


if __name__ == "__main__":
    main()

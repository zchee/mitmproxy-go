#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a",
#   "orjson",
# ]
# ///

"""Record which flows each filter expression selects in the pinned mitmproxy.

Collects the flows of every flow file fixture upstream can read, the flows
of mitmproxy.test.tflow.tflows(), and a few hand-made flows that exercise
operators the others do not reach. They are written to one flow file in
the current format and read back, so that both implementations evaluate
exactly what that file holds. For each expression the indexes of the
matching flows are printed as JSON.

Usage: match_oracle.py FIXTURE_DIR EXPRS_JSON OUT_FLOWS > results.json
"""

import gzip
import importlib
import os
import sys
from pathlib import Path

import orjson
from mitmproxy import (
    flowfilter,
    http,
    io,
)
from mitmproxy.flow import Flow
from mitmproxy.io import tnetstring
from mitmproxy.test import (
    tflow,
    tutils,
)

MIN_VERSION = 18


def fixture_flows(fixture_dir: Path) -> list[Flow]:
    """Return the flows of every flow file fixture in format 18 or later.

    mitmproxy-go reads formats 18 to 21 only. Older fixtures migrate in
    upstream, but leave str where the current model has bytes.
    """
    flows: list[Flow] = []
    paths = sorted(fixture_dir.glob("*.mitm")) + sorted(
        fixture_dir.glob("flows/*.mitm")
    )
    for path in paths:
        with path.open("rb") as f:
            version = tnetstring.load(f).get("version")
        if not isinstance(version, int) or version < MIN_VERSION:
            print(f"skipping {path.name}: format {version!r}", file=sys.stderr)
            continue
        with path.open("rb") as f:
            flows.extend(io.FlowReader(f).stream())
    return flows


def handmade_flows() -> list[Flow]:
    """Return flows that reach operators and corner cases the others miss."""
    trailing = tflow.tflow(
        req=tutils.treq(
            method=b"POST",
            headers=http.Headers(
                (
                    (b"Host", b"example.org:8443"),
                    (b"Content-Type", b"application/json\n"),
                )
            ),
            content=b"line one\ncontent\n",
        ),
        resp=tutils.tresp(
            headers=http.Headers(
                ((b"content-type", b"text/html\n"), (b"Server", b"test"))
            ),
            content=b"line one\nline two\n",
        ),
    )
    trailing.metadata.update(
        {
            "a": 1,
            "b": "string",
            "c": {"key": "value"},
            "d": b"by'tes",
            "e": [1, 2.5, None, True],
        }
    )
    trailing.marked = ":red:"
    trailing.comment = "needs\nreview"
    trailing.is_replay = "request"

    compressed = tflow.tflow(resp=True)
    compressed.request.headers["content-encoding"] = "gzip"
    compressed.request.raw_content = gzip.compress(b"compressed hello")
    compressed.response.headers["content-type"] = "image/png"
    compressed.is_replay = "response"
    compressed.marked = "X"

    broken = tflow.tflow()
    broken.request.headers["content-encoding"] = "gzip"
    broken.request.raw_content = b"not gzip hello"

    ipv6 = tflow.tflow(resp=tutils.tresp(status_code=404))
    ipv6.client_conn.peername = ("::1", 443)
    ipv6.server_conn.address = ("example.com", 443)

    # Method, host, path and marker ending in a newline, where only
    # Python's $ (and the rewritten one) matches "get$", "address$",
    # "path$" and "red:$".
    newline = tflow.tflow(
        req=tutils.treq(method=b"GET\n", host="address\n", path=b"/path\n")
    )
    newline.marked = ":red:\n"

    # Non-ASCII subjects for \d, \w, \s and \b, which are Unicode-aware
    # in the str patterns of ~u and ~comment and ASCII-only in the bytes
    # patterns of ~b and ~h: an Arabic-Indic digit, letters outside ASCII,
    # a fraction (a word character in Python, not in .NET), an em space
    # and the Kelvin sign.
    classes = tflow.tflow(
        req=tutils.treq(
            path="/caf\u00e9/\u0663/".encode(),
            headers=http.Headers(((b"X-Note", "caf\u00e9".encode()),)),
            content="n=\u0663; a\u2003b caf\u00e9x \u212aelvin".encode(),
        )
    )
    classes.comment = "caf\u00e9 \u00bd! \u00e9x a\u2003b \u0663"

    return [trailing, compressed, broken, ipv6, newline, classes]


def main() -> None:
    """Write the combined flow file and print the selections as JSON."""
    fixture_dir, exprs_path, out_path = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    exprs = orjson.loads(Path(exprs_path).read_bytes())
    # flowfilter reads the variable at import time.
    os.environ.pop("MITMPROXY_CASE_SENSITIVE_FILTERS", None)
    importlib.reload(flowfilter)

    flows = fixture_flows(fixture_dir) + tflow.tflows() + handmade_flows()
    with open(out_path, "wb") as f:
        writer = io.FlowWriter(f)
        for flw in flows:
            writer.add(flw)
    with open(out_path, "rb") as f:
        flows = list(io.FlowReader(f).stream())

    results = []
    for expr in exprs:
        flt = flowfilter.parse(expr)
        results.append([i for i, flw in enumerate(flows) if flt(flw)])
    out = {"flows": len(flows), "results": results}
    sys.stdout.buffer.write(orjson.dumps(out))
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()

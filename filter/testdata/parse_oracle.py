#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a",
#   "orjson",
# ]
# ///

"""Record how the pinned mitmproxy parses every expression in a corpus.

Reads a JSON array of filter expressions and writes, for each one, whether
mitmproxy.flowfilter.parse accepts it and, if so, the parsed tree, the
dump() output and str() with and without MITMPROXY_CASE_SENSITIVE_FILTERS=1.
The Go tests in the parent directory compare filter.Parse against it.

Usage: parse_oracle.py parse_corpus.json > parse_golden.json
"""

import importlib
import io
import os
import sys

import orjson

os.environ.pop("MITMPROXY_CASE_SENSITIVE_FILTERS", None)
from mitmproxy import flowfilter  # noqa: E402


def tree(flt: flowfilter.TFilter) -> list:
    """Return the filter as nested lists of class name and argument."""
    name = type(flt).__name__
    if isinstance(flt, (flowfilter.FAnd, flowfilter.FOr)):
        return [name, *(tree(x) for x in flt.lst)]
    if isinstance(flt, flowfilter.FNot):
        return [name, tree(flt.itm)]
    if isinstance(flt, flowfilter.FCode):
        return [name, str(flt.num)]
    if hasattr(flt, "expr"):
        return [name, flt.expr]
    return [name]


def record(expr: str) -> dict:
    """Parse expr with the case-insensitive default and describe the result."""
    try:
        flt = flowfilter.parse(expr)
    except ValueError:
        return {"expr": expr, "ok": False}
    dump = io.StringIO()
    flt.dump(fp=dump)
    return {
        "expr": expr,
        "ok": True,
        "tree": tree(flt),
        "describe": str(flt),
        "dump": dump.getvalue(),
    }


def main() -> None:
    """Write the golden records for the corpus named on the command line."""
    with open(sys.argv[1], "rb") as f:
        corpus = orjson.loads(f.read())
    records = [record(expr) for expr in corpus]

    os.environ["MITMPROXY_CASE_SENSITIVE_FILTERS"] = "1"
    importlib.reload(flowfilter)
    for rec in records:
        if rec["ok"]:
            rec["describe_case_sensitive"] = str(flowfilter.parse(rec["expr"]))

    help_table = [list(row) for row in flowfilter.help]
    sys.stdout.buffer.write(
        orjson.dumps({"help": help_table, "records": records}, option=orjson.OPT_INDENT_2)
    )
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()

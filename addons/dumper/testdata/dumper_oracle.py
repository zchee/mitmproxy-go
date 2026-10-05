#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
# ]
# ///

"""Render recorded flows through the pinned Python dumper with nonterminal output.

The positional directory contains flow fixtures. Each file is loaded anew for
all five detail levels, because eventsequence mutates message lists. JSON output
contains the rendered text and the automatic content views used by that file.
"""

import io
import sys
from pathlib import Path
from types import SimpleNamespace

import orjson
from mitmproxy import contentviews, ctx, eventsequence, http, options, tcp, udp
from mitmproxy import io as flow_io
from mitmproxy.addons.dumper import Dumper


def render(path: Path, detail: int) -> dict[str, object]:
    """Return uncoloured output and selected views for a file and detail level.

    Args:
        path: Mitmproxy flow file to read.
        detail: Upstream flow_detail option value.

    Returns:
        The rendered text and sorted content view names.

    Raises:
        OSError: If the input file cannot be read.
    """
    output = io.StringIO()
    addon = Dumper(output)
    opts = options.Options()
    addon.load(SimpleNamespace(add_option=opts.add_option))
    opts.update(flow_detail=detail)
    ctx.options = opts
    views: set[str] = set()
    with path.open("rb") as source:
        for flow in flow_io.FlowReader(source).stream():
            messages = []
            if isinstance(flow, http.HTTPFlow):
                messages.extend(m for m in (flow.request, flow.response) if m is not None)
                if flow.websocket:
                    messages.extend(flow.websocket.messages)
            elif isinstance(flow, (tcp.TCPFlow, udp.UDPFlow)):
                messages.extend(flow.messages)
            for message in messages:
                pretty = contentviews.prettify_message(message, flow, "auto")
                if pretty.view_name:
                    views.add(pretty.view_name)
            for hook in eventsequence.iterate(flow):
                handler = getattr(addon, hook.name, None)
                if handler:
                    try:
                        handler(*hook.args())
                    except UnicodeEncodeError as error:
                        name = type(error).__name__
                        return {"error": f"{name}: {error}", "views": sorted(views)}
    return {"text": output.getvalue(), "views": sorted(views)}


if __name__ == "__main__":
    results = {
        f"{path.name}/{detail}": render(path, detail)
        for path in sorted(Path(sys.argv[1]).glob("*.mitm"))
        for detail in range(5)
    }
    sys.stdout.buffer.write(orjson.dumps(results))

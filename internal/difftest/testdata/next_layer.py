#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
# ]
# ///
"""Run the pinned proxy and report next_layer calls for one client connection."""

import sys
from pathlib import Path

from mitmproxy import connection, ctx
from mitmproxy.proxy.layer import NextLayer
from mitmproxy.tools.main import mitmdump


class Counter:
    """Count layer-selection hooks separately for each client connection."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def running(self) -> None:
        """Publish the bound port without making a probe connection."""
        server = ctx.master.addons.get("proxyserver")
        if server is None:
            raise RuntimeError("mitmdump did not load its proxyserver addon")
        print(f"READY {server.listen_addrs()[0][1]}", flush=True)

    def next_layer(self, data: NextLayer) -> None:
        """Record one invocation for the hook's client."""
        client_id = data.context.client.id
        self.counts[client_id] = self.counts.get(client_id, 0) + 1

    def client_disconnected(self, client: connection.Client) -> None:
        """Publish the final count only after the scripted connection closes."""
        print(f"COUNT {self.counts.pop(client.id, 0)}", flush=True)
        ctx.master.shutdown()


addons = [Counter()]

if __name__ == "__main__":
    mode, port, origin, confdir, trusted_ca = sys.argv[1:]
    if mode.startswith("reverse:"):
        mode += f"://{origin}"
    mitmdump(
        [
            "--quiet",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            port,
            "--mode",
            mode,
            "--set",
            f"confdir={confdir}",
            "--set",
            f"ssl_verify_upstream_trusted_ca={trusted_ca}",
            "--set",
            "http2=false",
            "-s",
            str(Path(__file__).resolve()),
        ]
    )

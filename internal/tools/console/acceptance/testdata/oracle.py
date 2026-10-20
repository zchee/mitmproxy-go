#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
# ]
# ///
"""Render a shared flow fixture with the pinned upstream console.

The isolated master and fixed-size renderer follow the byte-exact upstream
conftest.py reference. Its MIT notice is retained in testdata/UPSTREAM_LICENSE.
The process emits one JSON object; the frame is not whitespace-normalized.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import orjson
import urwid
from mitmproxy import io, options
from mitmproxy.tools.console import signals, window
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.utils.signals import _SignalMixin

PINNED_COMMIT = "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"
REFERENCE_SHA256 = "b000690b8b084fa6c7f7e5dede9cce4400424154bc824aa0d3a2e33e7409a123"


class ConsoleTestMaster(ConsoleMaster):
    """Provide the upstream fixture's terminal-free console renderer."""

    def __init__(self, opts: options.Options) -> None:
        """Initialize from isolated options without the TLS configuration addon."""
        super().__init__(opts)
        self.addons.remove(self.addons.get("tlsconfig"))

    def type(self, text: str) -> None:
        """Inject characters and bracket-delimited upstream key names."""
        assert self.window is not None
        for index, part in enumerate(re.split("[<>]", text)):
            keys = [part] if index % 2 else list(part)
            for key in keys:
                self.window.keypress(self.ui.get_cols_rows(), key)

    def screen_contents(self) -> str:
        """Return the exact 80 by 24 cell frame from the upstream renderer."""
        assert self.window is not None
        return b"\n".join(self.window.render((80, 24), True).text).decode()


async def render(args: argparse.Namespace) -> bytes:
    """Render a flow file and return its frame plus runtime provenance as JSON.

    Args:
        args: Flow file, keystrokes, option strings and isolated working paths.

    Returns:
        UTF-8 JSON preserving the frame's complete decoded cell text.

    Raises:
        ValueError: If the source pin, reference digest or options are invalid.
        OSError: If an explicit input or working path cannot be accessed.
    """
    distribution = importlib.metadata.distribution("mitmproxy")
    direct_url_text = distribution.read_text("direct_url.json")
    if direct_url_text is None:
        raise ValueError("mitmproxy installation has no source provenance")
    provenance = orjson.loads(direct_url_text)
    if provenance.get("vcs_info", {}).get("commit_id") != PINNED_COMMIT:
        raise ValueError("mitmproxy installation does not match the pinned commit")
    reference_hash = hashlib.sha256(args.reference.read_bytes()).hexdigest()
    if reference_hash != REFERENCE_SHA256:
        raise ValueError("upstream console fixture reference digest differs")
    for value in args.settings:
        if value.partition("=")[0] in {"confdir", "server", "console_mouse"}:
            raise ValueError("fixture cannot override isolated console options")
    for signal in vars(signals).values():
        if isinstance(signal, _SignalMixin):
            signal.receivers.clear()
    with (
        tempfile.TemporaryDirectory(
            prefix="console-oracle-", dir=args.work_dir
        ) as confdir,
        patch.object(window.Screen, "start", lambda *_: True),
        patch.object(ConsoleTestMaster, "sig_call_in", lambda *args, **kwargs: True),
        patch.object(sys.stdout, "isatty", lambda: True),
    ):
        opts = options.Options(confdir=confdir, server=False)
        master = ConsoleTestMaster(opts)
        opts.console_mouse = False
        opts.set(*args.settings)
        await master.running()
        try:
            with args.flows.open("rb") as stream:
                flows = list(io.FlowReader(stream).stream())
            master.view.add(flows)
            master.type(args.keys)
            frame = master.screen_contents()
            assert master.window is not None
            canvas = master.window.render((80, 24), True)
            if canvas.cols() != 80 or canvas.rows() != 24:
                raise ValueError("upstream renderer returned unexpected dimensions")
            return orjson.dumps(
                {
                    "frame": frame,
                    "width": 80,
                    "height": 24,
                    "upstream_commit": PINNED_COMMIT,
                    "reference_sha256": reference_hash,
                    "adapter_sha256": hashlib.sha256(
                        Path(__file__).read_bytes()
                    ).hexdigest(),
                    "python": sys.version,
                    "urwid": urwid.__version__,
                    "mitmproxy": distribution.version,
                    "flow_count": len(flows),
                }
            )
        finally:
            await master.done()


def main() -> None:
    """Parse test-owned inputs and write one exact-frame JSON result to stdout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--keys", default="")
    parser.add_argument("--set", dest="settings", action="append", default=[])
    args = parser.parse_args()
    sys.stdout.buffer.write(asyncio.run(render(args)))
    sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()

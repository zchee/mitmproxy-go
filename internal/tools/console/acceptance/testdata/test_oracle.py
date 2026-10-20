#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
#   "pytest",
# ]
# ///
"""Exercise the live console oracle as a real subprocess."""

import os
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

ROOT = Path(__file__).resolve().parents[5]
ORACLE = Path(__file__).with_name("oracle.py")
REFERENCE = ROOT / "testdata/mitmproxy/tools/console/conftest.py"
FLOWS = ROOT / "testdata/mitmproxy/flows/successful_log.mitm"


@pytest.mark.parametrize(
    "keys,expected",
    [("", "Flows"), ("<enter>", "Flow Details"), (":console.view.", "console.view.")],
)
def test_render(tmp_path: Path, keys: str, expected: str) -> None:
    """Render source flow data in each required view without a terminal or proxy."""
    result = subprocess.run(
        [
            sys.executable,
            str(ORACLE),
            "--flows",
            str(FLOWS),
            "--reference",
            str(REFERENCE),
            "--work-dir",
            str(tmp_path),
            "--keys",
            keys,
        ],
        check=True,
        capture_output=True,
        env={**os.environ, "TZ": "UTC"},
        timeout=30,
    )
    frame = orjson.loads(result.stdout)
    assert frame["width"] == 80 and frame["height"] == 24
    assert len(frame["frame"].split("\n")) == 24
    assert expected in frame["frame"]
    assert frame["upstream_commit"] == "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"
    assert frame["flow_count"] > 0
    (tmp_path / "result.json").write_bytes(result.stdout)


def test_isolation_refusal(tmp_path: Path) -> None:
    """Reject options that could re-enable a server or read a host confdir."""
    result = subprocess.run(
        [
            sys.executable,
            str(ORACLE),
            "--flows",
            str(FLOWS),
            "--reference",
            str(REFERENCE),
            "--work-dir",
            str(tmp_path),
            "--set",
            "server=true",
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert b"fixture cannot override isolated console options" in result.stderr
    assert result.stdout == b""


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))

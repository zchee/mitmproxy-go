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

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import orjson
import pytest

ROOT = Path(__file__).resolve().parents[5]
ORACLE = Path(__file__).with_name("oracle.py")
REFERENCE = ROOT / "testdata/mitmproxy/tools/console/conftest.py"
FLOWS = Path(__file__).with_name("console.mitm")
FIXTURES = orjson.loads(Path(__file__).with_name("fixtures.json").read_bytes())


@pytest.mark.parametrize(
    "name,expected",
    [
        ("flowlist", "Flows"),
        ("flowview", "Flow Details"),
        ("commander", ": console.view.flow flow "),
    ],
)
def test_render(tmp_path: Path, name: str, expected: str) -> None:
    """Render source flow data in each required view without a terminal or proxy."""
    assert hashlib.sha256(FLOWS.read_bytes()).hexdigest() == FIXTURES["flow_sha256"]
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
            FIXTURES["states"][name],
            *[
                argument
                for value in FIXTURES["options"]
                for argument in ("--set", value)
            ],
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
    assert frame["flow_count"] == len(FIXTURES["ids"])
    (tmp_path / "result.json").write_bytes(result.stdout)


def test_fixture_generation(tmp_path: Path) -> None:
    """Regenerate identical flow bytes and state settings without live I/O."""
    subprocess.run(
        [sys.executable, str(ORACLE.with_name("generate_fixtures.py")), str(tmp_path)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    assert (tmp_path / "console.mitm").read_bytes() == FLOWS.read_bytes()
    assert orjson.loads((tmp_path / "fixtures.json").read_bytes()) == FIXTURES


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

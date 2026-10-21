#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
#   "pytest",
# ]
# ///
"""Verify console capture helpers with owned real files, pipes and HTTP requests."""

import argparse
import http.client as httpclient
import os
import pty
import shutil
import subprocess
import sys
import termios
from pathlib import Path

import orjson
import pytest
import qa_capture


@pytest.mark.parametrize(
    "screen,port,count",
    [
        ("proxy [127.0.0.1:4321] [1/10000]", 4321, 10000),
        ("header: value\n[0/0]", None, 0),
        ("not ready", None, None),
    ],
)
def test_screen_fields(screen: str, port: int | None, count: int | None) -> None:
    """Parse actual address/counter shapes without accepting missing fields."""
    assert qa_capture._proxy_address(screen) == port
    assert qa_capture._count(screen) == count


@pytest.mark.parametrize(
    "screen,expected",
    [
        ("Flows\n:\n", True),
        (": \n", True),
        (": set intercept /owned\n", True),
        ("Host: example.com\n", False),
    ],
)
def test_prompt_readiness(screen: str, expected: bool) -> None:
    """Recognize tmux-trimmed empty prompts without accepting body/header colons."""
    assert qa_capture._prompt_ready(screen) is expected


def test_exclusive_output(tmp_path: Path) -> None:
    """Retain prior evidence rather than replacing a capture accidentally."""
    output = tmp_path / "record.txt"
    qa_capture._write(output, b"first")
    with pytest.raises(FileExistsError):
        qa_capture._write(output, b"second")
    assert output.read_bytes() == b"first"
    assert output.stat().st_mode & 0o777 == 0o600
    qa_capture._append(tmp_path / "events.jsonl", {"event": "one"})
    qa_capture._append(tmp_path / "events.jsonl", {"event": "two"})
    assert [
        orjson.loads(row)
        for row in (tmp_path / "events.jsonl").read_bytes().splitlines()
    ] == [{"event": "one"}, {"event": "two"}]


def test_coalesced_notification() -> None:
    """A full real nonblocking pipe keeps its pending notification without failing."""
    read, write = os.pipe()
    os.set_blocking(write, False)
    try:
        while True:
            try:
                os.write(write, b"x" * 4096)
            except BlockingIOError:
                break
        qa_capture._notify(write)
        assert os.read(read, 1) == b"x"
    finally:
        os.close(read)
        os.close(write)


def test_real_origin(tmp_path: Path) -> None:
    """Join an actual loopback server and preserve nonce-scoped edited headers."""
    read, write = os.pipe()
    origin = qa_capture._Origin(tmp_path, "owned-fixture", write)
    connection = httpclient.HTTPConnection(
        "127.0.0.1", origin.server.server_port, timeout=5
    )
    try:
        connection.request(
            "GET", "/owned-fixture/initial", headers={"X-QA-Edited": "accepted"}
        )
        response = connection.getresponse()
        assert response.status == 200
        assert response.read() == b"owned console QA origin\n"
        assert os.read(read, 1) == b"\0"
        expected = [
            {"method": "GET", "path": "/owned-fixture/initial", "edited": "accepted"}
        ]
        assert origin.snapshot() == expected
        changed = origin.snapshot()
        changed[0]["edited"] = "detached"
        assert origin.snapshot() == expected
        connection.request("GET", "/unowned/initial")
        response = connection.getresponse()
        assert response.status == 404
        response.read()
        assert origin.snapshot() == expected
    finally:
        connection.close()
        origin.close()
        os.close(read)
        os.close(write)
    assert not origin.thread.is_alive()


def test_prototype_refuses_ci(tmp_path: Path) -> None:
    """Reject a prototype before starting a process or making a QA claim in CI."""
    output = tmp_path / "never-created"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("qa_capture.py")),
            "capture",
            "--prototype",
            "--binary",
            "/unused",
            "--tmux",
            "/unused",
            "--out",
            str(output),
            "--work-dir",
            str(tmp_path),
        ],
        env={**os.environ, "CI": "true"},
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode != 0
    assert b"prototype mode is forbidden in hosted CI" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("wrong_checkout", [True, False])
def test_carrier_refuses_unattested_binary(
    tmp_path: Path, wrong_checkout: bool
) -> None:
    """Refuse a mismatched checkout or real Go executable with no matching VCS stamp."""
    binary = shutil.which("go")
    assert binary is not None
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    output = tmp_path / "never-created"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("qa_capture.py")),
            "capture",
            "--expected-sha",
            "0" * 40 if wrong_checkout else checkout,
            "--binary",
            binary,
            "--tmux",
            "/unused",
            "--out",
            str(output),
            "--work-dir",
            str(tmp_path),
        ],
        env={**os.environ, "CI": "true"},
        capture_output=True,
        check=False,
        timeout=15,
    )
    assert result.returncode != 0
    expected = (
        b"carrier checkout does not match"
        if wrong_checkout
        else b"carrier binary revision or clean-source metadata differs"
    )
    assert expected in result.stderr
    assert not output.exists()


def test_capture_requires_scope(tmp_path: Path) -> None:
    """Refuse a real capture subprocess that omits both explicit scope flags."""
    output = tmp_path / "never-created"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("qa_capture.py")),
            "capture",
            "--binary",
            "/unused",
            "--tmux",
            "/unused",
            "--out",
            str(output),
            "--work-dir",
            str(tmp_path),
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 2
    assert (
        b"one of the arguments --prototype --expected-sha is required" in result.stderr
    )
    assert not output.exists()


def test_persistent_terminal_modes() -> None:
    """Ignore only Darwin pending-input state while retaining every actual mode field."""
    before: qa_capture._TerminalModes = {
        "c_iflag": 0x6B02,
        "c_oflag": 3,
        "c_cflag": 0x4B00,
        "c_lflag": 0x5CB,
        "input_speed": 9600,
        "output_speed": 9600,
        "c_cc": [4, 255, 127],
    }
    tests: dict[str, tuple[qa_capture._TerminalModes, str, bool]] = {
        "unchanged": (before.copy(), "darwin", True),
        "Darwin pending input only": (
            {**before, "c_lflag": 0x200005CB},
            "darwin",
            True,
        ),
        "Linux masks nothing": ({**before, "c_lflag": 0x200005CB}, "linux", False),
        "persistent local mode": ({**before, "c_lflag": 0x200004CB}, "darwin", False),
        "input mode": ({**before, "c_iflag": 0}, "darwin", False),
        "output mode": ({**before, "c_oflag": 0}, "darwin", False),
        "control mode": ({**before, "c_cflag": 0}, "darwin", False),
        "control bytes": ({**before, "c_cc": [4, 255, 126]}, "darwin", False),
    }
    for name, (after, platform, expected) in tests.items():
        result = qa_capture._restoration(before, after, platform)
        assert result["restored"] is expected, name
        assert result["modes_before"] == before and result["modes_after"] == after, name
    pending = qa_capture._restoration(
        before, {**before, "c_lflag": 0x200005CB}, "darwin"
    )
    assert pending["raw_lflag_delta"] == 0x20000000
    assert pending["masked_lflag_delta"] == 0


def test_real_pty_mode_change() -> None:
    """Read a real owned PTY and reject a persistent canonical-mode change."""
    master, slave = pty.openpty()
    try:
        before = qa_capture._terminal_modes(slave)
        values = termios.tcgetattr(slave)
        values[3] ^= termios.ICANON
        termios.tcsetattr(slave, termios.TCSANOW, values)
        after = qa_capture._terminal_modes(slave)
        assert before["c_cc"] and before["c_cc"] == after["c_cc"]
        assert qa_capture._restoration(before, after, sys.platform)["restored"] is False
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize(
    "screen,expected",
    [
        ("Flows\nQuit\n> Yes\n", True),
        ("Quit tab\n", False),
        ("message: Quit\n", False),
        ("\n", False),
    ],
)
def test_quit_prompt_readiness(screen: str, expected: bool) -> None:
    """Require the actual anchored quit title before confirming a signal prompt."""
    assert qa_capture._quit_prompt_ready(screen) is expected


def test_real_sigint_confirmation(tmp_path: Path) -> None:
    """Run the real CLI in tmux and confirm its SIGINT prompt before checking cleanup."""
    tmux = shutil.which("tmux")
    assert tmux is not None
    binary = tmp_path / "mitmproxy"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/mitmproxy"], check=True, timeout=180
    )
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    args = argparse.Namespace(
        binary=binary, tmux=Path(tmux), out=tmp_path, prototype=False, expected_sha=None
    )
    terminal = qa_capture._Terminal(args, "signal", work)
    try:
        terminal._wait(
            "ready", lambda text: qa_capture._proxy_address(text) is not None
        )
        terminal.signal()
        terminal._wait("quit-prompt", qa_capture._quit_prompt_ready)
        terminal._tmux("send-keys", "-t", terminal.target, "y")
        terminal.exited("restored")
    finally:
        terminal.close()
    result = orjson.loads((tmp_path / "signal/exit.json").read_bytes())
    assert result["returncode"] == 0 and result["restored"] and result["child_reaped"]
    assert (tmp_path / "signal/transcript.ansi").stat().st_size > 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, *sys.argv[1:]]))

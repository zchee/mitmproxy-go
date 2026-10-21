#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13,<3.14"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
# ]
# ///
"""Exercise an owned real console/tmux session against a loopback HTTP origin."""

import argparse
import hashlib
import http.client as httpclient
import logging
import os
import re
import secrets
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import TypedDict

import orjson
from mitmproxy import http, io

ROOT = Path.cwd().resolve()
LOGGER = logging.getLogger(__name__)


def _date() -> str:
    return subprocess.check_output(
        ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], text=True
    ).strip()


def _append(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "ab") as stream:
        stream.write(orjson.dumps(value) + b"\n")


def _write(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _notify(descriptor: int) -> None:
    try:
        os.write(descriptor, b"\0")
    except BlockingIOError:
        LOGGER.debug("coalesced owned terminal notification")


class _TerminalModes(TypedDict):
    c_iflag: int
    c_oflag: int
    c_cflag: int
    c_lflag: int
    input_speed: int
    output_speed: int
    c_cc: list[int]


def _terminal_modes(descriptor: int) -> _TerminalModes:
    values = termios.tcgetattr(descriptor)
    return {
        "c_iflag": values[0],
        "c_oflag": values[1],
        "c_cflag": values[2],
        "c_lflag": values[3],
        "input_speed": values[4],
        "output_speed": values[5],
        "c_cc": [
            value[0] if isinstance(value, bytes) else value for value in values[6]
        ],
    }


def _restoration(
    before: _TerminalModes, after: _TerminalModes, platform: str
) -> dict[str, object]:
    # Darwin PENDIN describes pending input state, not a persistent terminal mode.
    mask = 0x20000000 if platform == "darwin" else 0
    left = {**before, "c_lflag": before["c_lflag"] & ~mask}
    right = {**after, "c_lflag": after["c_lflag"] & ~mask}
    return {
        "restored": left == right,
        "modes_before": before,
        "modes_after": after,
        "pending_input_state_mask": mask,
        "raw_lflag_delta": before["c_lflag"] ^ after["c_lflag"],
        "masked_lflag_delta": (before["c_lflag"] ^ after["c_lflag"]) & ~mask,
    }


def _proxy_address(screen: str) -> int | None:
    match = re.search(r"\[127\.0\.0\.1:([1-9][0-9]*)\]", screen)
    return int(match[1]) if match else None


def _prompt_ready(screen: str) -> bool:
    return any(row == ":" or row.startswith(": ") for row in screen.splitlines())


def _quit_prompt_ready(screen: str) -> bool:
    return any(row == "Quit" for row in screen.splitlines())


def _count(screen: str) -> int | None:
    match = re.search(r"\[[0-9]+/([0-9]+)\]", screen)
    return int(match[1]) if match else None


class _Origin:
    def __init__(self, out: Path, nonce: str, wake: int) -> None:
        self.records: list[dict[str, str]] = []
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                """Serve only nonce-scoped fixture requests and retain their edit."""
                if not self.path.startswith(f"/{nonce}/"):
                    self.send_error(404)
                    return
                record = {
                    "method": self.command,
                    "path": self.path,
                    "edited": self.headers.get("X-QA-Edited", ""),
                }
                with owner.lock:
                    owner.records.append(record)
                    _append(out / "origin.jsonl", record)
                _notify(wake)
                body = b"owned console QA origin\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                """Keep generic protocol logs out of the synthetic request receipt."""
                LOGGER.debug("owned origin protocol event")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        self.server.block_on_close = True
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def snapshot(self) -> list[dict[str, str]]:
        """Return owned copies of all observed fixture requests."""
        with self.lock:
            return [record.copy() for record in self.records]

    def close(self) -> None:
        """Stop and join every owned HTTP request/server thread."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("owned origin thread survived shutdown")


class _Terminal:
    def __init__(self, args: argparse.Namespace, label: str, work: Path) -> None:
        self.args = args
        self.scope = "prototype" if args.prototype else "carrier-preflight"
        self.out = Path(args.out) / label
        self.out.mkdir(mode=0o700)
        self.socket = "console-qa-" + secrets.token_hex(8)
        self.target = "qa:0.0"
        self.selector = selectors.DefaultSelector()
        self.fifo = self.out / "events.fifo"
        os.mkfifo(self.fifo, 0o600)
        self.events = os.open(self.fifo, os.O_RDWR | os.O_NONBLOCK)
        self.selector.register(self.events, selectors.EVENT_READ)
        os.mkfifo(self.out / "control.fifo", 0o600)
        launch = [
            sys.executable,
            str(Path(__file__).resolve()),
            "launch",
            "--binary",
            str(args.binary),
            "--tmux",
            str(args.tmux),
            "--out",
            str(self.out),
            "--socket",
            self.socket,
            "--work-dir",
            str(work),
        ]
        self._tmux(
            "-f",
            "/dev/null",
            "new-session",
            "-d",
            "-x",
            "80",
            "-y",
            "24",
            "-c",
            str(ROOT),
            "-s",
            "qa",
            shlex.join(launch),
        )
        self._tmux("set-window-option", "-t", "qa:0", "remain-on-exit", "on")
        _write(self.out / "transcript.ansi", b"")
        quoted = shlex.quote(str(self.fifo)).replace("#", "##")
        transcript = shlex.quote(str(self.out / "transcript.ansi")).replace("#", "##")
        self._tmux(
            "pipe-pane",
            "-O",
            "-t",
            self.target,
            "exec tee -a " + transcript + " >> " + quoted,
        )
        self._tmux("wait-for", "-S", "launch")
        _write(self.out / "tmux.version", self._tmux("-V").encode())

    def _tmux(self, *arguments: str) -> str:
        command = [str(self.args.tmux), "-L", self.socket, *arguments]
        _append(self.out / "commands.jsonl", {"date": _date(), "argv": command})
        return subprocess.check_output(
            command, text=True, cwd=ROOT, stderr=subprocess.STDOUT
        )

    def _screen(self, label: str) -> str:
        plain = self._tmux("capture-pane", "-p", "-t", self.target)
        ansi = self._tmux("capture-pane", "-p", "-e", "-t", self.target)
        _write(self.out / f"{label}.txt", plain.encode())
        _write(self.out / f"{label}.ansi", ansi.encode())
        metadata = self._tmux(
            "display-message",
            "-p",
            "-t",
            self.target,
            "socket=#{socket_path};pid=#{pane_pid};size=#{pane_width}x#{pane_height};"
            "dead=#{pane_dead};cursor=#{cursor_flag},#{cursor_x},#{cursor_y}",
        )
        metadata = "scope=" + self.scope + ";final_qa=false;" + metadata
        _write(self.out / f"{label}.metadata", metadata.encode())
        return plain

    def _wait(self, label: str, ready: Callable[[str], bool]) -> str:
        deadline = time.monotonic() + 20
        while True:
            plain = self._tmux("capture-pane", "-p", "-t", self.target)
            if ready(plain):
                return self._screen(label)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                self._screen(label + "-failure")
                raise TimeoutError(f"owned console did not reach {label}")
            os.read(self.events, 65536)

    def key(self, label: str, key: str, ready: Callable[[str], bool]) -> str:
        """Capture a real key action and wait on terminal output, not sleeps."""
        self._screen(label + "-before")
        self._tmux("send-keys", "-t", self.target, key)
        return self._wait(label + "-after", ready)

    def command(self, label: str, line: str, ready: Callable[[str], bool]) -> str:
        """Run one typed command through the real console command prompt."""
        self.key(
            label + "-prompt",
            ":",
            _prompt_ready,
        )
        self._tmux("send-keys", "-t", self.target, "-l", "--", line)
        self._wait(
            label + "-typed",
            lambda screen: any(
                row.startswith(": " + line[:16]) for row in screen.splitlines()
            ),
        )
        return self.key(label + "-submit", "Enter", ready)

    def request(self, port: int, url: str, nonce: str) -> bytes:
        """Send a real absolute-URI proxy request without ambient proxy bypass."""
        connection = httpclient.HTTPConnection("127.0.0.1", port, timeout=30)
        try:
            connection.request(
                "GET", url, headers={"X-QA": nonce, "Connection": "close"}
            )
            response = connection.getresponse()
            body = response.read()
            if response.status != 200 or body != b"owned console QA origin\n":
                raise RuntimeError(f"real origin response differs: {response.status}")
            return body
        finally:
            connection.close()

    def signal(self) -> None:
        """Ask the owned launcher to signal its own unreaped child with SIGINT."""
        descriptor = os.open(self.out / "control.fifo", os.O_WRONLY | os.O_NONBLOCK)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(b"INT\n")

    def exited(self, label: str) -> None:
        """Require a reaped clean child and exact terminal-mode restoration."""
        self._wait(label, lambda _: (self.out / "exit.json").is_file())
        result = orjson.loads((self.out / "exit.json").read_bytes())
        if result["returncode"] != 0 or not result["restored"]:
            raise RuntimeError(f"console exit/restoration differs: {result}")

    def close(self, producer: threading.Thread | None = None) -> None:
        """Reap the owned console before stopping its server and descriptors.

        Args:
            producer: Owned proxy-request thread, if one was started.

        Raises:
            TimeoutError: If the launcher does not acknowledge child cleanup.
            RuntimeError: If the owned request thread does not join.
        """
        try:
            if not (self.out / "exit.json").is_file():
                descriptor = os.open(
                    self.out / "control.fifo", os.O_WRONLY | os.O_NONBLOCK
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(b"TERM\n")
                self._wait(
                    "cleanup-reaped", lambda _: (self.out / "exit.json").is_file()
                )
        finally:
            try:
                if producer is not None:
                    producer.join(timeout=35)
                    if producer.is_alive():
                        raise RuntimeError(
                            "owned request thread survived console cleanup"
                        )
            finally:
                try:
                    self._tmux("kill-server")
                except subprocess.CalledProcessError:
                    LOGGER.debug("owned tmux server had already exited")
                self.selector.close()
                os.close(self.events)


def _child_changed(_number: int, _frame: FrameType | None) -> None:
    return


def _launch(args: argparse.Namespace) -> None:
    out = Path(args.out)
    subprocess.run(
        [str(args.tmux), "-L", args.socket, "wait-for", "launch"], check=True
    )
    work = Path(args.work_dir)
    home, confdir = work / "home", work / "confdir"
    home.mkdir(mode=0o700)
    confdir.mkdir(mode=0o700)
    env = {
        **os.environ,
        "HOME": str(home),
        "TERM": "xterm-256color",
        "TZ": "UTC",
        "LANG": "C.UTF-8",
    }
    command = [
        str(args.binary),
        "--mode",
        "regular@127.0.0.1:0",
        "--set",
        "confdir=" + str(confdir),
        "--set",
        "console_mouse=false",
    ]
    before = subprocess.check_output(["stty", "-g"])
    before_modes = _terminal_modes(sys.stdin.fileno())
    _write(out / "stty-before.txt", before)
    _append(
        out / "launcher.jsonl", {"date": _date(), "argv": command, "TERM": env["TERM"]}
    )
    control = os.open(out / "control.fifo", os.O_RDWR | os.O_NONBLOCK)
    wake_read, wake_write = os.pipe()
    os.set_blocking(wake_read, False)
    os.set_blocking(wake_write, False)
    old_handler = signal.signal(signal.SIGCHLD, _child_changed)
    old_wakeup = signal.set_wakeup_fd(wake_write)
    selector = selectors.DefaultSelector()
    selector.register(control, selectors.EVENT_READ)
    selector.register(wake_read, selectors.EVENT_READ)
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(command, env=env, cwd=ROOT)
        deadline = time.monotonic() + 180
        while child.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("owned console exceeded QA watchdog")
            for event, _ in selector.select(remaining):
                data = os.read(event.fd, 65536)
                if event.fd == control:
                    for message in data.splitlines():
                        if message == b"INT":
                            child.send_signal(signal.SIGINT)
                        elif message == b"TERM":
                            child.terminate()
                        else:
                            raise ValueError("invalid owned launcher control message")
        child.wait()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        signal.set_wakeup_fd(old_wakeup)
        signal.signal(signal.SIGCHLD, old_handler)
        selector.close()
        for descriptor in (control, wake_read, wake_write):
            os.close(descriptor)
        after = subprocess.check_output(["stty", "-g"])
        _write(out / "stty-after.txt", after)
        _write(
            out / "exit.json",
            orjson.dumps(
                {
                    "date": _date(),
                    "returncode": child.returncode if child else None,
                    "pid": child.pid if child else None,
                    **_restoration(
                        before_modes, _terminal_modes(sys.stdin.fileno()), sys.platform
                    ),
                    "child_reaped": child is not None and child.returncode is not None,
                }
            ),
        )
        sys.stdout.write("\nCONSOLE_QA_EXIT\n")
        sys.stdout.flush()


def _capture(args: argparse.Namespace) -> None:
    if args.prototype and os.environ.get("CI"):
        raise ValueError("prototype mode is forbidden in hosted CI")
    checkout = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if args.expected_sha and (
        not re.fullmatch(r"[0-9a-f]{40}", args.expected_sha)
        or checkout != args.expected_sha
    ):
        raise ValueError("carrier checkout does not match the expected commit")
    build = subprocess.check_output(["go", "version", "-m", str(args.binary)], cwd=ROOT)
    if args.expected_sha:
        settings: dict[str, str] = {}
        for line in build.decode().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == "build":
                key, separator, value = fields[1].partition("=")
                if separator:
                    settings[key] = value
        if (
            settings.get("vcs.revision") != args.expected_sha
            or settings.get("vcs.modified") != "false"
        ):
            raise ValueError("carrier binary revision or clean-source metadata differs")
    out = Path(args.out)
    out.mkdir(mode=0o700)
    work_parent = Path(args.work_dir)
    work_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if work_parent.stat().st_uid != os.getuid() or work_parent.stat().st_mode & 0o077:
        raise ValueError("QA working directory must be owned and private")
    work = Path(tempfile.mkdtemp(prefix="console-qa-", dir=work_parent))
    _write(out / "binary-build-info.txt", build)
    _write(out / "source.txt", (checkout + "\n").encode())
    _write(
        out / "binary.sha256",
        (hashlib.sha256(Path(args.binary).read_bytes()).hexdigest() + "\n").encode(),
    )
    terminal = _Terminal(args, "quit", work)
    origin: _Origin | None = None
    producer: threading.Thread | None = None
    try:
        nonce = secrets.token_hex(8)
        origin = _Origin(out, nonce, terminal.events)
        screen = terminal._wait("ready", lambda text: _proxy_address(text) is not None)
        port = _proxy_address(screen)
        if port is None:
            raise RuntimeError("owned proxy listener absent")
        initial = f"/{nonce}/initial"
        url = f"http://127.0.0.1:{origin.server.server_port}{initial}"
        terminal.command(
            "intercept-set", "set intercept " + initial, lambda text: "[i:" in text
        )
        result: list[bytes | Exception] = []

        def request() -> None:
            try:
                result.append(terminal.request(port, url, nonce))
            except (OSError, httpclient.HTTPException, RuntimeError) as error:
                result.append(error)
            finally:
                _notify(terminal.events)

        producer = threading.Thread(target=request)
        producer.start()
        terminal._wait(
            "intercepted", lambda text: initial in text and _count(text) == 1
        )
        if origin.snapshot():
            raise RuntimeError("intercepted request reached origin before resume")
        terminal.command(
            "intercept-clear", "set intercept ''", lambda text: "[i:" not in text
        )
        if origin.snapshot():
            raise RuntimeError("clearing intercept unexpectedly resumed the request")
        terminal.command("resume", "flow.resume @focus", lambda _: bool(result))
        producer.join(timeout=5)
        if producer.is_alive() or len(result) != 1 or isinstance(result[0], Exception):
            raise RuntimeError(f"resumed request did not complete: {result}")
        terminal.key(
            "details",
            "Enter",
            lambda text: text.splitlines()[0].strip() == "Flow Details",
        )
        terminal.key(
            "response-tab", "Tab", lambda text: "owned console QA origin" in text
        )
        terminal.key(
            "details-back", "q", lambda text: text.splitlines()[0].strip() == "Flows"
        )
        terminal.key(
            "options", "O", lambda text: text.splitlines()[0].strip() == "Options"
        )
        terminal.key(
            "options-back", "q", lambda text: text.splitlines()[0].strip() == "Flows"
        )
        terminal.key("help", "?", lambda text: text.splitlines()[0].strip() == "Help")
        terminal.key(
            "help-back", "q", lambda text: text.splitlines()[0].strip() == "Flows"
        )
        terminal.command(
            "grid-open",
            "console.edit.focus request-headers",
            lambda text: "Key" in text and "Value" in text,
        )
        terminal._tmux("send-keys", "-t", terminal.target, "a")
        terminal._tmux("send-keys", "-t", terminal.target, "-l", "--", "X-QA-Edited")
        terminal.key("header-name", "Tab", lambda text: "X-QA-Edited" in text)
        terminal._tmux("send-keys", "-t", terminal.target, "-l", "--", "accepted")
        terminal.key("header-value", "Enter", lambda text: "accepted" in text)
        terminal.key(
            "grid-commit", "q", lambda text: text.splitlines()[0].strip() == "Flows"
        )
        terminal.command(
            "replay",
            "replay.client @focus",
            lambda _: any(
                record["edited"] == "accepted" for record in origin.snapshot()
            ),
        )
        terminal.request(
            port, f"http://127.0.0.1:{origin.server.server_port}/{nonce}/drop", nonce
        )
        terminal._wait("two-urls", lambda text: "/drop" in text and initial in text)
        terminal.command(
            "filter",
            "set view_filter '~u initial'",
            lambda text: initial in text and "/drop" not in text,
        )
        saved = out / "selected.mitm"
        terminal.command(
            "save",
            "save.file @shown " + orjson.dumps(str(saved)).decode(),
            lambda _: saved.is_file() and saved.stat().st_size > 0,
        )
        with saved.open("rb") as stream:
            flows = list(io.FlowReader(stream).stream())
        if not flows or any(
            not isinstance(flow, http.HTTPFlow)
            or flow.request.path != initial
            or flow.request.headers.get("X-QA-Edited") != "accepted"
            for flow in flows
        ):
            raise RuntimeError(
                "saved flows do not preserve edited/filter-selected input"
            )
        terminal.command("clear", "view.clear", lambda text: "[0/0]" in text)
        terminal.command(
            "reload",
            "view.flows.load " + orjson.dumps(str(saved)).decode(),
            lambda text: _count(text) == len(flows) and initial in text,
        )
        terminal.key("quit-prompt", "q", _quit_prompt_ready)
        terminal._tmux("send-keys", "-t", terminal.target, "y")
        terminal.exited("quit-restored")
    finally:
        try:
            terminal.close(producer)
        finally:
            if origin is not None:
                origin.close()
    signal_work = work / "interrupt"
    signal_work.mkdir(mode=0o700)
    terminal = _Terminal(args, "interrupt", signal_work)
    try:
        terminal._wait("signal-ready", lambda text: _proxy_address(text) is not None)
        terminal.signal()
        terminal._wait("signal-quit-prompt", _quit_prompt_ready)
        terminal._tmux("send-keys", "-t", terminal.target, "y")
        terminal.exited("signal-restored")
    finally:
        terminal.close()
    _write(
        out / "result.json",
        orjson.dumps(
            {
                "date": _date(),
                "scope": "prototype" if args.prototype else "carrier-preflight",
                "functional_checks": "PASS",
                "cursor_parity": "NOT_PROVED",
                "final_qa": False,
            }
        ),
    )


def main() -> None:
    """Run the owned launcher or capture prototype; propagate failed observations.

    Raises:
        OSError: If an owned file, executable, socket or descriptor is unavailable.
        RuntimeError: If a real console/origin observation differs.
        TimeoutError: If the owned program or expected output exceeds its watchdog.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for mode in ("capture", "launch"):
        command = modes.add_parser(mode)
        command.add_argument("--binary", type=Path, required=True)
        command.add_argument("--tmux", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        command.add_argument("--work-dir", type=Path, required=True)
        if mode == "capture":
            scope = command.add_mutually_exclusive_group(required=True)
            scope.add_argument("--prototype", action="store_true")
            scope.add_argument("--expected-sha")
        else:
            command.add_argument("--socket", required=True)
    args = parser.parse_args()
    repository = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    ).resolve()
    if repository != ROOT:
        raise ValueError("capture must run from its repository root")
    if args.mode == "launch":
        _launch(args)
    else:
        _capture(args)


if __name__ == "__main__":
    main()

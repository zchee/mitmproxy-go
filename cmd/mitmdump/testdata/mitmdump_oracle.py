#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
#   "orjson",
# ]
# ///

"""Run the pinned Python mitmdump as a subprocess for binary-level comparisons.

Modes:
    render <flowsdir>   read every *.mitm at flow_detail 0..4; JSON map keyed
                        "<name>/<detail>" of {returncode, stdout, stderr}.
    write <src> <dst>   mitmdump -n -r <src> -w <dst>; JSON {returncode, stderr}.
    read <file>         mitmdump -n -r <file>; JSON {returncode, stdout, stderr}.

Each run is a separate process with stdout and stderr on pipes, so the dumper
emits no colour, exactly as the Go binary is run by the differential test.
"""

import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import orjson

ENTRY = "from mitmproxy.tools.main import mitmdump; mitmdump()"


def run(args: list[str]) -> dict[str, object]:
    """Run mitmdump with args in a subprocess and capture its streams.

    Args:
        args: Command-line arguments passed to mitmdump.

    Returns:
        The exit status and the decoded standard output and error.
    Raises:
        subprocess.TimeoutExpired: If the child hits the hang detector.
        OSError: If the child cannot be started.
    """
    with TemporaryDirectory() as confdir:
        proc = subprocess.run(
            [sys.executable, "-c", ENTRY, "--set", f"confdir={confdir}", *args],
            capture_output=True,
            timeout=300,
            check=False,
        )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout.decode("utf-8", "replace"),
        "stderr": proc.stderr.decode("utf-8", "replace"),
    }


def main() -> None:
    """Dispatch on the mode argument and print one JSON document."""
    mode = sys.argv[1]
    if mode == "render":
        results = {
            f"{path.name}/{detail}": run(
                ["-n", "-r", str(path), "--flow-detail", str(detail)]
            )
            for path in sorted(Path(sys.argv[2]).glob("*.mitm"))
            for detail in range(5)
        }
        sys.stdout.buffer.write(orjson.dumps(results))
    elif mode == "write":
        result = run(["-n", "-r", sys.argv[2], "-w", sys.argv[3]])
        del result["stdout"]
        sys.stdout.buffer.write(orjson.dumps(result))
    elif mode == "read":
        sys.stdout.buffer.write(orjson.dumps(run(["-n", "-r", sys.argv[2]])))
    else:
        raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()

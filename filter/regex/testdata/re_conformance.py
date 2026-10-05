#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///

"""Record what Python's re does with every case of CPython's re_tests table.

Reads the table from the re_tests.py file named on the command line and
writes, for each (pattern, subject) case and each way a mitmproxy filter
compiles a pattern, whether re.compile accepts the pattern and, if so,
whether search finds it in the subject. A text operator such as ~u compiles
the str pattern with IGNORECASE; a bytes operator such as ~b compiles the
UTF-8 encoded pattern with IGNORECASE and DOTALL and searches the UTF-8
encoded subject. MITMPROXY_CASE_SENSITIVE_FILTERS drops IGNORECASE, so the
case-sensitive variants are recorded too.

Usage: re_conformance.py re_tests.py > results.json
"""

import importlib.util
import json
import re
import sys

MODES = {
    "text": re.IGNORECASE,
    "text-case-sensitive": re.NOFLAG,
    "bytes": re.IGNORECASE | re.DOTALL,
    "bytes-case-sensitive": re.DOTALL,
}


def load_table(path: str) -> list[tuple]:
    """Return the tests list of the re_tests.py file at path."""
    # The table is a byte-exact fixture; leave no bytecode cache beside it.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("re_tests", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.tests


def outcome(pattern: str, subject: str, mode: str) -> dict:
    """Compile pattern as mode does and search subject with it."""
    try:
        if mode.startswith("bytes"):
            found = re.compile(pattern.encode(), MODES[mode]).search(subject.encode())
        else:
            found = re.compile(pattern, MODES[mode]).search(subject)
    except (re.error, OverflowError, ValueError, RecursionError) as e:
        return {"compiled": False, "error": f"{type(e).__name__}: {e}"}
    return {"compiled": True, "match": found is not None}


def main() -> None:
    """Write the results for the table named on the command line."""
    cases = [
        {
            "pattern": case[0],
            "subject": case[1],
            "results": {mode: outcome(case[0], case[1], mode) for mode in MODES},
        }
        for case in load_table(sys.argv[1])
    ]
    json.dump({"python": sys.version.split()[0], "cases": cases}, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()

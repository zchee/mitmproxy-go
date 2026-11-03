#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7",
# ]
# ///
"""Print the projected upstream option inventory, or its unfiltered live table.

DumpMaster, WebMaster and ConsoleMaster retain their full addon lists. Only the
exact shared deferred names are removed from the default output. ``--raw``
exposes the unfiltered table for evidence, not for the checked-in manifest.
Every row holds name, type, JSON default and first help line separated by tabs.
Both outputs validate the complete live name set before writing anything.

Usage, from the repository root:

    hack/extract-upstream-options.py >| testdata/options-upstream.txt
"""

import argparse
import asyncio
import importlib.metadata
import json
import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol, cast

from mitmproxy import options
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
from mitmproxy.utils import typecheck

Row = tuple[str, str, str, str]

OLD_PIN = "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"
NEW_PIN = "51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7"
TESTDATA = Path(__file__).resolve().parent.parent / "testdata"


def deferred_names(data: str) -> tuple[str, str]:
    """Validate sorted, unique, newline-terminated deferred policy contents.

    Args:
        data: The complete shared policy file.

    Returns:
        Exactly the two deferred names.

    Raises:
        ValueError: If a name is missing, repeated, reordered or added.
    """
    if data != "emudhra\nemudhra_old\n":
        raise ValueError("deferred policy must contain exactly emudhra and emudhra_old")
    return "emudhra", "emudhra_old"


def parse_table(data: str) -> dict[str, Row]:
    """Parse an option table, rejecting malformed, duplicate or unsorted rows.

    Args:
        data: Newline-terminated tab-separated option rows.

    Returns:
        Validated rows keyed by option name.

    Raises:
        ValueError: If row fields, ordering, type or default are invalid.
    """
    rows: dict[str, Row] = {}
    previous = ""
    if not data.endswith("\n"):
        raise ValueError("option table must be newline-terminated")
    for line in data.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValueError(f"malformed option row: {line!r}")
        name, typ, default, help_text = fields
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name <= previous:
            raise ValueError(f"invalid, unsorted or duplicate option name: {name!r}")
        if not help_text or "\r" in line:
            raise ValueError(f"malformed help for option {name!r}")
        value = cast(object, json.loads(default))
        valid = {
            "bool": type(value) is bool,
            "int": type(value) is int,
            "str": isinstance(value, str),
            "optional int": value is None or type(value) is int,
            "optional str": value is None or isinstance(value, str),
            "sequence of str": isinstance(value, list)
            and all(isinstance(item, str) for item in cast(list[object], value)),
        }
        if not valid.get(typ, False):
            raise ValueError(
                f"invalid type/default for option {name!r}: {typ} {default}"
            )
        rows[name] = name, typ, default, help_text
        previous = name
    return rows


def installed_pin() -> str:
    """Read the installed distribution's exact VCS commit, never its version label.

    Returns:
        The supported installed upstream commit.

    Raises:
        ValueError: If distribution provenance is absent or uses an unknown commit.
        TypeError: If the VCS provenance is not an object.
    """
    raw = importlib.metadata.distribution("mitmproxy").read_text("direct_url.json")
    if raw is None:
        raise ValueError("mitmproxy has no VCS provenance")
    provenance = cast(dict[str, object], json.loads(raw))
    vcs = provenance.get("vcs_info")
    if not isinstance(vcs, dict):
        raise TypeError("mitmproxy VCS provenance must be an object")
    pin = cast(dict[str, object], vcs).get("commit_id")
    if pin not in (OLD_PIN, NEW_PIN):
        raise ValueError(f"unsupported upstream commit: {pin!r}")
    return cast(str, pin)


def project(
    rows: dict[str, Row], names: tuple[str, str], expected: dict[str, Row], pin: str
) -> dict[str, Row]:
    """Validate the complete raw union before excluding the frozen deferred names.

    Args:
        rows: The unmodified live union.
        names: The validated shared deferred policy.
        expected: The checked-in projected 117-name inventory.
        pin: The exact installed upstream commit.

    Returns:
        The 117 surviving rows, retaining their live metadata unchanged.

    Raises:
        ValueError: If a pin, shape, presence or complete name set is invalid.
    """
    _ = deferred_names("\n".join(names) + "\n")
    if pin not in (OLD_PIN, NEW_PIN):
        raise ValueError(f"unsupported upstream commit: {pin!r}")
    if len(expected) != 117 or set(expected).intersection(names):
        raise ValueError(
            "expected projected inventory must contain 117 non-deferred names"
        )
    for key, row in rows.items():
        if len(row) != 4 or key != row[0]:
            raise ValueError(f"malformed option row for {key!r}")
    validated = parse_table(
        "".join("\t".join(rows[name]) + "\n" for name in sorted(rows))
    )
    wanted = set(expected) | (set(names) if pin == NEW_PIN else set[str]())
    if set(validated) != wanted:
        raise ValueError(
            f"raw option inventory mismatch: missing={sorted(wanted - set(validated))}, "
            + f"extra={sorted(set(validated) - wanted)}"
        )
    for name in names:
        if name in validated and validated[name][1:3] != ("bool", "false"):
            raise ValueError(
                f"deferred option {name!r} must have type bool and default false"
            )
    return {name: row for name, row in validated.items() if name not in names}


def inventory_output(
    rows: dict[str, Row],
    names: tuple[str, str],
    expected: dict[str, Row],
    pin: str,
    *,
    raw: bool = False,
) -> str:
    """Render a validated raw or projected inventory without changing metadata.

    Args:
        rows: The unmodified live union.
        names: The shared deferred names.
        expected: The checked-in projected inventory.
        pin: The exact installed upstream commit.
        raw: Whether to emit the unfiltered table instead of the projected view.

    Returns:
        Sorted, newline-terminated option rows.

    Raises:
        ValueError: If the raw union fails the projection contract.
    """
    projected = project(rows, names, expected, pin)
    selected = rows if raw else projected
    return "".join("\t".join(selected[name]) + "\n" for name in sorted(selected))


class RegisteredOption(Protocol):
    """The upstream option fields consumed by the table renderer."""

    name: str
    typespec: object
    default: object
    help: str


def option_row(opt: RegisteredOption) -> Row:
    """Render one option as its output fields.

    Args:
        opt: The registered option.

    Returns:
        The name, type, JSON-encoded default and first help line.

    Raises:
        ValueError: If a field would contain a tab or a newline.
    """
    help_lines = opt.help.strip().splitlines()
    row = (
        opt.name,
        typecheck.typespec_to_str(opt.typespec),
        json.dumps(opt.default, ensure_ascii=False),
        help_lines[0].strip() if help_lines else "",
    )
    if any("\t" in field or "\n" in field for field in row):
        raise ValueError(f"option {opt.name!r} has a field with a tab or newline")
    return row


def master_rows(build: Callable[[options.Options], object]) -> dict[str, Row]:
    """Construct a master and render the options its addons registered.

    Args:
        build: A callable that constructs the master around the options.

    Returns:
        The rendered options keyed by name.
    """
    opts = options.Options()
    _ = build(opts)
    items = cast(Iterable[tuple[str, RegisteredOption]], opts.items())
    return {name: option_row(opt) for name, opt in items}


def merge(sources: Iterable[tuple[str, dict[str, Row]]]) -> dict[str, Row]:
    """Merge the options of several masters.

    Args:
        sources: Pairs of master name and its rendered options.

    Returns:
        The union of all options keyed by name.

    Raises:
        ValueError: If two masters render the same option differently.
    """
    merged: dict[str, Row] = {}
    owner: dict[str, str] = {}
    for master, rows in sources:
        for name, row in rows.items():
            if name in merged and merged[name] != row:
                raise ValueError(
                    f"option {name!r} differs between {owner[name]} and {master}: "
                    + f"{merged[name]!r} != {row!r}"
                )
            _ = merged.setdefault(name, row)
            _ = owner.setdefault(name, master)
    return merged


async def collect() -> dict[str, Row]:
    """Construct the three masters inside a running event loop.

    The masters keep their default addon sets: dropping the terminal log, for
    example, would also drop the termlog_verbosity option.

    Returns:
        The union of the options of all three masters keyed by name.
    """
    return merge(
        [
            ("DumpMaster", master_rows(DumpMaster)),
            ("WebMaster", master_rows(WebMaster)),
            ("ConsoleMaster", master_rows(ConsoleMaster)),
        ]
    )


def main() -> None:
    """Print the validated projected inventory, or the evidence-only raw table.

    Raises:
        ValueError: If policy, provenance or the live inventory is invalid.
        OSError: If an option manifest cannot be read.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument(
        "--raw", action="store_true", help="emit the unfiltered live table"
    )
    args = parser.parse_args()
    names = deferred_names((TESTDATA / "deferred-upstream-options.txt").read_text())
    expected = parse_table((TESTDATA / "options-upstream.txt").read_text())
    go_only = parse_table((TESTDATA / "options-go-only.txt").read_text())
    if set(go_only).intersection(set(expected) | set(names)):
        raise ValueError("Go-only options overlap upstream options")
    pin = installed_pin()
    rows = asyncio.run(collect())
    _ = sys.stdout.write(
        inventory_output(rows, names, expected, pin, raw=cast(bool, args.raw))
    )


if __name__ == "__main__":
    main()

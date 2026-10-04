#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "mitmproxy @ git+https://github.com/mitmproxy/mitmproxy@3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
# ]
# ///
"""Print every option that upstream mitmproxy registers, one per line.

The options are read from live masters: DumpMaster (mitmdump), WebMaster
(mitmweb) and ConsoleMaster (mitmproxy) are constructed with their full addon
lists, and the union of their option managers is printed. Each line holds four
tab-separated fields:

    name, type, default, help

``type`` is upstream's own rendering (``mitmproxy.utils.typecheck.
typespec_to_str``), ``default`` is the default value encoded as JSON, and
``help`` is the first line of the help text. Lines are sorted by name. When two
masters register the same name with different type, default or help, the
script fails instead of picking one.

Usage, from the repository root:

    hack/extract-upstream-options.py >| testdata/options-upstream.txt
"""

import asyncio
import json
import sys
from collections.abc import Callable, Iterable

from mitmproxy import options, optmanager
from mitmproxy.tools.console.master import ConsoleMaster
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.tools.web.master import WebMaster
from mitmproxy.utils import typecheck

Row = tuple[str, str, str, str]


def option_row(opt: optmanager._Option) -> Row:
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
    build(opts)
    return {name: option_row(opt) for name, opt in opts.items()}


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
                    f"{merged[name]!r} != {row!r}"
                )
            merged.setdefault(name, row)
            owner.setdefault(name, master)
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
    """Print the merged option table to standard output."""
    rows = asyncio.run(collect())
    sys.stdout.writelines("\t".join(rows[name]) + "\n" for name in sorted(rows))


if __name__ == "__main__":
    main()

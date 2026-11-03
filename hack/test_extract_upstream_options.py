#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "pytest==9.1.1",
# ]
# ///
"""Bounded policy checks and a real installed-pin runtime inventory check."""

import asyncio
import importlib.util
from collections.abc import Coroutine
from pathlib import Path
from typing import Protocol, cast

import pytest

Row = tuple[str, str, str, str]
OLD_PIN = "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1"
NEW_PIN = "51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7"
POLICY = ("emudhra", "emudhra_old")


class Extractor(Protocol):
    """Typed interface to the script, whose filename is not an import identifier."""

    def deferred_names(self, data: str) -> tuple[str, str]: ...
    def parse_table(self, data: str) -> dict[str, Row]: ...
    def project(
        self,
        rows: dict[str, Row],
        names: tuple[str, str],
        expected: dict[str, Row],
        pin: str,
    ) -> dict[str, Row]: ...
    def inventory_output(
        self,
        rows: dict[str, Row],
        names: tuple[str, str],
        expected: dict[str, Row],
        pin: str,
        *,
        raw: bool = False,
    ) -> str: ...
    def installed_pin(self) -> str: ...
    def collect(self) -> Coroutine[object, object, dict[str, Row]]: ...


spec = importlib.util.spec_from_file_location(
    "extract_upstream_options", Path(__file__).with_name("extract-upstream-options.py")
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
extractor = cast(Extractor, cast(object, module))


def base_rows() -> dict[str, Row]:
    """Return a bounded synthetic projected inventory for pure policy tests."""
    return {
        f"option_{index:03}": (f"option_{index:03}", "bool", "false", "Synthetic help.")
        for index in range(117)
    }


def new_rows() -> dict[str, Row]:
    """Return synthetic new-pin rows without constructing upstream masters."""
    rows = base_rows()
    rows.update({name: (name, "bool", "false", "Deferred help.") for name in POLICY})
    return rows


def test_exact_two_names() -> None:
    """Accept only the exact sorted, newline-terminated two-name policy."""
    assert extractor.deferred_names("emudhra\nemudhra_old\n") == POLICY
    for data in (
        "emudhra_old\nemudhra\n",
        "emudhra\nemudhra_old",
        "emudhra*\nemudhra_old\n",
    ):
        with pytest.raises(ValueError):
            _ = extractor.deferred_names(data)


def test_duplicate_rejected() -> None:
    """Reject a duplicate rather than treating the policy as a permissive set."""
    with pytest.raises(ValueError):
        _ = extractor.deferred_names("emudhra\nemudhra\n")


def test_third_name_rejected() -> None:
    """Reject any third exemption, including a similarly prefixed name."""
    with pytest.raises(ValueError):
        _ = extractor.deferred_names("emudhra\nemudhra_old\nemudhra_other\n")


def test_missing_name_rejected() -> None:
    """Reject incomplete or comment-bearing policies."""
    for data in ("emudhra\n", "emudhra_old\n", "", "# policy\nemudhra\nemudhra_old\n"):
        with pytest.raises(ValueError):
            _ = extractor.deferred_names(data)


def test_old_pin_raw_117() -> None:
    """Retain every old-pin row and its metadata unchanged."""
    rows = base_rows()
    assert extractor.project(rows, POLICY, base_rows(), OLD_PIN) == rows
    assert len(rows) == 117


def test_new_pin_raw_119() -> None:
    """Remove exactly two new-pin rows without changing the original raw table."""
    rows = new_rows()
    assert extractor.project(rows, POLICY, base_rows(), NEW_PIN) == base_rows()
    assert len(rows) == 119 and set(POLICY) <= rows.keys()


def test_projected_117() -> None:
    """Default output contains 117 survivors with unchanged type/default/help."""
    for pin, rows in ((OLD_PIN, base_rows()), (NEW_PIN, new_rows())):
        output = extractor.inventory_output(rows, POLICY, base_rows(), pin)
        assert extractor.parse_table(output) == base_rows()
        assert len(output.splitlines()) == 117
    with pytest.raises(ValueError):
        _ = extractor.project(base_rows(), POLICY, base_rows(), "unknown")
    for malformed in (
        "name\tbool\tfalse\n",
        "name\tbool\t0\tHelp\n",
        "name\tbool\tfalse\t\n",
    ):
        with pytest.raises(ValueError):
            _ = extractor.parse_table(malformed)


def test_old_pin_absent() -> None:
    """The old pin must not gain either deferred name."""
    for name in POLICY:
        rows = base_rows()
        rows[name] = (name, "bool", "false", "Deferred help.")
        with pytest.raises(ValueError):
            _ = extractor.project(rows, POLICY, base_rows(), OLD_PIN)


def test_new_pin_both_present() -> None:
    """Both new-pin deferred names must retain their exact bool/false shape."""
    assert not set(POLICY).intersection(
        extractor.project(new_rows(), POLICY, base_rows(), NEW_PIN)
    )
    for typ, default in (("str", '"false"'), ("bool", "true"), ("int", "0")):
        rows = new_rows()
        rows["emudhra"] = ("emudhra", typ, default, "Deferred help.")
        with pytest.raises(ValueError):
            _ = extractor.project(rows, POLICY, base_rows(), NEW_PIN)


def test_partial_presence_rejected() -> None:
    """A single present name is not an accepted transition state."""
    for name in POLICY:
        rows = new_rows()
        del rows[name]
        with pytest.raises(ValueError):
            _ = extractor.project(rows, POLICY, base_rows(), NEW_PIN)
    with pytest.raises(ValueError):
        _ = extractor.project(base_rows(), POLICY, base_rows(), NEW_PIN)


def test_lost_expected_name_rejected() -> None:
    """A lost known option is red at either pin before output."""
    for pin, rows in ((OLD_PIN, base_rows()), (NEW_PIN, new_rows())):
        del rows["option_000"]
        with pytest.raises(ValueError):
            _ = extractor.inventory_output(rows, POLICY, base_rows(), pin)


def test_unlisted_extra_rejected() -> None:
    """Do not exclude a third extra, duplicate name or malformed raw row."""
    for pin, rows in ((OLD_PIN, base_rows()), (NEW_PIN, new_rows())):
        rows["emudhra_other"] = ("emudhra_other", "bool", "false", "Extra.")
        with pytest.raises(ValueError):
            _ = extractor.inventory_output(rows, POLICY, base_rows(), pin, raw=True)
    with pytest.raises(ValueError):
        _ = extractor.parse_table("name\tbool\tfalse\tHelp\nname\tbool\tfalse\tHelp\n")
    rows = base_rows()
    rows["option_000"] = ("different_name", "bool", "false", "Help")
    with pytest.raises(ValueError):
        _ = extractor.project(rows, POLICY, base_rows(), OLD_PIN)


def test_raw_output_unfiltered() -> None:
    """Evidence output retains all 119 real fields rather than the projection."""
    rows = new_rows()
    output = extractor.inventory_output(rows, POLICY, base_rows(), NEW_PIN, raw=True)
    assert len(output.splitlines()) == 119
    assert extractor.parse_table(output) == rows
    assert all(name in extractor.parse_table(output) for name in POLICY)


def test_live_runtime_inventory_matches_pin() -> None:
    """Check actual full masters against the installed pin and checked-in names."""
    testdata = Path(__file__).resolve().parent.parent / "testdata"
    names = extractor.deferred_names(
        (testdata / "deferred-upstream-options.txt").read_text()
    )
    expected = extractor.parse_table((testdata / "options-upstream.txt").read_text())
    pin = extractor.installed_pin()
    rows = asyncio.run(extractor.collect())
    projected = extractor.project(rows, names, expected, pin)
    assert len(rows) == (117 if pin == OLD_PIN else 119)
    assert len(projected) == 117 and projected.keys() == expected.keys()
    assert set(names).intersection(rows) == (set() if pin == OLD_PIN else set(names))
    assert (
        extractor.parse_table(extractor.inventory_output(rows, names, expected, pin))
        == projected
    )
    assert (
        extractor.parse_table(
            extractor.inventory_output(rows, names, expected, pin, raw=True)
        )
        == rows
    )

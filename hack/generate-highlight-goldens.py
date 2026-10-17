#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["mitmproxy_rs==0.12.11"]
# ///
"""Generate validated, deterministic highlighting assets with the pinned wheel.

stdlib json keeps the frozen uv commands dependency-complete.
Inputs and source snapshots are read only; output must be outside their corpus.
The portable chunks and host-specific oracle provenance are separate files.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import logging
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from functools import cache
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Literal, cast
from urllib.parse import urlparse

# uv supplies this stub-typed binary extension, not the editor's interpreter.
from mitmproxy_rs import syntax_highlight  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

LOGGER = logging.getLogger(__name__)
VERSION = "0.12.11"
MANIFEST_SHA256 = "cfbb7073e43ba8e4468b6aca837c3efe0eed04dc62a5abeaeec7183bbf28536c"
PINS = {
    "python": "3368a0a06ae6195aad817a1ece1aaeb6fe0353a1",
    "rust": "51fe2b7c5aa8439c162abb665db61c6669d146d6",
    "wheel_source": "40f1dfb5dca7b03ff7793d3c90f23b8bdf873889",
}
LANGUAGES = ["css", "javascript", "xml", "yaml", "none", "error"]
TAGS = ["name", "string", "number", "boolean", "comment", "error"]
# Source occurrences remain distinct even when their decoded bytes are equal.
OCCURRENCES = {
    "css_debug": ("css", 48, 48, "debug"),
    "css_highlight": ("css", 59, 67, "test_highlight"),
    "javascript_debug": ("javascript", 50, 50, "debug"),
    "javascript_highlight": ("javascript", 61, 65, "test_highlight"),
    "xml_debug": ("xml", 46, 46, "debug"),
    "xml_highlight": ("xml", 57, 57, "test_highlight"),
    "yaml_highlight": ("yaml", 47, 51, "test_highlight"),
}
IDENTITIES = list(OCCURRENCES) + [f"{language}_real_200" for language in LANGUAGES[:4]]
LOCK_DIGESTS = {
    "v0.12.11": "ec0460b0d03626382b9ee1e35ead876c859da1065841ea5409100419cd5460af",
    PINS["rust"]: "ec0460b0d03626382b9ee1e35ead876c859da1065841ea5409100419cd5460af",
}
LOCK_NAMES = {
    "tree-sitter",
    "tree-sitter-css",
    "tree-sitter-highlight",
    "tree-sitter-javascript",
    "tree-sitter-language",
    "tree-sitter-xml",
    "tree-sitter-yaml",
}
SOURCE_PATHS = [
    f"mitmproxy-highlight/src/{name}.rs" for name in (*LANGUAGES[:4], "common", "lib")
] + ["mitmproxy-rs/src/syntax_highlight.rs"]
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 128 * 1024 * 1024
# The native redirector pins are shared with docs/dependencies.md.
COMPANION_PINS = {
    "mitmproxy_macos-0.12.11-py3-none-any.whl": "63349d9b46514ca679547651f7c0548f9222892edfbcba087b82b3244fbae859",
    "mitmproxy_windows-0.12.11-py3-none-any.whl": "59addc8864669a08f8cb48d8b29129efb1ca5f6cba9696e2d91f1f506b21a2d7",
    "mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.whl": "3de4f96c11565cca2d051655f8ca23f8f24f4b3220e9ca3b0ad81007f293e9da",
    "mitmproxy_linux-0.12.11-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": "0e5670a6b82546ebc0f947d79adfcb3c001ba3136a10ce848a2f4e2f336611c4",
}


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise TypeError(f"{label}: expected an object")
    return cast(dict[str, object], value)


def _array(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise TypeError(f"{label}: expected an array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label}: expected a string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label}: expected an integer")
    return cast(int, value)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    ).encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"source exceeds {limit} bytes: {path.name}")
    return data


def _snapshot(
    root: Path, record: dict[str, object], path_key: str = "snapshot"
) -> bytes:
    relative = PurePosixPath(_string(record.get(path_key), "source path"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("source path must be corpus-relative")
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("source path escapes corpus")
    data = _read(path)
    if _sha256(data) != record.get("sha256"):
        raise ValueError(f"source digest mismatch: {relative}")
    return data


def _literal(span: bytes) -> bytes:
    # Rust backslash-newline continuation removes subsequent whitespace, unlike
    # Python's literal parser. All other escapes in this corpus are shared.
    match = re.search(rb'b"(?:[^"\\]|\\.)*"', span, re.DOTALL)
    if match is None:
        raise ValueError("source span has no Rust byte literal")
    expression = re.sub(rb"\\\r?\n\s*", b"", match.group())
    value: object = ast.literal_eval(expression.decode("ascii"))
    if not isinstance(value, bytes):
        raise TypeError("source span is not a byte literal")
    return value


def _validate_sources(manifest: dict[str, object], root: Path) -> None:
    if manifest.get("source_pins") != PINS:
        raise ValueError("source pin mismatch")
    tables = _object(manifest.get("lock_tables"), "lock tables")
    if set(tables) != set(LOCK_DIGESTS):
        raise ValueError("lock table revisions mismatch")
    for revision, digest in LOCK_DIGESTS.items():
        table = _object(tables[revision], "lock table")
        data = _snapshot(root, table)
        if _sha256(data) != digest:
            raise ValueError("lock table source mismatch")
        extracted = _object(json.loads(data), "resolved lock tables")
        expected = _array(extracted.get(revision), "resolved lock entries")
        names = {
            _string(_object(item, "lock entry").get("name"), "package name")
            for item in expected
        }
        if (
            len(expected) != 7
            or names != LOCK_NAMES
            or table.get("entries") != expected
        ):
            raise ValueError("lock table entries mismatch")
    diff = _object(manifest.get("source_diff"), "source diff")
    if (diff.get("from"), diff.get("to"), diff.get("paths")) != (
        "v0.12.11",
        PINS["rust"],
        SOURCE_PATHS,
    ) or _snapshot(root, diff) != b"":
        raise ValueError("source diff mismatch")
    configuration = [
        {
            "language": language,
            "path": f"mitmproxy-highlight/src/{language}.rs",
            "function": "test_tags_ok",
            "start_line": start,
            "end_line": end,
        }
        for language, start, end in (
            ("css", 53, 55),
            ("javascript", 55, 57),
            ("xml", 51, 53),
            ("yaml", 41, 43),
        )
    ]
    if manifest.get("configuration_only") != configuration:
        raise ValueError("configuration-only inventory mismatch")
    licenses = _array(manifest.get("licenses"), "licenses")
    if len(licenses) != 5:
        raise ValueError("license inventory mismatch")
    for item in licenses:
        _snapshot(root, _object(item, "license"), "path")


def _validate_manifest(
    manifest: dict[str, object], inputs: Path
) -> list[tuple[dict[str, object], str]]:
    if manifest.get("schema_version") != 1:
        raise ValueError("input schema_version must be 1")
    if manifest.get("oracle") != {"distribution": "mitmproxy_rs", "version": VERSION}:
        raise ValueError("oracle declaration mismatch")
    _validate_sources(manifest, inputs.parent)
    entries = [
        _object(item, "input") for item in _array(manifest.get("inputs"), "inputs")
    ]
    identities = [_string(item.get("id"), "input identity") for item in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate input identity")
    if identities != IDENTITIES:
        raise ValueError("missing, extra, or reordered input identity")
    paths = [_string(item.get("path"), "input path") for item in entries]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate input path")
    if {path.name for path in inputs.iterdir()} != {"manifest.json", *paths}:
        raise ValueError("missing or extra input file")
    results = []
    origins = set()
    for item in entries:
        identity = _string(item["id"], "input identity")
        language = identity.split("_", 1)[0]
        if item.get("language") != language or language not in LANGUAGES[:4]:
            raise ValueError("wrong input language")
        path = _string(item["path"], "input path")
        if PurePosixPath(path).name != path or (inputs / path).is_symlink():
            raise ValueError("input path must be a regular file name")
        data = _read(inputs / path)
        if _sha256(data) != item.get("sha256"):
            raise ValueError("input digest mismatch")
        source = _object(item.get("source"), "input source")
        start = _integer(source.get("start_line"), "source start_line")
        end = _integer(source.get("end_line"), "source end_line")
        origin = (source.get("commit"), source.get("path"), start, end)
        if origin in origins:
            raise ValueError("duplicate source origin")
        origins.add(origin)
        if identity in OCCURRENCES:
            source_data = _snapshot(inputs.parent, source)
            blob = hashlib.sha1(
                f"blob {len(source_data)}\0".encode() + source_data
            ).hexdigest()
            if source.get("git_blob") != blob:
                raise ValueError("source Git blob mismatch")
            lines = source_data.splitlines(keepends=True)
            if not 1 <= start <= end <= len(lines):
                raise ValueError("source span outside snapshot")
            span = b"".join(lines[start - 1 : end])
            expected_language, expected_start, expected_end, function = OCCURRENCES[
                identity
            ]
            if item.get("kind") != "rust_literal" or (
                source.get("commit"),
                source.get("path"),
                start,
                end,
                source.get("function"),
            ) != (
                PINS["rust"],
                f"mitmproxy-highlight/src/{expected_language}.rs",
                expected_start,
                expected_end,
                function,
            ):
                raise ValueError("source span mismatch")
            expected_data = _literal(span)
        else:
            if item.get("kind") != "sample" or start != 1 or end != 200:
                raise ValueError("sample source span must contain 200 physical lines")
            if len(data.splitlines()) != 200:
                raise ValueError("sample must contain 200 physical lines")
            if source.get("excerpt_sha256") != _sha256(data):
                raise ValueError("source span mismatch or padded sample")
            if not re.fullmatch(
                r"[0-9a-f]{64}", _string(source.get("sha256"), "full-source digest")
            ):
                raise ValueError("invalid full-source digest")
            expected_url = f"{source.get('repository')}/blob/{source.get('commit')}/{source.get('path')}"
            if source.get("url") != expected_url:
                raise ValueError("sample source URL mismatch")
            expected_data = data
        if data != expected_data:
            raise ValueError("source span mismatch or padded sample")
        text = data.decode("utf-8", errors="strict")
        if item.get("physical_lines") != len(text.splitlines()):
            raise ValueError("physical line count mismatch")
        results.append((item, text))
    return results


def _download(url: str, limit: int) -> bytes:
    """Fetch bounded oracle provenance bytes, retrying interrupted connections."""
    attempt = 1
    while True:
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(limit + 1)
        except (
            urllib.error.URLError,
            ssl.SSLError,
            TimeoutError,
            ConnectionError,
        ) as error:
            reason = error.reason if isinstance(error, urllib.error.URLError) else error
            transient = isinstance(
                reason, (ssl.SSLEOFError, TimeoutError, ConnectionError)
            )
            if not transient or attempt == 3:
                raise
            LOGGER.warning(
                "Oracle download interrupted; retrying attempt %d of 3", attempt + 1
            )
            time.sleep(attempt)
            attempt += 1
            continue
        if len(data) > limit:
            raise ValueError("oracle download exceeds size limit")
        return data


@cache
def _installed_distribution(name: str) -> dict[str, object]:
    distribution = metadata.distribution(name)
    if distribution.version != VERSION:
        raise ValueError("wheel version mismatch")
    files = distribution.files
    if not files:
        raise ValueError("missing installed distribution file manifest")
    wheel_metadata = distribution.read_text("WHEEL")
    if wheel_metadata is None:
        raise ValueError("missing installed WHEEL metadata")
    tags = [
        line.removeprefix("Tag: ")
        for line in wheel_metadata.splitlines()
        if line.startswith("Tag: ")
    ]
    release = _object(
        json.loads(
            _download(f"https://pypi.org/pypi/{name}/{VERSION}/json", MAX_SOURCE_BYTES)
        ),
        "PyPI release",
    )
    candidates = []
    for value in _array(release.get("urls"), "PyPI files"):
        item = _object(value, "PyPI file")
        filename = _string(item.get("filename"), "wheel filename")
        parts = filename.removesuffix(".whl").rsplit("-", 3)
        if len(parts) != 4 or parts[0] != f"{name.replace('-', '_')}-{VERSION}":
            continue
        artifact_tags = {
            f"{python_tag}-{abi_tag}-{platform_tag}"
            for python_tag in parts[1].split(".")
            for abi_tag in parts[2].split(".")
            for platform_tag in parts[3].split(".")
        }
        if artifact_tags == set(tags):
            candidates.append(item)
    if len(candidates) != 1:
        raise ValueError("installed wheel artifact is not uniquely identified")
    artifact = candidates[0]
    url = _string(artifact.get("url"), "wheel URL")
    if (
        urlparse(url).scheme != "https"
        or urlparse(url).hostname != "files.pythonhosted.org"
    ):
        raise ValueError("unexpected wheel artifact origin")
    wheel = _download(url, MAX_WHEEL_BYTES)
    digest = _sha256(wheel)
    if _object(artifact.get("digests"), "wheel digests").get("sha256") != digest:
        raise ValueError("downloaded wheel digest mismatch")
    if (
        name != "mitmproxy_rs"
        and COMPANION_PINS.get(str(artifact["filename"])) != digest
    ):
        raise ValueError("companion wheel digest differs from the native artifact pin")
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        data_prefix = f"{name.replace('-', '_')}-{VERSION}.data"
        relocated = {
            info.filename
            for info in archive.infolist()
            if len(relocation_parts := PurePosixPath(info.filename).parts) >= 3
            and relocation_parts[0] == data_prefix
            and relocation_parts[1]
            in {"scripts", "data", "headers", "purelib", "platlib"}
            and not info.is_dir()
        }
        installed = {str(path): path for path in files}
        records = []
        for path in sorted(files, key=str):
            if path.suffix == ".pyc":
                continue
            # Installers may retain the archive path in RECORD after relocation.
            data = (
                archive.read(str(path))
                if str(path) in relocated
                else _read(Path(path.locate()), MAX_WHEEL_BYTES)
            )
            records.append(
                {"path": str(path), "size": len(data), "sha256": _sha256(data)}
            )
        payloads = [
            info
            for info in archive.infolist()
            if not info.is_dir() and ".dist-info/" not in info.filename
        ]
        if not payloads:
            raise ValueError("wheel has no payload")
        expanded_size = 0
        for info in payloads:
            expanded_size += info.file_size
            if expanded_size > MAX_WHEEL_BYTES:
                raise ValueError("wheel payload exceeds size limit")
            payload = archive.read(info)
            if info.filename in relocated:
                continue
            installed_path = installed.get(info.filename)
            if installed_path is None:
                raise ValueError("wheel payload missing from installed file manifest")
            if payload != _read(Path(installed_path.locate()), MAX_WHEEL_BYTES):
                raise ValueError("installed payload differs from wheel artifact")
    return {
        "distribution": name,
        "version": distribution.version,
        "filename": artifact["filename"],
        "wheel_sha256": digest,
        "files": records,
        "archive_verified_files": sorted(relocated),
        "installed_sha256": _sha256(_json_bytes(records)),
    }


@cache
def _installed_oracle() -> dict[str, object]:
    companion = {
        "darwin": "mitmproxy-macos",
        "linux": "mitmproxy-linux",
        "win32": "mitmproxy-windows",
    }.get(sys.platform)
    if companion is None:
        raise ValueError("unsupported oracle platform")
    oracle = _installed_distribution("mitmproxy_rs").copy()
    oracle["companion"] = _installed_distribution(companion)
    return oracle


def _validate_provenance(
    provenance: dict[str, object],
    manifest: dict[str, object],
    oracle: dict[str, object],
) -> None:
    if provenance.get("schema_version") != 1:
        raise ValueError("provenance schema_version must be 1")
    recorded = _object(provenance.get("oracle"), "oracle provenance")
    if recorded.get("version") != VERSION:
        raise ValueError("wheel version mismatch")
    records = _array(recorded.get("files"), "installed distribution files")
    if not records or recorded.get("installed_sha256") != _sha256(_json_bytes(records)):
        raise ValueError("installed distribution digest mismatch")
    companion = _object(recorded.get("companion"), "companion provenance")
    companion_records = _array(companion.get("files"), "companion distribution files")
    if (
        not companion_records
        or companion.get("installed_sha256") != _sha256(_json_bytes(companion_records))
        or companion != oracle.get("companion")
    ):
        raise ValueError("companion wheel digest or installed distribution mismatch")
    if recorded != oracle:
        raise ValueError("wheel digest or installed distribution mismatch")
    for key in (
        "source_pins",
        "lock_tables",
        "source_diff",
        "inputs",
        "configuration_only",
        "licenses",
    ):
        if provenance.get(key) != manifest.get(key):
            raise ValueError(f"provenance {key} mismatch")
    if provenance.get("source_pins") != PINS:
        raise ValueError("source pin mismatch")
    for key in ("uv_version", "python_version", "input_manifest_sha256"):
        if not _string(provenance.get(key), key):
            raise ValueError(f"missing {key}")


def _validate_goldens(
    goldens: dict[str, object], inputs: list[tuple[dict[str, object], str]]
) -> None:
    if (
        goldens.get("schema_version"),
        goldens.get("oracle"),
        goldens.get("languages"),
        goldens.get("tags"),
    ) != (1, {"distribution": "mitmproxy_rs", "version": VERSION}, LANGUAGES, TAGS):
        raise ValueError("golden schema or language/tag inventory mismatch")
    cases = _array(goldens.get("cases"), "golden cases")
    if len(cases) != len(inputs):
        raise ValueError("golden input inventory mismatch")
    for value, (item, text) in zip(cases, inputs, strict=True):
        case = _object(value, "golden case")
        if any(
            case.get(key) != item.get(key)
            for key in ("id", "language", "physical_lines")
        ) or case.get("input_sha256") != item.get("sha256"):
            raise ValueError("golden input metadata mismatch")
        chunks = [
            _object(chunk, "chunk") for chunk in _array(case.get("chunks"), "chunks")
        ]
        for chunk in chunks:
            if chunk.get("tag") not in ["", *TAGS]:
                raise ValueError("invalid tag")
        if (
            "".join(_string(chunk.get("text"), "chunk text") for chunk in chunks)
            != text
            or case.get("reconstruction_equal") is not True
        ):
            raise ValueError("chunk reconstruction mismatch")


def generate(inputs: Path, output: Path) -> None:
    """Validate a corpus and publish portable chunks plus runtime provenance.

    Args:
        inputs: Directory containing the frozen manifest and eleven inputs.
        output: Destination outside the source corpus.

    Raises:
        ValueError: If any input, oracle, provenance, or output invariant fails.
        OSError: If required files or the destination cannot be accessed.
    """
    root = inputs.resolve().parent
    if output.resolve().is_relative_to(root) or root.is_relative_to(output.resolve()):
        raise ValueError("output must not overlap the frozen corpus")
    manifest_bytes = _read(inputs / "manifest.json")
    if _sha256(manifest_bytes) != MANIFEST_SHA256:
        raise ValueError("frozen input manifest digest mismatch")
    manifest = _object(json.loads(manifest_bytes), "input manifest")
    validated = _validate_manifest(manifest, inputs)
    oracle = _installed_oracle()
    if syntax_highlight.languages() != LANGUAGES or syntax_highlight.tags() != TAGS:
        raise ValueError("installed oracle language/tag inventory mismatch")
    goldens: dict[str, object] = {
        "schema_version": 1,
        "oracle": {"distribution": "mitmproxy_rs", "version": VERSION},
        "languages": LANGUAGES,
        "tags": TAGS,
        "cases": [
            {
                "id": item["id"],
                "language": item["language"],
                "input_sha256": item["sha256"],
                "physical_lines": item["physical_lines"],
                "chunks": [
                    {"tag": tag, "text": chunk}
                    for tag, chunk in syntax_highlight.highlight(
                        text,
                        cast(
                            Literal[
                                "css", "javascript", "xml", "yaml", "none", "error"
                            ],
                            item["language"],
                        ),
                    )
                ],
                "reconstruction_equal": True,
            }
            for item, text in validated
        ],
    }
    provenance = {
        key: manifest[key]
        for key in (
            "source_pins",
            "lock_tables",
            "source_diff",
            "inputs",
            "configuration_only",
            "licenses",
        )
    }
    provenance.update(
        {
            "schema_version": 1,
            "oracle": oracle,
            "input_manifest_sha256": _sha256(manifest_bytes),
            "python_version": sys.version,
            "uv_version": subprocess.check_output(
                ["uv", "--version"], text=True, timeout=30
            ).strip(),
        }
    )
    _validate_goldens(goldens, validated)
    _validate_provenance(provenance, manifest, oracle)
    output.mkdir(parents=True, exist_ok=True)
    for name, value in (("goldens.json", goldens), ("provenance.json", provenance)):
        with tempfile.NamedTemporaryFile(dir=output, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(_json_bytes(value))
        os.replace(temporary, output / name)


def main() -> int:
    """Run generation from explicit arguments, returning zero only on success."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        generate(args.inputs, args.output)
    except (
        OSError,
        TypeError,
        ValueError,
        metadata.PackageNotFoundError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ) as error:
        LOGGER.error("highlight generation failed: %s", error)
        return 1
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    raise SystemExit(main())

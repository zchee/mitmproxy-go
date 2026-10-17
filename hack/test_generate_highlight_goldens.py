"""Exercise the frozen highlighter corpus and real pinned-wheel generator.

stdlib json keeps the frozen uv commands dependency-complete.
All temporary files are retained under the repository's ignored _test tree.
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
from email.message import Message
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import cast

# The canonical test command supplies pytest independently of the editor.
import pytest  # pyright: ignore[reportMissingImports]

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "hack/generate-highlight-goldens.py"
CORPUS = ROOT / "testdata/highlight"
OUTPUTS = ROOT / "_test/highlight-generator/selftests"


@pytest.fixture(scope="session")
def generator() -> ModuleType:
    """Load the actual generator, including the required installed wheel."""
    spec = importlib.util.spec_from_file_location("highlight_generator", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


@pytest.fixture
def directory() -> Path:
    """Allocate a retained test directory, never cleaned up after a test."""
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="case-", dir=OUTPUTS))


@pytest.fixture
def corpus(directory: Path) -> Path:
    """Copy the complete frozen corpus for file-level rejection tests."""
    return Path(shutil.copytree(CORPUS, directory / "corpus"))


def _read(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _entries(manifest: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], manifest["inputs"])


def _source(entry: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], entry["source"])


def _run(inputs: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--inputs", str(inputs), "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.fixture(scope="session")
def generated(
    generator: ModuleType,
) -> tuple[Path, dict[str, object], dict[str, object]]:
    """Generate real oracle results once for independent validator mutations."""
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="oracle-", dir=OUTPUTS)) / "output"
    generator.generate(CORPUS / "inputs", output)
    return output, _read(output / "goldens.json"), _read(output / "provenance.json")


def test_missing_input(generator: ModuleType, corpus: Path, directory: Path) -> None:
    """A missing identity or physical input fails before output publication."""
    manifest = _read(corpus / "inputs/manifest.json")
    missing = copy.deepcopy(manifest)
    _entries(missing).pop()
    with pytest.raises(ValueError, match="missing.*input identity"):
        generator._validate_manifest(missing, corpus / "inputs")
    # Move, rather than delete, the removed input so its original bytes remain.
    (corpus / "inputs/css-debug.css").rename(directory / "missing-css-debug.css")
    output = directory / "rejected"
    result = _run(corpus / "inputs", output)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "missing or extra input file" in result.stderr
    assert not output.exists()


def test_extra_input(generator: ModuleType, corpus: Path) -> None:
    """Unlisted files cannot enlarge the corpus or exemption denominator."""
    (corpus / "inputs/extra.css").write_text("a {}\n")
    with pytest.raises(ValueError, match="missing or extra input file"):
        generator._validate_manifest(
            _read(corpus / "inputs/manifest.json"), corpus / "inputs"
        )


def test_duplicate_identity(generator: ModuleType, corpus: Path) -> None:
    """Duplicate identities fail while distinct equal-byte XML origins pass."""
    manifest = _read(corpus / "inputs/manifest.json")
    validated = generator._validate_manifest(manifest, corpus / "inputs")
    assert validated[4][1] == validated[5][1]
    assert validated[4][0]["id"] != validated[5][0]["id"]
    _entries(manifest)[5]["id"] = "xml_debug"
    with pytest.raises(ValueError, match="duplicate input identity"):
        generator._validate_manifest(manifest, corpus / "inputs")
    manifest = _read(corpus / "inputs/manifest.json")
    _source(_entries(manifest)[5]).update(start_line=46, end_line=46)
    with pytest.raises(ValueError, match="duplicate source origin"):
        generator._validate_manifest(manifest, corpus / "inputs")


def test_wrong_language(generator: ModuleType, corpus: Path) -> None:
    """Known-but-misassigned and unknown languages both fail."""
    for language in ("javascript", "unknown"):
        manifest = _read(corpus / "inputs/manifest.json")
        _entries(manifest)[0]["language"] = language
        with pytest.raises(ValueError, match="wrong input language"):
            generator._validate_manifest(manifest, corpus / "inputs")


def test_invalid_schema(
    generator: ModuleType,
    corpus: Path,
    generated: tuple[Path, dict[str, object], dict[str, object]],
) -> None:
    """Wrong schemas and non-array chunk structures produce useful errors."""
    manifest = _read(corpus / "inputs/manifest.json")
    manifest["schema_version"] = 2
    with pytest.raises(ValueError, match="schema_version"):
        generator._validate_manifest(manifest, corpus / "inputs")
    goldens = copy.deepcopy(generated[1])
    cast(list[dict[str, object]], goldens["cases"])[0]["chunks"] = "not an array"
    valid = generator._validate_manifest(
        _read(corpus / "inputs/manifest.json"), corpus / "inputs"
    )
    with pytest.raises(TypeError, match="chunks: expected an array"):
        generator._validate_goldens(goldens, valid)
    with pytest.raises(TypeError, match="expected an object"):
        generator._object([], "manifest")


def test_source_span_mismatch(generator: ModuleType, corpus: Path) -> None:
    """A wrong pinned-literal line span is not accepted as provenance."""
    manifest = _read(corpus / "inputs/manifest.json")
    _source(_entries(manifest)[0])["start_line"] = 47
    with pytest.raises(ValueError, match="source span mismatch"):
        generator._validate_manifest(manifest, corpus / "inputs")


def test_input_digest_mismatch(generator: ModuleType, corpus: Path) -> None:
    """Changed bytes cannot retain their original input digest."""
    path = corpus / "inputs/css-debug.css"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="input digest mismatch"):
        generator._validate_manifest(
            _read(corpus / "inputs/manifest.json"), corpus / "inputs"
        )


def test_wheel_version_mismatch(
    generator: ModuleType, generated: tuple[Path, dict[str, object], dict[str, object]]
) -> None:
    """A provenance record for another wheel version fails closed."""
    provenance = copy.deepcopy(generated[2])
    cast(dict[str, object], provenance["oracle"])["version"] = "0.12.10"
    with pytest.raises(ValueError, match="wheel version mismatch"):
        generator._validate_provenance(
            provenance,
            _read(CORPUS / "inputs/manifest.json"),
            generator._installed_oracle(),
        )


def test_wheel_digest_mismatch(
    generator: ModuleType,
    generated: tuple[Path, dict[str, object], dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate wheel hashes and bounded retries without relaxing failures."""
    manifest = _read(CORPUS / "inputs/manifest.json")
    for target in ("oracle", "companion"):
        for key, value in (
            ("installed_sha256", None),
            ("installed_sha256", "0" * 64),
            ("wheel_sha256", "0" * 64),
            ("archive_verified_files", ["wrong"]),
        ):
            provenance = copy.deepcopy(generated[2])
            record = cast(dict[str, object], provenance["oracle"])
            if target == "companion":
                record = cast(dict[str, object], record["companion"])
            record[key] = value
            with pytest.raises(ValueError, match="digest.*mismatch"):
                generator._validate_provenance(
                    provenance, manifest, generator._installed_oracle()
                )

    url = "https://files.pythonhosted.org/test.whl"
    eof = urllib.error.URLError(ssl.SSLEOFError(8, "unexpected EOF"))
    certificate = urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate"))
    cases: list[tuple[str, tuple[Exception, ...], type[Exception] | None, int, int]] = [
        ("wrapped_eof", (eof,), None, 2, 16),
        ("direct_eof", (ssl.SSLEOFError(8, "unexpected EOF"),), None, 2, 16),
        ("timeout", (TimeoutError("timed out"),), None, 2, 16),
        ("reset", (urllib.error.URLError(ConnectionResetError()),), None, 2, 16),
        ("exhausted", (eof, eof, eof), urllib.error.URLError, 3, 16),
        ("certificate", (certificate,), urllib.error.URLError, 1, 16),
        (
            "http",
            (urllib.error.HTTPError(url, 404, "missing", Message(), None),),
            urllib.error.HTTPError,
            1,
            16,
        ),
        (
            "permanent",
            (urllib.error.URLError("unknown scheme"),),
            urllib.error.URLError,
            1,
            16,
        ),
        ("protocol", (ssl.SSLError(1, "protocol error"),), ssl.SSLError, 1, 16),
        ("oversized", (), ValueError, 1, 4),
    ]

    def open_attempt(
        failures: tuple[Exception, ...],
        calls: list[int],
        actual_url: str,
        timeout: int,
    ) -> io.BytesIO:
        assert actual_url == url
        calls.append(timeout)
        if len(calls) <= len(failures):
            raise failures[len(calls) - 1]
        return io.BytesIO(b"wheel")

    for name, failures, expected_error, expected_calls, limit in cases:
        calls: list[int] = []
        delays: list[int] = []
        with monkeypatch.context() as patch:
            patch.setattr(
                generator.urllib.request,
                "urlopen",
                partial(open_attempt, failures, calls),
            )
            patch.setattr(generator.time, "sleep", delays.append)
            if expected_error is None:
                assert generator._download(url, limit) == b"wheel", name
            else:
                with pytest.raises(expected_error):
                    generator._download(url, limit)
        assert calls == [60] * expected_calls, name
        assert delays == list(range(1, expected_calls)), name


def test_source_pin_mismatch(generator: ModuleType, corpus: Path) -> None:
    """Every missing or wrong Python, Rust or wheel-source pin is rejected."""
    for key in generator.PINS:
        for value in (None, "0" * 40):
            manifest = _read(corpus / "inputs/manifest.json")
            pins = cast(dict[str, object], manifest["source_pins"])
            if value is None:
                pins.pop(key)
            else:
                pins[key] = value
            with pytest.raises(ValueError, match="source pin mismatch"):
                generator._validate_manifest(manifest, corpus / "inputs")


def test_lock_table_mismatch(generator: ModuleType, corpus: Path) -> None:
    """Missing/altered lock entries and source-diff provenance are rejected."""
    for revision in generator.LOCK_DIGESTS:
        manifest = _read(corpus / "inputs/manifest.json")
        tables = cast(dict[str, dict[str, object]], manifest["lock_tables"])
        cast(list[dict[str, object]], tables[revision]["entries"])[0]["checksum"] = (
            "0" * 64
        )
        with pytest.raises(ValueError, match="lock table entries mismatch"):
            generator._validate_manifest(manifest, corpus / "inputs")
        tables.pop(revision)
        with pytest.raises(ValueError, match="lock table revisions mismatch"):
            generator._validate_manifest(manifest, corpus / "inputs")
    manifest = _read(corpus / "inputs/manifest.json")
    cast(dict[str, object], manifest["source_diff"])["paths"] = []
    with pytest.raises(ValueError, match="source diff mismatch"):
        generator._validate_manifest(manifest, corpus / "inputs")


def test_chunk_reconstruction_mismatch(
    generator: ModuleType, generated: tuple[Path, dict[str, object], dict[str, object]]
) -> None:
    """Changing ordered chunk text breaks exact input reconstruction."""
    goldens = copy.deepcopy(generated[1])
    case = cast(list[dict[str, object]], goldens["cases"])[0]
    cast(list[dict[str, object]], case["chunks"])[0]["text"] = "wrong"
    valid = generator._validate_manifest(
        _read(CORPUS / "inputs/manifest.json"), CORPUS / "inputs"
    )
    with pytest.raises(ValueError, match="chunk reconstruction mismatch"):
        generator._validate_goldens(goldens, valid)


def test_invalid_tag(
    generator: ModuleType, generated: tuple[Path, dict[str, object], dict[str, object]]
) -> None:
    """Tags outside empty Text and the six public strings are rejected."""
    goldens = copy.deepcopy(generated[1])
    case = cast(list[dict[str, object]], goldens["cases"])[0]
    cast(list[dict[str, object]], case["chunks"])[0]["tag"] = "Text"
    valid = generator._validate_manifest(
        _read(CORPUS / "inputs/manifest.json"), CORPUS / "inputs"
    )
    with pytest.raises(ValueError, match="invalid tag"):
        generator._validate_goldens(goldens, valid)


def test_invalid_sample_line_count(generator: ModuleType, corpus: Path) -> None:
    """Reject 199/201 lines and padding even when its input hash is updated."""
    original = _read(corpus / "inputs/manifest.json")
    sample = _entries(original)[7]
    path = corpus / "inputs" / str(sample["path"])
    data = path.read_bytes()
    for changed in (
        b"".join(data.splitlines(keepends=True)[:199]),
        data + b"\n",
        b"\n" * 200,
    ):
        path.write_bytes(changed)
        manifest = copy.deepcopy(original)
        _entries(manifest)[7]["sha256"] = generator._sha256(changed)
        _entries(manifest)[7]["physical_lines"] = len(changed.splitlines())
        with pytest.raises(ValueError, match="200 physical lines|padded sample"):
            generator._validate_manifest(manifest, corpus / "inputs")
    path.write_bytes(data)
    assert len(generator._validate_manifest(original, corpus / "inputs")) == 11


def test_deterministic_generation(directory: Path) -> None:
    """Two actual pinned-wheel CLI generations produce identical files."""
    outputs = [directory / "first", directory / "second"]
    for output in outputs:
        result = _run(CORPUS / "inputs", output)
        assert result.returncode == 0, result.stdout + result.stderr
        assert {file.name for file in output.iterdir()} == {
            "goldens.json",
            "provenance.json",
        }
    for filename in ("goldens.json", "provenance.json"):
        assert (outputs[0] / filename).read_bytes() == (
            outputs[1] / filename
        ).read_bytes()


def test_provenance_roundtrip(
    generator: ModuleType, generated: tuple[Path, dict[str, object], dict[str, object]]
) -> None:
    """Real output retains the complete source/oracle evidence and all inputs."""
    output, goldens, provenance = generated
    manifest = _read(CORPUS / "inputs/manifest.json")
    validated = generator._validate_manifest(manifest, CORPUS / "inputs")
    generator._validate_goldens(goldens, validated)
    generator._validate_provenance(provenance, manifest, generator._installed_oracle())
    cases = cast(list[dict[str, object]], goldens["cases"])
    assert [case["id"] for case in cases] == generator.IDENTITIES
    assert cases[4]["input_sha256"] == cases[5]["input_sha256"]
    assert cases[4]["id"] != cases[5]["id"]
    assert provenance["input_manifest_sha256"] == generator._sha256(
        (CORPUS / "inputs/manifest.json").read_bytes()
    )
    assert provenance["source_pins"] == generator.PINS
    assert len(cast(dict[str, object], provenance["lock_tables"])) == 2
    oracle = cast(dict[str, object], provenance["oracle"])
    companion = cast(dict[str, object], oracle["companion"])
    for distribution in (oracle, companion):
        assert str(distribution["filename"]).endswith(".whl")
        assert len(str(distribution["wheel_sha256"])) == 64
        assert distribution["installed_sha256"] == generator._sha256(
            generator._json_bytes(distribution["files"])
        )
        assert distribution["files"]
        archived = cast(list[str], distribution["archive_verified_files"])
        assert archived == sorted(set(archived))
        assert all(
            len(parts := Path(path).parts) >= 3
            and parts[0].endswith(".data")
            and parts[1] in {"scripts", "data", "headers", "purelib", "platlib"}
            for path in archived
        )
    if sys.platform == "linux":
        assert companion["archive_verified_files"] == [
            "mitmproxy_linux-0.12.11.data/scripts/mitmproxy-linux-redirector"
        ]
    assert companion["version"] == "0.12.11"
    assert (
        companion["distribution"]
        == {
            "darwin": "mitmproxy-macos",
            "linux": "mitmproxy-linux",
            "win32": "mitmproxy-windows",
        }[sys.platform]
    )
    assert companion["wheel_sha256"] == generator.COMPANION_PINS[companion["filename"]]
    assert (output / "goldens.json").read_bytes() == generator._json_bytes(goldens)
    assert (output / "provenance.json").read_bytes() == generator._json_bytes(
        provenance
    )

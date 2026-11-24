"""Unit tests for Phase 1: PE Loader stage."""

from pathlib import Path
import pytest
from reveng.loader import PELoader, LoadedPE
from samples.pe_builder import build_minimal_pe64


@pytest.fixture
def sample_pe_bytes() -> bytes:
    """Fixture providing minimal 64-bit PE binary bytes."""
    return build_minimal_pe64()


@pytest.fixture
def sample_pe_file(tmp_path: Path, sample_pe_bytes: bytes) -> Path:
    """Fixture writing the sample PE to a temporary file."""
    exe_path = tmp_path / "sample.exe"
    exe_path.write_bytes(sample_pe_bytes)
    return exe_path


def test_loader_from_bytes(sample_pe_bytes: bytes):
    """Verify loader can load from raw memory bytes."""
    loader = PELoader(sample_pe_bytes)
    pe = loader.loaded_pe

    assert pe.is_64bit is True
    assert pe.machine == "x86-64 (AMD64)"
    assert pe.image_base == 0x140000000
    assert pe.entry_point_rva == 0x1000
    assert pe.entry_point_va == 0x140001000
    assert len(pe.sections) == 1

    text = pe.sections[0]
    assert text.name == ".text"
    assert text.virtual_address == 0x1000
    assert text.is_executable is True
    assert text.is_readable is True
    assert text.is_writable is False


def test_loader_from_file(sample_pe_file: Path):
    """Verify loader parses PE file from disk correctly."""
    loader = PELoader(sample_pe_file)
    pe = loader.loaded_pe

    assert pe.file_path == str(sample_pe_file)
    assert pe.is_64bit is True
    assert pe.rva_to_va(0x1000) == 0x140001000
    assert pe.va_to_rva(0x140001000) == 0x1000


def test_loader_read_code_bytes(sample_pe_bytes: bytes):
    """Verify virtual memory byte extraction at RVA and VA."""
    loader = PELoader(sample_pe_bytes)

    # Entry point has: mov eax, 42 (b8 2a 00 00 00) ; ret (c3)
    entry_bytes = loader.read_bytes_at_rva(0x1000, 6)
    assert entry_bytes == b"\xb8\x2a\x00\x00\x00\xc3"

    entry_va_bytes = loader.read_bytes_at_va(0x140001000, 6)
    assert entry_va_bytes == b"\xb8\x2a\x00\x00\x00\xc3"

    sec, text_bytes = loader.get_text_section_bytes()
    assert sec.name == ".text"
    assert text_bytes.startswith(b"\xb8\x2a\x00\x00\x00\xc3")


def test_loader_to_json_and_dict(sample_pe_bytes: bytes):
    """Verify serialization to dict and JSON."""
    loader = PELoader(sample_pe_bytes)
    d = loader.loaded_pe.to_dict()
    assert d["is_64bit"] is True
    assert d["image_base_hex"] == "0x140000000"
    assert "sections" in d
    assert len(d["sections"]) == 1

    json_str = loader.loaded_pe.to_json()
    assert "0x140000000" in json_str
    assert ".text" in json_str


def test_loader_system_binary():
    """Verify loader parses standard Windows system binaries (e.g. notepad.exe or cmd.exe)."""
    system32 = Path("C:/Windows/System32")
    candidates = [system32 / "notepad.exe", system32 / "cmd.exe"]
    target = None
    for cand in candidates:
        if cand.exists():
            target = cand
            break

    if target is None:
        pytest.skip("No standard Windows system binary found for test")

    loader = PELoader(target)
    pe = loader.loaded_pe
    assert pe.is_64bit is True
    assert len(pe.sections) > 0
    assert len(pe.imports) > 0
    assert pe.entry_point_rva > 0
    sec, code = loader.get_text_section_bytes()
    assert sec.is_executable is True
    assert len(code) > 0

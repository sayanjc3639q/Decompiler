"""Data models for PE file loading and representation.

Reverse-Engineering Context:
A Portable Executable (PE) file on disk is an organized set of headers, section tables,
and raw binary data. When the Windows OS loader maps the PE into memory:
1. It allocates a virtual address space starting at an ImageBase (or relocated base).
2. It maps sections from their disk file offsets (PointerToRawData) to memory addresses (VirtualAddress / RVA).
3. It resolves imported symbols from external DLLs through the Import Address Table (IAT).
4. It sets up exports, relocations, and transfers execution to the Entry Point RVA.

This module encapsulates that mapped view so that downstream analysis phases (disassembly,
CFG recovery, SSA construction) operate on clean, typed virtual memory concepts without
coupling directly to raw file parsing libraries.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
import json


@dataclass
class SectionInfo:
    """Represents a mapped section of a PE binary.

    Attributes:
        name: Name of section (e.g. '.text', '.rdata', '.data').
        virtual_address: RVA (Relative Virtual Address) where section starts in memory.
        virtual_size: Size in bytes of section when mapped in memory.
        raw_data_offset: File offset on disk where section content begins.
        raw_data_size: Size in bytes of section content stored on disk.
        is_executable: True if section contains executable code (IMAGE_SCN_MEM_EXECUTE).
        is_readable: True if section is readable (IMAGE_SCN_MEM_READ).
        is_writable: True if section is writable (IMAGE_SCN_MEM_WRITE).
        entropy: Measure of randomness (0.0 - 8.0) to detect packing or encryption.
    """
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    is_executable: bool
    is_readable: bool
    is_writable: bool
    entropy: float


@dataclass
class ImportSymbol:
    """Represents an imported function or variable from an external DLL.

    Reverse-Engineering Context:
    Windows executables rely on dynamic linking for OS APIs (e.g., kernel32.dll, ntdll.dll).
    Imports are resolved via the Import Address Table (IAT). In disassembly, calls to library
    functions often appear as indirect calls through IAT slots (`call qword ptr [rip + disp]`).
    Identifying import RVAs/VAs allows the decompiler to replace cryptic pointers with friendly
    names like `ExitProcess` or `printf`.
    """
    dll_name: str
    name: Optional[str]
    ordinal: Optional[int]
    iat_rva: int
    iat_va: int


@dataclass
class ExportSymbol:
    """Represents an exported function or symbol.

    Reverse-Engineering Context:
    Exported functions represent designated entry points that other modules or the OS can call.
    For standard executables, exports are rare unless they expose plugin interfaces, but DLLs
    rely heavily on them. Export addresses are immediate function entry points for analysis.
    """
    name: Optional[str]
    ordinal: int
    rva: int
    va: int
    forwarder: Optional[str] = None


@dataclass
class LoadedPE:
    """Complete structured representation of a loaded PE binary ready for analysis.

    This dataclass is the primary output artifact of the loader stage and the input to
    subsequent stages like disassembly and CFG generation.
    """
    file_path: str
    image_base: int
    entry_point_rva: int
    entry_point_va: int
    machine: str
    subsystem: str
    is_64bit: bool
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportSymbol] = field(default_factory=list)
    exports: List[ExportSymbol] = field(default_factory=list)

    def rva_to_va(self, rva: int) -> int:
        """Convert a Relative Virtual Address (RVA) to Virtual Address (VA)."""
        return self.image_base + rva

    def va_to_rva(self, va: int) -> int:
        """Convert a Virtual Address (VA) to Relative Virtual Address (RVA)."""
        return va - self.image_base

    def find_section_by_rva(self, rva: int) -> Optional[SectionInfo]:
        """Find the section containing the given RVA."""
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
                return sec
        return None

    def find_section_by_name(self, name: str) -> Optional[SectionInfo]:
        """Find the first section matching a specific name (e.g. '.text')."""
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def to_dict(self) -> Dict:
        """Serialize LoadedPE metadata to a clean Python dictionary."""
        d = asdict(self)
        # Format hex addresses for human inspection
        d["image_base_hex"] = hex(self.image_base)
        d["entry_point_rva_hex"] = hex(self.entry_point_rva)
        d["entry_point_va_hex"] = hex(self.entry_point_va)
        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialize LoadedPE metadata to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

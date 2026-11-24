"""PE binary parsing, mapping, and validation.

Reverse-Engineering Concept:
The Windows PE (Portable Executable) format is a derived version of COFF (Common Object
File Format). Key structures parsed here:
- DOS Header ('MZ'): Backward-compatibility header containing `e_lfanew`, which points to the PE header.
- PE Signature ('PE\\0\\0'): Validates that the file is indeed a valid PE.
- COFF File Header: Specifies architecture (x86 vs x86-64 / AMD64), number of sections, timestamp.
- Optional Header: Despite its name, mandatory for executables. Provides `ImageBase`, `AddressOfEntryPoint`,
  `SectionAlignment`, `FileAlignment`, and Data Directories (Imports, Exports, Relocations, Exceptions).
- Section Table: Array of headers defining `.text` (code), `.data` (initialized globals), `.rdata` (constants/imports),
  `.pdata` (x64 structured exception handling runtime function tables), etc.

This loader reads raw file bytes, parses headers with `pefile`, computes section characteristics,
resolves imports/exports, and builds a virtual memory buffer so memory reads at arbitrary RVAs
match what the CPU sees at runtime.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import pefile

from reveng.loader.models import (
    LoadedPE,
    SectionInfo,
    ImportSymbol,
    ExportSymbol,
)


# Standard machine constants
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C

# Section characteristic masks
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class PELoader:
    """Parses and loads a Windows PE binary into structured memory models."""

    def __init__(self, file_path_or_bytes: Union[str, Path, bytes, bytearray]):
        """Initialize loader with file path or raw bytes."""
        if isinstance(file_path_or_bytes, (str, Path)):
            self.file_path = str(file_path_or_bytes)
            self._pe = pefile.PE(self.file_path, fast_load=False)
        elif isinstance(file_path_or_bytes, (bytes, bytearray)):
            self.file_path = "<memory>"
            self._pe = pefile.PE(data=bytes(file_path_or_bytes), fast_load=False)
        else:
            raise TypeError("Expected file path, bytes, or bytearray for PE loading")

        self.loaded_pe = self._build_loaded_pe()

    @property
    def pe(self) -> pefile.PE:
        """Underlying pefile instance for low-level queries."""
        return self._pe

    def _build_loaded_pe(self) -> LoadedPE:
        """Parse all PE headers and build the LoadedPE dataclass."""
        machine_val = self._pe.FILE_HEADER.Machine
        is_64bit = (machine_val == IMAGE_FILE_MACHINE_AMD64)
        machine_str = "x86-64 (AMD64)" if is_64bit else f"0x{machine_val:04x}"

        subsystem_val = getattr(self._pe.OPTIONAL_HEADER, "Subsystem", 0)
        subsystem_str = pefile.SUBSYSTEM_TYPE.get(subsystem_val, f"Unknown ({subsystem_val})")

        image_base = self._pe.OPTIONAL_HEADER.ImageBase
        entry_point_rva = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_point_va = image_base + entry_point_rva

        # Parse sections
        sections: List[SectionInfo] = []
        for sec in self._pe.sections:
            sec_name = sec.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            chars = sec.Characteristics
            sec_info = SectionInfo(
                name=sec_name,
                virtual_address=sec.VirtualAddress,
                virtual_size=sec.Misc_VirtualSize,
                raw_data_offset=sec.PointerToRawData,
                raw_data_size=sec.SizeOfRawData,
                is_executable=bool(chars & IMAGE_SCN_MEM_EXECUTE),
                is_readable=bool(chars & IMAGE_SCN_MEM_READ),
                is_writable=bool(chars & IMAGE_SCN_MEM_WRITE),
                entropy=sec.get_entropy(),
            )
            sections.append(sec_info)

        # Parse imports
        imports: List[ImportSymbol] = []
        if hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore") if entry.dll else "unknown"
                for imp in entry.imports:
                    imp_name = imp.name.decode("utf-8", errors="ignore") if imp.name else None
                    imp_symbol = ImportSymbol(
                        dll_name=dll_name,
                        name=imp_name,
                        ordinal=imp.ordinal if imp_name is None else None,
                        iat_rva=imp.address - image_base,
                        iat_va=imp.address,
                    )
                    imports.append(imp_symbol)

        # Parse exports
        exports: List[ExportSymbol] = []
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode("utf-8", errors="ignore") if exp.name else None
                exp_symbol = ExportSymbol(
                    name=exp_name,
                    ordinal=exp.ordinal,
                    rva=exp.address,
                    va=image_base + exp.address,
                    forwarder=exp.forwarder.decode("utf-8", errors="ignore") if exp.forwarder else None,
                )
                exports.append(exp_symbol)

        return LoadedPE(
            file_path=self.file_path,
            image_base=image_base,
            entry_point_rva=entry_point_rva,
            entry_point_va=entry_point_va,
            machine=machine_str,
            subsystem=subsystem_str,
            is_64bit=is_64bit,
            sections=sections,
            imports=imports,
            exports=exports,
        )

    def read_bytes_at_rva(self, rva: int, length: int) -> bytes:
        """Read a sequence of bytes from virtual memory at a specific RVA.

        Reverse-Engineering Concept:
        Code and data are indexed by Virtual Addresses in memory. However, file data
        is stored in sections that may have different file offsets and sizes than their
        virtual footprint (due to uninitialized data .bss or section alignment padding).
        This method translates the RVA to the appropriate section and extracts the bytes,
        simulating direct memory reads in the mapped process address space.
        """
        try:
            data = self._pe.get_data(rva, length)
            return bytes(data)
        except Exception as exc:
            raise ValueError(f"Failed to read {length} bytes at RVA 0x{rva:x}: {exc}") from exc

    def read_bytes_at_va(self, va: int, length: int) -> bytes:
        """Read bytes at an absolute Virtual Address (VA)."""
        rva = self.loaded_pe.va_to_rva(va)
        return self.read_bytes_at_rva(rva, length)

    def get_section_bytes(self, section_name: str) -> bytes:
        """Retrieve the entire byte payload of a named section (e.g., '.text')."""
        sec = self.loaded_pe.find_section_by_name(section_name)
        if not sec:
            raise KeyError(f"Section '{section_name}' not found in PE.")
        return self.read_bytes_at_rva(sec.virtual_address, sec.virtual_size)

    def get_text_section_bytes(self) -> Tuple[SectionInfo, bytes]:
        """Convenience method to retrieve the main executable section (typically .text) and its bytes."""
        # First look for an executable section named .text
        text_sec = self.loaded_pe.find_section_by_name(".text")
        if not text_sec or not text_sec.is_executable:
            # Fallback to the first executable section
            for sec in self.loaded_pe.sections:
                if sec.is_executable:
                    text_sec = sec
                    break

        if not text_sec:
            raise ValueError("No executable code section found in PE.")

        data = self.read_bytes_at_rva(text_sec.virtual_address, text_sec.virtual_size)
        return text_sec, data

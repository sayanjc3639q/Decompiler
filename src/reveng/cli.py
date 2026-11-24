"""RevEng Command Line Interface.

Provides runnable and inspectable stage outputs across the decompiler pipeline.
Every stage can dump its output as JSON or human-readable text.
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from reveng.loader import PELoader


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reveng",
        description="RevEng: Educational x86-64 Windows PE Decompiler",
    )
    parser.add_argument("file", help="Path to input Windows PE (.exe / .dll)")
    
    # Inspection stage flags
    stage_group = parser.add_argument_group("Stage Dumps")
    stage_group.add_argument(
        "--dump-loader",
        action="store_true",
        help="Dump PE loader stage output (headers, sections, imports, exports)",
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for stage dump (default: text)",
    )

    return parser


def print_loader_stage_text(loader: PELoader) -> None:
    pe = loader.loaded_pe
    print("=" * 60)
    print("RevEng - PE Loader Stage")
    print("=" * 60)
    print(f"File:           {pe.file_path}")
    print(f"Architecture:   {pe.machine} (64-bit: {pe.is_64bit})")
    print(f"Subsystem:      {pe.subsystem}")
    print(f"Image Base:     0x{pe.image_base:016x}")
    print(f"Entry Point:    RVA 0x{pe.entry_point_rva:08x} -> VA 0x{pe.entry_point_va:016x}")
    print(f"Sections:       {len(pe.sections)}")
    print(f"Imports:        {len(pe.imports)}")
    print(f"Exports:        {len(pe.exports)}")

    print("\n--- Sections ---")
    print(f"{'Name':<10} {'VirtAddr':<12} {'VirtSize':<10} {'RawOffset':<12} {'RawSize':<10} {'Flags':<8} {'Entropy':<6}")
    print("-" * 72)
    for s in pe.sections:
        flags = ("R" if s.is_readable else "-") + ("W" if s.is_writable else "-") + ("X" if s.is_executable else "-")
        print(f"{s.name:<10} 0x{s.virtual_address:08x}  0x{s.virtual_size:06x}    0x{s.raw_data_offset:08x}  0x{s.raw_data_size:06x}    {flags:<8} {s.entropy:.2f}")

    if pe.imports:
        print(f"\n--- Imports ({len(pe.imports)}) ---")
        by_dll = {}
        for imp in pe.imports:
            by_dll.setdefault(imp.dll_name, []).append(imp)
        for dll, imps in by_dll.items():
            print(f"  [{dll}] ({len(imps)} functions)")
            for imp in imps[:8]:
                sym = imp.name if imp.name else f"Ordinal #{imp.ordinal}"
                print(f"    - 0x{imp.iat_va:016x} (RVA 0x{imp.iat_rva:08x}): {sym}")
            if len(imps) > 8:
                print(f"    ... and {len(imps) - 8} more")

    if pe.exports:
        print(f"\n--- Exports ({len(pe.exports)}) ---")
        for exp in pe.exports[:10]:
            name = exp.name if exp.name else f"Ordinal #{exp.ordinal}"
            print(f"  - 0x{exp.va:016x} (RVA 0x{exp.rva:08x}): {name}")
        if len(pe.exports) > 10:
            print(f"  ... and {len(pe.exports) - 10} more")


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        return 1

    try:
        loader = PELoader(file_path)
    except Exception as exc:
        print(f"Error loading PE file: {exc}", file=sys.stderr)
        return 1

    if args.dump_loader:
        if args.format == "json":
            print(loader.loaded_pe.to_json())
        else:
            print_loader_stage_text(loader)
        return 0

    # Default action if no stage dump specified
    print(f"Loaded PE successfully: {file_path.name}")
    print(f"Machine: {loader.loaded_pe.machine}, Entry Point: 0x{loader.loaded_pe.entry_point_va:016x}")
    print("Run with --dump-loader (--format json/text) to inspect PE structures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

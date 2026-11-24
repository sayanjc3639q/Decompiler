"""Synthetic minimal x86-64 PE binary builder for testing without relying on external compilers."""

import struct

def build_minimal_pe64() -> bytes:
    """Constructs a strictly valid minimal 64-bit Windows PE executable in memory.
    
    Contains:
    - DOS Header ('MZ') with e_lfanew -> 0x80
    - PE Signature ('PE\\0\\0')
    - COFF Header for AMD64 (IMAGE_FILE_MACHINE_AMD64 = 0x8664) with 1 section (.text)
    - Optional Header 64-bit (Magic = 0x20B, PE32+)
    - ImageBase: 0x140000000
    - SectionAlignment: 0x1000
    - FileAlignment: 0x200
    - AddressOfEntryPoint: 0x1000
    - Section Table: '.text' (RVA 0x1000, Size 0x200, Executable/Readable)
    - Code payload: x86-64 instructions (mov eax, 42; ret)
    """
    dos_header = bytearray(0x80)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 0x3C, 0x80)  # e_lfanew = 128

    pe_sig = b'PE\x00\x00'

    # COFF File Header (20 bytes)
    # Machine = 0x8664 (AMD64), NumberOfSections = 1, TimeDateStamp = 0, PtrToSymbolTable = 0,
    # NumberOfSymbols = 0, SizeOfOptionalHeader = 240, Characteristics = 0x0022 (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
    coff_header = struct.pack(
        '<HHIIIHH',
        0x8664,  # Machine
        1,       # NumberOfSections
        0,       # TimeDateStamp
        0,       # PointerToSymbolTable
        0,       # NumberOfSymbols
        240,     # SizeOfOptionalHeader (112 header + 128 directories)
        0x0022   # Characteristics
    )

    # Optional Header PE32+ (240 bytes: 112 standard/NT fields + 16 data directories * 8 bytes = 240)
    magic = 0x020B  # PE32+ (64-bit)
    major_linker_ver = 14
    minor_linker_ver = 0
    size_of_code = 0x200
    size_of_initialized_data = 0
    size_of_uninitialized_data = 0
    entry_point_rva = 0x1000
    base_of_code = 0x1000
    image_base = 0x140000000
    section_alignment = 0x1000
    file_alignment = 0x200
    major_os_ver = 6
    minor_os_ver = 0
    major_img_ver = 0
    minor_img_ver = 0
    major_subsys_ver = 6
    minor_subsys_ver = 0
    win32_ver_val = 0  # Reserved1 in PE32+
    size_of_image = 0x2000
    size_of_headers = 0x200
    checksum = 0
    subsystem = 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)
    dll_characteristics = 0x8160
    size_of_stack_reserve = 0x100000
    size_of_stack_commit = 0x1000
    size_of_heap_reserve = 0x100000
    size_of_heap_commit = 0x1000
    loader_flags = 0
    number_of_rva_and_sizes = 16

    # Format from pefile: HBBIIIIIQIIHHHHHHIIIIHHQQQQII
    opt_header_fixed = struct.pack(
        '<HBBIIIIIQIIHHHHHHIIIIHHQQQQII',
        magic, major_linker_ver, minor_linker_ver, size_of_code,
        size_of_initialized_data, size_of_uninitialized_data, entry_point_rva, base_of_code,
        image_base, section_alignment, file_alignment,
        major_os_ver, minor_os_ver, major_img_ver, minor_img_ver, major_subsys_ver, minor_subsys_ver,
        win32_ver_val, size_of_image, size_of_headers, checksum,
        subsystem, dll_characteristics,
        size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit,
        loader_flags, number_of_rva_and_sizes
    )
    # 16 Data Directories of 8 bytes each (all zero for minimal)
    data_directories = b'\x00' * (16 * 8)
    opt_header = opt_header_fixed + data_directories

    # Section Table entry for .text (40 bytes)
    sec_name = b'.text\x00\x00\x00'
    sec_vsize = 0x200
    sec_va = 0x1000
    sec_raw_size = 0x200
    sec_raw_ptr = 0x200
    sec_relocs = 0
    sec_lineno = 0
    sec_num_relocs = 0
    sec_num_lineno = 0
    sec_chars = 0x60000020

    section_header = struct.pack(
        '<8sIIIIIIHHI',
        sec_name, sec_vsize, sec_va, sec_raw_size, sec_raw_ptr,
        sec_relocs, sec_lineno, sec_num_relocs, sec_num_lineno, sec_chars
    )

    headers = dos_header + pe_sig + coff_header + opt_header + section_header
    # Pad headers to FileAlignment (0x200)
    headers = headers.ljust(0x200, b'\x00')

    # .text section code:
    # 0x00: b8 2a 00 00 00  mov eax, 42
    # 0x05: c3              ret
    code_bytes = b'\xb8\x2a\x00\x00\x00\xc3'
    code_section = code_bytes.ljust(0x200, b'\x90')  # NOP-padded to 0x200

    return headers + code_section

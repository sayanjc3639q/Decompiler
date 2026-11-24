# RevEng: Educational x86-64 Windows PE Decompiler

**RevEng** is an educational, production-quality reverse engineering pipeline and decompiler for x86-64 Windows Portable Executable (`.exe` / `.dll`) binaries written in Python 3.11+.

Designed as both a CV showcase project and an in-depth learning vehicle, it emphasizes code clarity, rigorous type hinting, comprehensive reverse-engineering concept documentation, and stage-by-stage inspectability.

---

## 🎯 Architecture & Pipeline Overview

RevEng decomposes the decompilation process into modular, decoupled stages. Every stage accepts a typed dataclass and outputs an inspectable dataclass, serializable to both human-readable text and structured JSON:

```
PE Binary (.exe)
       │
       ▼
[1. PE Loader] ───────────────► Section mapping, virtual address resolution, IAT & exports
       │
       ▼
[2. Disassembler] ────────────► Linear sweep / recursive descent, instruction decoding (Capstone)
       │
       ▼
[3. CFG Recovery] ────────────► Basic blocks, control-flow edges, call graph (NetworkX)
       │
       ▼
[4. Intermediate Rep (IR)] ───► High-level SSA representation, expression trees, phi nodes
       │
       ▼
[5. Analysis Passes] ─────────► Dead code elimination, constant propagation, stack analysis
       │
       ▼
[6. Structuring] ─────────────► AST recovery, loop & condition structuring (minimal gotos)
       │
       ▼
[7. Type/Variable Recovery] ──► Calling conventions (Win64 ABI), stack variable slots, types
       │
       ▼
[8. C Code Emission] ─────────► Recompilable, clean ISO C output
```

---

## 📦 Project Structure

```
RevEng/
├── pyproject.toml              # Build config and dependency definitions
├── README.md                   # Living project documentation and concept notes
├── docs/                       # Architectural specifications and deep dives
├── samples/                    # Sample C programs and their compiled/built PEs
│   ├── simple.c                # Human-written C reference code
│   ├── simple.exe              # Target PE binary
│   ├── pe_builder.py           # Self-contained minimal PE64 builder
│   └── build_samples.py        # Sample generator script
├── src/
│   └── reveng/
│       ├── __init__.py
│       ├── cli.py              # Unified CLI with stage dump inspection flags
│       ├── loader/             # Stage 1: PE file parsing & memory layout
│       ├── disasm/             # Stage 2: x86-64 disassembly engine
│       ├── cfg/                # Stage 3: Control flow graph generation
│       ├── ir/                 # Stage 4: SSA intermediate representation
│       ├── analysis/           # Stage 5: Optimization & data-flow passes
│       ├── structuring/        # Stage 6: Control-flow restructuring (no-goto)
│       ├── types/              # Stage 7: Type inference & stack recovery
│       ├── codegen/            # Stage 8: Recompilable C emitter
│       └── ui/                 # Interactive inspection and visualization
└── tests/                      # Automated test suite (pytest)
    └── test_loader.py          # Phase 1 unit and integration tests
```

---

## 🚀 Phase 1: PE Loader

### What Was Built
- **`src/reveng/loader/models.py`**:
  - `SectionInfo`: Encapsulates section boundaries, permissions (Read/Write/Execute), file offsets, and Shannon entropy.
  - `ImportSymbol`: Encapsulates dynamically linked library imports and Import Address Table (IAT) virtual addresses.
  - `ExportSymbol`: Encapsulates exported function symbols and forwarders.
  - `LoadedPE`: The central immutable output dataclass containing the loaded binary's virtual memory map, entry points, architecture metadata, and RVA $\leftrightarrow$ VA conversion helpers.
- **`src/reveng/loader/loader.py`**:
  - `PELoader`: Parses raw file bytes or PE file paths using `pefile`, computes section layout, and exposes virtual address reading (`read_bytes_at_rva`, `read_bytes_at_va`, `get_text_section_bytes`).
- **`src/reveng/cli.py`**:
  - Command-line interface with `--dump-loader` supporting `--format text` and `--format json`.
- **`samples/pe_builder.py`**:
  - A standalone, pure-Python 64-bit PE builder capable of producing valid, minimal x86-64 executables without requiring an external C compiler toolchain.

---

### How It Works (Plain English)
When Windows launches an `.exe`, the OS loader does not simply dump the file into RAM. A PE binary contains specific layout instructions:
1. **Headers**: Specify architecture compatibility (x86-64 AMD64 vs x86 32-bit), preferred load address (`ImageBase`), entry point relative offset (`AddressOfEntryPoint`), and subsystem (Console vs GUI).
2. **Section Mapping**: Files on disk are organized into pages (`FileAlignment`, usually 512 bytes). In memory, sections expand into memory pages (`SectionAlignment`, typically 4096 bytes). `PELoader` simulates this mapping, translating any Relative Virtual Address (RVA) directly to the exact bytes corresponding to code or data.
3. **Symbol Extraction**: Locates dynamic dependencies (like `kernel32.dll`) and their imported APIs so later stages can turn raw function pointer calls into readable function names.

---

### 🧠 Reverse-Engineering Concepts & Glossary

| Term | Concept & Significance |
| :--- | :--- |
| **RVA (Relative Virtual Address)** | An address offset relative to the base address where the image is loaded into memory (`VA = ImageBase + RVA`). Using RVAs makes Position Independent Code and ASLR relocations possible. |
| **VA (Virtual Address)** | The absolute virtual memory address at runtime where a byte of code or data resides. |
| **ImageBase** | The default virtual address where the executable prefers to be loaded (standard for 64-bit Windows executables is `0x140000000`). |
| **IAT (Import Address Table)** | An array of pointers populated at load time by the Windows loader with the actual addresses of imported DLL functions. Indirect calls (`call qword ptr [rip + offset]`) jump through the IAT. |
| **Section Entropy** | A statistical measure of randomness (0.0 to 8.0) in a section's byte stream. High entropy ($> 7.0$) often indicates compressed code, encrypted payloads, or executable packers. |
| **.text Section** | The primary section containing executable machine instructions marked with `IMAGE_SCN_MEM_EXECUTE` and `IMAGE_SCN_MEM_READ`. |
| **.rdata Section** | Read-only initialized data, containing string literals, constant tables, runtime type information, and IAT structures. |
| **.data Section** | Writable initialized global variables. |

---

### 🛠️ How to Run & Inspect

1. **Run Unit Tests**:
   ```powershell
   $env:PYTHONPATH="src;."
   python -m pytest -v
   ```

2. **Inspect PE Loader Output on a Binary (Text Format)**:
   ```powershell
   $env:PYTHONPATH="src;."
   python -m reveng.cli samples/simple.exe --dump-loader
   ```

3. **Inspect PE Loader Output (JSON Format)**:
   ```powershell
   $env:PYTHONPATH="src;."
   python -m reveng.cli samples/simple.exe --dump-loader --format json
   ```

4. **Inspect a Real Windows Binary**:
   ```powershell
   $env:PYTHONPATH="src;."
   python -m reveng.cli C:\Windows\System32\notepad.exe --dump-loader
   ```

---

### ⚠️ Known Limitations (Phase 1)
- **Relocation Table (`.reloc`)**: Currently, base relocations (ASLR fixups) are parsed via `pefile` default mechanisms, but manual rebasing to non-preferred image bases is not yet needed since subsequent stages work on normalized RVAs.
- **Delay-Loaded Imports**: Only standard directory imports (`IMAGE_DIRECTORY_ENTRY_IMPORT`) are parsed in this phase; delay-load imports (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`) will be integrated if encountered in real-world samples.

---

### 📝 Reverse-Engineering Notes
- In 64-bit Windows PE (`PE32+`), pointers are 64-bit (`Q` in struct packing), and the optional header size is 240 bytes (112 bytes header + 128 bytes data directory entries). Unlike 32-bit PE (`PE32`), there is no `BaseOfData` field in the optional header.
- The entry point specified in `OPTIONAL_HEADER.AddressOfEntryPoint` is an RVA. To disassemble starting from the program entry point, downstream disassemblers must add `ImageBase` or query `read_bytes_at_rva(entry_point_rva)`.

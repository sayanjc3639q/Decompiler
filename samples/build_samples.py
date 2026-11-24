"""Build and save samples/simple.exe if not already present."""
from pathlib import Path
from samples.pe_builder import build_minimal_pe64

def generate_samples():
    out_dir = Path(__file__).parent
    exe_path = out_dir / "simple.exe"
    data = build_minimal_pe64()
    exe_path.write_bytes(data)
    print(f"Generated {exe_path} ({len(data)} bytes)")

if __name__ == "__main__":
    generate_samples()

"""Code reading, writing, and testing utilities."""
import os
import subprocess
import glob
from config import TARGET_DIR


def read_all_code() -> str:
    """Read all Python files in target/ directory."""
    parts = []
    for f in sorted(glob.glob(os.path.join(TARGET_DIR, "*.py"))):
        with open(f) as fh:
            parts.append(f"# === {os.path.basename(f)} ===\n{fh.read()}")
    return "\n\n".join(parts) if parts else "# (no code yet)"


def write_file(filename: str, content: str):
    """Write content to a file in target/."""
    path = os.path.join(TARGET_DIR, filename)
    os.makedirs(os.path.dirname(path) or TARGET_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def run_tests() -> tuple[bool, str]:
    """Run pytest on target/ and return (success, output)."""
    result = subprocess.run(
        ["python3", "-m", "pytest", TARGET_DIR, "-v", "--tb=short"],
        capture_output=True, text=True, timeout=60,
    )
    output = result.stdout + result.stderr
    return result.returncode == 0, output

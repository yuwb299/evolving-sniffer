"""Core evolution loop for the protocol analyzer project."""
import os
import subprocess
import json
from agent.models import call_llm
from agent.coder import read_all_code, write_file, run_tests
from agent.memory import load_memory, record, get_recent_failures
from config import TARGET_DIR

PROJECT_GOAL = """
Build a cross-platform network protocol analyzer (similar to Wireshark).

Architecture:
- **Main Program (Controller)**: Python-based, runs on Windows. Provides GUI/CLI interface,
  manages connected agents, aggregates and displays captured packets.
- **Linux Agent (Capture)**: Python-based, runs on Linux. Captures raw packets from network
  interfaces using raw sockets or scapy, sends captured data to the controller.

Protocols to support (progressive):
  Phase 1: Ethernet frame parsing, IP header parsing, TCP/UDP port extraction
  Phase 2: HTTP request/response parsing
  Phase 3: DNS query/response parsing
  Phase 4: HTTPS/TLS metadata (SNI, certificate info - not payload decryption)
  Phase 5: FTP command/response parsing
  Phase 6: SFTP (SSH) packet structure identification

Current target: Phase 1 - Implement basic packet capture (Linux agent) and frame parsing (main program).

Requirements:
  - Clean, well-documented Python code
  - Each module should have comprehensive pytest tests
  - Use dataclasses for packet structures
  - Support both live capture and pcap file reading
  - Modular design: separate protocol parsers, capture engine, and controller
"""

SYSTEM_PROMPT = f"""You are an expert network engineer and Python developer. You are building a protocol analyzer tool.

{PROJECT_GOAL}

You evolve the code iteratively. Each iteration you:
1. Read the current code state
2. Plan ONE concrete improvement or new feature
3. Write/modify the code files
4. Generate corresponding tests

Rules:
- Always write complete, runnable Python files (no placeholders)
- Every new function needs tests
- Use dataclasses for data structures
- Keep backwards compatibility - don't break existing tests
- Focus on one feature per iteration
- If recent iterations failed, try a different approach
"""


def evolve(iteration: int):
    """Run one evolution iteration."""
    print(f"\n{'='*60}")
    print(f"🧬 Evolution Iteration #{iteration}")
    print(f"{'='*60}\n")

    # Step 1: Read current state
    print("[1/6] 📖 Reading current code...")
    current_code = read_all_code()
    memory = load_memory()
    recent_failures = get_recent_failures(3)

    # Step 2: Plan and generate
    print("[2/6] 🧠 Planning and generating code...")
    context = f"""
## Current code state:
```
{current_code}
```

## Evolution history:
- Total iterations: {len(memory)}
- Recent failures: {json.dumps(recent_failures, indent=2) if recent_failures else 'None'}

## Task:
Plan ONE concrete improvement for this iteration. Then write the COMPLETE updated code files.

IMPORTANT RULES:
1. All files go directly in the target/ directory - NO subdirectories like src/ or tests/
2. Source files: target/packet_structures.py, target/ethernet_parser.py, etc.
3. Test files: target/test_packet_structures.py, target/test_ethernet_parser.py, etc.
4. All imports should be relative to target/ (e.g., `from packet_structures import ...`)

Output format - for each file, use:
---FILE: filename.py---
(complete file content)
---END FILE---

Include ALL files that need to exist (both source and test files).
If you're adding a new module, also keep all existing modules intact.
"""

    response = call_llm(SYSTEM_PROMPT, context, max_tokens=8192)

    # Step 3: Parse and write files
    print("[3/6] ✍️ Writing code files...")
    files_written = parse_and_write(response)
    print(f"   Written {len(files_written)} files: {files_written}")

    # Step 4: Run tests
    print("[4/6] 🧪 Running tests...")
    success, output = run_tests()
    print(f"   Test result: {'✅ PASS' if success else '❌ FAIL'}")
    if not success:
        print(f"   Test output (last 500 chars):\n{output[-500:]}")

    if not success:
        print(f"\n[5/6] 🔄 Tests failed, rolling back...")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(["git", "checkout", "--", "target/"], cwd=script_dir, capture_output=True)
        subprocess.run(["git", "clean", "-fd", "target/"], cwd=script_dir, capture_output=True)
        record(iteration, False, "Tests failed, rolled back", output[:500])
        print("   Rolled back successfully.")
        return False

    # Step 5: Commit
    print("[5/6] 📦 Committing changes...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    subprocess.run(["git", "add", "target/"], cwd=script_dir, capture_output=True)
    commit_result = subprocess.run(
        ["git", "commit", "-m", f"🧬 Auto evolution #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"],
        cwd=script_dir, capture_output=True, text=True,
    )
    committed = commit_result.returncode == 0
    if committed:
        print(f"   Committed: {commit_result.stdout.strip()[:100]}")
    else:
        print("   No changes to commit (code identical to previous).")

    # Step 6: Record
    print("[6/6] 📝 Recording experience...")
    record(iteration, True, f"Iteration #{iteration} successful", f"Files: {files_written}")
    return True


def parse_and_write(response: str) -> list:
    """Parse LLM response and extract files."""
    files = []
    lines = response.split("\n")
    current_file = None
    current_content = []

    for line in lines:
        if line.strip().startswith("---FILE:") and line.strip().endswith("---"):
            if current_file and current_content:
                write_file(current_file, "\n".join(current_content))
                files.append(current_file)
            current_file = line.strip().replace("---FILE:", "").replace("---", "").strip()
            current_content = []
        elif line.strip() == "---END FILE---":
            if current_file and current_content:
                write_file(current_file, "\n".join(current_content))
                files.append(current_file)
            current_file = None
            current_content = []
        elif current_file is not None:
            current_content.append(line)

    # Handle case where END FILE marker is missing
    if current_file and current_content:
        write_file(current_file, "\n".join(current_content))
        files.append(current_file)

    return files


if __name__ == "__main__":
    import sys
    from datetime import datetime
    # Determine iteration number from memory
    mem = load_memory()
    iteration = len(mem) + 1
    success = evolve(iteration)

    # Push to GitHub
    script_dir = os.path.dirname(os.path.abspath(__file__))
    push_result = subprocess.run(
        ["git", "push", "origin", "HEAD"],
        cwd=script_dir, capture_output=True, text=True,
    )
    print(f"\nGit push: {push_result.stdout.strip() or push_result.stderr.strip() or 'ok'}")
    print(f"\n{'✅' if success else '❌'} Iteration #{iteration} {'succeeded' if success else 'failed'}")
    sys.exit(0 if success else 1)

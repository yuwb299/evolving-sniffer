"""Evolution memory - track successes and failures."""
import json
import os
from datetime import datetime
from config import EVOLUTION_LOG, MEMORY_DIR


def load_memory() -> list:
    if not os.path.exists(EVOLUTION_LOG):
        return []
    with open(EVOLUTION_LOG) as f:
        return json.load(f)


def save_memory(log: list):
    os.makedirs(MEMORY_DIR, exist_ok=True)
    with open(EVOLUTION_LOG, "w") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)


def record(iteration: int, success: bool, summary: str, details: str = ""):
    log = load_memory()
    log.append({
        "iteration": iteration,
        "timestamp": datetime.now().isoformat(),
        "success": success,
        "summary": summary,
        "details": details[:500],
    })
    save_memory(log)


def get_success_count() -> int:
    return sum(1 for e in load_memory() if e["success"])


def get_recent_failures(n: int = 3) -> list:
    entries = load_memory()
    failures = [e for e in entries if not e["success"]]
    return failures[-n:]

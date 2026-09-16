"""Read-only WSL environment probe. No model calls or credential reads."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(argv):
    try:
        result = subprocess.run(
            argv, shell=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=15,
        )
        # Never include arbitrary stderr in reports.
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().root.expanduser().resolve()
    checks = {"root": str(root), "platform": sys.platform, "tools": {}}
    ok = sys.platform == "linux"
    for name in ("git", "python3", "node", "npm", "bwrap", "codex", "agy"):
        path = shutil.which(name)
        entry = {"path": path, "available": bool(path)}
        if path and name != "agy":
            code, output = run([path, "--version"])
            entry["version"] = output.splitlines()[0][:160] if code == 0 and output else "unverified"
        checks["tools"][name] = entry
        ok = ok and bool(path)
    git = checks["tools"]["git"]["path"]
    if git:
        code, output = run([git, "-C", str(root), "rev-parse", "--show-toplevel"])
        repository_matches = code == 0 and Path(output).resolve() == root
        checks["repository_root_matches"] = repository_matches
        ok = ok and repository_matches
        code, output = run([git, "-C", str(root), "rev-parse", "--verify", "HEAD"])
        checks["has_commit"] = code == 0
        code, output = run([git, "-C", str(root), "ls-files", "-z"])
        checks["tracked_file_count"] = len([p for p in output.split("\0") if p]) if code == 0 else None
    # Presence only; never print values or enumerate the entire environment.
    checks["api_key_variables_present"] = [
        name for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
        if os.environ.get(name)
    ]
    checks["note"] = (
        "Environment probe only. OAuth, model availability, tool restrictions and app E2E are NOT tested. "
        "Missing CLI may indicate PATH differences; do not reinstall automatically. "
        "Exclude API key variables from runner child environments."
    )
    checks["environment_ready"] = ok
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Demonstrate the checker using disposable logs and integrity state."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PROJECT = Path(__file__).resolve().parents[1]


def run(root, script, arguments, expected_code):
    result = subprocess.run(
        [sys.executable, "-B", str(PROJECT / script), *arguments],
        cwd=root, capture_output=True, text=True, timeout=10,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    print(f"Exit code: {result.returncode}\n")
    if result.returncode != expected_code:
        raise RuntimeError(f"Expected exit code {expected_code}.")


def main():
    with tempfile.TemporaryDirectory(prefix="integrity-demo-") as temporary:
        root = Path(temporary)
        logs = root / "logs"
        shutil.copytree(PROJECT / "examples" / "logs", logs)

        print("1. Create a temporary key and baseline")
        run(root, "key-gen.py", [], 0)
        run(root, "integrity-check.py", ["init", str(logs)], 0)

        print("2. Check unchanged logs")
        run(root, "integrity-check.py", ["check"], 0)

        print("3. Modify, add, and delete sample logs")
        with (logs / "app.log").open("a", encoding="utf-8") as file:
            file.write("2026-10-13 09:02:00 INFO New request\n")
        (logs / "new.log").write_text("New log file\n", encoding="utf-8")
        (logs / "archive" / "old.log").unlink()
        run(root, "integrity-check.py", ["check"], 1)

        print("4. Explicitly accept these sample changes")
        run(root, "integrity-check.py", ["update"], 0)
        run(root, "integrity-check.py", ["check"], 0)

        print("5. Change the baseline without updating its signature")
        with (root / "directory_baseline.json").open("ab") as file:
            file.write(b"\n")
        run(root, "integrity-check.py", ["check"], 2)

    print("Demo passed. Temporary files were removed.")


if __name__ == "__main__":
    main()

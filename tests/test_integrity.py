import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "integrity-check.py"
KEY_SCRIPT = PROJECT / "key-gen.py"
STATE_FILES = ("integrity.key", "directory_baseline.json", "directory_baseline.sig")
spec = importlib.util.spec_from_file_location("integrity_checker", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="integrity-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.log = self.logs / "app.log"
        self.log.write_text("Example log\n", encoding="utf-8")
        self.key = secrets.token_bytes(32)
        (self.root / "integrity.key").write_bytes(self.key)

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *map(str, arguments)],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )

    def initialize(self, target=None):
        result = self.run_cli("init", self.logs if target is None else target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def snapshot(self):
        return {
            name: (self.root / name).read_bytes()
            for name in STATE_FILES if (self.root / name).is_file()
        }

    def assert_state_unchanged(self, before):
        # Boolean assertions never display the temporary secret on failure.
        self.assertTrue(before == self.snapshot(), "Integrity state was changed.")

    def assert_check(self, code, label):
        before = self.snapshot()
        result = self.run_cli("check")
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertIn(label, result.stdout)
        self.assert_state_unchanged(before)

    def assert_rejected_without_writes(self, action="check"):
        before = self.snapshot()
        result = self.run_cli(action)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Error:", result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("UNCHANGED:", result.stdout)
        self.assert_state_unchanged(before)

    def sign_test_baseline(self, data):
        baseline = self.root / "directory_baseline.json"
        baseline.write_bytes(data)
        signature = hmac.new(self.key, data, hashlib.sha256).hexdigest()
        (self.root / "directory_baseline.sig").write_text(signature, encoding="utf-8")

    def test_unchanged_files(self):
        self.initialize()
        self.assert_check(0, "UNCHANGED:")

    def test_modified_file(self):
        self.initialize()
        self.log.write_text("Changed log\n", encoding="utf-8")
        self.assert_check(1, "MODIFIED:")

    def test_missing_file(self):
        self.initialize()
        self.log.unlink()
        self.assert_check(1, "MISSING:")

    def test_new_file(self):
        self.initialize()
        (self.logs / "new.log").write_text("New log\n", encoding="utf-8")
        self.assert_check(1, "NEW:")

    def test_missing_directory(self):
        self.initialize()
        self.log.unlink()
        self.logs.rmdir()
        self.assert_check(1, "MISSING TARGET:")

    def test_empty_directory(self):
        self.log.unlink()
        self.initialize()
        self.assert_check(0, "Baseline signature is valid.")

    def test_recursive_scanning(self):
        nested = self.logs / "archive" / "older"
        nested.mkdir(parents=True)
        nested_log = nested / "old.log"
        nested_log.write_text("Older log\n", encoding="utf-8")
        self.initialize()
        data = json.loads((self.root / "directory_baseline.json").read_text())
        self.assertIn(str(nested_log), data["files"])
        nested_log.write_text("Changed nested log\n", encoding="utf-8")
        self.assert_check(1, "MODIFIED: " + str(nested_log))

    def test_single_file(self):
        self.initialize(self.log)
        self.assert_check(0, "UNCHANGED:")
        self.log.write_text("Modified\n", encoding="utf-8")
        self.assert_check(1, "MODIFIED:")
        self.log.unlink()
        self.assert_check(1, "MISSING TARGET:")

    def test_manual_update(self):
        self.initialize()
        self.log.write_text("Authorized change\n", encoding="utf-8")
        (self.logs / "new.log").write_text("New\n", encoding="utf-8")
        self.assert_check(1, "MODIFIED:")
        result = self.run_cli("update")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "integrity.key").read_bytes() == self.key)
        data = (self.root / "directory_baseline.json").read_bytes()
        expected = hmac.new(self.key, data, hashlib.sha256).hexdigest()
        self.assertEqual((self.root / "directory_baseline.sig").read_text(), expected)
        self.assert_check(0, "UNCHANGED:")

    def test_update_accepts_deleted_file(self):
        self.initialize()
        self.log.unlink()
        self.assertEqual(self.run_cli("update").returncode, 0)
        self.assert_check(0, "Baseline signature is valid.")

    def test_single_file_update(self):
        self.initialize(self.log)
        self.log.write_text("Authorized\n", encoding="utf-8")
        self.assertEqual(self.run_cli("update").returncode, 0)
        self.assert_check(0, "UNCHANGED:")

    def test_update_missing_target_preserves_state(self):
        self.initialize(self.log)
        self.log.unlink()
        self.assert_rejected_without_writes("update")

    def test_tampered_baseline(self):
        self.initialize()
        baseline = self.root / "directory_baseline.json"
        baseline.write_bytes(baseline.read_bytes() + b" ")
        for action in ("check", "update"):
            with self.subTest(action=action):
                self.assert_rejected_without_writes(action)

    def test_wrong_key(self):
        self.initialize()
        (self.root / "integrity.key").write_bytes(secrets.token_bytes(32))
        self.assert_rejected_without_writes()

    def test_missing_state_files(self):
        self.initialize()
        for name in STATE_FILES:
            original = (self.root / name).read_bytes()
            for action in ("check", "update"):
                with self.subTest(file=name, action=action):
                    (self.root / name).unlink()
                    self.assert_rejected_without_writes(action)
                    (self.root / name).write_bytes(original)

    def test_invalid_key_lengths(self):
        self.initialize()
        for length in (0, 1, 31, 33, 64):
            (self.root / "integrity.key").write_bytes(secrets.token_bytes(length))
            for action in ("check", "update"):
                with self.subTest(length=length, action=action):
                    self.assert_rejected_without_writes(action)

    def test_invalid_signatures(self):
        self.initialize()
        for signature in (b"", b"0" * 64, b"a" * 63, b"g" * 64, b"a" * 64 + b"\n", b"\xff", "é".encode()):
            (self.root / "directory_baseline.sig").write_bytes(signature)
            for action in ("check", "update"):
                with self.subTest(size=len(signature), action=action):
                    self.assert_rejected_without_writes(action)

    def test_init_rejects_invalid_key_before_writing(self):
        for key in (b"", b"x" * 31, b"x" * 33):
            (self.root / "integrity.key").write_bytes(key)
            before = self.snapshot()
            self.assertEqual(self.run_cli("init", self.logs).returncode, 2)
            self.assert_state_unchanged(before)
        (self.root / "integrity.key").unlink()
        self.assertEqual(self.run_cli("init", self.logs).returncode, 2)
        self.assertFalse((self.root / "directory_baseline.json").exists())

    def test_init_refuses_existing_state(self):
        self.initialize()
        before = self.snapshot()
        self.assertEqual(self.run_cli("init", self.logs).returncode, 2)
        self.assert_state_unchanged(before)

    def test_init_refuses_orphan_signature(self):
        (self.root / "directory_baseline.sig").write_text("existing signature")
        before = self.snapshot()
        self.assertEqual(self.run_cli("init", self.logs).returncode, 2)
        self.assert_state_unchanged(before)

    def test_cli_validation(self):
        for arguments in ((), ("unknown",), ("init",), ("check", "extra"), ("update", "extra"), ("check", "--unknown")):
            with self.subTest(arguments=arguments):
                before = self.snapshot()
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage:", result.stderr)
                self.assert_state_unchanged(before)

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("update", result.stdout)

    def test_nonexistent_init_target(self):
        self.assertEqual(self.run_cli("init", self.root / "absent").returncode, 2)
        self.assertFalse((self.root / "directory_baseline.json").exists())

    def test_storage_inside_target_is_rejected(self):
        before = self.snapshot()
        self.assertEqual(self.run_cli("init", self.root).returncode, 2)
        self.assert_state_unchanged(before)
        self.assertEqual(self.run_cli("init", self.root / "integrity.key").returncode, 2)
        self.assert_state_unchanged(before)

    def test_existing_unsafe_target_is_rejected(self):
        data = {"directory": str(self.root), "algorithm": "SHA-256", "files": {}}
        self.sign_test_baseline(json.dumps(data).encode())
        self.assert_rejected_without_writes()
        self.assert_rejected_without_writes("update")

    def test_signed_invalid_baselines(self):
        examples = [
            b"not JSON", b"[]", b"{}",
            json.dumps({"directory": str(self.logs), "algorithm": "MD5", "files": {}}).encode(),
            json.dumps({"directory": "relative", "algorithm": "SHA-256", "files": {}}).encode(),
            json.dumps({"directory": str(self.logs), "algorithm": "SHA-256", "files": []}).encode(),
            json.dumps({"directory": str(self.logs), "algorithm": "SHA-256", "files": {str(self.log): "bad"}}).encode(),
        ]
        for data in examples:
            with self.subTest(size=len(data)):
                self.sign_test_baseline(data)
                self.assert_rejected_without_writes()

    def test_nested_symlink_is_skipped(self):
        (self.logs / "loop").symlink_to(self.logs, target_is_directory=True)
        self.initialize()
        self.assert_check(0, "UNCHANGED:")

    def test_symlink_target_is_rejected(self):
        link = self.root / "linked.log"
        link.symlink_to(self.log)
        self.assertEqual(self.run_cli("init", link).returncode, 2)
        self.assertFalse((self.root / "directory_baseline.json").exists())

    def test_key_generation_permissions_and_no_overwrite(self):
        (self.root / "integrity.key").unlink()
        command = [sys.executable, "-B", str(KEY_SCRIPT)]
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        key_path = self.root / "integrity.key"
        self.assertEqual(key_path.stat().st_size, 32)
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode) & 0o077, 0)
        before = key_path.read_bytes()
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(before == key_path.read_bytes(), "Key generator replaced the key.")

    @unittest.skipIf(os.geteuid() == 0, "Root bypasses ordinary file permissions.")
    def test_permission_errors(self):
        self.initialize()
        for path in [self.root / name for name in STATE_FILES] + [self.log, self.logs]:
            mode = stat.S_IMODE(path.stat().st_mode)
            try:
                path.chmod(0)
                for action in ("check", "update"):
                    with self.subTest(file=path.name, action=action):
                        result = self.run_cli(action)
                        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                        self.assertIn("Permission denied", result.stdout)
            finally:
                path.chmod(mode)

    def test_write_errors_return_two(self):
        # Simulated write failures work even when tests are run as root.
        for action, function in (("init", "save_directory_baseline"), ("update", "update_baseline")):
            arguments = [action, str(self.logs)] if action == "init" else [action]
            for error in (PermissionError("Permission denied"), OSError("Disk full")):
                with self.subTest(action=action, error=type(error).__name__):
                    with mock.patch.object(checker, function, side_effect=error):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.assertEqual(checker.main(arguments), 2)


if __name__ == "__main__":
    unittest.main()

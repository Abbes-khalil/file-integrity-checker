import argparse
import hashlib
import hmac
import json
import os
import stat
import sys


KEY_FILE = "integrity.key"
BASELINE_FILE = "directory_baseline.json"
SIGNATURE_FILE = "directory_baseline.sig"


def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def validate_storage_location(path):
    target = os.path.realpath(path)
    for name in (KEY_FILE, BASELINE_FILE, SIGNATURE_FILE):
        storage_path = os.path.realpath(name)
        if os.path.commonpath([target, storage_path]) == target:
            raise ValueError(
                f"{name} must stay outside the monitored target. "
                "Run from a separate storage directory."
            )


def hash_directory_files(directory):
    file_hashes = {}
    for name in os.listdir(directory):
        file_path = os.path.join(directory, name)
        mode = os.lstat(file_path).st_mode
        # Skip symbolic links and special files.
        if stat.S_ISREG(mode):
            file_hashes[file_path] = calculate_hash(file_path)
        elif stat.S_ISDIR(mode):
            file_hashes.update(hash_directory_files(file_path))
    return file_hashes


def collect_hashes(path):
    path = os.path.abspath(path)
    mode = os.lstat(path).st_mode
    if stat.S_ISREG(mode):
        return {path: calculate_hash(path)}
    if stat.S_ISDIR(mode):
        return hash_directory_files(path)
    raise ValueError("Target must be a regular file or directory, not a symbolic link.")


def load_key():
    with open(KEY_FILE, "rb") as file:
        key = file.read()
    if len(key) != 32:
        raise ValueError("integrity.key must be exactly 32 bytes long.")
    return key


def sign_baseline():
    key = load_key()
    with open(BASELINE_FILE, "rb") as file:
        baseline_bytes = file.read()
    return hmac.new(key, baseline_bytes, hashlib.sha256).hexdigest()


def save_baseline_signature():
    signature = sign_baseline()
    with open(SIGNATURE_FILE, "w", encoding="utf-8") as file:
        file.write(signature)
    print("Baseline signature saved.")


def verify_baseline_signature(baseline_bytes=None):
    key = load_key()
    if baseline_bytes is None:
        with open(BASELINE_FILE, "rb") as file:
            baseline_bytes = file.read()
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
        saved_signature = file.read()
    if len(saved_signature) != 64 or any(
        character not in "0123456789abcdef" for character in saved_signature
    ):
        raise ValueError("directory_baseline.sig must contain a 64-character SHA-256 HMAC.")
    calculated_signature = hmac.new(key, baseline_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(saved_signature, calculated_signature)


def load_baseline():
    with open(BASELINE_FILE, "rb") as file:
        baseline_bytes = file.read()
    if not verify_baseline_signature(baseline_bytes):
        raise ValueError("Baseline authentication failed. Operation refused.")
    # Parse the same bytes that were authenticated, rather than reopening the file.
    baseline_data = json.loads(baseline_bytes)
    if not isinstance(baseline_data, dict):
        raise ValueError("Baseline must be a JSON object.")
    target = baseline_data["directory"]
    files = baseline_data["files"]
    if not isinstance(target, str) or not os.path.isabs(target):
        raise ValueError("Baseline target must be an absolute path.")
    if baseline_data["algorithm"] != "SHA-256" or not isinstance(files, dict):
        raise ValueError("Baseline must use SHA-256 and contain a files object.")
    for path, digest in files.items():
        if (
            not os.path.isabs(path)
            or os.path.commonpath([target, path]) != target
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("Baseline contains an invalid file path or SHA-256 hash.")
    validate_storage_location(target)
    return baseline_data


def save_directory_baseline(path):
    load_key()
    validate_storage_location(path)
    if os.path.lexists(BASELINE_FILE) or os.path.lexists(SIGNATURE_FILE):
        raise FileExistsError("Baseline or signature already exists.")
    baseline_data = {
        # Keep this field name for compatibility; the target can also be a file.
        "directory": os.path.abspath(path),
        "algorithm": "SHA-256",
        "files": collect_hashes(path),
    }
    with open(BASELINE_FILE, "x", encoding="utf-8") as file:
        json.dump(baseline_data, file, indent=4)
    save_baseline_signature()


def baseline_check(baseline_data=None):
    if baseline_data is None:
        baseline_data = load_baseline()
    expected_files = baseline_data["files"]
    target_path = baseline_data["directory"]
    changes_found = False

    try:
        current_files = collect_hashes(target_path)
    except FileNotFoundError:
        # A file disappearing during scanning is an execution error.
        if os.path.lexists(target_path):
            raise
        print(f"MISSING TARGET: {target_path}")
        for file_path in expected_files:
            print(f"MISSING: {file_path}")
        return True

    for file_path, expected_hash in expected_files.items():
        if file_path not in current_files:
            print(f"MISSING: {file_path}")
            changes_found = True
        elif current_files[file_path] == expected_hash:
            print(f"UNCHANGED: {file_path}")
        else:
            print(f"MODIFIED: {file_path}")
            changes_found = True

    for file_path in current_files:
        if file_path not in expected_files:
            print(f"NEW: {file_path}")
            changes_found = True
    return changes_found


def update_baseline():
    baseline_data = load_baseline()
    baseline_data["files"] = collect_hashes(baseline_data["directory"])
    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(baseline_data, file, indent=4)
    save_baseline_signature()
    print("Baseline updated successfully.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create, check, or explicitly update an HMAC-protected baseline."
    )
    parser.add_argument("action", choices=["init", "check", "update"])
    parser.add_argument("path", nargs="?", help="File or directory required for init.")
    args = parser.parse_args(argv)
    if args.action == "init" and args.path is None:
        parser.error("Path is required for 'init'.")
    if args.action in ("check", "update") and args.path is not None:
        parser.error("'check' and 'update' use the saved target; do not provide a path.")

    try:
        if args.action == "init":
            save_directory_baseline(args.path)
            print("Baseline saved successfully.")
        elif args.action == "check":
            baseline = load_baseline()
            print("Baseline signature is valid. Proceeding with integrity check.")
            print("ALGORITHM USED:", baseline["algorithm"])
            print("TARGET PATH:", baseline["directory"])
            return 1 if baseline_check(baseline) else 0
        else:
            update_baseline()
        return 0
    except json.JSONDecodeError:
        print("Error: directory_baseline.json is not valid JSON.")
    except KeyError as error:
        print(f"Error: Baseline format is incompatible. Missing field: {error}")
    except (OSError, ValueError, TypeError) as error:
        print(f"Error: {error}")
    return 2


if __name__ == "__main__":
    sys.exit(main())

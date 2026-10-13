# Log integrity checker

A beginner Python project that detects changes to log files using SHA-256
hashes and protects its saved baseline with an HMAC-SHA-256 signature.

## Installation

Use Linux or another Unix-like system with Python 3.8 or newer. Only Python's
standard library is used; there are no packages to install.

Download or clone this repository, open its directory, and check Python:

```bash
python3 --version
```

The main script is `integrity-check.py`. `key-gen.py` creates the secret key.

## Try the demonstration first

From the project directory:

```bash
python3 -B examples/demo.py
```

The demo copies the sample logs into a temporary directory and creates a
separate temporary key, baseline, and signature. It never uses your real
integrity state or displays a key. It demonstrates:

1. Creating a key and baseline.
2. Checking unchanged logs: exit code `0`.
3. Detecting a modified log, a deleted nested log, and a new log: exit code `1`.
4. Explicitly accepting changes with `update`, then checking again: `0`.
5. Refusing a tampered baseline: exit code `2`.

All demo files are automatically removed afterward.

## Create a baseline

The key, baseline, and signature are stored in the **current working directory**.
Keep that directory outside the file or directory you want to monitor.

For a new practice baseline, run these commands from the project directory:

```bash
project_dir="$PWD"
mkdir -p .integrity-state
cd .integrity-state
python3 "$project_dir/key-gen.py"
python3 "$project_dir/integrity-check.py" init "$project_dir/examples/logs"
```

`key-gen.py` generates a random 32-byte key and refuses to replace an existing
key. `init` validates the key before writing. It refuses to overwrite an existing
baseline or signature.

To monitor one file instead, pass its absolute path to `init`. Each storage
directory holds one baseline for one target. Use another storage directory for
another target.

## Check logs

Continue from the same storage directory:

```bash
python3 "$project_dir/integrity-check.py" check
echo "Exit code: $?"
```

The baseline is authenticated before its contents are used. Missing keys,
baselines, or signatures, invalid key lengths, malformed signatures, and failed
authentication produce an error. Checking never creates or rewrites the key,
baseline, or signature.

| Label | Meaning |
| --- | --- |
| `UNCHANGED` | The current file hash matches the baseline. |
| `MODIFIED` | The file contents have changed. |
| `MISSING` | A recorded file no longer exists. |
| `NEW` | A file exists that was not recorded. |
| `MISSING TARGET` | The entire monitored target is gone. |

Directories are scanned recursively. Nested symbolic links and special files
are skipped; a symbolic link or special file cannot be used as the top-level
target. Empty directories are supported. A file disappearing during a scan is
an execution error; run the check again once the target is stable.

## Manually accept authorized changes

Review the changes and establish that the current logs are trusted, then run:

```bash
python3 "$project_dir/integrity-check.py" update
python3 "$project_dir/integrity-check.py" check
```

`update` authenticates the existing baseline, collects current hashes for its
saved target, replaces the baseline, and regenerates its HMAC with the existing
key. It accepts modified, new, and deleted files. It refuses an absent target or
an unauthenticated baseline. An update cannot recover a baseline with an invalid
signature or a lost key.

Neither `check` nor `update` takes a path argument; both use the saved target.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Initialization/update succeeded, or a check found no changes. |
| `1` | A check detected modified, missing, or new files. |
| `2` | CLI, execution, storage, format, or authentication error. |

## Baseline format and storage

The local files are `integrity.key`, `directory_baseline.json`, and
`directory_baseline.sig`. The signature is a 64-character hexadecimal HMAC
computed over the exact bytes of the JSON file.

One JSON format is used for both files and directories:

```json
{
    "directory": "/absolute/path/to/target",
    "algorithm": "SHA-256",
    "files": {
        "/absolute/path/to/target/app.log": "64-character SHA-256 hash"
    }
}
```

The `directory` field retains its original name for compatibility, but can also
hold a single file's path. The example hash above is a placeholder.

The checker rejects monitored targets that contain the key, baseline, or
signature. It resolves symbolic links when checking this location rule.

On Unix, the key generator creates the key with owner-only read/write permissions
(`600`). As a deliberate simplification, baseline and signature permissions are
left to the system's default creation rules; this version does not enforce
owner-only permissions on them or validate permissions on an existing key.
Use a storage directory accessible only to your account for private logs.

## Tests

From the project directory:

```bash
python3 -B -m unittest discover -s tests -v
```

Tests use disposable directories and temporary keys. They cover unchanged,
modified, missing, and new files; recursive scanning; single-file targets;
manual updates; baseline tampering; missing and invalid integrity state;
permission errors; storage separation; and CLI validation. Actual permission
checks are skipped when run as root, which bypasses ordinary file permissions;
simulated write-error tests still run.

## Limitations

- Normal log appends and rotation change hashes. A mismatch means contents
  changed, not that an attacker changed them.
- The initial baseline must be trusted. The checker cannot determine whether
  existing logs were already altered before initialization.
- HMAC protection depends on keeping the key secret. Someone with the key can
  forge a valid signature for a changed baseline. It does not encrypt the logs
  or baseline.
- Losing the key prevents authentication of the old baseline. There is no
  automatic replacement or recovery during a check.
- Writes to the baseline and signature are separate, not transactional. A write
  failure or interruption can leave an incomplete or mismatched pair. Keep a
  trusted backup before manual updates; do not run simultaneous commands.
- There is no locking or guarantee that logs stay unchanged while being hashed.
  Use stable sample files or a consistent snapshot when that matters.
- Metadata such as ownership and permissions is not monitored. Skipped symbolic
  links and special files are not protected by this checker.
- Paths in the baseline are absolute; moving the target requires a new baseline
  in a separate storage directory.
- The location rule does not detect hard-link aliases of integrity state.

## Preparing for GitHub

`.gitignore` excludes secret keys, local baselines/signatures, integrity storage,
and Python cache files. Ignoring a file does not untrack a file already committed
or remove it from Git history. If a key has ever been published, treat it as
exposed.

When Git is installed, inspect the files and stage only the project sources:

```bash
git init
git add integrity-check.py key-gen.py tests examples README.md LICENSE .gitignore
git diff --cached --name-only
git commit -m "Complete log integrity checker with HMAC and tests"
```

Before committing, confirm the staged file list contains no `integrity.key`,
`directory_baseline.json`, or `directory_baseline.sig`. Then create a repository
on GitHub and follow its instructions for connecting and pushing this local
repository. This project does not upload or publish anything automatically.

## License

MIT; see [LICENSE](LICENSE).

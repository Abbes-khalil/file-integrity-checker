import os
import secrets
import sys

key_path = "integrity.key"

try:
    descriptor = os.open(
        key_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )

    with os.fdopen(descriptor, "wb") as file:
        file.write(secrets.token_bytes(32))

    print("Secret key created.")

except FileExistsError:
    print("Key already exists. Keeping the original.")
except OSError as error:
    print(f"Error: Cannot create secret key: {error}")
    sys.exit(2)

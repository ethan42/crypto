# Short example showcasing the use of PKBDF2 to store and verify passwords
# Credit: https://til.simonwillison.net/python/password-hashing-with-pbkdf2
# See also django: https://github.com/django/django/blob/136ec9b62bd0b105f281218d7cad54b7db7a4bab/django/contrib/auth/hashers.py#L247
# Storage format: algorithm$iterations$salt$hash

import argparse
import base64
import hashlib
import secrets
import sys

ALGORITHM = "pbkdf2_sha256"


def hash_password(password, salt=None, iterations=1):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


def main():
    parser = argparse.ArgumentParser(description="Store and verify passwords using PBKDF2.")
    parser.add_argument("password", help="Password to store")
    parser.add_argument(
        "--password-hash",
        help="Stored password hash to verify against",
        default=None,
    )
    args = parser.parse_args()

    if args.password_hash:
        if verify_password(args.password, args.password_hash):
            print("Password verified.")
        else:
            print("Password verification failed.")
            sys.exit(1)
    else:
        password_hash = hash_password(args.password)
        print("Password hash:", password_hash)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

"""Quick script to encrypt and decrypt a message using base58 encoding.

Security through obscurity works?
"""

import argparse
import base58


def encrypt(plaintext):
    """Encode the message using base58."""
    return base58.b58encode(plaintext.encode())


def decrypt(ciphertext):
    """Decode the ciphertext using base58."""
    return base58.b58decode(ciphertext).decode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt and decrypt a message using base58 encoding.")
    parser.add_argument("message", help="Message to encrypt")
    parser.add_argument("-d", "--decrypt", help="Decrypt the message", action="store_true")
    args = parser.parse_args()

    if args.decrypt:
        plaintext = decrypt(args.message)
        print(f"Decrypted message: {plaintext}")
    else:
        ciphertext = encrypt(args.message)
        print(f"Encrypted message: {ciphertext.decode()}")

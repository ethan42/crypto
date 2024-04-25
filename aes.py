#!/usr/bin/env python3

"""Encrypt and decrypt a string up to 16 bytes using AES in ECB mode."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import argparse

def encrypt_ecb(data, key):
    """Encrypt data using AES in ECB mode with the provided key."""
    # Ensure the key length is valid for AES (128, 192, or 256 bits)
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be either 16, 24, or 32 bytes long")

    # Create an AES ECB cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    return encrypted_data


def decrypt_ecb(data, key):
    """Decrypt data using AES in ECB mode with the provided key."""
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be either 16, 24, or 32 bytes long")

    # Create an AES ECB cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(data) + decryptor.finalize()

    return decrypted_data


def main():
    parser = argparse.ArgumentParser(description="Encrypt a string up to 16 bytes using AES in ECB mode.")
    parser.add_argument("data", help="Data to encrypt (up to 16 bytes)")
    parser.add_argument("key", help="Key to use for encryption (16, 24, or 32 bytes)")
    parser.add_argument("-d", "--decrypt", help="Decrypt the data", action="store_true")
    args = parser.parse_args()

    if args.decrypt:
        # unhex the data from the ciphertext
        ciphertext = bytes.fromhex(args.data)
        key = args.key + " " * (16 - len(args.key))
        decrypted_data = decrypt_ecb(ciphertext, key.encode())
        print(f"Decrypted data: {decrypted_data}")
    else:
        plaintext = args.data + " " * (16 - len(args.data))
        key = args.key + " " * (16 - len(args.key))

        encrypted_data = encrypt_ecb(plaintext.encode(), key.encode())
        print(f"Encrypted data: {encrypted_data.hex()}")


if __name__ == "__main__":
    main()
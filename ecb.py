#!/usr/bin/env python3
"""Toy program to encrypt BMP pixel data using AES in ECB mode."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import argparse
import os


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


def main():

    parser = argparse.ArgumentParser(description="Encrypt BMP pixel data using AES in ECB mode.")
    parser.add_argument("bmpfile", help="BMP file to encrypt")
    parser.add_argument("-o", "--output", help="Output file to save the encrypted BMP data", default="output.bmp")
    parser.add_argument("--header-length", help="Length of the BMP header in bytes", type=int, default=54)
    args = parser.parse_args()

    key = os.urandom(16)

    with open(args.bmpfile, "rb") as f:
        data = f.read()

    header = data[:args.header_length]
    rest = data[args.header_length:]

    # Padding data to make it a multiple of 16 bytes
    padding_length = 16 - len(rest) % 16
    rest += bytes([padding_length] * padding_length)

    # Encrypt the data
    encrypted_rest = encrypt_ecb(rest, key)

    with open(args.output, "wb") as f:
        f.write(header + encrypted_rest)



if __name__ == "__main__":
    main()

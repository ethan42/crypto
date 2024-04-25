#!/usr/bin/env python3
"""Small program that generates sequences of three messages with different
probabilities and encrypts them using OTP."""

import argparse
import secrets
import time

MESSAGES = [
    b"ok",
    b"hi",
    b"no"
]

def alice_generate_message():
    """Generate one of the following messages with different probabilities:

    - "ok" with probability 0.5
    - "hi" with probability 0.25
    - "no" with probability 0.25

    Encrypt the message using OTP and return the message, key, and ciphertext.
    """

    num = secrets.randbelow(100)
    if num >= 50:
        msg = MESSAGES[0]
    elif num >= 25:
        msg = MESSAGES[1]
    else:
        msg = MESSAGES[2]

    key = secrets.token_bytes(len(msg))
    ciphertext = bytes([a ^ b for a, b in zip(msg, key)])
    return msg, key, ciphertext


def main():
    parser = argparse.ArgumentParser(description="Encrypt messages using OTP.")
    parser.add_argument("-i", "--interactive", help="Interactive mode", action="store_true")
    parser.add_argument("-t", "--time", help="Time between messages in seconds", type=float, default=0.3)
    parser.add_argument("-s", "--show-all", help="Show all messages", action="store_true")
    args = parser.parse_args()

    if args.interactive:
        while True:
            msg, key, ciphertext = alice_generate_message()
            if not args.show_all:
                while ciphertext not in MESSAGES:
                    msg, key, ciphertext = alice_generate_message()
            print(f"ciphertext: {repr(ciphertext):<16}")
            input("What do you think was the message? (bet)")
            print(f"msg: {repr(msg)}, ciphertext: {repr(ciphertext):<16} (key: {repr(key)})")
    else:
        while True:
            msg, key, ciphertext = alice_generate_message()
            print(f"msg: {repr(msg)}, ciphertext: {repr(ciphertext):<16} (key: {repr(key)})")
            time.sleep(args.time)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")

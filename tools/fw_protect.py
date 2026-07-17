#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool
"""
import argparse
import struct

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Signature import eddsa


def protect_firmware(infile, outfile, version, message):
    with open(infile, "rb") as fp:
        firmware = fp.read()

    with open("secret_build_output.txt", "rb") as f:
        blob = f.read()
    key = blob[:32]
    sk = ECC.construct(curve="Ed25519", seed=blob[32:64])

    # Null keeps an empty release message legal: msg_len is 1, never 0.
    msg = message.encode() + b"\x00"
    aad = struct.pack("<HHH", version, len(firmware), len(msg))

    # Nonce is per image: the Poly1305 key derives from key+nonce and must never repeat.
    nonce = get_random_bytes(12)
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(firmware + msg)

    # Sign everything but the signature itself, so a key leak still cannot forge.
    sig = eddsa.new(sk, "rfc8032").sign(aad + nonce + tag + ct)

    with open(outfile, "wb") as f:
        f.write(aad + nonce + tag + sig + ct)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Protect Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)

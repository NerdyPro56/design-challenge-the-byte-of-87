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
    msg = message.encode() + b"\x00"
    if len(firmware) == 0 or len(firmware) > 30720:
        raise ValueError("firmware must be 1 to 30720 bytes")
    if len(msg) > 1025:
        raise ValueError("message must be at most 1024 encoded bytes")
    if version < 0 or version > 0xFFFF:
        raise ValueError("version must be 0 to 65535")

    with open("secret_build_output.txt", "rb") as f:
        blob = f.read()          # factory secrets from bl_build
    key = blob[:32]              # fw_key
    sk = ECC.construct(curve="Ed25519", seed=blob[32:64]) # signing seed, factory only

    aad = struct.pack("<HHH", version, len(firmware), len(msg)) # signed + tag-covered metadata

    nonce = get_random_bytes(12) # per image; reuse under one key breaks confidentiality and the tag
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad)                # bind metadata into the tag
    ct, tag = c.encrypt_and_digest(firmware + msg)

    sig = eddsa.new(sk, "rfc8032").sign(aad + nonce + tag + ct) # covers all but the sig itself

    with open(outfile, "wb") as f:
        f.write(aad + nonce + tag + sig + ct) # 98-byte header then ciphertext


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Protect Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)

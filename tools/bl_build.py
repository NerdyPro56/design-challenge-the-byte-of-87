#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

Generates the factory secrets, provisions the bootloader source with them, and
builds the bootloader.
"""
import os
import pathlib
import subprocess
import sys

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def make_bootloader() -> bool:
    # fw_key protects firmware in transit; the Ed25519 keypair signs it.
    key = get_random_bytes(32)
    sk = ECC.generate(curve="Ed25519")
    seed = sk.seed
    pub = sk.public_key().export_key(format="raw")

    # Public values into the bootloader, private seed only into the factory secret file.
    with open(os.path.join(BOOTLOADER_DIR, "inc", "secrets.h"), "w") as f:
        f.write("#define FW_KEY {%s}\n" % ",".join(hex(b) for b in key))
        f.write("#define ED25519_PUB {%s}\n" % ",".join(hex(b) for b in pub))
    with open(os.path.join(REPO_ROOT, "tools", "secret_build_output.txt"), "wb") as f:
        f.write(key + seed)

    os.chdir(BOOTLOADER_DIR)

    # Default locked; a developer sets ECTF_LOCK=0 to build a board that keeps its debug port.
    lock = os.environ.get("ECTF_LOCK", "1")

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make LOCK=%s" % lock, shell=True)

    return status == 0


if __name__ == "__main__":
    if not make_bootloader():
        sys.exit(1)

#!/usr/bin/env python3
# Fault-injection regression for F-1: a single value-fault on the version floor must
# NOT roll back to v1. cur_floor is re-read at each gate, so corrupting one read is caught;
# only corrupting every read commits, which is the intended multi-fault cost.
# Toolchain-independent: the `bl cur_floor` call sites are found by disassembling the built
# binary, and each faulted call has its return value (r0) overwritten with 1.
import struct, subprocess, sys, os, tempfile, shutil
sys.path.insert(0, os.path.dirname(__file__))
import emu
from unicorn.arm_const import UC_ARM_REG_R0

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY = sys.executable
HERE = tempfile.mkdtemp()
AXF = REPO + "/bootloader/bin/bootloader.axf"
BOOT_MAGIC = 0x544F4F42
METADATA_BASE, MIN_VER_BASE = 0xFC00, 0xF800
FLOOR2 = [(MIN_VER_BASE, struct.pack("<I", 2))] # device already at floor 2

def tool(name):
    for c in (name, "/Applications/ArmGNUToolchain/15.2.rel1/arm-none-eabi/bin/" + name):
        p = shutil.which(c) or (c if os.path.exists(c) else None)
        if p:
            return p
    sys.exit(name + " not found on PATH")

def floor_return_sites():
    out = subprocess.check_output([tool("arm-none-eabi-objdump"), "-d", AXF]).decode()
    sites = []
    for line in out.splitlines():
        if "\tbl\t" in line and "<cur_floor>" in line:
            addr = int(line.strip().split(":")[0], 16)
            sites.append(addr + 4) # return address after the 4-byte bl; r0 = floor here
    return sites

SITES = floor_return_sites()
if not SITES:
    sys.exit("no cur_floor call sites found")

def set_floor_one(uc):
    uc.reg_write(UC_ARM_REG_R0, 1) # this floor read returns 1 so v1 is not below it

def v1_image():
    fw = bytes((i * 9 + 5) & 0xff for i in range(1024))
    with open(HERE + "/v1.bin", "wb") as f:
        f.write(fw)
    subprocess.check_call([PY, "fw_protect.py", "--infile", HERE + "/v1.bin",
                           "--outfile", HERE + "/v1p.bin", "--version", "1",
                           "--message", "rollback"], cwd=REPO + "/tools")
    with open(HERE + "/v1p.bin", "rb") as f:
        return f.read()

def wire(blob):
    hdr, ct = blob[:98], blob[98:]
    s = b"U" + hdr
    for i in range(0, len(ct), 256):
        c = ct[i:i+256]
        s += struct.pack(">H", len(c)) + c
    return s

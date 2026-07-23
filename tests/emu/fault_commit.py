#!/usr/bin/env python3
# A single skip of the `magic = BOOT_MAGIC ^ diff` step must not commit a bad image;
# the record write is gated on diff==0. XOR site found by disassembly, toolchain-independent.
import struct, subprocess, sys, os, tempfile, shutil
sys.path.insert(0, os.path.dirname(__file__))
import emu
from unicorn.arm_const import UC_ARM_REG_R0

def regnum(name):
    return UC_ARM_REG_R0 + int(name.strip().strip(",").lstrip("r"))

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY = sys.executable
HERE = tempfile.mkdtemp()
AXF = REPO + "/bootloader/bin/bootloader.axf"
BOOT_MAGIC = 0x544F4F42
METADATA_BASE = 0xFC00
FLOOR2 = [(MIN_VER_BASE := 0xF800, struct.pack("<I", 2))]

def tool(name):
    for c in (name, "/Applications/ArmGNUToolchain/15.2.rel1/arm-none-eabi/bin/" + name):
        p = shutil.which(c) or (c if os.path.exists(c) else None)
        if p:
            return p
    sys.exit(name + " not found on PATH")

def is_hex4(t):
    return len(t) == 4 and all(c in "0123456789abcdef" for c in t)

def commit_xor_site():
    out = subprocess.check_output([tool("arm-none-eabi-objdump"), "-d", AXF]).decode()
    lines = out.splitlines()
    infn = False
    last_eor = None
    for i, ln in enumerate(lines):
        if "<load_firmware>:" in ln:
            infn = True
            continue
        if not infn:
            continue
        if ln and not ln[0].isspace() and ">:" in ln:
            break
        parts = ln.split(":", 1)
        if len(parts) != 2:
            continue
        try:
            addr = int(parts[0].strip(), 16)
        except ValueError:
            continue
        toks = parts[1].split()
        nbytes = 2 * sum(1 for t in toks if is_hex4(t)) # thumb: 1 word=2B, 2 words=4B
        rest = [t for t in toks if not is_hex4(t)]
        mnem = rest[0] if rest else ""
        if mnem.startswith("eor") and len(rest) > 1 and rest[1].startswith("r"):
            last_eor = (addr, nbytes, regnum(rest[1])) # dest reg of the magic XOR
        if "program_flash" in ln and "#64512" in "".join(lines[max(0, i-6):i]):
            return last_eor
    return last_eor

SITE = commit_xor_site()
if not SITE:
    sys.exit("commit XOR site not found")
ADDR, SIZE, DST = SITE

def skip(uc):
    uc.reg_write(DST, BOOT_MAGIC) # eors executed, then undo it: models the XOR being skipped, diff intact

def bad_image():
    fw = bytes((i * 7 + 3) & 0xff for i in range(1024))
    with open(HERE + "/f.bin", "wb") as f:
        f.write(fw)
    subprocess.check_call([PY, "fw_protect.py", "--infile", HERE + "/f.bin",
                           "--outfile", HERE + "/fp.bin", "--version", "3",
                           "--message", "attack"], cwd=REPO + "/tools")
    b = bytearray(open(HERE + "/fp.bin", "rb").read())
    b[200] ^= 1 # break the signature and the tag: diff != 0
    return bytes(b)

def wire(blob):
    hdr, ct = blob[:98], blob[98:]
    s = b"U" + hdr
    for i in range(0, len(ct), 256):
        c = ct[i:i+256]
        s += struct.pack(">H", len(c)) + c
    return s

def committed(hooks):
    r = emu.run(wire(bad_image()), preload_flash=FLOOR2, code_hooks=hooks)
    magic = struct.unpack("<I", r["flash"][METADATA_BASE+8:METADATA_BASE+12])[0]
    return magic == BOOT_MAGIC

print(f"commit XOR at 0x{ADDR:04x} (size {SIZE})")
results = []
for label, hooks, want in (("no fault", [], False), ("skip XOR", [(ADDR + SIZE, skip)], False)):
    got = committed(hooks)
    print(f"{label:>9}: bad image committed = {got}  (want {want})")
    results.append(got is want)

print("PASS" if all(results) else "FAIL", f"({sum(results)}/{len(results)})")
sys.exit(0 if all(results) else 1)

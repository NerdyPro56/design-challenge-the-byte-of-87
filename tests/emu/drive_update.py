#!/usr/bin/env python3
# fw_update wire protocol through the emulated bootloader, then checks flash
import struct, subprocess, sys, os, tempfile
sys.path.insert(0, os.path.dirname(__file__))
import emu

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PY = sys.executable
HERE = tempfile.mkdtemp()
FRAME = 256
BOOT_MAGIC = 0x544F4F42
FW_BASE, METADATA_BASE, MIN_VER_BASE = 0x10000, 0xFC00, 0xF800

def protect(version, message, fw_bytes):
    with open(HERE + "/fw.bin", "wb") as f:
        f.write(fw_bytes)
    subprocess.check_call([PY, "fw_protect.py", "--infile", HERE + "/fw.bin",
                           "--outfile", HERE + "/protected.bin", "--version", str(version),
                           "--message", message], cwd=REPO + "/tools")
    with open(HERE + "/protected.bin", "rb") as f:
        return f.read()

def wire(blob):
    # 'U' + 98-byte header + 256-byte frames
    hdr, ct = blob[:98], blob[98:]
    s = b"U" + hdr
    for i in range(0, len(ct), FRAME):
        chunk = ct[i:i+FRAME]
        s += struct.pack(">H", len(chunk)) + chunk
    return s

def check(label, version, message, fw_bytes, preload=None, expect_commit=True):
    blob = protect(version, message, fw_bytes)
    r = emu.run(wire(blob), preload_flash=preload)
    fl = r["flash"]
    magic = struct.unpack("<I", fl[METADATA_BASE+8:METADATA_BASE+12])[0]
    rec_ver, rec_size, rec_msg = struct.unpack("<HHH", fl[METADATA_BASE:METADATA_BASE+6])
    fw_region = fl[FW_BASE:FW_BASE+len(fw_bytes)]
    msg_region = fl[FW_BASE+len(fw_bytes):FW_BASE+len(fw_bytes)+len(message)+1]
    ratchet = [struct.unpack("<I", fl[MIN_VER_BASE+4*i:MIN_VER_BASE+4*i+4])[0] for i in range(4)]
    oks = r["uart_out"].count(0x00)
    print(f"\n{label}")
    if r["err"]:
        print("  emu err:", r["err"][0], "PC=0x%08x" % r["err"][1])
    print(f"  magic=0x{magic:08x} (want 0x{BOOT_MAGIC:08x} = {'MATCH' if magic==BOOT_MAGIC else 'NO'})")
    print(f"  record ver={rec_ver} size={rec_size} msg_len={rec_msg}")
    print(f"  firmware region matches plaintext: {fw_region == fw_bytes}")
    print(f"  message region: {bytes(msg_region)!r}")
    print(f"  ratchet[0:4]={[hex(x) for x in ratchet]}")
    print(f"  OK bytes seen: {oks}")
    committed = (magic == BOOT_MAGIC)
    ok = committed == expect_commit
    if expect_commit:
        ok = ok and fw_region == fw_bytes and rec_size == len(fw_bytes)
    print(f"  => {'PASS' if ok else 'FAIL'} (expected commit={expect_commit})")
    return ok, r

FW = bytes((i*37+11) & 0xff for i in range(2048))

results = []

ok, r1 = check("update v5 (fresh device)", 5, "release five", FW)
results.append(ok)

def check_boot(post_flash):
    r = emu.run(b"B", preload_flash=[(0, post_flash)], max_count=5_000_000)
    out = r["boot_out"] if "boot_out" in r else r["uart_out"]
    jumped = r["err"] is not None and 0x10000 <= r["err"][1] < 0x18000
    print("\nboot the updated device (B)")
    print(f"  uart_out tail: {out[-40:]!r}")
    print(f"  printed release message: {b'release five' in out}")
    print(f"  jumped into firmware region: {jumped} (PC=0x{r['err'][1]:08x})" if r['err'] else "  no jump/fault")
    ok = (b"release five" in out) and jumped
    print(f"  => {'PASS' if ok else 'FAIL'}")
    return ok
results.append(check_boot(r1["flash"]))

print("ALL PASS" if all(results) else "SOME FAILED", f"({sum(results)}/{len(results)})")
sys.exit(0 if all(results) else 1)

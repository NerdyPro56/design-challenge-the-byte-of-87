import os
import sys
import struct
import subprocess
import tempfile
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "tests", "emu"))

BIN = os.path.join(REPO, "bootloader", "bin", "bootloader.bin")
SECRET = os.path.join(REPO, "tools", "secret_build_output.txt")
MAGIC = 0x544F4F42

# boot trusts the magic, verifies nothing; a stray verify is ~100M instr, this budget trips on it
BOOT_BUDGET = 500_000

# ED25519_SMALL scalar mult dominates: ~100M instr, ~8s at 16MHz on hardware; ceiling guards rule 6 latency
UPDATE_BUDGET = 150_000_000


@unittest.skipUnless(os.path.exists(BIN) and os.path.exists(SECRET), "bootloader not built")
class EmuBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import emu
        cls.emu = emu
        d = tempfile.mkdtemp()
        fw = bytes((i * 37 + 11) & 0xff for i in range(2048))
        with open(d + "/f.bin", "wb") as f:
            f.write(fw)
        subprocess.check_call([sys.executable, "fw_protect.py", "--infile", d + "/f.bin",
                               "--outfile", d + "/p.bin", "--version", "5", "--message", "budget"],
                              cwd=os.path.join(REPO, "tools"), stdout=subprocess.DEVNULL)
        with open(d + "/p.bin", "rb") as f:
            blob = f.read()
        hdr, ct = blob[:98], blob[98:]
        w = b"U" + hdr
        for i in range(0, len(ct), 256):
            c = ct[i:i+256]
            w += struct.pack(">H", len(c)) + c
        cls.wire = w

    def magic_of(self, flash):
        return struct.unpack("<I", flash[0xFC08:0xFC0C])[0]

    def test_update_commits_within_budget(self):
        r = self.emu.run(self.wire, max_count=UPDATE_BUDGET)
        self.assertEqual(self.magic_of(r["flash"]), MAGIC)

    def test_boot_is_crypto_free(self):
        post = self.emu.run(self.wire)["flash"]
        r = self.emu.run(b"B", preload_flash=[(0, post)], max_count=BOOT_BUDGET)
        self.assertIn(b"budget", r["uart_out"])


if __name__ == "__main__":
    unittest.main()

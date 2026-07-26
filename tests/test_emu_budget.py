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

        def make_wire(infile, name, version, message):
            path = d + "/" + name
            subprocess.check_call(
                [sys.executable, "fw_protect.py", "--infile", infile,
                 "--outfile", path, "--version", str(version), "--message", message],
                cwd=os.path.join(REPO, "tools"), stdout=subprocess.DEVNULL)
            with open(path, "rb") as f:
                blob = f.read()
            hdr, ct = blob[:98], blob[98:]
            w = b"U" + hdr
            for i in range(0, len(ct), 256):
                c = ct[i:i+256]
                w += struct.pack(">H", len(c)) + c
            return w

        cls.wire = make_wire(d + "/f.bin", "p5.bin", 5, "budget")
        cls.debug_wire = make_wire(d + "/f.bin", "p0.bin", 0, "debug")
        with open(d + "/max.bin", "wb") as f:
            f.write(bytes((i * 37 + 11) & 0xff for i in range(30720)))
        cls.max_wire = make_wire(d + "/max.bin", "maxp.bin", 5, "m" * 1024)

    def magic_of(self, flash):
        return struct.unpack("<I", flash[0xFC08:0xFC0C])[0]

    def test_update_commits_within_budget(self):
        r = self.emu.run(self.wire, max_count=UPDATE_BUDGET)
        self.assertEqual(self.magic_of(r["flash"]), MAGIC)
        self.assertIsNone(r["flash_error"])
        self.assertGreaterEqual(r["min_sp"], r["sp"] - 4096)

    def test_max_image_and_backup_fit_tm4c(self):
        first = self.emu.run(self.max_wire, max_count=UPDATE_BUDGET)
        second = self.emu.run(self.max_wire, max_count=UPDATE_BUDGET,
                              preload_flash=[(0, first["flash"])])
        self.assertEqual(self.emu.FLASH_SIZE, 0x40000)
        self.assertEqual(self.emu.SRAM_SIZE, 0x8000)
        self.assertEqual(len(second["flash"]), 0x40000)
        self.assertEqual(self.magic_of(second["flash"]), MAGIC)
        self.assertIsNone(second["flash_error"])
        self.assertGreaterEqual(second["min_sp"], second["sp"] - 4096)
        # a completed install must not leave the replaced image readable in the backup
        self.assertEqual(second["flash"][0x20000:0x28400], b"\xff" * 0x8400)

    def test_boot_is_crypto_free(self):
        post = self.emu.run(self.wire)["flash"]
        r = self.emu.run(b"B", preload_flash=[(0, post)], max_count=BOOT_BUDGET)
        self.assertIn(b"budget", r["uart_out"])

    def test_reset_during_frames_keeps_old_firmware(self):
        post = self.emu.run(self.wire)["flash"]
        partial = self.debug_wire[:1 + 98 + 4 * (2 + 256)]
        cut = self.emu.run(partial, preload_flash=[(0, post)],
                           max_count=1_000_000)["flash"]
        r = self.emu.run(b"B", preload_flash=[(0, cut)],
                         max_count=BOOT_BUDGET)
        self.assertIn(b"budget", r["uart_out"])
        self.assertNotIn(b"debug", r["uart_out"])

    def test_reset_during_install_restores_old_firmware(self):
        post = self.emu.run(self.wire)["flash"]
        cut = self.emu.run(self.wire, preload_flash=[(0, post)],
                           stop_on_flash=("erase", 0x10000))["flash"]
        cut = self.emu.run(b"B", preload_flash=[(0, cut)],
                           stop_on_flash=("erase", 0x10000))["flash"]
        r = self.emu.run(b"B", preload_flash=[(0, cut)],
                         max_count=2_000_000)
        self.assertIn(b"budget", r["uart_out"])

    def test_debug_firmware_installs_twice(self):
        post = self.emu.run(self.wire)["flash"]
        post = self.emu.run(self.debug_wire, preload_flash=[(0, post)])["flash"]
        post = self.emu.run(self.debug_wire, preload_flash=[(0, post)])["flash"]
        self.assertEqual(self.magic_of(post), MAGIC)
        self.assertEqual(struct.unpack("<H", post[0xFC00:0xFC02])[0], 0)
        self.assertEqual(struct.unpack("<I", post[0xF800:0xF804])[0], 5)
        r = self.emu.run(b"B", preload_flash=[(0, post)],
                         max_count=BOOT_BUDGET)
        self.assertIn(b"debug", r["uart_out"])


if __name__ == "__main__":
    unittest.main()

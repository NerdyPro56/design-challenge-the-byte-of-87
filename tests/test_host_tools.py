import os
import sys
import struct
import tempfile
import unittest

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Random import get_random_bytes

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import fw_protect

AAD = 6
NONCE = 12
TAG = 16
SIG = 64
HDR = 98


class HostTools(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cwd = os.getcwd()
        os.chdir(self.dir)

        self.key = get_random_bytes(32)
        sk = ECC.generate(curve="Ed25519")
        self.pub = sk.public_key()
        with open("secret_build_output.txt", "wb") as f:
            f.write(self.key + sk.seed)

        self.fw = bytes((i * 7 + 3) & 0xff for i in range(1500))
        with open("fw.bin", "wb") as f:
            f.write(self.fw)

    def tearDown(self):
        os.chdir(self.cwd)

    def protect(self, ver, msg):
        fw_protect.protect_firmware("fw.bin", "out.bin", ver, msg)
        with open("out.bin", "rb") as f:
            return f.read()

    def split(self, blob):
        aad = blob[0:AAD]
        nonce = blob[AAD:AAD + NONCE]
        tag = blob[AAD + NONCE:AAD + NONCE + TAG]
        sig = blob[AAD + NONCE + TAG:HDR]
        ct = blob[HDR:]
        return aad, nonce, tag, sig, ct

    def test_header_layout(self):
        msg = "release five"
        blob = self.protect(5, msg)
        ver, size, mlen = struct.unpack("<HHH", blob[:AAD])
        self.assertEqual(ver, 5)
        self.assertEqual(size, len(self.fw))
        self.assertEqual(mlen, len(msg) + 1)
        self.assertEqual(len(blob), HDR + size + mlen)


if __name__ == "__main__":
    unittest.main()

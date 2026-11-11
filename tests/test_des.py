"""
test_des.py - Kiem thu loi DES / 2DES / 3DES.

Chay:
    python -m unittest tests.test_des -v      # chay cac ca kiem thu
    python tests/test_des.py --compare        # in bang doi chieu "khop/lech" voi thu vien

LUU Y: thu vien mat ma (PyCryptodome) CHI duoc import trong file nay de DOI CHIEU,
tuyet doi khong import trong thu muc core/.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.des import des_encrypt_block, des_decrypt_block, generate_subkeys, hex_to_int, int_to_hex
from core.des_multi import (
    encrypt_2des, decrypt_2des,
    encrypt_3des, decrypt_3des,
    encrypt_3des_2key, decrypt_3des_2key,
    encrypt_3des_1key, decrypt_3des_1key,
)

# --- Test vector chuan ----------------------------------------------------
# (khoa, ban ro, ban ma)
STANDARD_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),  # vi du kinh dien
    ("0101010101010101", "0000000000000000", "8CA64DE9C1B123A7"),
    # Khoa 0101...01 la KHOA YEU (weak key): ma hoa == giai ma, nen hai dong duoi doi xung nhau.
    ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
    ("0101010101010101", "95F8A5E5DD31D900", "8000000000000000"),
]

# Khoa dung cho 2DES/3DES
K1 = hex_to_int("133457799BBCDFF1")
K2 = hex_to_int("0E329232EA6D0D73")
K3 = hex_to_int("FEDCBA9876543210")


class TestDES(unittest.TestCase):

    def test_standard_vectors_encrypt(self):
        for key, pt, ct in STANDARD_VECTORS:
            with self.subTest(key=key, pt=pt):
                got = int_to_hex(des_encrypt_block(hex_to_int(pt), hex_to_int(key)))
                self.assertEqual(got, ct)

    def test_standard_vectors_decrypt(self):
        for key, pt, ct in STANDARD_VECTORS:
            with self.subTest(key=key, ct=ct):
                got = int_to_hex(des_decrypt_block(hex_to_int(ct), hex_to_int(key)))
                self.assertEqual(got, pt)

    def test_first_subkey_matches_classic_example(self):
        # K1 cua vi du kinh dien (ban tinh tay): 000110 110000 001011 101111 111111 000111 000001 110010
        k1 = generate_subkeys(hex_to_int("133457799BBCDFF1"))[0]
        self.assertEqual(format(k1, "048b"), "000110110000001011101111111111000111000001110010")

    # ---- 3 ca tu viet cho DES ---------------------------------------------
    def test_own_case_all_zero_plaintext(self):
        key = hex_to_int("A1B2C3D4E5F60718")
        pt = 0
        self.assertEqual(des_decrypt_block(des_encrypt_block(pt, key), key), pt)

    def test_own_case_all_one_plaintext(self):
        key = hex_to_int("FEDCBA9876543210")
        pt = (1 << 64) - 1
        self.assertEqual(des_decrypt_block(des_encrypt_block(pt, key), key), pt)

    def test_own_case_random_roundtrip(self):
        rng = random.Random(2026)
        for _ in range(200):
            key = rng.getrandbits(64)
            pt = rng.getrandbits(64)
            self.assertEqual(des_decrypt_block(des_encrypt_block(pt, key), key), pt)

    def test_complementation_property(self):
        # Tinh chat bu cua DES: E_{~K}(~P) = ~E_K(P)
        mask = (1 << 64) - 1
        key, pt = K1, hex_to_int("0123456789ABCDEF")
        c = des_encrypt_block(pt, key)
        self.assertEqual(des_encrypt_block(pt ^ mask, key ^ mask), c ^ mask)


class TestMultiDES(unittest.TestCase):

    PT = hex_to_int("0123456789ABCDEF")

    def test_2des_roundtrip(self):
        c = encrypt_2des(self.PT, K1, K2)
        self.assertEqual(decrypt_2des(c, K1, K2), self.PT)

    def test_2des_equals_two_des(self):
        c = encrypt_2des(self.PT, K1, K2)
        self.assertEqual(c, des_encrypt_block(des_encrypt_block(self.PT, K1), K2))

    def test_2des_differs_from_des(self):
        self.assertNotEqual(encrypt_2des(self.PT, K1, K2), des_encrypt_block(self.PT, K1))

    def test_3des_roundtrip_three_keys(self):
        c = encrypt_3des(self.PT, K1, K2, K3)
        self.assertEqual(decrypt_3des(c, K1, K2, K3), self.PT)

    def test_3des_equals_ede(self):
        expected = des_encrypt_block(des_decrypt_block(des_encrypt_block(self.PT, K1), K2), K3)
        self.assertEqual(encrypt_3des(self.PT, K1, K2, K3), expected)

    def test_3des_roundtrip_two_keys(self):
        c = encrypt_3des_2key(self.PT, K1, K2)
        self.assertEqual(decrypt_3des_2key(c, K1, K2), self.PT)
        self.assertEqual(c, encrypt_3des(self.PT, K1, K2, K1))

    def test_3des_one_key_backward_compatible_with_des(self):
        # K1 = K2 = K3  ->  ket qua phai trung DES don
        for key, pt, ct in STANDARD_VECTORS:
            with self.subTest(key=key):
                k = hex_to_int(key)
                got = encrypt_3des_1key(hex_to_int(pt), k)
                self.assertEqual(int_to_hex(got), ct)
                self.assertEqual(decrypt_3des_1key(got, k), hex_to_int(pt))


# ----------------------------------------------------------------------------
# Doi chieu voi thu vien chuan (chi dung de kiem tra)
# ----------------------------------------------------------------------------

def _load_library_backend():
    """Tra ve (ten, lib_des, lib_3des) dung PyCryptodome, neu khong co thi dung `cryptography`.

    lib_des(key, pt)         -> DES don
    lib_3des(k1, k2, k3, pt) -> 3DES-EDE
    Tat ca la int 64-bit.
    """
    def b(x):
        return x.to_bytes(8, "big")

    try:
        from Crypto.Cipher import DES, DES3  # chi de doi chieu

        def lib_des(k, pt):
            return int.from_bytes(DES.new(b(k), DES.MODE_ECB).encrypt(b(pt)), "big")

        def lib_3des(k1, k2, k3, pt):
            # Khong dung adjust_key_parity de khoa giu nguyen; PyCryptodome chi tu choi khoa suy bien
            key = b(k1) + b(k2) + b(k3)
            return int.from_bytes(DES3.new(key, DES3.MODE_ECB).encrypt(b(pt)), "big")

        return "PyCryptodome", lib_des, lib_3des
    except ImportError:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

        def _run(key, pt):
            enc = Cipher(TripleDES(key), modes.ECB()).encryptor()
            return int.from_bytes(enc.update(b(pt)) + enc.finalize(), "big")

        def lib_des(k, pt):
            return _run(b(k) * 3, pt)  # K1=K2=K3 -> tuong duong DES don

        def lib_3des(k1, k2, k3, pt):
            return _run(b(k1) + b(k2) + b(k3), pt)

        return "cryptography", lib_des, lib_3des
    except ImportError:
        return None


def compare_with_library():
    """In bang doi chieu ket qua cua nhom voi thu vien chuan."""
    backend = _load_library_backend()
    if backend is None:
        print("Chua co thu vien doi chieu. Cai bang: pip install pycryptodome")
        return 1
    name, lib_des, lib_3des = backend
    print("Thu vien doi chieu: {}".format(name))

    rows = []
    rng = random.Random(7)
    cases = []
    # Test vector chuan + vai ca ngau nhien
    for key, pt, _ in STANDARD_VECTORS:
        cases.append((hex_to_int(key), hex_to_int(pt)))
    for _ in range(5):
        cases.append((rng.getrandbits(64), rng.getrandbits(64)))

    for k, pt in cases:
        mine = des_encrypt_block(pt, k)
        lib = lib_des(k, pt)
        rows.append(("DES", int_to_hex(k), int_to_hex(pt), int_to_hex(mine), int_to_hex(lib)))

    # 3DES ba khoa doc lap
    for _ in range(5):
        ka, kb, kc = rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64)
        pt = rng.getrandbits(64)
        mine = encrypt_3des(pt, ka, kb, kc)
        lib = lib_3des(ka, kb, kc, pt)
        rows.append(("3DES", "{}..".format(int_to_hex(ka)[:8]), int_to_hex(pt), int_to_hex(mine), int_to_hex(lib)))

    # 3DES hai khoa (K3 = K1)
    for _ in range(3):
        ka, kb = rng.getrandbits(64), rng.getrandbits(64)
        pt = rng.getrandbits(64)
        mine = encrypt_3des_2key(pt, ka, kb)
        lib = lib_3des(ka, kb, ka, pt)
        rows.append(("3DES2", "{}..".format(int_to_hex(ka)[:8]), int_to_hex(pt), int_to_hex(mine), int_to_hex(lib)))

    print("{:<5} {:<18} {:<18} {:<18} {:<18} {}".format(
        "He ma", "Khoa", "Ban ro", "Nhom cai dat", "Thu vien", "Ket qua"))
    print("-" * 95)
    bad = 0
    for alg, k, pt, mine, lib in rows:
        ok = (mine == lib)
        bad += (not ok)
        print("{:<5} {:<18} {:<18} {:<18} {:<18} {}".format(alg, k, pt, mine, lib, "KHOP" if ok else "LECH"))
    print("-" * 95)
    print("Tong: {} ca, {} lech".format(len(rows), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    if "--compare" in sys.argv:
        sys.exit(compare_with_library())
    unittest.main()

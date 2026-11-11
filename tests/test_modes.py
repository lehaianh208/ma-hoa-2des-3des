"""
test_modes.py - Kiem thu ECB/CBC, padding, ma hoa tep va ban toi uu des_fast.

Chay:  python -m unittest tests.test_modes -v

Thu vien mat ma (`cryptography`) CHI duoc import o day de doi chieu; neu may khong co thi
cac ca doi chieu bi bo qua (skip), khong anh huong cac ca con lai.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.des import des_encrypt_block, des_decrypt_block, generate_subkeys
from core.des_fast import fast_subkeys, fast_encrypt_block, fast_decrypt_block
from core.des_multi import (
    encrypt_2des, decrypt_2des, encrypt_3des, decrypt_3des,
)
from core.ciphers import make_cipher
from core.modes import (
    pkcs7_pad, pkcs7_unpad, encrypt_bytes, decrypt_bytes,
    ecb_encrypt, cbc_encrypt, BLOCK_SIZE,
)

KEYS = [0x133457799BBCDFF1, 0x0E329232EA6D0D73, 0xFEDCBA9876543210]
SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "sample.txt")


def read_sample():
    with open(SAMPLE, "rb") as f:
        return f.read()


def _lib_cipher(keys, mode, iv=None):
    """Tra ve (encryptor_factory) cua `cryptography` hoac None neu khong co."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    except ImportError:
        return None
    key = b"".join(k.to_bytes(8, "big") for k in keys)
    m = modes.ECB() if mode == "ecb" else modes.CBC(iv)
    return Cipher(TripleDES(key), m).encryptor()


class TestPadding(unittest.TestCase):

    def test_roundtrip_all_lengths(self):
        for n in range(0, 40):
            data = bytes(range(n))
            padded = pkcs7_pad(data)
            self.assertEqual(len(padded) % BLOCK_SIZE, 0)
            self.assertGreater(len(padded), len(data))       # luon them it nhat 1 byte
            self.assertEqual(pkcs7_unpad(padded), data)

    def test_full_block_adds_whole_block(self):
        self.assertEqual(pkcs7_pad(b"A" * 8), b"A" * 8 + bytes([8]) * 8)

    def test_invalid_padding_rejected(self):
        for bad in (b"", b"1234567", b"12345670", b"12345609", b"12345\x03\x03\x02"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    pkcs7_unpad(bad)


class TestFastMatchesSlow(unittest.TestCase):
    """des_fast.py phai cho ket qua giong het des.py / des_multi.py."""

    def test_subkeys_and_blocks(self):
        rng = random.Random(11)
        for _ in range(500):
            k, p = rng.getrandbits(64), rng.getrandbits(64)
            self.assertEqual(fast_subkeys(k), generate_subkeys(k))
            self.assertEqual(fast_encrypt_block(p, k), des_encrypt_block(p, k))
            self.assertEqual(fast_decrypt_block(p, k), des_decrypt_block(p, k))

    def test_block_cipher_matches_des_multi(self):
        rng = random.Random(12)
        for _ in range(200):
            k1, k2, k3, p = (rng.getrandbits(64) for _ in range(4))
            self.assertEqual(make_cipher("des", [k1]).encrypt(p), des_encrypt_block(p, k1))
            c2 = make_cipher("2des", [k1, k2])
            self.assertEqual(c2.encrypt(p), encrypt_2des(p, k1, k2))
            self.assertEqual(c2.decrypt(p), decrypt_2des(p, k1, k2))
            c3 = make_cipher("3des", [k1, k2, k3])
            self.assertEqual(c3.encrypt(p), encrypt_3des(p, k1, k2, k3))
            self.assertEqual(c3.decrypt(p), decrypt_3des(p, k1, k2, k3))
            self.assertEqual(make_cipher("3des", [k1, k2]).encrypt(p), encrypt_3des(p, k1, k2, k1))
            self.assertEqual(make_cipher("3des", [k1]).encrypt(p), des_encrypt_block(p, k1))

    def test_wrong_key_count_rejected(self):
        with self.assertRaises(ValueError):
            make_cipher("des", [1, 2])
        with self.assertRaises(ValueError):
            make_cipher("2des", [1])
        with self.assertRaises(ValueError):
            make_cipher("3des", [1, 2, 3, 4])
        with self.assertRaises(ValueError):
            make_cipher("aes", [1])


class TestModes(unittest.TestCase):

    CASES = [("des", KEYS[:1]), ("2des", KEYS[:2]), ("3des", KEYS), ("3des", KEYS[:2]), ("3des", KEYS[:1])]

    def test_roundtrip_every_algorithm_and_mode(self):
        for alg, keys in self.CASES:
            cipher = make_cipher(alg, keys)
            for mode in ("ecb", "cbc"):
                for n in (0, 1, 7, 8, 9, 63, 64, 65, 1000):
                    data = os.urandom(n)
                    with self.subTest(alg=alg, keys=len(keys), mode=mode, n=n):
                        self.assertEqual(decrypt_bytes(encrypt_bytes(data, cipher, mode), cipher, mode), data)

    def test_text_file_roundtrip(self):
        data = read_sample()                  # co ky tu UTF-8 tieng Viet
        for alg, keys in self.CASES:
            cipher = make_cipher(alg, keys)
            for mode in ("ecb", "cbc"):
                with self.subTest(alg=alg, mode=mode):
                    self.assertEqual(decrypt_bytes(encrypt_bytes(data, cipher, mode), cipher, mode), data)

    def test_ecb_leaks_repeated_blocks_but_cbc_does_not(self):
        cipher = make_cipher("3des", KEYS)
        data = b"A" * 64                                   # 8 khoi giong nhau
        ecb = encrypt_bytes(data, cipher, "ecb")
        blocks = {ecb[i:i + 8] for i in range(0, 64, 8)}
        self.assertEqual(len(blocks), 1)                   # ECB: 8 khoi ban ma giong nhau
        cbc = encrypt_bytes(data, cipher, "cbc", iv=bytes(8))
        blocks = {cbc[8 + i:16 + i] for i in range(0, 64, 8)}
        self.assertEqual(len(blocks), 8)                   # CBC: tat ca khac nhau

    def test_cbc_iv_changes_ciphertext_and_is_prepended(self):
        cipher = make_cipher("des", KEYS[:1])
        a = encrypt_bytes(b"hello world", cipher, "cbc", iv=bytes(8))
        b = encrypt_bytes(b"hello world", cipher, "cbc", iv=bytes([1]) * 8)
        self.assertEqual(a[:8], bytes(8))
        self.assertEqual(b[:8], bytes([1]) * 8)
        self.assertNotEqual(a[8:], b[8:])
        # IV ngau nhien: hai lan ma hoa cung ban ro cho ket qua khac nhau
        self.assertNotEqual(encrypt_bytes(b"x", cipher, "cbc"), encrypt_bytes(b"x", cipher, "cbc"))

    def test_wrong_key_does_not_recover_plaintext(self):
        data = read_sample()
        enc = encrypt_bytes(data, make_cipher("3des", KEYS), "cbc")
        # Dao 1 bit KHOA THAT (0x0200 = bit 1 cua byte 1; bit parity la bit 0 cua moi byte)
        wrong = make_cipher("3des", [KEYS[0], KEYS[1], KEYS[2] ^ 0x0200])
        try:
            self.assertNotEqual(decrypt_bytes(enc, wrong, "cbc"), data)
        except ValueError:
            pass                                           # padding sai cung la ket qua hop le

    def test_parity_bits_are_ignored_by_des(self):
        # Bit cuoi moi byte cua khoa 64-bit la bit parity, DES bo qua -> cung khoa hieu dung
        data = b"parity bits do not matter"
        a = encrypt_bytes(data, make_cipher("des", [KEYS[0]]), "ecb")
        b = encrypt_bytes(data, make_cipher("des", [KEYS[0] ^ 0x0101010101010101]), "ecb")
        self.assertEqual(a, b)

    def test_low_level_requires_aligned_data(self):
        cipher = make_cipher("des", KEYS[:1])
        with self.assertRaises(ValueError):
            ecb_encrypt(b"123", cipher.encrypt)
        with self.assertRaises(ValueError):
            cbc_encrypt(b"123", cipher.encrypt, 0)

    def test_bad_arguments(self):
        cipher = make_cipher("des", KEYS[:1])
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", cipher, "ctr")
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", cipher, "cbc", iv=b"short")
        with self.assertRaises(ValueError):
            decrypt_bytes(b"1234", cipher, "cbc")


class TestAgainstLibrary(unittest.TestCase):
    """Doi chieu voi thu vien chuan (bo qua neu may khong co `cryptography`)."""

    def _check(self, alg, keys, lib_keys):
        iv = bytes(range(8))
        data = read_sample()
        padded = pkcs7_pad(data)
        for mode in ("ecb", "cbc"):
            enc = _lib_cipher(lib_keys, mode, iv)
            if enc is None:
                self.skipTest("Khong co thu vien cryptography de doi chieu")
            expected = enc.update(padded) + enc.finalize()
            mine = encrypt_bytes(data, make_cipher(alg, keys), mode, iv=iv)
            with self.subTest(alg=alg, mode=mode):
                self.assertEqual(mine[8:] if mode == "cbc" else mine, expected)

    def test_des_matches_library(self):
        self._check("des", KEYS[:1], [KEYS[0]] * 3)

    def test_3des_three_keys_matches_library(self):
        self._check("3des", KEYS, KEYS)

    def test_3des_two_keys_matches_library(self):
        self._check("3des", KEYS[:2], [KEYS[0], KEYS[1], KEYS[0]])


if __name__ == "__main__":
    unittest.main()

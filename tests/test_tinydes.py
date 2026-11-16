"""
test_tinydes.py - Kiem thu TinyDES (phien ban thu nho cua lop), 2TinyDES, 3TinyDES va MITM tren khoa 8 bit day du.

Chay:  python -m unittest tests.test_tinydes -v

Cac ca kiem thu do nhom tu viet:
  1. Vi du tren lop (bai giang): P = 5C, K = 9A -> K1,K2,K3 va C = 92, tung vong.
  2. Bai 9 trong file bai tap: K1,K2,K3, C = 8E, giai ma ve ban ro, va cach 'chay lai so do ma hoa voi khoa dao'
     cho 01110100 (khac ban ro).
  3. Cac ham thanh phan theo vi du trong bai giang: Expand(0110) = 101110, S-box(101010) = 0110.
  4. Giai ma khoi phuc dung ban ro voi MOI khoa 8 bit x MOI khoi 8 bit.
  5. Moi khoa la mot hoan vi cua 256 khoi.
  6. 2TinyDES, 3TinyDES (3 khoa / 2 khoa / 1 khoa) va MITM khop voi vet can.
  7. Doi chieu cheo voi mot cai dat viet theo cach khac (chuoi ky tu) - tuong ung 'doi chieu thu vien'.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.tinydes import (
    generate_subkeys, tinydes_encrypt_block, tinydes_decrypt_block, bin_to_int, int_to_bin,
    expand, sbox, pbox, compress, f_function, SBOX,
)
from core.tinydes_multi import (
    encrypt_2tinydes, decrypt_2tinydes, encrypt_3tinydes, decrypt_3tinydes, crypt_block,
)
from core.mitm_tinydes import mitm_2tinydes, brute_force_2tinydes, double_encrypt


def b8(text):
    return bin_to_int(text, 8)


def b6(text):
    return int(text, 2)


class TestClassExample(unittest.TestCase):
    """Vi du trong bai giang: P = 01011100 (5C), K = 10011010."""

    def test_subkeys(self):
        self.assertEqual(generate_subkeys(b8("10011010")), [b6("101110"), b6("110011"), b6("001001")])

    def test_encrypt_and_steps(self):
        lines = []
        c = tinydes_encrypt_block(b8("01011100"), b8("10011010"), lines.append)
        self.assertEqual(c, b8("10010010"))                       # 92
        text = "\n".join(lines)
        # cac gia tri trung gian ghi trong bai giang
        for expected in ("001011", "100101", "L1 = 1100, R1 = 0001", "L2 = 0001, R2 = 1001",
                         "010001", "011000", "L3 = 1001, R3 = 0010"):
            self.assertIn(expected, text)

    def test_decrypt(self):
        self.assertEqual(tinydes_decrypt_block(b8("10010010"), b8("10011010")), b8("01011100"))


class TestExercise9(unittest.TestCase):
    """Bai 9 trong file bai tap: P = 01010011 (53), K = 10111011 (BB)."""
    P, K = b8("01010011"), b8("10111011")

    def test_subkeys(self):
        self.assertEqual(generate_subkeys(self.K), [b6("111110"), b6("111011"), b6("001111")])

    def test_encrypt(self):
        self.assertEqual(tinydes_encrypt_block(self.P, self.K), b8("10001110"))   # 8E

    def test_decrypt_returns_plaintext(self):
        self.assertEqual(tinydes_decrypt_block(b8("10001110"), self.K), self.P)

    def test_reversed_keys_in_encryption_circuit_is_wrong(self):
        """Cau (4): chay lai so do MA HOA tren ban ma voi khoa dao thu tu cho 01110100, khong phai ban ro
        (thieu buoc doi cho hai nua)."""
        keys = generate_subkeys(self.K)[::-1]
        left, right = 0b1000, 0b1110                      # C = 1000 1110
        for ki in keys:
            left, right = right, left ^ f_function(right, ki)
        result = (left << 4) | right
        self.assertEqual(result, b8("01110100"))
        self.assertNotEqual(result, self.P)


class TestComponents(unittest.TestCase):
    def test_expand_example(self):
        self.assertEqual(expand(0b0110), b6("101110"))

    def test_sbox_example(self):
        self.assertEqual(sbox(b6("101010")), 0b0110)

    def test_sbox_row_column(self):
        # hang = b0 b5, cot = b1 b2 b3 b4
        self.assertEqual(sbox(b6("000000")), SBOX[0][0])
        self.assertEqual(sbox(b6("100001")), SBOX[0b11][0])
        self.assertEqual(sbox(b6("011110")), SBOX[0][0b1111])

    def test_pbox_and_compress_examples_from_lecture(self):
        self.assertEqual(pbox(0b1000), 0b0100)            # vong 1: P-box(1000) = 0100
        self.assertEqual(pbox(0b1100), 0b0101)            # vong 2: P-box(1100) = 0101
        self.assertEqual(pbox(0b0101), 0b0011)            # vong 3: P-box(0101) = 0011
        self.assertEqual(compress(b8("00110101")), b6("101110"))   # K1 = Compress(KL1 KR1)


class TestProperties(unittest.TestCase):
    def test_round_trip_all_keys_and_blocks(self):
        for k in range(256):
            for p in range(256):
                self.assertEqual(tinydes_decrypt_block(tinydes_encrypt_block(p, k), k), p)

    def test_each_key_is_a_permutation(self):
        rnd = random.Random(3)
        for k in rnd.sample(range(256), 32):
            self.assertEqual(len({tinydes_encrypt_block(p, k) for p in range(256)}), 256)

    def test_bin_helpers(self):
        self.assertEqual(int_to_bin(b8("01011100"), 8), "01011100")
        with self.assertRaises(ValueError):
            bin_to_int("0101", 8)
        with self.assertRaises(ValueError):
            bin_to_int("0101110x", 8)


# ---- doi chieu cheo: cai dat viet theo cach khac (xu ly chuoi '0'/'1') -------------------------------------------
def ref_tinydes(plain, key):
    def expand_s(r):                                    # b2 b3 b1 b2 b1 b0
        return r[2] + r[3] + r[1] + r[2] + r[1] + r[0]

    def xor(a, b):
        return "".join("1" if x != y else "0" for x, y in zip(a, b))

    def sbox_s(x):
        row = int(x[0] + x[5], 2)
        col = int(x[1:5], 2)
        return format(SBOX[row][col], "04b")

    def pbox_s(x):                                      # b2 b0 b3 b1
        return x[2] + x[0] + x[3] + x[1]

    def rot(s, n):
        n %= len(s)
        return s[n:] + s[:n]

    kl, kr = key[:4], key[4:]
    subkeys = []
    for shift in (1, 2, 1):
        kl, kr = rot(kl, shift), rot(kr, shift)
        k = kl + kr
        subkeys.append(k[5] + k[1] + k[3] + k[2] + k[7] + k[0])
    left, right = plain[:4], plain[4:]
    for ki in subkeys:
        f = pbox_s(sbox_s(xor(expand_s(right), ki)))
        left, right = right, xor(left, f)
    return left + right


class TestAgainstReference(unittest.TestCase):
    def test_all_keys_random_blocks(self):
        rnd = random.Random(11)
        for k in range(256):
            for p in rnd.sample(range(256), 8):
                expect = ref_tinydes(format(p, "08b"), format(k, "08b"))
                self.assertEqual(format(tinydes_encrypt_block(p, k), "08b"), expect)


class TestMulti(unittest.TestCase):
    K1, K2, K3, P = b8("10011010"), b8("10111011"), b8("01100101"), b8("01011100")

    def test_2tinydes_formula_and_round_trip(self):
        c = encrypt_2tinydes(self.P, self.K1, self.K2)
        self.assertEqual(c, tinydes_encrypt_block(tinydes_encrypt_block(self.P, self.K1), self.K2))
        self.assertEqual(decrypt_2tinydes(c, self.K1, self.K2), self.P)

    def test_3tinydes_ede_formula_and_round_trip(self):
        c = encrypt_3tinydes(self.P, self.K1, self.K2, self.K3)
        a = tinydes_encrypt_block(self.P, self.K1)
        b = tinydes_decrypt_block(a, self.K2)
        self.assertEqual(c, tinydes_encrypt_block(b, self.K3))
        self.assertEqual(decrypt_3tinydes(c, self.K1, self.K2, self.K3), self.P)

    def test_3tinydes_key_options(self):
        # 2 khoa (K3 = K1, nhu bai giang) va 1 khoa (tuong thich TinyDES don)
        c2 = crypt_block("3tinydes", "enc", [self.K1, self.K2], self.P)
        self.assertEqual(c2, encrypt_3tinydes(self.P, self.K1, self.K2, self.K1))
        self.assertEqual(crypt_block("3tinydes", "dec", [self.K1, self.K2], c2), self.P)
        c1 = crypt_block("3tinydes", "enc", [self.K1], self.P)
        self.assertEqual(c1, tinydes_encrypt_block(self.P, self.K1))

    def test_wrong_key_count(self):
        with self.assertRaises(ValueError):
            crypt_block("2tinydes", "enc", [self.K1], self.P)


class TestMITM(unittest.TestCase):
    def setUp(self):
        rnd = random.Random(5)
        self.k1, self.k2 = rnd.randrange(256), rnd.randrange(256)
        self.pairs = [(p, double_encrypt(p, self.k1, self.k2)) for p in rnd.sample(range(256), 10)]

    def test_double_encrypt_matches_multi(self):
        self.assertEqual(double_encrypt(0x5C, self.k1, self.k2), encrypt_2tinydes(0x5C, self.k1, self.k2))

    def test_mitm_finds_true_key_and_matches_brute_force(self):
        m = mitm_2tinydes(self.pairs)
        b = brute_force_2tinydes(self.pairs)
        self.assertIn((self.k1, self.k2), m["final"])
        self.assertEqual(sorted(m["final"]), sorted(b["final"]))
        self.assertEqual(m["mitm_ops"], 512)
        self.assertEqual(m["brute_force_ops"], 131072)

    def test_one_pair_leaves_many_candidates(self):
        m = mitm_2tinydes(self.pairs[:1])
        self.assertGreater(len(m["final"]), 50)          # ky vong ~256


if __name__ == "__main__":
    unittest.main()

"""
test_sdes.py - Kiem thu S-DES, 2S-DES, 3S-DES (phien ban thu nho) va MITM tren khoa 10 bit day du.

Chay:  python -m unittest tests.test_sdes -v

Cac ca kiem thu do nhom tu viet:
  1. Vi du chuan trong giao trinh (khoa con va ban ma).
  2. Giai ma khoi phuc dung ban ro voi MOI khoa 10 bit x MOI khoi 8 bit.
  3. Moi khoa la mot hoan vi cua 256 khoi (ma hoa khong mat thong tin).
  4. 2S-DES, 3S-DES: cong thuc va ba kieu khoa; 3S-DES 1 khoa trung S-DES.
  5. MITM tim ra khoa that va khop voi vet can.
  6. Doi chieu cheo voi mot cai dat viet theo cach khac (chuoi ky tu) - tuong ung 'doi chieu thu vien'.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.sdes import (
    generate_subkeys, sdes_encrypt_block, sdes_decrypt_block, bin_to_int, int_to_bin, permute,
    IP, IP_INV, S0, S1,
)
from core.sdes_multi import (
    encrypt_2sdes, decrypt_2sdes, encrypt_3sdes, decrypt_3sdes, crypt_block,
)
from core.mitm_sdes import mitm_2sdes, brute_force_2sdes, double_encrypt


def b8(text):
    return bin_to_int(text, 8)


def b10(text):
    return bin_to_int(text, 10)


# ----------------------------------------------------------------------------
# Cai dat doi chung viet THEO CACH KHAC (chuoi ky tu '0'/'1', viet nhu lam tay tren giay)
# de kiem tra cheo voi core/sdes.py (viet bang so nguyen va phep dich bit).
# ----------------------------------------------------------------------------

def _ref_perm(bits, table):
    return "".join(bits[i - 1] for i in table)


def _ref_xor(a, b):
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _ref_sbox(box, bits4):
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    return format(box[row][col], "02b")


def _ref_fk(bits8, k8):
    left, right = bits8[:4], bits8[4:]
    x = _ref_xor(_ref_perm(right, [4, 1, 2, 3, 2, 3, 4, 1]), k8)
    out = _ref_perm(_ref_sbox(S0, x[:4]) + _ref_sbox(S1, x[4:]), [2, 4, 3, 1])
    return _ref_xor(left, out) + right


def reference_sdes(plain8, key10, decrypt=False):
    k = _ref_perm(key10, [3, 5, 2, 7, 4, 10, 1, 9, 8, 6])
    l, r = k[:5], k[5:]
    l, r = l[1:] + l[:1], r[1:] + r[:1]
    k1 = _ref_perm(l + r, [6, 3, 7, 4, 8, 5, 10, 9])
    l, r = l[2:] + l[:2], r[2:] + r[:2]
    k2 = _ref_perm(l + r, [6, 3, 7, 4, 8, 5, 10, 9])
    first, second = (k2, k1) if decrypt else (k1, k2)
    t = _ref_perm(plain8, [2, 6, 3, 1, 4, 8, 5, 7])
    t = _ref_fk(t, first)
    t = t[4:] + t[:4]
    t = _ref_fk(t, second)
    return _ref_perm(t, [4, 1, 3, 5, 7, 2, 8, 6])


class TestAgainstReference(unittest.TestCase):

    def test_matches_independent_string_implementation(self):
        for key in random.Random(11).sample(range(1024), 60):
            for block in range(256):
                kb, pb = format(key, "010b"), format(block, "08b")
                self.assertEqual(int_to_bin(sdes_encrypt_block(block, key), 8), reference_sdes(pb, kb))
                self.assertEqual(int_to_bin(sdes_decrypt_block(block, key), 8), reference_sdes(pb, kb, decrypt=True))


class TestSDESStandard(unittest.TestCase):
    """Vi du trong giao trinh: khoa 1010000010."""

    KEY = "1010000010"

    def test_subkeys(self):
        k1, k2 = generate_subkeys(b10(self.KEY))
        self.assertEqual(int_to_bin(k1, 8), "10100100")
        self.assertEqual(int_to_bin(k2, 8), "01000011")

    def test_known_ciphertexts(self):
        for plain, cipher in (("01110010", "01110111"), ("10010111", "00111000")):
            self.assertEqual(int_to_bin(sdes_encrypt_block(b8(plain), b10(self.KEY)), 8), cipher)
            self.assertEqual(int_to_bin(sdes_decrypt_block(b8(cipher), b10(self.KEY)), 8), plain)

    def test_trace_prints_intermediate_steps(self):
        lines = []
        out = sdes_encrypt_block(b8("01110010"), b10(self.KEY), lines.append)
        self.assertEqual(int_to_bin(out, 8), "01110111")
        text = "\n".join(lines)
        for needle in ("K1 = P8", "K2 = P8", "IP ", "Vong 1", "SW", "Vong 2", "IP^-1"):
            self.assertIn(needle, text)

    def test_ip_and_inverse_are_inverse(self):
        for x in range(256):
            self.assertEqual(permute(permute(x, IP, 8), IP_INV, 8), x)

    def test_sboxes_have_values_0_to_3(self):
        for box in (S0, S1):
            self.assertEqual(len(box), 4)
            for row in box:
                self.assertEqual(len(row), 4)
                self.assertTrue(all(0 <= v <= 3 for v in row))

    def test_input_validation(self):
        with self.assertRaises(ValueError):
            bin_to_int("101", 10)
        with self.assertRaises(ValueError):
            bin_to_int("10100x0010", 10)


class TestSDESProperties(unittest.TestCase):

    def test_decrypt_inverts_encrypt_for_every_key_and_block(self):
        for key in range(1024):
            for block in range(256):
                self.assertEqual(sdes_decrypt_block(sdes_encrypt_block(block, key), key), block)

    def test_each_key_is_a_permutation_of_blocks(self):
        for key in random.Random(7).sample(range(1024), 40):
            outs = {sdes_encrypt_block(x, key) for x in range(256)}
            self.assertEqual(len(outs), 256)

    def test_all_subkey_pairs_distinct(self):
        self.assertEqual(len({generate_subkeys(k) for k in range(1024)}), 1024)


class TestMulti(unittest.TestCase):

    def setUp(self):
        self.k1, self.k2, self.k3 = b10("1010000010"), b10("0110111001"), b10("0011010101")
        self.p = b8("01110010")

    def test_2sdes_formula_and_roundtrip(self):
        c = encrypt_2sdes(self.p, self.k1, self.k2)
        self.assertEqual(c, sdes_encrypt_block(sdes_encrypt_block(self.p, self.k1), self.k2))
        self.assertEqual(decrypt_2sdes(c, self.k1, self.k2), self.p)

    def test_3sdes_ede_formula_and_roundtrip(self):
        c = encrypt_3sdes(self.p, self.k1, self.k2, self.k3)
        expect = sdes_encrypt_block(sdes_decrypt_block(sdes_encrypt_block(self.p, self.k1), self.k2), self.k3)
        self.assertEqual(c, expect)
        self.assertEqual(decrypt_3sdes(c, self.k1, self.k2, self.k3), self.p)

    def test_3sdes_one_key_equals_single_sdes(self):
        self.assertEqual(crypt_block("3sdes", "enc", [self.k1], self.p),
                         sdes_encrypt_block(self.p, self.k1))

    def test_3sdes_two_key_means_k3_equals_k1(self):
        self.assertEqual(crypt_block("3sdes", "enc", [self.k1, self.k2], self.p),
                         encrypt_3sdes(self.p, self.k1, self.k2, self.k1))

    def test_crypt_block_roundtrip_all_algorithms(self):
        for alg, keys in (("sdes", [self.k1]), ("2sdes", [self.k1, self.k2]),
                          ("3sdes", [self.k1, self.k2, self.k3]), ("3sdes", [self.k1, self.k2])):
            for x in range(256):
                c = crypt_block(alg, "enc", keys, x)
                self.assertEqual(crypt_block(alg, "dec", keys, c), x)

    def test_wrong_number_of_keys(self):
        with self.assertRaises(ValueError):
            crypt_block("2sdes", "enc", [self.k1], self.p)
        with self.assertRaises(ValueError):
            crypt_block("sdes", "enc", [self.k1, self.k2], self.p)


class TestMITM2SDES(unittest.TestCase):

    def make_pairs(self, k1, k2, n, seed):
        plains = random.Random(seed).sample(range(256), n)
        return [(p, double_encrypt(p, k1, k2)) for p in plains]

    def test_finds_true_key_with_full_10_bit_keys(self):
        k1, k2 = b10("1010000010"), b10("0110111001")
        r = mitm_2sdes(self.make_pairs(k1, k2, 12, seed=3))
        self.assertIn((k1, k2), r["final"])
        self.assertEqual(r["mitm_ops"], 2 * 1024)
        self.assertEqual(r["brute_force_ops"], 2 * 1024 * 1024)

    def test_one_pair_leaves_about_2_pow_12_candidates(self):
        k1, k2 = 300, 700
        r = mitm_2sdes(self.make_pairs(k1, k2, 1, seed=1))
        self.assertIn((k1, k2), r["final"])
        self.assertTrue(3000 < r["candidates_per_pair"][0] < 5500)   # ky vong ~ 2^20/2^8 = 4096

    def test_more_pairs_never_increase_candidates(self):
        r = mitm_2sdes(self.make_pairs(123, 456, 10, seed=2))
        c = r["candidates_per_pair"]
        self.assertTrue(all(a >= b for a, b in zip(c, c[1:])))
        self.assertLess(c[-1], 10)

    def test_mitm_equals_brute_force(self):
        k1, k2 = 77, 901
        pairs = self.make_pairs(k1, k2, 4, seed=5)
        self.assertEqual(sorted(mitm_2sdes(pairs)["final"]), sorted(brute_force_2sdes(pairs)["final"]))


if __name__ == "__main__":
    unittest.main()

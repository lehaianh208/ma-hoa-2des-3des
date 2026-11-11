"""
test_mitm.py - Kiem thu tan cong meet-in-the-middle (bo so nho va DES khoa rut gon).

Chay:  python -m unittest tests.test_mitm -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.mitm_toy import mitm_toy, double_encrypt, enc, dec, S, S_INV, KEY_SPACE
from core.mitm_des import (
    expand_key56, reduced_key, make_demo_case, mitm_2des, brute_force_2des, full_scale_estimate,
)
from core.des_fast import fast_subkeys, fast_crypt


class TestToy(unittest.TestCase):

    def test_sbox_is_permutation_and_invertible(self):
        self.assertEqual(sorted(S), list(range(16)))
        for x in range(16):
            for k in range(16):
                self.assertEqual(dec(enc(x, k), k), x)

    def test_documented_example(self):
        # Vi du trong bao cao: khoa that (6, B), cac cap P = 3, A, 7
        prs = [(p, double_encrypt(p, 0x6, 0xB)) for p in (0x3, 0xA, 0x7)]
        self.assertEqual(prs, [(3, 8), (0xA, 2), (7, 1)])
        res = mitm_toy(prs)
        self.assertEqual([len(s) for s in res["survivors"]], [16, 4, 1])
        self.assertEqual(res["final"], [(0x6, 0xB)])
        self.assertEqual((res["mitm_ops"], res["brute_force_ops"]), (32, 256))

    def test_one_pair_gives_exactly_16_candidates_incl_true_key(self):
        # Moi k1 xac dinh dung 1 k2 -> 16 ung vien
        for k1 in range(16):
            for k2 in range(16):
                res = mitm_toy([(5, double_encrypt(5, k1, k2))])
                self.assertEqual(len(res["matches"]), KEY_SPACE)
                self.assertIn((k1, k2), res["matches"])

    def test_true_key_always_survives(self):
        for k1 in range(16):
            for k2 in range(16):
                prs = [(p, double_encrypt(p, k1, k2)) for p in (3, 0xA, 7, 0xC)]
                self.assertIn((k1, k2), mitm_toy(prs)["final"])

    def test_matches_brute_force(self):
        k1, k2 = 0x2, 0xE
        prs = [(p, double_encrypt(p, k1, k2)) for p in (1, 6, 0xD)]
        brute = [(a, b) for a in range(16) for b in range(16)
                 if all(double_encrypt(p, a, b) == c for p, c in prs)]
        self.assertEqual(mitm_toy(prs)["final"], brute)


class TestReducedDES(unittest.TestCase):

    def test_expand_key_has_odd_parity(self):
        for k56 in (0, (1 << 56) - 1, 0x123456789ABCDE, 0xA5A5A5A5A5A5A5):
            k = expand_key56(k56)
            for i in range(8):
                self.assertEqual(bin((k >> (8 * i)) & 0xFF).count("1") % 2, 1)

    def test_reduced_key_keeps_fixed_bits_and_varies_free_bits(self):
        fixed = 0xABCDEF123456AB
        a, b = reduced_key(fixed, 8, 0x00), reduced_key(fixed, 8, 0xFF)
        self.assertNotEqual(a, b)
        # DES bo qua bit parity: cung gia tri free -> cung khoa hieu dung
        self.assertEqual(reduced_key(fixed, 8, 0x5A), reduced_key(fixed | 0xFF, 8, 0x5A))

    def test_finds_planted_key_for_several_sizes_and_seeds(self):
        for n in (4, 6, 8, 10):
            for seed in (1, 2, 3):
                with self.subTest(n=n, seed=seed):
                    pairs, f1, f2, true = make_demo_case(n, seed=seed)
                    r = mitm_2des(pairs, f1, f2, n)
                    self.assertEqual(r["found"], [true])
                    self.assertEqual(r["table_entries"] <= (1 << n), True)
                    self.assertEqual(r["mitm_ops"], 2 << n)

    def test_found_keys_really_encrypt_pairs(self):
        pairs, f1, f2, true = make_demo_case(8, seed=9)
        r = mitm_2des(pairs, f1, f2, 8)
        k1, k2 = r["found_keys"][0]
        for p, c in pairs:
            self.assertEqual(fast_crypt(fast_crypt(p, fast_subkeys(k1)), fast_subkeys(k2)), c)

    def test_mitm_equals_brute_force(self):
        for seed in (1, 2):
            pairs, f1, f2, true = make_demo_case(6, seed=seed)
            self.assertEqual(mitm_2des(pairs, f1, f2, 6)["found"], brute_force_2des(pairs, f1, f2, 6)["found"])

    def test_brute_force_refuses_large_n(self):
        pairs, f1, f2, _ = make_demo_case(4)
        with self.assertRaises(ValueError):
            brute_force_2des(pairs, f1, f2, 12)

    def test_second_pair_needed_to_filter_when_single_pair_is_ambiguous(self):
        # Voi mot cap duy nhat, khoa that van nam trong danh sach ung vien
        pairs, f1, f2, true = make_demo_case(8, seed=4)
        r = mitm_2des(pairs[:1], f1, f2, 8)
        self.assertIn(true, r["found"])

    def test_full_scale_numbers(self):
        f = full_scale_estimate()
        self.assertEqual(f["table_bytes_values_only"], 2 ** 59)
        self.assertAlmostEqual(f["table_bytes_values_only"] / 1e15, 576.46, places=1)


if __name__ == "__main__":
    unittest.main()

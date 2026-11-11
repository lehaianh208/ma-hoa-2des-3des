"""
mitm_des.py - Tan cong meet-in-the-middle len 2DES tren DES THAT, voi KHOA RUT GON.

Vi sao phai rut gon?
  MITM len 2DES day du can bang tra ~2^56 muc (2^56 x 8 byte = 2^59 byte ~ 576 petabyte,
  chua tinh khoa) va ~2^57 phep tinh -> khong the chay. Vi vay ta dat truoc phan lon bit
  khoa (ke tan cong biet) va chi de `n_bits` bit chua biet cho MOI khoa:

      khoa 56-bit hieu dung = (phan co dinh 56-n bit) || (n bit chua biet)

  Khoa 56-bit duoc mo rong thanh khoa 64-bit bang cach them bit parity le (DES bo qua bit nay).

So sanh chi phi (n = so bit chua biet moi khoa):
  Vet can 2DES : 2^(2n) cap khoa, moi cap 2 phep ma hoa        -> ~2^(2n+1) phep
  MITM         : 2^n (lap bang) + 2^n (tra bang)               -> ~2^(n+1) phep, bo nho 2^n muc

Loc ung vien sai (false positive):
  Mot cap (P, C) cho ~ 2^(2n) / 2^64 ung vien sai. Voi n nho con xap xi 0, nhung voi khoa 56-bit
  day du la 2^112 / 2^64 = 2^48 ung vien sai -> BAT BUOC dung >= 2 cap known-plaintext.
"""

import time

from core.des_fast import fast_subkeys, fast_crypt

M56 = (1 << 56) - 1


# ----------------------------------------------------------------------------
# Khoa rut gon
# ----------------------------------------------------------------------------

def expand_key56(k56):
    """56-bit hieu dung -> khoa 64-bit voi bit parity le o bit cuoi moi byte."""
    key = 0
    for i in range(8):
        seven = (k56 >> (49 - 7 * i)) & 0x7F
        parity = 1 if bin(seven).count("1") % 2 == 0 else 0   # parity le: tong so bit 1 la le
        key = (key << 8) | (seven << 1) | parity
    return key


def reduced_key(fixed56, n_bits, v):
    """Khoa 64-bit: (56-n bit cao cua fixed56) || v (n bit chua biet)."""
    return expand_key56(((fixed56 >> n_bits) << n_bits) | v)


# ----------------------------------------------------------------------------
# Tan cong
# ----------------------------------------------------------------------------

def mitm_2des(pairs, fixed1, fixed2, n_bits, progress=None):
    """MITM len 2DES (C = E_K2(E_K1(P))) khi moi khoa chi co `n_bits` bit chua biet.

    pairs   : danh sach (P, C) (int 64-bit); cap dau lap bang, cac cap sau de loc.
    fixed1/2: phan khoa 56-bit da biet cua K1/K2 (n bit thap bi bo qua).
    progress: ham nhan (giai_doan, da_xong, tong) hoac None.
    """
    n = 1 << n_bits
    p1, c1 = pairs[0]
    t0 = time.perf_counter()

    # Buoc 1: bang X = E_K1(P1)
    table = {}
    dup = {}
    for v in range(n):
        x = fast_crypt(p1, fast_subkeys(reduced_key(fixed1, n_bits, v)))
        if x in table:
            dup.setdefault(x, [table[x]]).append(v)
        else:
            table[x] = v
        if progress and v % 4096 == 0:
            progress("table", v, n)
    t_table = time.perf_counter() - t0

    # Buoc 2: Y = D_K2(C1), tim trung
    t1 = time.perf_counter()
    candidates = []
    for v2 in range(n):
        y = fast_crypt(c1, fast_subkeys(reduced_key(fixed2, n_bits, v2))[::-1])
        if y in table:
            for v1 in dup.get(y, [table[y]]):
                candidates.append((v1, v2))
        if progress and v2 % 4096 == 0:
            progress("lookup", v2, n)
    t_lookup = time.perf_counter() - t1
    after_first = len(candidates)

    # Buoc 3: loc bang cac cap con lai
    survivors = candidates
    per_pair = [after_first]
    for p, c in pairs[1:]:
        kept = []
        for v1, v2 in survivors:
            s1 = fast_subkeys(reduced_key(fixed1, n_bits, v1))
            s2 = fast_subkeys(reduced_key(fixed2, n_bits, v2))
            if fast_crypt(fast_crypt(p, s1), s2) == c:
                kept.append((v1, v2))
        survivors = kept
        per_pair.append(len(survivors))

    total = time.perf_counter() - t0
    return {
        "n_bits": n_bits,
        "found": survivors,                        # [(v1, v2)] gia tri n bit chua biet
        "found_keys": [(reduced_key(fixed1, n_bits, a), reduced_key(fixed2, n_bits, b))
                       for a, b in survivors],
        "candidates_per_pair": per_pair,           # so ung vien con lai sau tung cap
        "table_entries": len(table),
        "mitm_ops": 2 * n,
        "time_table": t_table,
        "time_lookup": t_lookup,
        "time_total": total,
        "expected_false_positives_one_pair": (n * n) / float(1 << 64),
    }


def brute_force_2des(pairs, fixed1, fixed2, n_bits, limit_bits=9):
    """Vet can 2DES: thu moi cap (v1, v2). Chi chay that khi n_bits <= limit_bits."""
    if n_bits > limit_bits:
        raise ValueError("Vet can that chi chay duoc khi n_bits <= {}".format(limit_bits))
    n = 1 << n_bits
    p1, c1 = pairs[0]
    sk = [fast_subkeys(reduced_key(fixed1, n_bits, v)) for v in range(n)]
    sk2 = [fast_subkeys(reduced_key(fixed2, n_bits, v)) for v in range(n)]
    t0 = time.perf_counter()
    found = []
    trials = 0
    for v1 in range(n):
        s1 = sk[v1]
        for v2 in range(n):
            trials += 1
            if fast_crypt(fast_crypt(p1, s1), sk2[v2]) == c1:
                if all(fast_crypt(fast_crypt(p, s1), sk2[v2]) == c for p, c in pairs[1:]):
                    found.append((v1, v2))
    return {"found": found, "trials": trials, "time": time.perf_counter() - t0}


def estimate_brute_force_seconds(n_bits, samples=20000):
    """Uoc luong thoi gian vet can 2DES = 2^(2n) x (thoi gian 2 phep ma hoa), do bang may nay."""
    sk = fast_subkeys(0x133457799BBCDFF1)
    t0 = time.perf_counter()
    for i in range(samples):
        fast_crypt(fast_crypt(i, sk), sk)
    per_trial = (time.perf_counter() - t0) / samples
    return per_trial * (1 << (2 * n_bits)), per_trial


def make_demo_case(n_bits, seed=1, n_pairs=3):
    """Tao mot bai toan MITM: chon phan co dinh, khoa that, cac cap (P, C).

    Tra ve (pairs, fixed1, fixed2, (true_v1, true_v2)).
    """
    import random
    rng = random.Random(seed)
    fixed1 = rng.getrandbits(56)
    fixed2 = rng.getrandbits(56)
    v1 = rng.getrandbits(n_bits)
    v2 = rng.getrandbits(n_bits)
    s1 = fast_subkeys(reduced_key(fixed1, n_bits, v1))
    s2 = fast_subkeys(reduced_key(fixed2, n_bits, v2))
    pairs = []
    for _ in range(n_pairs):
        p = rng.getrandbits(64)
        pairs.append((p, fast_crypt(fast_crypt(p, s1), s2)))
    return pairs, fixed1, fixed2, (v1, v2)


def full_scale_estimate():
    """Chi phi MITM len 2DES day du (56-bit moi khoa) de dua vao bao cao."""
    entries = 1 << 56
    return {
        "mitm_ops": "2^57",
        "table_entries": "2^56",
        "table_bytes_values_only": entries * 8,         # chi luu X (8 byte), khoa la chi so
        "table_bytes_with_key": entries * 15,           # luu them 7 byte khoa
        "false_positives_one_pair": "2^112 / 2^64 = 2^48",
    }

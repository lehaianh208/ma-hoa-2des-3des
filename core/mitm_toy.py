"""
mitm_toy.py - Tan cong meet-in-the-middle (MITM) tren "ma do choi" 4-bit de TINH TAY duoc.

DAY KHONG PHAI MOT PHIEN BAN HE MA THU HAI. Day la mot hop den nho dung de minh hoa
nguyen ly MITM vao 2DES, ung voi ban tinh tay "phan C" cua bao cao. MITM that duoc chay
tren DES day du o core/mitm_des.py.

Ma do choi (khoi 4-bit, khoa 4-bit):
        E_k(x) = S[x XOR k]          D_k(y) = Sinv[y] XOR k
    S la S-box 4-bit cua he ma PRESENT (co dinh, tra bang duoc bang tay).

Ma kep (giong 2DES):   C = E_k2( E_k1(P) )  = S[ S[P xor k1] xor k2 ]

MITM:
  1. Voi MOI k1: tinh X = E_k1(P1), luu bang  X -> k1        (16 muc)
  2. Voi MOI k2: tinh Y = D_k2(C1); neu Y trung mot X da luu -> ung vien (k1, k2)
  3. Loc cac ung vien bang cap known-plaintext thu 2, thu 3, ... cho den khi con 1 ung vien.
Tong chi 2*16 = 32 phep ma/giai ma thay vi 16*16 = 256 phep neu vet can.
"""

S = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
S_INV = [S.index(v) for v in range(16)]
KEY_SPACE = 16


def enc(x, k):
    """E_k(x) = S[x xor k]."""
    return S[x ^ k]


def dec(y, k):
    """D_k(y) = Sinv[y] xor k."""
    return S_INV[y] ^ k


def double_encrypt(p, k1, k2):
    """Ma kep: C = E_k2(E_k1(P))."""
    return enc(enc(p, k1), k2)


def mitm_toy(pairs, trace=None):
    """Tan cong MITM tren ma kep do choi.

    pairs: danh sach cap (P, C) da biet (known-plaintext), cap dau dung de lap bang.
    trace: ham in (vd print) hoac None.
    Tra ve dict: bang1, bang2, matches (sau cap 1), survivors_per_pair, final, so phep tinh.
    """
    log = trace or (lambda *_: None)
    p1, c1 = pairs[0]

    log("Cap 1: P1 = {:X}, C1 = {:X}".format(p1, c1))
    log("")
    log("Buoc 1: bang  X = E_k1(P1)  voi moi k1")
    table = {}
    table_rows = []
    for k1 in range(KEY_SPACE):
        x = enc(p1, k1)
        table_rows.append((k1, x))
        table.setdefault(x, []).append(k1)
        log("  k1 = {:X}:  X = S[{:X} xor {:X}] = S[{:X}] = {:X}".format(k1, p1, k1, p1 ^ k1, x))

    log("")
    log("Buoc 2: voi moi k2 tinh  Y = D_k2(C1),  tim Y trung mot X trong bang")
    matches = []
    rev_rows = []
    for k2 in range(KEY_SPACE):
        y = dec(c1, k2)
        rev_rows.append((k2, y))
        hit = table.get(y, [])
        note = "  <-- trung voi k1 = " + ", ".join("{:X}".format(k) for k in hit) if hit else ""
        log("  k2 = {:X}:  Y = Sinv[{:X}] xor {:X} = {:X}{}".format(k2, c1, k2, y, note))
        for k1 in hit:
            matches.append((k1, k2))

    log("")
    log("Sau cap 1 con {} ung vien (k1,k2): {}".format(
        len(matches), ", ".join("({:X},{:X})".format(a, b) for a, b in matches)))

    survivors = [list(matches)]
    current = matches
    for i, (p, c) in enumerate(pairs[1:], start=2):
        current = [(a, b) for (a, b) in current if double_encrypt(p, a, b) == c]
        survivors.append(list(current))
        log("Loc bang cap {} (P={:X}, C={:X}): con {} ung vien: {}".format(
            i, p, c, len(current),
            ", ".join("({:X},{:X})".format(a, b) for a, b in current)))

    return {
        "table": table_rows,            # (k1, E_k1(P1))
        "reverse": rev_rows,            # (k2, D_k2(C1))
        "matches": matches,
        "survivors": survivors,         # ung vien sau tung cap
        "final": current,
        "mitm_ops": 2 * KEY_SPACE,
        "brute_force_ops": KEY_SPACE * KEY_SPACE,
    }


if __name__ == "__main__":
    # Vi du: khoa that (k1, k2) = (0x6, 0xB); 3 cap known-plaintext
    K1, K2 = 0x6, 0xB
    plain = [0x3, 0xA, 0x7]
    prs = [(p, double_encrypt(p, K1, K2)) for p in plain]
    print("Khoa that (an doi voi ke tan cong): k1 = {:X}, k2 = {:X}".format(K1, K2))
    print("Cac cap (P, C):", ", ".join("({:X},{:X})".format(p, c) for p, c in prs))
    print()
    res = mitm_toy(prs, trace=print)
    print()
    print("KET QUA:", ", ".join("k1 = {:X}, k2 = {:X}".format(a, b) for a, b in res["final"]))
    print("So phep ma/giai ma: MITM = {}, vet can = {}".format(res["mitm_ops"], res["brute_force_ops"]))

"""
mitm_sdes.py - Tấn công meet-in-the-middle (MITM) lên 2S-DES với KHÓA ĐẦY ĐỦ (mỗi khóa 10 bit).

Đây là bản MITM "thật" chạy được trên máy: không gian khóa của 2S-DES chỉ là 2^10 x 2^10 = 2^20.
Vét cạn thử 2^20 cặp khóa; MITM chỉ cần 2 x 2^10 phép mã/giải mã.

    C = E_K2( E_K1(P) )
    1. Với MỌI K1: tính X = E_K1(P1), lưu bảng  X -> K1                     (1024 mục)
    2. Với MỌI K2: tính Y = D_K2(C1); nếu Y có trong bảng -> ứng viên (K1, K2)
    3. Lọc ứng viên bằng cặp known-plaintext thứ 2, 3, ... cho đến khi còn 1.

Vì sao một cặp (P, C) chưa đủ: khối chỉ 8 bit nên có 2^20 / 2^8 = 2^12 = 4096 ứng viên "đúng với
cặp đầu"; mỗi cặp thêm loại bớt khoảng 255/256 số ứng viên. Cần khoảng 3 cặp để còn 1 ứng viên.
(Với 2DES thật: 2^112 / 2^64 = 2^48 ứng viên sau 1 cặp, cần >= 2 cặp.)
"""

import time

from core.sdes import generate_subkeys, _crypt_block

KEY_SPACE = 1 << 10      # 1024 khóa 10 bit


def _precompute_subkeys():
    """Sinh sẵn (K1, K2) của cả 1024 khóa để các vòng lặp lớn không phải sinh lại."""
    return [generate_subkeys(k) for k in range(KEY_SPACE)]


def _enc(x, sk):
    return _crypt_block(x, sk[0], sk[1])


def _dec(y, sk):
    return _crypt_block(y, sk[1], sk[0])


def double_encrypt(p, k1, k2):
    """Mã kép C = E_k2(E_k1(P)) cho khóa 10 bit (dùng để tạo dữ liệu thử)."""
    sk1, sk2 = generate_subkeys(k1), generate_subkeys(k2)
    return _enc(_enc(p, sk1), sk2)


def mitm_2sdes(pairs, trace=None):
    """Tấn công MITM lên 2S-DES.

    pairs: danh sách (P, C) known-plaintext (int 8 bit); cặp đầu dùng để lập bảng.
    trace: hàm in (vd print) hoặc None.
    Trả về dict: candidates_per_pair, final, mitm_ops, brute_force_ops, table_entries, time.
    """
    log = trace or (lambda *_: None)
    t0 = time.perf_counter()
    sks = _precompute_subkeys()
    p1, c1 = pairs[0]

    # Bước 1: bảng X -> [K1]
    table = {}
    for k1 in range(KEY_SPACE):
        table.setdefault(_enc(p1, sks[k1]), []).append(k1)
    log("Buoc 1: lap bang X = E_K1(P1) cho {} khoa K1 -> {} gia tri X khac nhau".format(KEY_SPACE, len(table)))

    # Bước 2: với mỗi K2 tính Y = D_K2(C1), tra bảng
    matches = []
    for k2 in range(KEY_SPACE):
        for k1 in table.get(_dec(c1, sks[k2]), ()):
            matches.append((k1, k2))
    counts = [len(matches)]
    log("Buoc 2: tra bang voi {} khoa K2 -> con {} ung vien (K1,K2) sau cap 1 "
        "(ky vong ~ 2^20/2^8 = {})".format(KEY_SPACE, len(matches), (KEY_SPACE * KEY_SPACE) >> 8))

    # Bước 3: lọc bằng các cặp còn lại
    current = matches
    for i, (p, c) in enumerate(pairs[1:], start=2):
        current = [(a, b) for (a, b) in current if _enc(_enc(p, sks[a]), sks[b]) == c]
        counts.append(len(current))
        log("Buoc 3: loc bang cap {}: con {} ung vien".format(i, len(current)))

    return {
        "candidates_per_pair": counts,
        "final": current,
        "table_entries": len(table),
        "mitm_ops": 2 * KEY_SPACE,
        "brute_force_ops": 2 * KEY_SPACE * KEY_SPACE,
        "time": time.perf_counter() - t0,
    }


def brute_force_2sdes(pairs):
    """Vét cạn: thử MỌI cặp (K1, K2) (2^20 cặp), mỗi cặp mã hóa hai lần cặp đầu rồi so với C1.

    Trả về dict: final (các cặp khóa khớp TẤT CẢ các cặp), trials, time.
    """
    t0 = time.perf_counter()
    sks = _precompute_subkeys()
    p1, c1 = pairs[0]
    found = []
    trials = 0
    for k1 in range(KEY_SPACE):
        for k2 in range(KEY_SPACE):
            trials += 1
            if _enc(_enc(p1, sks[k1]), sks[k2]) != c1:
                continue
            if all(_enc(_enc(p, sks[k1]), sks[k2]) == c for p, c in pairs[1:]):
                found.append((k1, k2))
    return {"final": found, "trials": trials, "time": time.perf_counter() - t0}

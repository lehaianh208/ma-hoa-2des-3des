import time

from core.tinydes import generate_subkeys, f_function

KEY_SPACE = 1 << 8       # 256 khóa 8 bit
ROUNDS = 3


def _precompute_subkeys():
    """Sinh sẵn [K1, K2, K3] của cả 256 khóa."""
    return [generate_subkeys(k) for k in range(KEY_SPACE)]


def _enc(x, sk):
    left, right = (x >> 4) & 0xF, x & 0xF
    for ki in sk:
        left, right = right, left ^ f_function(right, ki)
    return (left << 4) | right


def _dec(y, sk):
    left, right = (y >> 4) & 0xF, y & 0xF
    for ki in reversed(sk):
        left, right = right ^ f_function(left, ki), left
    return (left << 4) | right


def double_encrypt(p, k1, k2):
    """Mã kép C = E_k2(E_k1(P)) cho khóa 8 bit (dùng để tạo dữ liệu thử)."""
    return _enc(_enc(p, generate_subkeys(k1)), generate_subkeys(k2))


def mitm_2tinydes(pairs, trace=None):
    """Tấn công MITM lên 2TinyDES.

    pairs: danh sách (P, C) known-plaintext (int 8 bit); cặp đầu dùng để lập bảng.
    Trả về dict: candidates_per_pair, final, mitm_ops, brute_force_ops, table_entries, time.
    """
    log = trace or (lambda *_: None)
    t0 = time.perf_counter()
    sks = _precompute_subkeys()
    p1, c1 = pairs[0]

    table = {}
    for k1 in range(KEY_SPACE):
        table.setdefault(_enc(p1, sks[k1]), []).append(k1)
    log("Buoc 1: lap bang X = E_K1(P1) cho {} khoa K1 -> {} gia tri X khac nhau".format(KEY_SPACE, len(table)))

    matches = []
    for k2 in range(KEY_SPACE):
        for k1 in table.get(_dec(c1, sks[k2]), ()):
            matches.append((k1, k2))
    counts = [len(matches)]
    log("Buoc 2: tra bang voi {} khoa K2 -> con {} ung vien (K1,K2) sau cap 1 "
        "(ky vong ~ 2^16/2^8 = {})".format(KEY_SPACE, len(matches), (KEY_SPACE * KEY_SPACE) >> 8))

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


def brute_force_2tinydes(pairs):
    """Vét cạn: thử MỌI cặp (K1, K2) (2^16 cặp). Trả về dict: final, trials, time."""
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

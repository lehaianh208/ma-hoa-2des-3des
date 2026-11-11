"""des.py - DES tự cài đặt, không dùng thư viện mật mã."""

from core.tables import IP, FP, E, P, PC1, PC2, SHIFTS, SBOXES


def bits(x, n, group):
    """Chuỗi nhị phân n bit, chia nhóm `group` bit cho dễ đọc (chỉ dùng để in)."""
    s = format(x, "0%db" % n)
    return " ".join(s[i:i + group] for i in range(0, n, group))


def permute(value, table, in_bits):
    """Áp dụng bảng hoán vị `table` lên số nguyên `value` có `in_bits` bit."""
    out = 0
    for pos in table:
        bit = (value >> (in_bits - pos)) & 1    # lấy bit thứ `pos` tính từ TRÁI
        out = (out << 1) | bit                  # nối vào bên phải kết quả
    return out


def rotl28(x, n):
    """Dịch vòng trái n bit cho số 28-bit."""
    return ((x << n) | (x >> (28 - n))) & 0xFFFFFFF


def generate_subkeys(key, trace=None):
    """Sinh 16 khóa con 48-bit từ khóa 64-bit."""
    kplus = permute(key, PC1, 64)        # 64 -> 56 bit
    c = kplus >> 28                      # nửa trái 28 bit
    d = kplus & 0xFFFFFFF                # nửa phải 28 bit
    if trace:
        trace("K+ = " + bits(kplus, 56, 7))
        trace("C0 = " + bits(c, 28, 7))
        trace("D0 = " + bits(d, 28, 7))
    subkeys = []
    for i, n in enumerate(SHIFTS, start=1):
        c = rotl28(c, n)                 # dịch CỘNG DỒN qua các vòng
        d = rotl28(d, n)
        k = permute((c << 28) | d, PC2, 56)     # 56 -> 48 bit
        subkeys.append(k)
        if trace:
            trace("K%d = %s (hex %012X)" % (i, bits(k, 48, 6), k))
    return subkeys


def feistel_f(r, k, trace=None):
    """F(R, K): mở rộng E -> XOR khóa -> 8 S-box -> hoán vị P."""
    e = permute(r, E, 32)                # 32 -> 48 bit
    x = e ^ k
    if trace:
        trace("    E(R)       = " + bits(e, 48, 6))
        trace("    E(R) xor K = " + bits(x, 48, 6))
    out = 0
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F          # nhóm 6 bit thứ i, từ trái sang
        row = ((six >> 4) & 0b10) | (six & 1)     # hàng = bit đầu và bit cuối
        col = (six >> 1) & 0xF                    # cột = 4 bit giữa
        out = (out << 4) | SBOXES[i][row][col]    # mỗi S-box cho ra 4 bit
    if trace:
        trace("    S-box out  = " + bits(out, 32, 4))
    result = permute(out, P, 32)
    if trace:
        trace("    P(S-box)   = " + bits(result, 32, 4))
    return result


def crypt_block(block, subkeys, trace=None):
    """Lõi DES: IP -> 16 vòng Feistel -> hoán đổi cuối -> FP."""
    x = permute(block, IP, 64)
    l = x >> 32                          # L0
    r = x & 0xFFFFFFFF                   # R0
    if trace:
        trace("IP = " + bits(x, 64, 8))
        trace("L0 = " + bits(l, 32, 4))
        trace("R0 = " + bits(r, 32, 4))
    for i, k in enumerate(subkeys, start=1):
        if trace:
            trace("--- Vòng %d ---" % i)
        l, r = r, l ^ feistel_f(r, k, trace)    # L_i = R_(i-1);  R_i = L_(i-1) xor F(R_(i-1), K_i)
        if trace:
            trace("    L%d = %s" % (i, bits(l, 32, 4)))
            trace("    R%d = %s" % (i, bits(r, 32, 4)))
    out = permute((r << 32) | l, FP, 64)        # chú ý: ghép R16 || L16, KHÔNG phải L16 || R16
    if trace:
        trace("Kết quả = %016X" % out)
    return out


def des_encrypt_block(block, key, trace=None):
    """Mã hóa một khối 64-bit (số nguyên) bằng khóa 64-bit."""
    return crypt_block(block, generate_subkeys(key, trace), trace)


def des_decrypt_block(block, key, trace=None):
    """Giải mã = cùng thuật toán, dùng 16 khóa con theo thứ tự ngược."""
    return crypt_block(block, generate_subkeys(key, trace)[::-1], trace)


def hex_to_int(s):
    """Chuỗi hex 16 ký tự -> số nguyên 64-bit."""
    s = s.strip().replace(" ", "")
    if len(s) != 16:
        raise ValueError("Cần đúng 16 ký tự hex, nhận được %d" % len(s))
    return int(s, 16)


def int_to_hex(v):
    """Số nguyên 64-bit -> chuỗi hex 16 ký tự viết hoa."""
    return "%016X" % v
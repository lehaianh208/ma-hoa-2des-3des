

# ----------------------------------------------------------------------------
# Bảng hằng số
# ----------------------------------------------------------------------------

# S-box: SBOX[hàng b0b5][cột b1b2b3b4] = giá trị 4 bit (bảng viết theo hệ 16 trong bài giảng, trang 63)
SBOX = [
    [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8, 0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7],   # hàng 00
    [0x0, 0xF, 0x7, 0x4, 0xE, 0x2, 0xD, 0x1, 0xA, 0x6, 0xC, 0xB, 0x9, 0x5, 0x3, 0x8],   # hàng 01
    [0x4, 0x1, 0xE, 0x8, 0xD, 0x6, 0x2, 0xB, 0xF, 0xC, 0x9, 0x7, 0x3, 0xA, 0x5, 0x0],   # hàng 10
    [0xF, 0xC, 0x8, 0x2, 0x4, 0x9, 0x1, 0x7, 0x5, 0xB, 0x3, 0xE, 0xA, 0x0, 0x6, 0xD],   # hàng 11
]

# Các bảng hoán vị: số thứ tự bit đánh từ 0 theo cách đánh của bài giảng (bit 0 = trái nhất).
EXPAND = [2, 3, 1, 2, 1, 0]            # b2 b3 b1 b2 b1 b0
PBOX = [2, 0, 3, 1]                    # b2 b0 b3 b1
COMPRESS = [5, 1, 3, 2, 7, 0]          # k5 k1 k3 k2 k7 k0
SHIFTS = [1, 2, 1]                     # số bit dịch trái thêm ở vòng 1, 2, 3
ROUNDS = 3


# ----------------------------------------------------------------------------
# Hàm tiện ích về bit
# ----------------------------------------------------------------------------

def permute(value, table, in_bits):
    """Hoán vị bit: bit thứ i của đầu ra (từ trái, bắt đầu 0) = bit table[i] của đầu vào (từ trái, bắt đầu 0)."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - 1 - pos)) & 1)
    return out


def rotl4(value, n):
    """Dịch vòng trái n bit cho số 4 bit."""
    n %= 4
    return ((value << n) | (value >> (4 - n))) & 0xF


def _b(value, bits):
    """Chuỗi nhị phân có độ dài cố định (để in)."""
    return format(value, "0{}b".format(bits))


def bin_to_int(text, bits):
    """Chuỗi nhị phân (vd '01011100') -> int; kiểm tra đúng số bit. Cũng nhận hệ 16 'bb' khi bits chia hết cho 4? Không:
    chỉ nhận nhị phân để tránh nhầm lẫn."""
    text = text.strip().replace(" ", "").replace(".", "")
    if len(text) != bits or any(ch not in "01" for ch in text):
        raise ValueError("Can dung chuoi {} bit nhi phan (chi gom 0 va 1), nhan duoc '{}'".format(bits, text))
    return int(text, 2)


def int_to_bin(value, bits):
    """int -> chuỗi nhị phân `bits` ký tự."""
    return _b(value, bits)


# ----------------------------------------------------------------------------
# Các hàm thành phần
# ----------------------------------------------------------------------------

def expand(r):
    """Expand: 4 bit -> 6 bit theo b2 b3 b1 b2 b1 b0. Ví dụ 0110 -> 101110."""
    return permute(r, EXPAND, 4)


def sbox(x):
    """S-box: 6 bit -> 4 bit. Hàng = b0 b5 (bit đầu và bit cuối), cột = b1 b2 b3 b4 (4 bit giữa)."""
    row = ((x >> 4) & 0b10) | (x & 1)
    col = (x >> 1) & 0xF
    return SBOX[row][col]


def pbox(x):
    """P-box: hoán vị 4 bit b0 b1 b2 b3 thành b2 b0 b3 b1."""
    return permute(x, PBOX, 4)


def compress(k8):
    """Nén 8 bit (KL KR) xuống khóa con 6 bit: k5 k1 k3 k2 k7 k0."""
    return permute(k8, COMPRESS, 8)


def f_function(r, subkey, trace=None):
    """F(R, K) = P-box( S-box( Expand(R) xor K ) )."""
    e = expand(r)
    x = e ^ subkey
    s = sbox(x)
    f = pbox(s)
    if trace:
        trace("    Expand(R)        = " + _b(e, 6))
        trace("    Expand(R) xor K  = " + _b(x, 6))
        trace("    S-box            = " + _b(s, 4))
        trace("    F = P-box        = " + _b(f, 4))
    return f


# ----------------------------------------------------------------------------
# Sinh khóa con
# ----------------------------------------------------------------------------

def generate_subkeys(key, trace=None):
    """Sinh ba khóa con 6 bit [K1, K2, K3] từ khóa 8 bit."""
    kl, kr = (key >> 4) & 0xF, key & 0xF
    if trace:
        trace("Khoa K = " + _b(key, 8) + "   KL0 = " + _b(kl, 4) + ", KR0 = " + _b(kr, 4))
    subkeys = []
    for i, shift in enumerate(SHIFTS, start=1):
        kl, kr = rotl4(kl, shift), rotl4(kr, shift)
        ki = compress((kl << 4) | kr)
        subkeys.append(ki)
        if trace:
            trace("  Vong {}: KL{} = {}, KR{} = {} (dich them {} bit)  ->  K{} = Compress = {}".format(
                i, i, _b(kl, 4), i, _b(kr, 4), shift, i, _b(ki, 6)))
    return subkeys


# ----------------------------------------------------------------------------
# Mã hóa / giải mã một khối
# ----------------------------------------------------------------------------

def tinydes_encrypt_block(block, key, trace=None):
    """Mã hóa khối 8 bit (int) bằng khóa 8 bit (int). Trả về bản mã 8 bit."""
    subkeys = generate_subkeys(key, trace)
    left, right = (block >> 4) & 0xF, block & 0xF
    if trace:
        trace("Ban ro P = " + _b(block, 8) + "   L0 = " + _b(left, 4) + ", R0 = " + _b(right, 4))
    for i, ki in enumerate(subkeys, start=1):
        if trace:
            trace("--- Vong {} (K{} = {}) ---".format(i, i, _b(ki, 6)))
        f = f_function(right, ki, trace)
        left, right = right, left ^ f                 # L_i = R_{i-1};  R_i = L_{i-1} xor F
        if trace:
            trace("    L{} = {}, R{} = {}".format(i, _b(left, 4), i, _b(right, 4)))
    out = (left << 4) | right                         # C = L3 R3 (không đổi chỗ)
    if trace:
        trace("Ban ma C = L3R3 = " + _b(out, 8) + " (" + format(out, "02X") + ")")
    return out


def tinydes_decrypt_block(block, key, trace=None):
    """Giải mã khối 8 bit: R_{i-1} = L_i;  L_{i-1} = R_i xor F(R_{i-1}, K_i), khóa theo thứ tự K3, K2, K1."""
    subkeys = generate_subkeys(key, trace)
    left, right = (block >> 4) & 0xF, block & 0xF
    if trace:
        trace("Ban ma C = " + _b(block, 8) + "   L3 = " + _b(left, 4) + ", R3 = " + _b(right, 4))
    for i in range(ROUNDS, 0, -1):
        ki = subkeys[i - 1]
        if trace:
            trace("--- Vong {} nguoc (K{} = {}) ---".format(i, i, _b(ki, 6)))
        prev_right = left                              # R_{i-1} = L_i
        f = f_function(prev_right, ki, trace)
        left, right = right ^ f, prev_right            # L_{i-1} = R_i xor F(R_{i-1}, K_i)
        if trace:
            trace("    L{} = {}, R{} = {}".format(i - 1, _b(left, 4), i - 1, _b(right, 4)))
    out = (left << 4) | right
    if trace:
        trace("Ban ro P = L0R0 = " + _b(out, 8) + " (" + format(out, "02X") + ")")
    return out

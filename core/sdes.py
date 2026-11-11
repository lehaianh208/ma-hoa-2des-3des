"""DES rút gọn: khối 8 bit, khóa 10 bit, 2 vòng. """

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]          # hoán vị khóa 10 bit
P8 = [6, 3, 7, 4, 8, 5, 10, 9]                 # chọn 8 trong 10 bit để ra khóa con
IP = [2, 6, 3, 1, 4, 8, 5, 7]                  # hoán vị đầu
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]              # hoán vị cuối (nghịch đảo của IP)
EP = [4, 1, 2, 3, 2, 3, 4, 1]                  # mở rộng 4 -> 8 bit
P4 = [2, 4, 3, 1]                              # hoán vị sau S-box

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]



def permute(value, table, in_bits):    # Hoán vị `value` (số nguyên `in_bits` bit) theo `table`. Bit 1 là bit trái nhất.
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_bits - pos)) & 1)
    return out


def rotl5(value, n):                    # Dịch vòng trái n bit cho số 5 bit.
    mask = 0b11111
    return ((value << n) | (value >> (5 - n))) & mask


def _b(value, bits):    # Chuỗi nhị phân độ dài cố định (dùng để in)
    return format(value, "0{}b".format(bits))


def bin_to_int(text, bits): # Chuỗi nhị phân ('10010111') -> số nguyên; kiểm tra đúng số bit.
    text = text.strip().replace(" ", "")
    if len(text) != bits or any(ch not in "01" for ch in text):
        raise ValueError("Can dung chuoi {} bit nhi phan (chi gom 0 va 1), nhan duoc '{}'".format(bits, text))
    return int(text, 2)


def int_to_bin(value, bits):    # Số nguyên -> chuỗi nhị phân `bits` ký tự.
    return _b(value, bits)

def generate_subkeys(key, trace=None):     #Từ khóa 10 bit sinh (K1, K2), mỗi khóa con 8 bit.
    k = permute(key, P10, 10)
    left = (k >> 5) & 0b11111          # nửa trái 5 bit
    right = k & 0b11111                # nửa phải 5 bit
    if trace:
        trace("Khoa 10 bit      = " + _b(key, 10))
        trace("P10(khoa)        = " + _b(k, 10) + "   (nua trai " + _b(left, 5) + " | nua phai " + _b(right, 5) + ")")

    left, right = rotl5(left, 1), rotl5(right, 1)
    k1 = permute((left << 5) | right, P8, 10)
    if trace:
        trace("Sau dich trai 1  = " + _b(left, 5) + " | " + _b(right, 5))
        trace("K1 = P8(...)     = " + _b(k1, 8))

    left, right = rotl5(left, 2), rotl5(right, 2)
    k2 = permute((left << 5) | right, P8, 10)
    if trace:
        trace("Sau dich them 2  = " + _b(left, 5) + " | " + _b(right, 5))
        trace("K2 = P8(...)     = " + _b(k2, 8))
    return k1, k2

# Hàm F và hàm fK
def sbox_lookup(sbox, four_bits):
    """Tra S-box: hàng = bit 1 và bit 4, cột = bit 2 và bit 3 của 4 bit đầu vào."""
    row = ((four_bits >> 2) & 0b10) | (four_bits & 1)
    col = (four_bits >> 1) & 0b11
    return sbox[row][col]

def f_function(r, subkey, trace=None):    # Hàm F(R, K): mở rộng EP (4->8) -> XOR khóa -> S0, S1 -> hoán vị P4.
    expanded = permute(r, EP, 4)               # 8 bit
    xored = expanded ^ subkey                  # 8 bit
    left4 = (xored >> 4) & 0xF                 # đi vào S0
    right4 = xored & 0xF                       # đi vào S1
    s0 = sbox_lookup(S0, left4)
    s1 = sbox_lookup(S1, right4)
    sbox_out = (s0 << 2) | s1                  # 4 bit
    result = permute(sbox_out, P4, 4)
    if trace:
        trace("    EP(R)        = " + _b(expanded, 8))
        trace("    EP(R) xor K  = " + _b(xored, 8) + "   (S0 nhan " + _b(left4, 4) + ", S1 nhan " + _b(right4, 4) + ")")
        trace("    S0 = {} S1 = {}  -> {}".format(_b(s0, 2), _b(s1, 2), _b(sbox_out, 4)))
        trace("    P4           = " + _b(result, 4))
    return result

def fk(left, right, subkey, trace=None):
    """fK(L, R) = (L xor F(R, K), R)."""
    return left ^ f_function(right, subkey, trace), right

#  Mã hóa / giải mã một khối

def _crypt_block(block, first_key, second_key, trace=None):
    """Lõi chung: IP -> fK(khóa đầu) -> SW -> fK(khóa sau) -> IP^-1.

    Mã hóa dùng (K1, K2); giải mã dùng (K2, K1).
    """
    permuted = permute(block, IP, 8)
    left = (permuted >> 4) & 0xF
    right = permuted & 0xF
    if trace:
        trace("IP        = " + _b(permuted, 8) + "   (L = " + _b(left, 4) + ", R = " + _b(right, 4) + ")")
        trace("--- Vong 1 (fK voi khoa {}) ---".format(_b(first_key, 8)))
    left, right = fk(left, right, first_key, trace)
    if trace:
        trace("    sau fK    : L = " + _b(left, 4) + ", R = " + _b(right, 4))

    left, right = right, left                  # SW: đổi chỗ hai nửa
    if trace:
        trace("--- SW (doi cho hai nua): L = " + _b(left, 4) + ", R = " + _b(right, 4))
        trace("--- Vong 2 (fK voi khoa {}) ---".format(_b(second_key, 8)))
    left, right = fk(left, right, second_key, trace)
    if trace:
        trace("    sau fK    : L = " + _b(left, 4) + ", R = " + _b(right, 4))

    out = permute((left << 4) | right, IP_INV, 8)
    if trace:
        trace("IP^-1     = " + _b(out, 8))
    return out


def sdes_encrypt_block(block, key, trace=None): #Mã hóa một khối 8 bit (int) bằng khóa 10 bit (int).
    k1, k2 = generate_subkeys(key, trace)
    return _crypt_block(block, k1, k2, trace)


def sdes_decrypt_block(block, key, trace=None): #Giải mã một khối 8 bit (int) bằng khóa 10 bit (int).
    k1, k2 = generate_subkeys(key, trace)
    return _crypt_block(block, k2, k1, trace)



from core.tinydes import tinydes_encrypt_block, tinydes_decrypt_block


def encrypt_2tinydes(block, k1, k2, trace=None):
    """2TinyDES: C = E_K2(E_K1(P))."""
    middle = tinydes_encrypt_block(block, k1, trace)      # giá trị "ở giữa" X = E_K1(P)
    if trace:
        trace(">>> 2TinyDES: X = E_K1(P) = {:08b}".format(middle))
    return tinydes_encrypt_block(middle, k2, trace)


def decrypt_2tinydes(block, k1, k2, trace=None):
    """2TinyDES: P = D_K1(D_K2(C))."""
    middle = tinydes_decrypt_block(block, k2, trace)      # X = D_K2(C)
    if trace:
        trace(">>> 2TinyDES: X = D_K2(C) = {:08b}".format(middle))
    return tinydes_decrypt_block(middle, k1, trace)


def encrypt_3tinydes(block, k1, k2, k3, trace=None):
    """3TinyDES-EDE: C = E_K3(D_K2(E_K1(P)))."""
    a = tinydes_encrypt_block(block, k1, trace)
    if trace:
        trace(">>> 3TinyDES: A = E_K1(P) = {:08b}".format(a))
    b = tinydes_decrypt_block(a, k2, trace)
    if trace:
        trace(">>> 3TinyDES: B = D_K2(A) = {:08b}".format(b))
    return tinydes_encrypt_block(b, k3, trace)


def decrypt_3tinydes(block, k1, k2, k3, trace=None):
    """3TinyDES-EDE: P = D_K1(E_K2(D_K3(C)))."""
    b = tinydes_decrypt_block(block, k3, trace)
    if trace:
        trace(">>> 3TinyDES: B = D_K3(C) = {:08b}".format(b))
    a = tinydes_encrypt_block(b, k2, trace)
    if trace:
        trace(">>> 3TinyDES: A = E_K2(B) = {:08b}".format(a))
    return tinydes_decrypt_block(a, k1, trace)


def crypt_block(alg, op, keys, block, trace=None):
    """Mã hóa (op='enc') hoặc giải mã (op='dec') một khối 8 bit.

    alg: 'tinydes' | '2tinydes' | '3tinydes';  keys: danh sách khóa int
         (TinyDES: 1 khóa, 2TinyDES: 2 khóa, 3TinyDES: 1, 2 hoặc 3 khóa).
    """
    enc = (op == "enc")
    if alg == "tinydes":
        if len(keys) != 1:
            raise ValueError("TinyDES can dung 1 khoa")
        return (tinydes_encrypt_block if enc else tinydes_decrypt_block)(block, keys[0], trace)
    if alg == "2tinydes":
        if len(keys) != 2:
            raise ValueError("2TinyDES can dung 2 khoa (K1, K2)")
        return (encrypt_2tinydes if enc else decrypt_2tinydes)(block, keys[0], keys[1], trace)
    if alg == "3tinydes":
        if len(keys) == 1:
            k1 = k2 = k3 = keys[0]       # 1 khóa: tương thích TinyDES
        elif len(keys) == 2:
            k1, k2 = keys
            k3 = k1                      # 2 khóa: K3 = K1
        elif len(keys) == 3:
            k1, k2, k3 = keys
        else:
            raise ValueError("3TinyDES can 1, 2 hoac 3 khoa")
        return (encrypt_3tinydes if enc else decrypt_3tinydes)(block, k1, k2, k3, trace)
    raise ValueError("He ma phai la tinydes, 2tinydes hoac 3tinydes")

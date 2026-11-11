"""
sdes_multi.py - 2S-DES và 3S-DES: cùng cách ghép như 2DES, 3DES nhưng xây trên S-DES (core/sdes.py).

    2S-DES:  C = E_K2( E_K1(P) )          P = D_K1( D_K2(C) )
    3S-DES:  C = E_K3( D_K2( E_K1(P) ) )  (dạng EDE)
             P = D_K1( E_K2( D_K3(C) ) )

Ba kiểu khóa của 3S-DES (giống 3DES):
    - 3 khóa độc lập : K1, K2, K3 khác nhau
    - 2 khóa         : K3 = K1
    - 1 khóa         : K1 = K2 = K3  ->  E(D(E(P))) = E(P), tương thích ngược với S-DES đơn

Khối là int 8 bit, mỗi khóa là int 10 bit (xem sdes.py).
Vì S-DES chỉ có 10 bit khóa nên 2S-DES có không gian khóa 2^20: đủ nhỏ để CHẠY THẬT cả vét cạn
lẫn MITM trên khóa đầy đủ (xem core/mitm_sdes.py) - điều không làm được với 2DES thật (2^112).
"""

from core.sdes import sdes_encrypt_block, sdes_decrypt_block


def encrypt_2sdes(block, k1, k2, trace=None):
    """2S-DES: C = E_K2(E_K1(P))."""
    middle = sdes_encrypt_block(block, k1, trace)      # giá trị "ở giữa" X = E_K1(P)
    if trace:
        trace(">>> 2S-DES: X = E_K1(P) = {:08b}".format(middle))
    return sdes_encrypt_block(middle, k2, trace)


def decrypt_2sdes(block, k1, k2, trace=None):
    """2S-DES: P = D_K1(D_K2(C))."""
    middle = sdes_decrypt_block(block, k2, trace)      # X = D_K2(C)
    if trace:
        trace(">>> 2S-DES: X = D_K2(C) = {:08b}".format(middle))
    return sdes_decrypt_block(middle, k1, trace)


def encrypt_3sdes(block, k1, k2, k3, trace=None):
    """3S-DES-EDE: C = E_K3(D_K2(E_K1(P)))."""
    a = sdes_encrypt_block(block, k1, trace)
    if trace:
        trace(">>> 3S-DES: A = E_K1(P) = {:08b}".format(a))
    b = sdes_decrypt_block(a, k2, trace)
    if trace:
        trace(">>> 3S-DES: B = D_K2(A) = {:08b}".format(b))
    return sdes_encrypt_block(b, k3, trace)


def decrypt_3sdes(block, k1, k2, k3, trace=None):
    """3S-DES-EDE: P = D_K1(E_K2(D_K3(C)))."""
    b = sdes_decrypt_block(block, k3, trace)
    if trace:
        trace(">>> 3S-DES: B = D_K3(C) = {:08b}".format(b))
    a = sdes_encrypt_block(b, k2, trace)
    if trace:
        trace(">>> 3S-DES: A = E_K2(B) = {:08b}".format(a))
    return sdes_decrypt_block(a, k1, trace)


def crypt_block(alg, op, keys, block, trace=None):
    """Mã hóa (op='enc') hoặc giải mã (op='dec') một khối 8 bit.

    alg: 'sdes' | '2sdes' | '3sdes';  keys: danh sách khóa int
         (S-DES: 1 khóa, 2S-DES: 2 khóa, 3S-DES: 1, 2 hoặc 3 khóa).
    """
    enc = (op == "enc")
    if alg == "sdes":
        if len(keys) != 1:
            raise ValueError("S-DES can dung 1 khoa")
        return (sdes_encrypt_block if enc else sdes_decrypt_block)(block, keys[0], trace)
    if alg == "2sdes":
        if len(keys) != 2:
            raise ValueError("2S-DES can dung 2 khoa (K1, K2)")
        return (encrypt_2sdes if enc else decrypt_2sdes)(block, keys[0], keys[1], trace)
    if alg == "3sdes":
        if len(keys) == 1:
            k1 = k2 = k3 = keys[0]       # 1 khóa: tương thích S-DES
        elif len(keys) == 2:
            k1, k2 = keys
            k3 = k1                      # 2 khóa: K3 = K1
        elif len(keys) == 3:
            k1, k2, k3 = keys
        else:
            raise ValueError("3S-DES can 1, 2 hoac 3 khoa")
        return (encrypt_3sdes if enc else decrypt_3sdes)(block, k1, k2, k3, trace)
    raise ValueError("He ma phai la sdes, 2sdes hoac 3sdes")

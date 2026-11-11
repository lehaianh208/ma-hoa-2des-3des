"""
des_multi.py - 2DES va 3DES xay dung tren loi DES (core/des.py).

  2DES:  C = E_K2( E_K1(P) )          P = D_K1( D_K2(C) )
  3DES:  C = E_K3( D_K2( E_K1(P) ) )  (dang EDE)
         P = D_K1( E_K2( D_K3(C) ) )

Ba kieu khoa cua 3DES:
  - 3 khoa doc lap : K1, K2, K3 khac nhau       (~112-bit hieu dung vi MITM)
  - 2 khoa         : K3 = K1                    (~80-bit theo uoc luong NIST)
  - 1 khoa         : K1 = K2 = K3 -> E(D(E(P))) = E(P), tuong thich nguoc voi DES don

Khoa va khoi deu la int 64-bit (xem des.py).
"""

from core.des import des_encrypt_block, des_decrypt_block


# ----------------------------------------------------------------------------
# 2DES
# ----------------------------------------------------------------------------

def encrypt_2des(block, k1, k2, trace=None):
    """2DES: C = E_K2(E_K1(P))."""
    middle = des_encrypt_block(block, k1, trace)   # gia tri "o giua" X = E_K1(P)
    if trace:
        trace(">>> 2DES: X = E_K1(P) = {:016X}".format(middle))
    return des_encrypt_block(middle, k2, trace)


def decrypt_2des(block, k1, k2, trace=None):
    """2DES: P = D_K1(D_K2(C))."""
    middle = des_decrypt_block(block, k2, trace)   # X = D_K2(C)
    if trace:
        trace(">>> 2DES: X = D_K2(C) = {:016X}".format(middle))
    return des_decrypt_block(middle, k1, trace)


# ----------------------------------------------------------------------------
# 3DES (EDE)
# ----------------------------------------------------------------------------

def encrypt_3des(block, k1, k2, k3, trace=None):
    """3DES-EDE: C = E_K3(D_K2(E_K1(P)))."""
    a = des_encrypt_block(block, k1, trace)
    if trace:
        trace(">>> 3DES: A = E_K1(P)    = {:016X}".format(a))
    b = des_decrypt_block(a, k2, trace)
    if trace:
        trace(">>> 3DES: B = D_K2(A)    = {:016X}".format(b))
    return des_encrypt_block(b, k3, trace)


def decrypt_3des(block, k1, k2, k3, trace=None):
    """3DES-EDE: P = D_K1(E_K2(D_K3(C)))."""
    b = des_decrypt_block(block, k3, trace)
    if trace:
        trace(">>> 3DES: B = D_K3(C)    = {:016X}".format(b))
    a = des_encrypt_block(b, k2, trace)
    if trace:
        trace(">>> 3DES: A = E_K2(B)    = {:016X}".format(a))
    return des_decrypt_block(a, k1, trace)


# Kieu khoa 2 khoa (K3 = K1) va 1 khoa (K1 = K2 = K3)

def encrypt_3des_2key(block, k1, k2, trace=None):
    """3DES hai khoa: K3 = K1."""
    return encrypt_3des(block, k1, k2, k1, trace)


def decrypt_3des_2key(block, k1, k2, trace=None):
    return decrypt_3des(block, k1, k2, k1, trace)


def encrypt_3des_1key(block, k, trace=None):
    """3DES mot khoa: K1 = K2 = K3 -> cho ket qua giong DES don."""
    return encrypt_3des(block, k, k, k, trace)


def decrypt_3des_1key(block, k, trace=None):
    return decrypt_3des(block, k, k, k, trace)


# ----------------------------------------------------------------------------
# Ham tien ich chung cho CLI va web: ma/giai ma MOT khoi 64-bit (co trace)
# ----------------------------------------------------------------------------

def crypt_block(alg, op, keys, block, trace=None):
    """Ma hoa (op='enc') hoac giai ma (op='dec') mot khoi 64-bit.

    alg: 'des' | '2des' | '3des';  keys: danh sach khoa int (DES: 1, 2DES: 2, 3DES: 1-3).
    Dung ban cham (des.py) de co the in trace tung buoc.
    """
    enc = (op == "enc")
    if alg == "des":
        if len(keys) != 1:
            raise ValueError("DES can dung 1 khoa")
        return (des_encrypt_block if enc else des_decrypt_block)(block, keys[0], trace)
    if alg == "2des":
        if len(keys) != 2:
            raise ValueError("2DES can dung 2 khoa (K1, K2)")
        return (encrypt_2des if enc else decrypt_2des)(block, keys[0], keys[1], trace)
    if alg == "3des":
        if len(keys) == 1:
            k1 = k2 = k3 = keys[0]       # 1 khoa: tuong thich DES
        elif len(keys) == 2:
            k1, k2 = keys
            k3 = k1                      # 2 khoa: K3 = K1
        elif len(keys) == 3:
            k1, k2, k3 = keys
        else:
            raise ValueError("3DES can 1, 2 hoac 3 khoa")
        return (encrypt_3des if enc else decrypt_3des)(block, k1, k2, k3, trace)
    raise ValueError("He ma phai la des, 2des hoac 3des")

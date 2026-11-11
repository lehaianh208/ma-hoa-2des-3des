"""
modes.py - Che do hoat dong ECB / CBC va padding PKCS#7, de ma hoa du lieu/tep that.

Cac ham muc thap nhan HAM MA HOA MOT KHOI (int -> int) lam tham so, nen dung duoc voi
DES, 2DES, 3DES hoac bat ky ma khoi 64-bit nao (xem core/ciphers.py).

  ECB:  C_i = E(P_i)                 -> cac khoi giong nhau cho ban ma giong nhau (lo mau)
  CBC:  C_i = E(P_i xor C_{i-1}),    C_0 = IV  (ngau nhien, gui kem ban ma)

Dinh dang ban ma do encrypt_bytes tao ra:
    ECB: ban ma
    CBC: IV (8 byte) || ban ma
Moi ban ro deu duoc padding PKCS#7 (them 1..8 byte, moi byte = so byte them).
"""

import os

BLOCK_SIZE = 8  # byte (khoi 64-bit)


# ----------------------------------------------------------------------------
# Padding PKCS#7
# ----------------------------------------------------------------------------

def pkcs7_pad(data):
    """Them 1..8 byte, moi byte bang so byte them (luon them, ke ca khi du 8 byte)."""
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return bytes(data) + bytes([n]) * n


def pkcs7_unpad(data):
    """Bo padding; bao loi ValueError neu padding sai (thuong do sai khoa / sai che do)."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Du lieu khong phai boi so cua {} byte".format(BLOCK_SIZE))
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding khong hop le (sai khoa hoac sai che do?)")
    return data[:-n]


# ----------------------------------------------------------------------------
# Muc thap: du lieu DA padding (boi so cua 8 byte)
# ----------------------------------------------------------------------------

def _blocks(data):
    for i in range(0, len(data), BLOCK_SIZE):
        yield int.from_bytes(data[i:i + BLOCK_SIZE], "big")


def _to_bytes(blocks):
    return b"".join(b.to_bytes(BLOCK_SIZE, "big") for b in blocks)


def ecb_encrypt(data, enc_block):
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB: du lieu phai boi so cua 8 byte (da padding)")
    return _to_bytes(enc_block(b) for b in _blocks(data))


def ecb_decrypt(data, dec_block):
    if len(data) % BLOCK_SIZE:
        raise ValueError("ECB: ban ma phai boi so cua 8 byte")
    return _to_bytes(dec_block(b) for b in _blocks(data))


def cbc_encrypt(data, enc_block, iv):
    """iv: int 64-bit. Tra ve ban ma (KHONG kem IV)."""
    if len(data) % BLOCK_SIZE:
        raise ValueError("CBC: du lieu phai boi so cua 8 byte (da padding)")
    prev = iv
    out = []
    for b in _blocks(data):
        prev = enc_block(b ^ prev)
        out.append(prev)
    return _to_bytes(out)


def cbc_decrypt(data, dec_block, iv):
    if len(data) % BLOCK_SIZE:
        raise ValueError("CBC: ban ma phai boi so cua 8 byte")
    prev = iv
    out = []
    for c in _blocks(data):
        out.append(dec_block(c) ^ prev)
        prev = c
    return _to_bytes(out)


# ----------------------------------------------------------------------------
# Muc cao: bytes <-> bytes voi padding (dung cho tep)
# ----------------------------------------------------------------------------

def encrypt_bytes(data, cipher, mode="cbc", iv=None):
    """Ma hoa `data` (bytes). `cipher` co .encrypt/.decrypt tren int 64-bit.

    iv: bytes 8 byte (chi CBC). Neu None se sinh ngau nhien bang os.urandom.
    """
    mode = mode.lower()
    padded = pkcs7_pad(data)
    if mode == "ecb":
        return ecb_encrypt(padded, cipher.encrypt)
    if mode == "cbc":
        if iv is None:
            iv = os.urandom(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV phai dai 8 byte")
        return iv + cbc_encrypt(padded, cipher.encrypt, int.from_bytes(iv, "big"))
    raise ValueError("Che do phai la 'ecb' hoac 'cbc'")


def decrypt_bytes(data, cipher, mode="cbc"):
    """Giai ma du lieu do encrypt_bytes tao ra va bo padding."""
    mode = mode.lower()
    if mode == "ecb":
        return pkcs7_unpad(ecb_decrypt(data, cipher.decrypt))
    if mode == "cbc":
        if len(data) < 2 * BLOCK_SIZE:
            raise ValueError("Ban ma CBC qua ngan (can IV + it nhat 1 khoi)")
        iv, body = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
        return pkcs7_unpad(cbc_decrypt(body, cipher.decrypt, int.from_bytes(iv, "big")))
    raise ValueError("Che do phai la 'ecb' hoac 'cbc'")

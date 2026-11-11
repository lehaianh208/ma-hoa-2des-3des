"""
ciphers.py - Doi tuong ma khoi 64-bit thong nhat cho DES / 2DES / 3DES.

    cipher = make_cipher("3des", [k1, k2, k3])
    c = cipher.encrypt(block)      # block, c: int 64-bit
    p = cipher.decrypt(c)

Khoa con duoc sinh MOT LAN khi tao doi tuong (nhanh hon nhieu khi ma hoa ca tep).
Ben trong dung ban toi uu des_fast.py (da test khop voi des.py / des_multi.py).

Quy uoc so khoa:
    des  : 1 khoa
    2des : 2 khoa (K1, K2)                 C = E_K2(E_K1(P))
    3des : 3 khoa (K1, K2, K3)             C = E_K3(D_K2(E_K1(P)))
           2 khoa -> K3 = K1;  1 khoa -> K1 = K2 = K3 (tuong thich DES don)
"""

from core.des_fast import fast_subkeys, fast_crypt

ALGORITHMS = ("des", "2des", "3des")


class BlockCipher:
    """Ma khoi 64-bit: chuoi cac tang DES (moi tang la ma hoa hoac giai ma)."""

    def __init__(self, alg, keys):
        alg = alg.lower()
        if alg not in ALGORITHMS:
            raise ValueError("He ma phai la mot trong {}".format(ALGORITHMS))
        keys = list(keys)

        if alg == "des":
            if len(keys) != 1:
                raise ValueError("DES can dung 1 khoa")
            stages = [fast_subkeys(keys[0])]
        elif alg == "2des":
            if len(keys) != 2:
                raise ValueError("2DES can dung 2 khoa (K1, K2)")
            stages = [fast_subkeys(keys[0]), fast_subkeys(keys[1])]
        else:  # 3des (EDE)
            if len(keys) == 1:
                k1 = k2 = k3 = keys[0]
            elif len(keys) == 2:
                k1, k2 = keys
                k3 = k1
            elif len(keys) == 3:
                k1, k2, k3 = keys
            else:
                raise ValueError("3DES can 1, 2 hoac 3 khoa")
            # E_K1 -> D_K2 (khoa con dao nguoc) -> E_K3
            stages = [fast_subkeys(k1), fast_subkeys(k2)[::-1], fast_subkeys(k3)]

        self.alg = alg
        self._enc_stages = stages
        # Giai ma: lat nguoc thu tu cac tang, moi tang dung khoa con dao nguoc
        self._dec_stages = [s[::-1] for s in reversed(stages)]

    def encrypt(self, block):
        for sk in self._enc_stages:
            block = fast_crypt(block, sk)
        return block

    def decrypt(self, block):
        for sk in self._dec_stages:
            block = fast_crypt(block, sk)
        return block


def make_cipher(alg, keys):
    """Tao BlockCipher tu ten he ma va danh sach khoa (int 64-bit)."""
    return BlockCipher(alg, keys)

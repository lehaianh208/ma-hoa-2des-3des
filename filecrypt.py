"""
filecrypt.py - Ma hoa / giai ma TEP bang DES, 2DES, 3DES (ECB hoac CBC).

Vi du:
    # Ma hoa roi giai ma lai va so sanh (demo 1 lenh)
    python filecrypt.py demo --alg 3des --mode cbc --keys 133457799BBCDFF1 0E329232EA6D0D73 FEDCBA9876543210 \
                             --in samples/sample.txt

    # Ma hoa / giai ma tung buoc
    python filecrypt.py enc --alg 2des --mode ecb --keys K1 K2 --in samples/sample.txt --out sample.enc
    python filecrypt.py dec --alg 2des --mode ecb --keys K1 K2 --in sample.enc --out sample.dec.txt

Dinh dang tep ma: CBC = IV(8 byte) || ban ma;  ECB = ban ma. Co padding PKCS#7.
Khoa: hex 16 ky tu; DES 1 khoa, 2DES 2 khoa, 3DES 1-3 khoa.
"""

import argparse
import sys
import time

from core.ciphers import make_cipher
from core.des import hex_to_int
from core.modes import encrypt_bytes, decrypt_bytes


def _cipher(args):
    return make_cipher(args.alg, [hex_to_int(k) for k in args.keys])


def cmd_enc(args):
    data = open(args.inp, "rb").read()
    t = time.perf_counter()
    out = encrypt_bytes(data, _cipher(args), args.mode)
    dt = time.perf_counter() - t
    open(args.out, "wb").write(out)
    print("Ma hoa {} ({} byte) -> {} ({} byte) trong {:.3f}s".format(
        args.inp, len(data), args.out, len(out), dt))


def cmd_dec(args):
    data = open(args.inp, "rb").read()
    t = time.perf_counter()
    out = decrypt_bytes(data, _cipher(args), args.mode)
    dt = time.perf_counter() - t
    open(args.out, "wb").write(out)
    print("Giai ma {} ({} byte) -> {} ({} byte) trong {:.3f}s".format(
        args.inp, len(data), args.out, len(out), dt))


def cmd_demo(args):
    data = open(args.inp, "rb").read()
    cipher = _cipher(args)
    t = time.perf_counter()
    enc = encrypt_bytes(data, cipher, args.mode)
    t_enc = time.perf_counter() - t
    t = time.perf_counter()
    dec = decrypt_bytes(enc, cipher, args.mode)
    t_dec = time.perf_counter() - t

    print("He ma: {}  Che do: {}  Tep: {}".format(args.alg.upper(), args.mode.upper(), args.inp))
    print("Kich thuoc ban ro : {} byte".format(len(data)))
    print("Kich thuoc ban ma : {} byte (gom padding{})".format(
        len(enc), " va IV 8 byte" if args.mode == "cbc" else ""))
    print("Ban ma (hex, 64 byte dau): {}".format(enc[:64].hex().upper()))
    print("Thoi gian ma hoa  : {:.4f}s   giai ma: {:.4f}s".format(t_enc, t_dec))
    if args.save:
        open(args.save + ".enc", "wb").write(enc)
        open(args.save + ".dec", "wb").write(dec)
        print("Da luu {0}.enc va {0}.dec".format(args.save))
    ok = (dec == data)
    print("Giai ma khoi phuc dung ban ro: {}".format("KHOP" if ok else "LECH"))
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description="Ma hoa/giai ma tep bang DES, 2DES, 3DES")
    ap.add_argument("cmd", choices=["enc", "dec", "demo"])
    ap.add_argument("--alg", choices=["des", "2des", "3des"], required=True)
    ap.add_argument("--mode", choices=["ecb", "cbc"], default="cbc")
    ap.add_argument("--keys", nargs="+", required=True)
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out")
    ap.add_argument("--save", help="(demo) tien to de luu .enc / .dec")
    args = ap.parse_args()
    if args.cmd in ("enc", "dec") and not args.out:
        sys.exit("Thieu --out")
    try:
        {"enc": cmd_enc, "dec": cmd_dec, "demo": cmd_demo}[args.cmd](args)
    except (ValueError, OSError) as e:
        sys.exit("Loi: {}".format(e))


if __name__ == "__main__":
    main()

"""
cli.py - Demo dong lenh cho DES / 2DES / 3DES: ma hoa, giai ma MOT khoi 64-bit.

Vi du:
    python cli.py enc --alg des  --keys 133457799BBCDFF1 --data 0123456789ABCDEF
    python cli.py dec --alg des  --keys 133457799BBCDFF1 --data 85E813540F0AB405
    python cli.py enc --alg 2des --keys 133457799BBCDFF1 0E329232EA6D0D73 --data 0123456789ABCDEF
    python cli.py enc --alg 3des --keys K1 K2 K3 --data ...        (3 khoa)
    python cli.py enc --alg 3des --keys K1 K2    --data ...        (2 khoa, K3 = K1)
    python cli.py enc --alg 3des --keys K1       --data ...        (1 khoa, tuong thich DES)

Them --verbose de in cac buoc trung gian (khoa con, L/R tung vong, ham F) de
doi chieu voi ban tinh tay. Khoi va khoa nhap duoi dang hex 16 ky tu.

Ma hoa tep: xem filecrypt.py.   Tan cong MITM: xem mitm_demo.py.
"""

import argparse
import sys

from core.des import hex_to_int, int_to_hex
from core.des_multi import crypt_block


def main():
    ap = argparse.ArgumentParser(description="Demo DES / 2DES / 3DES (tu cai dat)")
    ap.add_argument("mode", choices=["enc", "dec"], help="enc = ma hoa, dec = giai ma")
    ap.add_argument("--alg", choices=["des", "2des", "3des"], required=True)
    ap.add_argument("--keys", nargs="+", required=True, help="khoa hex 16 ky tu (1-3 khoa)")
    ap.add_argument("--data", required=True, help="khoi 64-bit dang hex 16 ky tu")
    ap.add_argument("--verbose", action="store_true", help="in cac buoc trung gian")
    args = ap.parse_args()

    try:
        keys = [hex_to_int(k) for k in args.keys]
        out = crypt_block(args.alg, args.mode, keys, hex_to_int(args.data),
                          print if args.verbose else None)
    except ValueError as e:
        sys.exit("Loi: {}".format(e))
    print("{}: {}".format("Ban ma" if args.mode == "enc" else "Ban ro ", int_to_hex(out)))


if __name__ == "__main__":
    main()

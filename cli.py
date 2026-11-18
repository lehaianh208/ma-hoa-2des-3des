
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


import argparse
import sys

from core.sdes import bin_to_int, int_to_bin
from core.sdes_multi import crypt_block


def main():
    ap = argparse.ArgumentParser(description="Demo S-DES / 2S-DES / 3S-DES (tu cai dat)")
    ap.add_argument("mode", choices=["enc", "dec"], help="enc = ma hoa, dec = giai ma")
    ap.add_argument("--alg", choices=["sdes", "2sdes", "3sdes"], required=True)
    ap.add_argument("--keys", nargs="+", required=True, help="khoa nhi phan 10 bit (1-3 khoa)")
    ap.add_argument("--data", required=True, help="khoi 8 bit dang nhi phan, vd 01110010")
    ap.add_argument("--verbose", action="store_true", help="in cac buoc trung gian")
    args = ap.parse_args()

    try:
        keys = [bin_to_int(k, 10) for k in args.keys]
        out = crypt_block(args.alg, args.mode, keys, bin_to_int(args.data, 8),
                          print if args.verbose else None)
    except ValueError as e:
        sys.exit("Loi: {}".format(e))
    print("{}: {}".format("Ban ma" if args.mode == "enc" else "Ban ro ", int_to_bin(out, 8)))


if __name__ == "__main__":
    main()

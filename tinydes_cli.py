

import argparse
import sys

from core.tinydes import bin_to_int, int_to_bin
from core.tinydes_multi import crypt_block


def main():
    ap = argparse.ArgumentParser(description="Demo TinyDES / 2TinyDES / 3TinyDES (tu cai dat)")
    ap.add_argument("mode", choices=["enc", "dec"], help="enc = ma hoa, dec = giai ma")
    ap.add_argument("--alg", choices=["tinydes", "2tinydes", "3tinydes"], required=True)
    ap.add_argument("--keys", nargs="+", required=True, help="khoa nhi phan 8 bit (1-3 khoa)")
    ap.add_argument("--data", required=True, help="khoi 8 bit dang nhi phan, vd 01011100")
    ap.add_argument("--verbose", action="store_true", help="in cac buoc trung gian")
    args = ap.parse_args()

    try:
        keys = [bin_to_int(k, 8) for k in args.keys]
        out = crypt_block(args.alg, args.mode, keys, bin_to_int(args.data, 8),
                          print if args.verbose else None)
    except ValueError as e:
        sys.exit("Loi: {}".format(e))
    print("{}: {} ({:02X})".format("Ban ma" if args.mode == "enc" else "Ban ro ", int_to_bin(out, 8), out))


if __name__ == "__main__":
    main()

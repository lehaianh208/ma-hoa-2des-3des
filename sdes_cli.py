"""
sdes_cli.py - Demo dòng lệnh cho S-DES / 2S-DES / 3S-DES (PHIÊN BẢN THU NHỎ của DES).

Khối 8 bit, khóa 10 bit, nhập và in dưới dạng chuỗi nhị phân.

Ví dụ (ví dụ chuẩn trong giáo trình):
    python sdes_cli.py enc --alg sdes  --keys 1010000010 --data 01110010 --verbose
    python sdes_cli.py dec --alg sdes  --keys 1010000010 --data 01110111
    python sdes_cli.py enc --alg 2sdes --keys 1010000010 0110111001 --data 01110010
    python sdes_cli.py enc --alg 3sdes --keys K1 K2 K3 --data ...      (3 khóa)
    python sdes_cli.py enc --alg 3sdes --keys K1 K2    --data ...      (2 khóa, K3 = K1)
    python sdes_cli.py enc --alg 3sdes --keys K1       --data ...      (1 khóa, tương thích S-DES)

Thêm --verbose để in các bước trung gian (khóa con, IP, từng vòng, S-box...) đối chiếu với bản tính tay.
Với DES đầy đủ xem cli.py;  tấn công MITM xem mitm_demo.py (sdes).
"""

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

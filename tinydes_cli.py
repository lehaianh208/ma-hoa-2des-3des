"""
tinydes_cli.py - Demo dòng lệnh cho TinyDES / 2TinyDES / 3TinyDES (PHIÊN BẢN THU NHỎ CỦA DES MÀ LỚP ĐÃ HỌC).

Khối 8 bit, khóa 8 bit, 3 vòng Feistel; nhập và in dưới dạng chuỗi nhị phân.

Ví dụ trên lớp (bài giảng ATBMTT, chương 2):
    python tinydes_cli.py enc --alg tinydes --keys 10011010 --data 01011100 --verbose     # -> 10010010 (92)
    python tinydes_cli.py dec --alg tinydes --keys 10011010 --data 10010010
Bài 9 trong file bài tập:
    python tinydes_cli.py enc --alg tinydes --keys 10111011 --data 01010011 --verbose     # -> 10001110 (8E)
2TinyDES / 3TinyDES:
    python tinydes_cli.py enc --alg 2tinydes --keys 10011010 10111011 --data 01011100
    python tinydes_cli.py enc --alg 3tinydes --keys K1 K2 K3 --data ...      (3 khóa)
    python tinydes_cli.py enc --alg 3tinydes --keys K1 K2    --data ...      (2 khóa, K3 = K1, như bài giảng)

Thêm --verbose để in các bước trung gian (khóa con, Expand, S-box, P-box, từng vòng) đối chiếu với bản tính tay.
DES đầy đủ xem cli.py;  S-DES (giáo trình Stallings) xem sdes_cli.py;  tấn công MITM xem mitm_demo.py (tinydes).
"""

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

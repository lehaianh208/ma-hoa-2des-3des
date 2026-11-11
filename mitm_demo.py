"""
mitm_demo.py - Demo tan cong meet-in-the-middle (MITM) len 2DES.

    python mitm_demo.py toy                      # bo so nho 4-bit, in tung buoc (khop ban tinh tay)
    python mitm_demo.py des --bits 12            # DES that, moi khoa chi con 12 bit chua biet
    python mitm_demo.py des --bits 16 --seed 5   # ~ vai giay
    python mitm_demo.py des --bits 8 --brute     # chay ca vet can that de so sanh (chi voi bits <= 9)
    python mitm_demo.py sdes                     # 2S-DES voi KHOA DAY DU 10 bit: MITM that, ~0.05 giay
    python mitm_demo.py sdes --brute             # them vet can 2^20 cap khoa de so sanh (~10 giay)

Vi sao phai rut gon khoa: MITM len 2DES day du can ~2^56 muc bang tra (~576 petabyte
neu chi luu gia tri trung gian), khong the chay.
"""

import argparse
import random

from core.mitm_sdes import mitm_2sdes, brute_force_2sdes, double_encrypt as double_encrypt_sdes
from core.mitm_toy import mitm_toy, double_encrypt
from core.mitm_des import (
    make_demo_case, mitm_2des, brute_force_2des, estimate_brute_force_seconds, full_scale_estimate,
)


def human(seconds):
    for unit, div in (("nam", 365 * 86400), ("ngay", 86400), ("gio", 3600), ("phut", 60)):
        if seconds >= div:
            return "{:.3g} {}".format(seconds / div, unit)
    return "{:.3g} giay".format(seconds)


def run_toy():
    K1, K2 = 0x6, 0xB
    plain = [0x3, 0xA, 0x7]
    prs = [(p, double_encrypt(p, K1, K2)) for p in plain]
    print("Khoa that (an doi voi ke tan cong): k1 = {:X}, k2 = {:X}".format(K1, K2))
    print("Cac cap (P, C):", ", ".join("({:X},{:X})".format(p, c) for p, c in prs))
    print()
    res = mitm_toy(prs, trace=print)
    print()
    print("KET QUA:", ", ".join("k1 = {:X}, k2 = {:X}".format(a, b) for a, b in res["final"]))
    print("So phep ma/giai ma: MITM = {}, vet can = {}".format(res["mitm_ops"], res["brute_force_ops"]))


def run_des(args):
    n = args.bits
    pairs, f1, f2, true = make_demo_case(n, seed=args.seed, n_pairs=args.pairs)
    print("DES that, moi khoa co {} bit chua biet (khong gian {} khoa moi ben)".format(n, 1 << n))
    print("Phan co dinh K1 = {:014X}, K2 = {:014X} (56-bit hieu dung)".format(f1, f2))
    print("{} cap known-plaintext".format(len(pairs)))
    print()

    def progress(stage, done, total):
        if done and done % 16384 == 0:
            print("  {} {}/{}".format("lap bang" if stage == "table" else "tra bang", done, total), flush=True)

    r = mitm_2des(pairs, f1, f2, n, progress)
    print("Bang tra: {} muc | Thoi gian lap bang {:.2f}s + tra bang {:.2f}s = {:.2f}s".format(
        r["table_entries"], r["time_table"], r["time_lookup"], r["time_total"]))
    print("Ung vien con lai sau tung cap: {}".format(r["candidates_per_pair"]))
    print("Ung vien sai ky vong sau 1 cap: {:.3g} (= 2^{}/2^64)".format(
        r["expected_false_positives_one_pair"], 2 * n))
    print("Tim thay: {}   | Khoa that: {}   -> {}".format(
        r["found"], true, "DUNG" if r["found"] == [true] else "SAI"))
    print()

    est, per = estimate_brute_force_seconds(n)
    print("So phep ma/giai ma: MITM ~ 2^{} = {} | vet can ~ 2^{} cap khoa x 2 phep".format(
        n + 1, r["mitm_ops"], 2 * n))
    print("Uoc luong vet can tren may nay: {} (moi cap khoa ~{:.1f} us)".format(human(est), per * 1e6))
    if args.brute:
        if n > 9:
            print("(Bo qua vet can that: n = {} > 9 se mat qua lau; dung --bits <= 9)".format(n))
        else:
            b = brute_force_2des(pairs, f1, f2, n)
            print("Vet can THAT: {} lan thu, {:.2f}s, tim thay {}".format(b["trials"], b["time"], b["found"]))

    f = full_scale_estimate()
    print()
    print("--- Voi 2DES day du (56-bit moi khoa) ---")
    print("Phep tinh MITM ~ {}; bang tra ~ {} muc".format(f["mitm_ops"], f["table_entries"]))
    print("Dung luong bang: {:.0f} PB (chi luu X) / {:.2f} EB (kem khoa 7 byte)".format(
        f["table_bytes_values_only"] / 1e15, f["table_bytes_with_key"] / 1e18))
    print("Ung vien sai sau 1 cap: {} -> bat buoc >= 2 cap known-plaintext".format(f["false_positives_one_pair"]))


def run_sdes(args):
    rnd = random.Random(args.seed)
    k1, k2 = rnd.randrange(1 << 10), rnd.randrange(1 << 10)
    plains = rnd.sample(range(256), args.pairs)
    pairs = [(p, double_encrypt_sdes(p, k1, k2)) for p in plains]
    print("2S-DES voi khoa DAY DU: moi khoa 10 bit -> khong gian 2^20 = {} cap khoa".format(1 << 20))
    print("Khoa that (an doi voi ke tan cong): K1 = {:010b}, K2 = {:010b}".format(k1, k2))
    print("{} cap known-plaintext (P, C): {}".format(
        len(pairs), ", ".join("({:08b},{:08b})".format(p, c) for p, c in pairs)))
    print()
    r = mitm_2sdes(pairs, trace=print)
    print()
    print("Ung vien con lai sau tung cap: {}".format(r["candidates_per_pair"]))
    print("Ung vien cuoi cung: {}".format(
        ", ".join("K1 = {:010b}, K2 = {:010b}".format(a, b) for a, b in r["final"])))
    print("Khoa that co nam trong ket qua: {}".format("DUNG" if (k1, k2) in r["final"] else "SAI"))
    if len(r["final"]) > 1:
        print("(Con {} ung vien: cac khoa gan nhau co the cho cung ket qua tren it cap; "
              "tang --pairs de loai not.)".format(len(r["final"])))
    print("So phep ma/giai ma: MITM = {} | vet can = {}  (ti le ~{:.0f} lan)".format(
        r["mitm_ops"], r["brute_force_ops"], r["brute_force_ops"] / r["mitm_ops"]))
    print("Thoi gian MITM: {:.3f}s".format(r["time"]))
    if args.brute:
        print()
        print("Dang vet can that (thu {} cap khoa), vui long cho ...".format(1 << 20), flush=True)
        b = brute_force_2sdes(pairs)
        print("Vet can THAT: {} lan thu, {:.2f}s, ung vien khop tat ca cap: {}".format(
            b["trials"], b["time"], len(b["final"])))
        print("Hai cach cho cung tap ung vien: {}".format("DUNG" if sorted(b["final"]) == sorted(r["final"]) else "SAI"))


def main():
    ap = argparse.ArgumentParser(description="Demo MITM len 2DES")
    ap.add_argument("what", choices=["toy", "des", "sdes"])
    ap.add_argument("--bits", type=int, default=12, help="so bit chua biet moi khoa (des), mac dinh 12")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--pairs", type=int, default=None, help="so cap known-plaintext (des: 3, sdes: 12)")
    ap.add_argument("--brute", action="store_true", help="chay them vet can that (bits <= 9)")
    args = ap.parse_args()
    if args.pairs is None:
        args.pairs = 12 if args.what == "sdes" else 3
    if args.what == "toy":
        run_toy()
    elif args.what == "sdes":
        if not 1 <= args.pairs <= 256:
            ap.error("--pairs phai trong khoang 1..256")
        run_sdes(args)
    else:
        if not 1 <= args.bits <= 20:
            ap.error("--bits phai trong khoang 1..20")
        run_des(args)


if __name__ == "__main__":
    main()

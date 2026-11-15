"""demo.py - Chạy lần lượt các bước demo (thay cho demo.bat khi Windows chặn file .bat).

Cách chạy (từ thư mục gốc project):
    python demo.py            chạy tất cả các mục, dừng chờ Enter giữa các mục
    python demo.py 1 5        chỉ chạy mục 1 và mục 5 (để tập từng đoạn)
Trong PyCharm: bấm chuột phải file này -> Run 'demo'.
"""

import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable                      # dùng đúng Python đang chạy file này

BRUTE = True                             # False: bỏ vét cạn thật ở mục MITM (nếu thiếu giờ)

K1 = "133457799BBCDFF1"
K2 = "0123456789ABCDEF"
K3 = "FEDCBA9876543210"
P = "0123456789ABCDEF"


def find_image():
    """Tìm một ảnh trong samples/ (png, jpg, jpeg, bmp) để demo mã hóa ảnh."""
    for ext in ("png", "jpg", "jpeg", "bmp"):
        found = sorted(glob.glob(os.path.join(ROOT, "samples", "*." + ext)))
        if found:
            return os.path.join("samples", os.path.basename(found[0]))
    return None


def build_steps():
    steps = []
    steps.append(("1. S-DES (ban thu nho): ma hoa co in tung buoc, roi giai ma", [
        ["sdes_cli.py", "enc", "--alg", "sdes", "--keys", "1010000010", "--data", "01110010", "--verbose"],
        ["sdes_cli.py", "dec", "--alg", "sdes", "--keys", "1010000010", "--data", "01110111"],
    ]))
    steps.append(("2. DES day du: ma hoa co in tung buoc (vi du kinh dien), roi giai ma", [
        ["cli.py", "enc", "--alg", "des", "--keys", K1, "--data", P, "--verbose"],
        ["cli.py", "dec", "--alg", "des", "--keys", K1, "--data", "85E813540F0AB405"],
    ]))
    steps.append(("3. 2DES va 3DES", [
        ["cli.py", "enc", "--alg", "2des", "--keys", K1, K2, "--data", P],
        ["cli.py", "dec", "--alg", "2des", "--keys", K1, K2, "--data", "8D0AAB998757B0AF"],
        ["cli.py", "enc", "--alg", "3des", "--keys", K1, K2, K3, "--data", P],
        ["cli.py", "dec", "--alg", "3des", "--keys", K1, K2, K3, "--data", "EB2EF3D233BBEB25"],
    ]))
    files = [["filecrypt.py", "demo", "--alg", "3des", "--mode", "cbc", "--keys", K1, K2, K3,
              "--in", os.path.join("samples", "sample.txt"), "--save", "demo_out"]]
    image = find_image()
    if image:
        files.append(["filecrypt.py", "demo", "--alg", "3des", "--mode", "cbc", "--keys", K1, K2, K3,
                      "--in", image, "--save", "demo_anh"])
    steps.append(("4. Ma hoa tep that (CBC): van ban va anh, roi giai ma lai", files))
    mitm = ["mitm_demo.py", "sdes"] + (["--brute"] if BRUTE else [])
    steps.append(("5. Tan cong gap nhau o giua (MITM) len 2S-DES (co vet can de so sanh)", [mitm]))
    steps.append(("6. MITM o quy mo that: 2DES khoa day du", [["mitm_demo.py", "des", "--bits", "12"]]))
    steps.append(("7. Bo kiem thu va doi chieu voi thu vien chuan", [
        ["-m", "unittest", "discover", "tests"],
        [os.path.join("tests", "test_des.py"), "--compare"],
    ]))
    return steps


def run(args):
    """Chạy một lệnh Python con và in ra dòng lệnh để người xem theo dõi."""
    print("\n> python " + " ".join(args))
    sys.stdout.flush()
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    subprocess.run([PY] + args, cwd=ROOT, env=env)


def main():
    steps = build_steps()
    chosen = [int(a) for a in sys.argv[1:] if a.isdigit()] or list(range(1, len(steps) + 1))
    for number in chosen:
        if not 1 <= number <= len(steps):
            print("Khong co muc {} (chi co 1..{})".format(number, len(steps)))
            continue
        title, commands = steps[number - 1]
        print("\n" + "=" * 70)
        print(" " + title)
        print("=" * 70)
        for cmd in commands:
            run(cmd)
        input("\n[Enter] de sang muc tiep theo...")


if __name__ == "__main__":
    main()
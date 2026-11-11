"""
server.py - Web server cho demo DES / 2DES / 3DES + MITM. Chi dung thu vien chuan.

Chay (tu thu muc goc cua project):
    python -m app.server              # http://127.0.0.1:8000
    python -m app.server --port 9000

Phan thuat toan nam hoan toan o core/; file nay chi lam giao dien HTTP/JSON.

API (JSON):
    POST /api/block      ma/giai ma 1 khoi 64-bit, co the tra ve trace tung buoc
    POST /api/sblock     S-DES / 2S-DES / 3S-DES (phien ban thu nho): khoi 8-bit, khoa 10-bit, co trace
    POST /api/smitm      MITM len 2S-DES voi khoa day du 10 bit (co the chay them vet can)
    POST /api/crypt      ma/giai ma van ban hoac tep (base64), ECB/CBC, do thoi gian
    POST /api/mitm       MITM do choi 4-bit hoac MITM len DES khoa rut gon
    POST /api/benchmark  do thoi gian theo kich thuoc du lieu
    GET  /api/selftest   doi chieu test vector chuan
"""

import argparse
import base64
import binascii
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from core.ciphers import make_cipher
from core.des import hex_to_int, int_to_hex
from core.des_multi import crypt_block, encrypt_3des_1key
from core.modes import encrypt_bytes, decrypt_bytes
from core.mitm_toy import mitm_toy, double_encrypt
from core.sdes import bin_to_int, int_to_bin
from core.sdes_multi import crypt_block as scrypt_block
from core.mitm_sdes import mitm_2sdes, brute_force_2sdes, double_encrypt as sdes_double_encrypt
from core.mitm_des import (
    make_demo_case, mitm_2des, brute_force_2des, estimate_brute_force_seconds, full_scale_estimate,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 8 * 1024 * 1024        # 8 MB (JSON/base64)
MAX_FILE = 2 * 1000 * 1000        # 2 MB du lieu that
MAX_MITM_BITS = 18
MAX_BENCH_BYTES = 512 * 1024

STANDARD_VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405", "Vi du kinh dien (Grabbe)"),
    ("0101010101010101", "0000000000000000", "8CA64DE9C1B123A7", "Khoa yeu, ban ro toan 0"),
    ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900", "Khoa yeu, ban ro 1 bit"),
]


class ApiError(Exception):
    pass


# ----------------------------------------------------------------------------
# Xu ly tung API
# ----------------------------------------------------------------------------

def _keys(req):
    try:
        return [hex_to_int(k) for k in req.get("keys", [])]
    except ValueError as e:
        raise ApiError("Khoa khong hop le: {}".format(e))


def api_block(req):
    alg, op = req.get("alg", "des"), req.get("op", "enc")
    if op not in ("enc", "dec"):
        raise ApiError("op phai la enc hoac dec")
    try:
        block = hex_to_int(req.get("data", ""))
    except ValueError as e:
        raise ApiError("Khoi du lieu khong hop le: {}".format(e))
    trace = []
    try:
        out = crypt_block(alg, op, _keys(req), block, trace.append if req.get("verbose") else None)
    except ValueError as e:
        raise ApiError(str(e))
    return {"result": int_to_hex(out), "trace": trace}


def _check_alg_mode(req):
    alg, mode = req.get("alg", "des").lower(), req.get("mode", "cbc").lower()
    if alg not in ("des", "2des", "3des"):
        raise ApiError("He ma khong hop le")
    if mode not in ("ecb", "cbc"):
        raise ApiError("Che do khong hop le")
    return alg, mode


def api_crypt(req):
    alg, mode = _check_alg_mode(req)
    op = req.get("op", "roundtrip")
    try:
        data = base64.b64decode(req.get("data", ""), validate=True)
    except (binascii.Error, ValueError):
        raise ApiError("Du lieu base64 khong hop le")
    if len(data) > MAX_FILE:
        raise ApiError("Tep qua lon (toi da {} MB cho ban demo web)".format(MAX_FILE // 1000000))
    try:
        cipher = make_cipher(alg, _keys(req))
        resp = {"size_in": len(data)}
        if op in ("enc", "roundtrip"):
            t = time.perf_counter()
            enc = encrypt_bytes(data, cipher, mode)
            resp["t_enc"] = time.perf_counter() - t
            resp["cipher_b64"] = base64.b64encode(enc).decode()
            resp["cipher_hex_preview"] = enc[:256].hex().upper()
            resp["size_cipher"] = len(enc)
            if op == "roundtrip":
                t = time.perf_counter()
                dec = decrypt_bytes(enc, cipher, mode)
                resp["t_dec"] = time.perf_counter() - t
                resp["plain_b64"] = base64.b64encode(dec).decode()
                resp["match"] = (dec == data)
        elif op == "dec":
            t = time.perf_counter()
            dec = decrypt_bytes(data, cipher, mode)
            resp["t_dec"] = time.perf_counter() - t
            resp["plain_b64"] = base64.b64encode(dec).decode()
        else:
            raise ApiError("op phai la enc, dec hoac roundtrip")
    except ValueError as e:
        raise ApiError(str(e))
    return resp


def api_mitm(req):
    kind = req.get("kind", "toy")
    if kind == "toy":
        k1, k2 = 0x6, 0xB
        prs = [(p, double_encrypt(p, k1, k2)) for p in (0x3, 0xA, 0x7)]
        lines = []
        res = mitm_toy(prs, trace=lines.append)
        return {
            "true_key": "k1 = {:X}, k2 = {:X}".format(k1, k2),
            "pairs": ["({:X},{:X})".format(p, c) for p, c in prs],
            "trace": lines,
            "final": ["k1 = {:X}, k2 = {:X}".format(a, b) for a, b in res["final"]],
            "survivors": [len(s) for s in res["survivors"]],
            "mitm_ops": res["mitm_ops"], "brute_force_ops": res["brute_force_ops"],
        }
    if kind != "des":
        raise ApiError("kind phai la toy hoac des")
    try:
        n = int(req.get("bits", 12))
        seed = int(req.get("seed", 1))
        n_pairs = int(req.get("pairs", 3))
    except (TypeError, ValueError):
        raise ApiError("Tham so khong hop le")
    if not 1 <= n <= MAX_MITM_BITS:
        raise ApiError("bits phai trong khoang 1..{}".format(MAX_MITM_BITS))
    if not 1 <= n_pairs <= 5:
        raise ApiError("pairs phai trong khoang 1..5")
    pairs, f1, f2, true = make_demo_case(n, seed=seed, n_pairs=n_pairs)
    r = mitm_2des(pairs, f1, f2, n)
    est, per = estimate_brute_force_seconds(n, samples=5000)
    out = {
        "bits": n, "space": 1 << n,
        "fixed1": "{:014X}".format(f1), "fixed2": "{:014X}".format(f2),
        "pairs": [{"p": int_to_hex(p), "c": int_to_hex(c)} for p, c in pairs],
        "true": list(true), "found": [list(x) for x in r["found"]],
        "correct": r["found"] == [tuple(true)],
        "candidates_per_pair": r["candidates_per_pair"],
        "table_entries": r["table_entries"],
        "mitm_ops": r["mitm_ops"], "brute_ops": 1 << (2 * n),
        "time_table": r["time_table"], "time_lookup": r["time_lookup"], "time_total": r["time_total"],
        "false_pos_one_pair": r["expected_false_positives_one_pair"],
        "brute_estimate_seconds": est,
    }
    if n <= 9:
        b = brute_force_2des(pairs, f1, f2, n)
        out["brute_measured"] = {"trials": b["trials"], "time": b["time"], "found": [list(x) for x in b["found"]]}
    full = full_scale_estimate()
    out["full_scale"] = {
        "mitm_ops": full["mitm_ops"], "table_entries": full["table_entries"],
        "table_pb_values_only": full["table_bytes_values_only"] / 1e15,
        "table_eb_with_key": full["table_bytes_with_key"] / 1e18,
        "false_positives_one_pair": full["false_positives_one_pair"],
    }
    return out


def api_sblock(req):
    """S-DES / 2S-DES / 3S-DES: ma/giai ma 1 khoi 8-bit bang khoa 10-bit (chuoi nhi phan)."""
    alg, op = req.get("alg", "sdes"), req.get("op", "enc")
    if op not in ("enc", "dec"):
        raise ApiError("op phai la enc hoac dec")
    try:
        block = bin_to_int(req.get("data", ""), 8)
        keys = [bin_to_int(k, 10) for k in req.get("keys", [])]
    except ValueError as e:
        raise ApiError(str(e))
    trace = []
    try:
        out = scrypt_block(alg, op, keys, block, trace.append if req.get("verbose") else None)
    except ValueError as e:
        raise ApiError(str(e))
    return {"result": int_to_bin(out, 8), "trace": trace}


def api_smitm(req):
    """MITM len 2S-DES, khoa day du 10 bit moi ben (khong gian 2^20)."""
    import random
    try:
        seed = int(req.get("seed", 1))
        n_pairs = int(req.get("pairs", 12))
    except (TypeError, ValueError):
        raise ApiError("Tham so khong hop le")
    if not 1 <= n_pairs <= 64:
        raise ApiError("pairs phai trong khoang 1..64")
    rnd = random.Random(seed)
    k1, k2 = rnd.randrange(1 << 10), rnd.randrange(1 << 10)
    pairs = [(p, sdes_double_encrypt(p, k1, k2)) for p in rnd.sample(range(256), n_pairs)]
    lines = []
    r = mitm_2sdes(pairs, trace=lines.append)
    out = {
        "true": "K1 = {:010b}, K2 = {:010b}".format(k1, k2),
        "pairs": ["({:08b},{:08b})".format(p, c) for p, c in pairs],
        "trace": lines,
        "candidates_per_pair": r["candidates_per_pair"],
        "final": ["K1 = {:010b}, K2 = {:010b}".format(a, b) for a, b in r["final"]],
        "correct": (k1, k2) in r["final"],
        "mitm_ops": r["mitm_ops"], "brute_ops": r["brute_force_ops"], "time": r["time"],
    }
    if req.get("brute"):
        b = brute_force_2sdes(pairs)
        out["brute_measured"] = {"trials": b["trials"], "time": b["time"], "candidates": len(b["final"]),
                                 "same": sorted(b["final"]) == sorted(r["final"])}
    return out


def api_benchmark(req):
    alg, mode = _check_alg_mode(req)
    sizes = req.get("sizes", [1024, 4096, 16384, 65536])
    if not isinstance(sizes, list) or not 1 <= len(sizes) <= 8:
        raise ApiError("sizes phai la danh sach 1..8 so")
    try:
        sizes = [int(s) for s in sizes]
    except (TypeError, ValueError):
        raise ApiError("sizes phai la so nguyen")
    if any(s < 1 or s > MAX_BENCH_BYTES for s in sizes):
        raise ApiError("Moi kich thuoc phai trong khoang 1..{} byte".format(MAX_BENCH_BYTES))
    nkeys = {"des": 1, "2des": 2, "3des": 3}[alg]
    cipher = make_cipher(alg, [0x133457799BBCDFF1 ^ (i * 0x0101010101010101) for i in range(nkeys)])
    rows = []
    for s in sizes:
        data = os.urandom(s)
        t = time.perf_counter()
        enc = encrypt_bytes(data, cipher, mode)
        te = time.perf_counter() - t
        t = time.perf_counter()
        dec = decrypt_bytes(enc, cipher, mode)
        td = time.perf_counter() - t
        rows.append({"size": s, "t_enc": te, "t_dec": td, "ok": dec == data,
                     "kb_per_s": (s / 1000.0) / te if te > 0 else None})
    return {"alg": alg, "mode": mode, "rows": rows}


def api_selftest(_req=None):
    rows = []
    for key, pt, ct, note in STANDARD_VECTORS:
        k, p = hex_to_int(key), hex_to_int(pt)
        got = int_to_hex(crypt_block("des", "enc", [k], p))
        back = int_to_hex(crypt_block("des", "dec", [k], hex_to_int(got)))
        three = int_to_hex(encrypt_3des_1key(p, k))
        rows.append({"note": note, "key": key, "plain": pt, "expected": ct, "got": got,
                     "ok": got == ct, "roundtrip": back == pt, "des3_same": three == ct})
    return {"rows": rows}


ROUTES = {
    "/api/block": api_block,
    "/api/sblock": api_sblock,
    "/api/smitm": api_smitm,
    "/api/crypt": api_crypt,
    "/api/mitm": api_mitm,
    "/api/benchmark": api_benchmark,
}


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "DESDemo/1.0"

    def log_message(self, fmt, *args):   # giu console gon
        print("[{}] {}".format(self.log_date_time_string(), fmt % args))

    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path == "/api/selftest":
            return self._send(200, api_selftest())
        self._send(404, {"error": "Khong tim thay"})

    def do_POST(self):
        fn = ROUTES.get(self.path.split("?", 1)[0])
        if fn is None:
            return self._send(404, {"error": "Khong tim thay"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send(400, {"error": "Content-Length khong hop le"})
        if length > MAX_BODY:
            return self._send(413, {"error": "Yeu cau qua lon"})
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(req, dict):
                raise ApiError("Noi dung phai la doi tuong JSON")
            self._send(200, fn(req))
        except ApiError as e:
            self._send(400, {"error": str(e)})
        except json.JSONDecodeError:
            self._send(400, {"error": "JSON khong hop le"})
        except Exception as e:  # loi bat ngo: bao cho nguoi dung thay vi sap server
            self._send(500, {"error": "Loi noi bo: {}".format(e)})


def main():
    ap = argparse.ArgumentParser(description="Web demo DES / 2DES / 3DES + MITM")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print("Mo trinh duyet tai http://{}:{}  (Ctrl+C de dung)".format(args.host, args.port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nDa dung server.")


if __name__ == "__main__":
    main()

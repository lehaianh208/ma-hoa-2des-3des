# Double DES và Triple DES – kèm tấn công meet-in-the-middle

Bài tập nhóm môn An toàn bảo mật thông tin. Toàn bộ phần lõi mật mã tự cài đặt từ đầu bằng Python
(không dùng thư viện mật mã). Thư viện chuẩn (`cryptography` hoặc PyCryptodome) chỉ được dùng trong `tests/` để đối chiếu.

Nội dung:

- S-DES (DES rút gọn): phiên bản thu nhỏ để tính tay (khối 8 bit, khóa 10 bit, 2 vòng), cùng 2S-DES và 3S-DES.
- DES đầy đủ (16 vòng Feistel, hàm F, sinh khóa con) – nền tảng cho các hệ mã bên dưới.
- 2DES: `C = E_K2(E_K1(P))`.
- 3DES (EDE): `C = E_K3(D_K2(E_K1(P)))` với 3 kiểu khóa: 3 khóa, 2 khóa (K3 = K1), 1 khóa (K1 = K2 = K3, tương thích DES).
- Chế độ ECB / CBC và padding PKCS#7 để mã hóa tệp thật.
- Tấn công meet-in-the-middle (MITM) lên 2DES: ví dụ nhỏ tính tay được, MITM trên DES thật với khóa rút gọn,
  và MITM trên 2S-DES với khóa đầy đủ (chạy thật, không cần rút gọn).
- Giao diện web, các chương trình dòng lệnh, và bộ kiểm thử (64 ca).

## 1. Yêu cầu và cài đặt

- Python 3.8 trở lên (đã chạy thử trên Python 3.13). Không cần cài thêm gói nào để chạy chương trình.
- Tùy chọn, chỉ để đối chiếu với thư viện chuẩn khi kiểm thử:

```bash
pip install pycryptodome        # hoặc: pip install cryptography
```

Tải mã nguồn rồi chạy mọi lệnh từ thư mục gốc của project (thư mục chứa `README.md`):

```bash
git clone <https://github.com/lehaianh208/ma_hoa_2des_>
cd des_project
```

## 2. Cách chạy

### 2.1 Giao diện web (khuyến nghị cho demo)

```bash
python -m app.server            # mở http://127.0.0.1:8000
python -m app.server --port 9000
```

Các tab:

| Tab | Chức năng |
|---|---|
| Mã hóa / giải mã | Nhập văn bản hoặc chọn tệp (≤ 2 MB), chọn DES/2DES/3DES, ECB/CBC, nhập khóa; hiện bản mã (hex), giải mã ngược lại, báo KHỚP/LỆCH, tải tệp `.enc` / bản giải mã, đo thời gian |
| Từng bước (1 khối) | Mã/giải mã một khối 64-bit và in khóa con, L/R từng vòng, kết quả hàm F để đối chiếu bản tính tay |
| S-DES (bản thu nhỏ) | S-DES / 2S-DES / 3S-DES với khối 8 bit, khóa 10 bit, in từng bước; MITM trên 2S-DES với khóa đầy đủ, so với vét cạn |
| Tấn công MITM | (A) ví dụ đồ chơi 4-bit in từng bước; (B) MITM trên DES thật với n bit chưa biết mỗi khóa, so với vét cạn |
| Đo thời gian | Thời gian mã/giải mã theo kích thước dữ liệu (1 KB … 256 KB) |
| Kiểm thử | Bảng đối chiếu test vector chuẩn |

### 2.2 Dòng lệnh

Mã hóa một khối 64-bit (khóa và khối là hex 16 ký tự):

```bash
python cli.py enc --alg des  --keys 133457799BBCDFF1 --data 0123456789ABCDEF          # -> 85E813540F0AB405
python cli.py dec --alg des  --keys 133457799BBCDFF1 --data 85E813540F0AB405          # -> 0123456789ABCDEF
python cli.py enc --alg 2des --keys 133457799BBCDFF1 0E329232EA6D0D73 --data 0123456789ABCDEF
python cli.py enc --alg 3des --keys <K1> <K2> <K3> --data <khối>                      # 3 khóa
python cli.py enc --alg 3des --keys <K1> <K2>      --data <khối>                      # 2 khóa (K3 = K1)
python cli.py enc --alg 3des --keys <K1>           --data <khối>                      # 1 khóa = DES đơn
python cli.py enc --alg des  --keys 133457799BBCDFF1 --data 0123456789ABCDEF --verbose   # in từng bước
```

Phiên bản thu nhỏ S-DES (khối và khóa nhập dạng nhị phân; ví dụ trong giáo trình):

```bash
python sdes_cli.py enc --alg sdes  --keys 1010000010 --data 01110010 --verbose   # -> 01110111
python sdes_cli.py dec --alg sdes  --keys 1010000010 --data 01110111             # -> 01110010
python sdes_cli.py enc --alg 2sdes --keys 1010000010 0110111001 --data 01110010  # -> 01011010
python sdes_cli.py enc --alg 3sdes --keys <K1> <K2> <K3> --data <khối 8 bit>     # 3 khóa; 2 khóa: K3 = K1; 1 khóa = S-DES
```

Mã hóa tệp (CBC: tệp mã = IV 8 byte ‖ bản mã; có padding PKCS#7):

```bash
# Demo một lệnh: mã hóa -> giải mã -> so sánh -> đo thời gian
python filecrypt.py demo --alg 3des --mode cbc \
    --keys 133457799BBCDFF1 0E329232EA6D0D73 FEDCBA9876543210 --in samples/sample.txt

# Từng bước
python filecrypt.py enc --alg 2des --mode ecb --keys <K1> <K2> --in samples/sample.txt --out sample.enc
python filecrypt.py dec --alg 2des --mode ecb --keys <K1> <K2> --in sample.enc --out sample.dec.txt
```

Tấn công MITM:

```bash
python mitm_demo.py toy                       # bộ số nhỏ 4-bit, khớp bản tính tay
python mitm_demo.py des --bits 12             # DES thật, mỗi khóa 12 bit chưa biết (~0,3 giây)
python mitm_demo.py des --bits 16 --seed 5    # ~vài giây đến vài chục giây tùy máy
python mitm_demo.py des --bits 8 --brute      # chạy cả vét cạn thật để so sánh (--bits ≤ 9)
python mitm_demo.py sdes                      # 2S-DES khóa ĐẦY ĐỦ 10 bit: MITM ~0,05 giây
python mitm_demo.py sdes --brute              # thêm vét cạn 2^20 cặp khóa để so sánh (~7 giây)
```

### 2.3 Kiểm thử

```bash
python -m unittest discover -s tests -t . -v        # 64 ca kiểm thử
python tests/test_des.py --compare                  # in bảng đối chiếu KHỚP/LỆCH với thư viện chuẩn
```

Bảng `--compare` dùng PyCryptodome nếu có, nếu không thì dùng `cryptography`; không có cả hai thì in hướng dẫn cài.
Các ca đối chiếu thư viện trong `tests/test_modes.py` tự bỏ qua (skip) khi máy không có thư viện nào.

## 3. Cấu trúc thư mục

```text
des_project/
├── core/                    # THUẬT TOÁN (không có giao diện, không import thư viện mật mã)
│   ├── tables.py            # các bảng hằng số của chuẩn DES (FIPS 46-3)
│   ├── des.py               # DES gốc, dễ đọc, có trace từng bước (--verbose)
│   ├── des_multi.py         # 2DES, 3DES (3 khóa / 2 khóa / 1 khóa), crypt_block()
│   ├── des_fast.py          # DES tối ưu bằng bảng tra, dùng cho tệp và MITM
│   ├── ciphers.py           # BlockCipher thống nhất DES/2DES/3DES, sinh khóa con 1 lần
│   ├── modes.py             # ECB, CBC, padding PKCS#7, encrypt_bytes/decrypt_bytes
│   ├── mitm_toy.py          # MITM trên mã đồ chơi 4-bit (ví dụ tính tay)
│   ├── mitm_des.py          # MITM trên DES thật với khóa rút gọn, ước lượng chi phí
│   ├── sdes.py              # S-DES (phiên bản thu nhỏ): khối 8 bit, khóa 10 bit, 2 vòng
│   ├── sdes_multi.py        # 2S-DES, 3S-DES, crypt_block()
│   └── mitm_sdes.py         # MITM và vét cạn trên 2S-DES với khóa 10 bit đầy đủ
├── app/                     # GIAO DIỆN WEB (chỉ thư viện chuẩn)
│   ├── server.py
│   └── static/index.html
├── cli.py                   # mã/giải mã 1 khối DES/2DES/3DES, có --verbose
├── sdes_cli.py              # mã/giải mã 1 khối S-DES/2S-DES/3S-DES, có --verbose
├── filecrypt.py             # mã/giải mã tệp
├── mitm_demo.py             # demo MITM
├── tests/                   # test_des.py, test_modes.py, test_mitm.py, test_sdes.py
├── samples/sample.txt       # tệp văn bản mẫu (có tiếng Việt UTF-8) để demo
├── docs/doi_chieu_tinh_tay.md        # cột "máy" của ví dụ DES kinh điển (do chương trình sinh ra)
├── demo.bat                 # chạy lần lượt các bước demo trên Windows (có pause giữa các bước)
├── docs/kich_ban_demo.md    # kịch bản demo 5–7 phút
└── docs/doi_chieu_tinh_tay_sdes.md   # ví dụ tính tay đầy đủ trên S-DES, khớp chương trình
```

Thiết kế: `des.py` giữ cách viết rõ ràng, từng bước đúng như đặc tả FIPS 46-3 để đối chiếu bản tính tay;
`des_fast.py` sinh bảng tra từ chính các bảng của `des.py` (nên không thể lệch) và được test khớp `des.py`
trên hàng nghìn ca ngẫu nhiên. Nhờ đó mã hóa tệp và MITM nhanh gấp khoảng 10 lần mà vẫn chứng minh được tính đúng.

## 4. Đối chiếu với yêu cầu của giảng viên

| Yêu cầu | Đáp ứng |
|---|---|
| Tự cài đặt từ đầu, không dùng thư viện mật mã cho phần lõi | `core/` không gọi thư viện mật mã; thư viện chỉ xuất hiện trong `tests/` (xem mục 7 về phần có AI hỗ trợ) |
| Có cả mã hóa và giải mã, giải mã khôi phục đúng bản rõ | Mọi hệ mã và chế độ đều có hai chiều, được test round-trip |
| Hai phiên bản: bản thu nhỏ tái hiện ví dụ học trên lớp | S-DES (ví dụ giáo trình: khóa `1010000010`, `01110010` → `01110111`), `docs/doi_chieu_tinh_tay_sdes.md` |
| Ít nhất 3 ca kiểm thử tự viết + đối chiếu test vector chuẩn / thư viện, in kết quả đối chiếu | 64 ca; vector chuẩn DES và S-DES; `tests/test_des.py --compare` in bảng KHỚP/LỆCH với thư viện; S-DES đối chiếu chéo với một cài đặt viết theo cách khác |
| Mã nguồn chia module, có chú thích, tách thuật toán khỏi giao diện | `core/` (thuật toán) tách khỏi `app/`, `cli.py`, `filecrypt.py`, `mitm_demo.py` |
| Nhập bản rõ + khóa, hiện bản mã, giải mã ngược lại đúng | Tab “Mã hóa / giải mã”; `filecrypt.py demo` |
| In các bước trung gian (khóa con, kết quả từng vòng…) | `--verbose` trong `cli.py` và `sdes_cli.py`; tab “Từng bước” và tab “S-DES”; `docs/doi_chieu_tinh_tay*.md` |
| Demo trên dữ liệu thật: mã hóa tệp rồi giải mã lại | `samples/sample.txt`, tải tệp bất kỳ ≤ 2 MB trên web |
| (Khuyến khích) giao diện web, đo thời gian theo kích thước dữ liệu | Giao diện web, tab “Đo thời gian” |
| (Khuyến khích) minh họa một tình huống tấn công | MITM lên 2DES (bộ số nhỏ + DES khóa rút gọn) và lên 2S-DES với khóa đầy đủ |

## 5. Quy ước và lưu ý kỹ thuật

- Định dạng khóa: hex 16 ký tự (64-bit). Trong 64 bit chỉ có 56 bit hiệu dụng; bit cuối mỗi byte là bit parity và DES bỏ qua
  (đổi bit này không làm thay đổi bản mã – có test minh họa).
- Quy ước bit: các bảng hoán vị đánh số từ 1, bit 1 là bit trái nhất (MSB), đúng FIPS 46-3.
- Giải mã DES dùng đúng thuật toán mã hóa với 16 khóa con theo thứ tự ngược. 3DES giải mã: `P = D_K1(E_K2(D_K3(C)))`.
- CBC: IV sinh ngẫu nhiên bằng `os.urandom` và đặt ở đầu tệp mã. ECB để lộ khối lặp (xem dòng `AAAA…` trong `samples/sample.txt`)
  nên chỉ dùng để minh họa.
- Sai khóa: thường báo lỗi padding; vì padding chỉ có 8 byte nên khoảng 1/256 trường hợp sai khóa vẫn qua được bước kiểm tra
  và trả về dữ liệu rác. Đây là hành vi bình thường của padding, không phải lỗi chương trình.
- Tốc độ: Python thuần, khoảng 100–150 KB/s cho 3DES trên máy thử (tùy máy). Web giới hạn tệp 2 MB.
- Bảo mật web: server mặc định chỉ lắng nghe `127.0.0.1`, dùng để demo, không dùng cho dữ liệu thật.

## 6. Về tấn công meet-in-the-middle

Với cặp known-plaintext `(P, C)` của 2DES: lập bảng `X = E_K1(P)` cho mọi K1, rồi tính `Y = D_K2(C)` cho mọi K2 và tìm `Y` trùng `X`.

| | Vét cạn 2DES | MITM |
|---|---|---|
| Số phép (khóa 56-bit mỗi khóa) | ≈ 2¹¹² | ≈ 2⁵⁷ |
| Bộ nhớ | không đáng kể | ≈ 2⁵⁶ mục (2⁵⁶ × 8 byte = 2⁵⁹ byte ≈ **576 PB** nếu chỉ lưu giá trị trung gian) |
| Độ mạnh hiệu dụng | 112-bit (danh nghĩa) | ≈ 57-bit, chỉ hơn DES đơn khoảng 1 bit |

- Vì sao cần ≥ 2 cặp (P, C): một cặp cho khoảng 2¹¹² / 2⁶⁴ = 2⁴⁸ ứng viên sai; cặp thứ hai (và thứ ba) loại gần hết.
- 3DES: MITM làm 3 khóa còn ≈ 112-bit hiệu dụng (không phải 168); 2 khóa còn ≈ 80-bit theo ước lượng của NIST. 
- Vì sao demo dùng khóa rút gọn: không thể chạy bảng 2⁵⁶ mục. Chương trình đặt trước phần lớn bit khóa và chỉ để n bit chưa biết cho mỗi khóa:
  MITM tốn ≈ 2·2ⁿ phép với bảng 2ⁿ mục, còn vét cạn tốn 2²ⁿ cặp khóa. Ví dụ n = 12: MITM mất khoảng 0,3 giây, vét cạn ước tính vài phút
  (n = 16: vài giây so với ước tính vài ngày). Con số đo thật phụ thuộc máy; chương trình tự đo và in ra.
- 2S-DES với khóa đầy đủ (`core/mitm_sdes.py`): mỗi khóa chỉ 10 bit nên không gian khóa là 2²⁰. MITM chỉ cần 2·2¹⁰ = 2048 phép
  (≈ 0,05 giây), vét cạn cần 2²⁰ cặp khóa (≈ 7 giây trên máy thử) và cho đúng cùng tập ứng viên. Vì khối chỉ 8 bit nên một cặp (P, C)
  còn khoảng 2²⁰/2⁸ = 4096 ứng viên; cần khoảng 10 cặp để còn 1 ứng viên (với 2DES thật, khối 64 bit: 2⁴⁸ ứng viên sau 1 cặp).
- Bộ số nhỏ 4-bit (`core/mitm_toy.py`) chỉ để tính tay trọn vẹn nguyên lý MITM (bảng 16 mục), không phải hệ mã thứ hai.

## 7. Nguồn tham khảo và phần tự viết

- Đặc tả DES: NIST FIPS PUB 46-3 (các bảng IP, FP, E, P, PC-1, PC-2, S-box, lịch dịch vòng) – nhập lại từ đặc tả, kiểm tra bằng test vector.
- Ví dụ DES kinh điển (khóa `133457799BBCDFF1`, bản rõ `0123456789ABCDEF` → `85E813540F0AB405`): J. Orlin Grabbe, *The DES Algorithm Illustrated*.
- Phân tích 2DES/3DES và MITM: W. Diffie, M. Hellman, “Exhaustive Cryptanalysis of the NBS Data Encryption Standard”, *Computer*, 1977;
  W. Stallings, *Cryptography and Network Security*; NIST SP 800-67 và SP 800-131A (độ mạnh hiệu dụng và lộ trình ngừng dùng 3DES – cần tra lại số liệu mới nhất khi viết báo cáo).
- Đối chiếu kết quả: OpenSSL, `cryptography`, PyCryptodome (chỉ trong `tests/`).
- S-DES: E. Schaefer, “A Simplified Data Encryption Standard Algorithm”, *Cryptologia*, 1996; W. Stallings, *Cryptography and Network Security* (phụ lục S-DES).
- Phần tự viết và phần có AI hỗ trợ: mã nguồn được viết với sự hỗ trợ của các trợ lý AI (Claude/Anthropic, ChatGPT, Gemini).
  Các bảng hằng số lấy từ FIPS 46-3 và tài liệu S-DES nêu trên. Phân định cụ thể:

  | Phần | Người làm          | Nhận xét                                                                       |
  |---|--------------------|--------------------------------------------------------------------------------|
  | `core/tables.py`, `core/des.py`, `core/des_multi.py`, `core/sdes.py` | H.Anh              | Tự gõ, tự chạy và đối chiếu kết quả ( có tham khảo AI)                         |
  | `core/modes.py`, `core/mitm_toy.py`, `core/mitm_des.py`, `core/mitm_sdes.py`, `filecrypt.py`, `mitm_demo.py`, `tests/test_modes.py`, `tests/test_mitm.py`, `tests/test_sdes.py` | Ngọc               | Mã do AI viết, Ngọc đọc, chạy và kiểm thử lại                                  |
  | `cli.py`, `sdes_cli.py`, `core/ciphers.py`, `core/des_fast.py`, `app/`, `tests/test_des.py`, `demo.bat`, `docs/doi_chieu_tinh_tay*.md` | Cả nhóm            | Do AI hướng dẫn và sửa; nhóm đọc, chạy và kiểm thử lại                         |
  | Báo cáo, sơ đồ khối, bài tính tay trên giấy, phân tích an toàn, so sánh AES, slide | Trang, Hiếu        | Hai bạn tự viết; bài tính tay được đối chiếu với `docs/doi_chieu_tinh_tay*.md` |

## 8. Thành viên và phân công

| Thành viên | Phần phụ trách                                                                                                                                                                                  |
|---|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Trang, Hiếu | Tìm hiểu hệ mã: bối cảnh ra đời, mô tả thuật toán và sơ đồ khối, ví dụ tính tay (DES, ghép 2DES/3DES, MITM bộ số nhỏ, S-DES), phân tích an toàn, so sánh AES; báo cáo ( Hiếu) và slide ( Trang) |
| H. Anh | Lõi DES / 2DES / 3DES và phiên bản thu nhỏ S-DES, chế độ `--verbose`, chạy và trình diễn giao diện web; thuyết trình và video demo dự phòng                                                     |
| Ngọc | Chế độ ECB/CBC, tấn công MITM, bộ kiểm thử và bảng đối chiếu thư viện, GitHub và README, so sánh kết quả tay với máy; chủ trì họp online (test case)                                            |

Đối chiếu chéo: Ngọc chạy test cho phần lõi của H.Anh; H.Anh xem lại MITM của Ngọc; Trang hoặc Hiếu đối chiếu `--verbose` và `docs/doi_chieu_tinh_tay*.md` với bài tính tay.



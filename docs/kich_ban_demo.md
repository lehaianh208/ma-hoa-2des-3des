# Kịch bản demo 5–7 phút

Cách chạy nhanh: bấm đúp `demo.bat` (hoặc chạy từng lệnh bên dưới). Mỗi mục dừng chờ một phím (`pause`), bấm phím bất kỳ để sang mục sau.
Nếu Python không nằm ở đường dẫn trong `demo.bat`, sửa dòng `set PY=...` ở đầu file.

| Thời điểm | Nội dung | Lệnh | Kết quả cần thấy |
|---|---|---|---|
| 0:00–0:30 | Giới thiệu đề tài | | |
| 0:30–1:30 | S-DES (bản thu nhỏ), in từng bước | `python sdes_cli.py enc --alg sdes --keys 1010000010 --data 01110010 --verbose` | `01110111`; K1 = `10100100`, K2 = `01000011`; giải mã về `01110010` |
| 1:30–2:30 | DES đầy đủ, in từng bước | `python cli.py enc --alg des --keys 133457799BBCDFF1 --data 0123456789ABCDEF --verbose` | `85E813540F0AB405` |
| 2:30–3:15 | 2DES và 3DES | `python cli.py enc --alg 2des --keys 133457799BBCDFF1 0123456789ABCDEF --data 0123456789ABCDEF` | `8D0AAB998757B0AF`; 3DES (thêm khóa `FEDCBA9876543210`): `EB2EF3D233BBEB25` |
| 3:15–4:15 | Mã hóa tệp thật (văn bản, rồi ảnh) | `python filecrypt.py demo --alg 3des --mode cbc --keys 133457799BBCDFF1 0123456789ABCDEF FEDCBA9876543210 --in samples/sample.txt --save demo_out` | `Giai ma khoi phuc dung ban ro: KHOP` |
| 4:15–6:00 | Tấn công MITM lên 2S-DES | `python mitm_demo.py sdes --brute` | tìm ra khóa thật; MITM 2048 phép so với vét cạn 2 097 152 (~1000 lần) |
| 6:00–6:40 | Quy mô thật của 2DES | `python mitm_demo.py des --bits 12` | MITM ~ 2^57 phép, bảng ~ 576 PB, 2DES chỉ ~ 57 bit hiệu dụng |
| 6:40–7:00 | Bộ test, kết luận | `python -m unittest discover tests` và `python tests/test_des.py --compare` | tất cả passed; 17 ca đối chiếu, 0 lệch |

## Lưu ý khi trình bày
- Demo MITM trên S-DES: khối chỉ 8 bit nên với 1 cặp (bản rõ, bản mã) còn khoảng 4 000 ứng viên; chương trình lọc dần bằng các cặp tiếp theo.
  Ở cuối còn **2 ứng viên** là hai cặp khóa "tương đương hàm" (cho cùng bản mã trên mọi bản rõ), vẫn có khóa thật trong đó.
- Nếu máy trường chậm hoặc thiếu giờ: bỏ cờ `--brute` ở mục MITM, chỉ nói "vét cạn thật mất vài giây".
- Chuẩn bị sẵn một ảnh nhỏ (vài chục KB) trong `samples/` để demo mã hóa ảnh: đổi đuôi file `.dec` thành `.png` để mở xem.
- Luôn có video dự phòng 3–5 phút quay theo đúng kịch bản này.

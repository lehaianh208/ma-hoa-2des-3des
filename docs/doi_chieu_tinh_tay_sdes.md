# Ví dụ tính tay đầy đủ trên phiên bản thu nhỏ: S-DES (và 2S-DES, 3S-DES)

S-DES là DES thu nhỏ: **khối 8 bit, khóa 10 bit, 2 vòng**. Mọi bước đủ nhỏ để tính tay. Tài liệu này là bản tính tay **đã được chương trình kiểm chứng**: mỗi dòng dưới đây khớp với kết quả của

```text
python sdes_cli.py enc --alg sdes --keys 1010000010 --data 01110010 --verbose
```

- Khóa: `K = 1010000010`
- Bản rõ: `P = 01110010`
- Bản mã (kết quả cuối): `01110111`

**Quy ước.** Bảng hoán vị đánh số từ 1, bit số 1 là bit **trái nhất**. `Bảng[i]` cho biết bit của đầu ra ở vị trí `i` lấy từ vị trí nào của đầu vào.

## 0. Các bảng của S-DES

| Tên | Bảng |
|---|---|
| P10 | 3 5 2 7 4 10 1 9 8 6 |
| P8 | 6 3 7 4 8 5 10 9 |
| IP | 2 6 3 1 4 8 5 7 |
| IP⁻¹ | 4 1 3 5 7 2 8 6 |
| EP (mở rộng 4→8) | 4 1 2 3 2 3 4 1 |
| P4 | 2 4 3 1 |

```text
S0:  cột 0 1 2 3          S1:  cột 0 1 2 3
hàng 0:  1 0 3 2          hàng 0:  0 1 2 3
hàng 1:  3 2 1 0          hàng 1:  2 0 1 3
hàng 2:  0 2 1 3          hàng 2:  3 0 1 0
hàng 3:  3 1 3 2          hàng 3:  2 1 0 3
```

**Cách tra S-box** (4 bit đầu vào `b1 b2 b3 b4`): hàng = `b1 b4` (đọc thành số nhị phân), cột = `b2 b3`. Kết quả là số 2 bit.

## 1. Sinh khóa con

`K = 1010000010` (đánh số bit 1..10 từ trái: 1,0,1,0,0,0,0,0,1,0).

**Bước 1.1: P10.** Lấy các bit theo thứ tự 3 5 2 7 4 10 1 9 8 6:

| bit thứ | 3 | 5 | 2 | 7 | 4 | 10 | 1 | 9 | 8 | 6 |
|---|---|---|---|---|---|---|---|---|---|---|
| giá trị | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |

→ `P10(K) = 1000001100`. Tách hai nửa 5 bit: **L = 10000**, **R = 01100**.

**Bước 1.2: tạo K1.** Dịch vòng trái 1 bit mỗi nửa: `10000 → 00001`, `01100 → 11000`. Ghép `0000111000`, rồi áp P8 (lấy bit 6 3 7 4 8 5 10 9):

| bit thứ | 6 | 3 | 7 | 4 | 8 | 5 | 10 | 9 |
|---|---|---|---|---|---|---|---|---|
| giá trị | 1 | 0 | 1 | 0 | 0 | 1 | 0 | 0 |

→ **K1 = 10100100**.

**Bước 1.3: tạo K2.** Dịch vòng trái **thêm 2 bit** mỗi nửa (tổng cộng 3 bit so với ban đầu): `00001 → 00100`, `11000 → 00011`. Ghép `0010000011`, áp P8:

| bit thứ | 6 | 3 | 7 | 4 | 8 | 5 | 10 | 9 |
|---|---|---|---|---|---|---|---|---|
| giá trị | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 |

→ **K2 = 01000011**.

## 2. Mã hóa `P = 01110010`

**Bước 2.1: hoán vị đầu IP** (lấy bit 2 6 3 1 4 8 5 7 của `01110010`):

| bit thứ | 2 | 6 | 3 | 1 | 4 | 8 | 5 | 7 |
|---|---|---|---|---|---|---|---|---|
| giá trị | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 1 |

→ `IP(P) = 10101001`, tách **L0 = 1010**, **R0 = 1001**.

**Bước 2.2: vòng 1, fK với K1 = 10100100.**

1. EP(R0 = 1001): lấy bit 4 1 2 3 2 3 4 1 → `11000011`.
2. XOR với K1: `11000011 ⊕ 10100100 = 01100111`. Nửa trái `0110` vào S0, nửa phải `0111` vào S1.
3. S0 với `0110`: hàng = `b1b4 = 00 = 0`, cột = `b2b3 = 11 = 3` → S0[0][3] = 2 = `10`.
4. S1 với `0111`: hàng = `b1b4 = 01 = 1`, cột = `b2b3 = 11 = 3` → S1[1][3] = 3 = `11`.
5. Ghép `10 11 = 1011`, áp P4 (lấy bit 2 4 3 1): `0 1 1 1` → `0111`.
6. L mới = L0 ⊕ F = `1010 ⊕ 0111 = 1101`, R giữ nguyên = `1001`.

Sau fK: **L = 1101, R = 1001**.

**Bước 2.3: SW (đổi chỗ hai nửa)** → **L = 1001, R = 1101**.

**Bước 2.4: vòng 2, fK với K2 = 01000011.**

1. EP(R = 1101): lấy bit 4 1 2 3 2 3 4 1 → `11101011`.
2. XOR với K2: `11101011 ⊕ 01000011 = 10101000`. S0 nhận `1010`, S1 nhận `1000`.
3. S0 với `1010`: hàng = `b1b4 = 10 = 2`, cột = `b2b3 = 01 = 1` → S0[2][1] = 2 = `10`.
4. S1 với `1000`: hàng = `b1b4 = 10 = 2`, cột = `b2b3 = 00 = 0` → S1[2][0] = 3 = `11`.
5. Ghép `1011`, áp P4 → `0111`.
6. L mới = `1001 ⊕ 0111 = 1110`, R = `1101`.

Sau fK: **L = 1110, R = 1101**.

**Bước 2.5: hoán vị cuối IP⁻¹.** Ghép `11101101`, lấy bit 4 1 3 5 7 2 8 6:

| bit thứ | 4 | 1 | 3 | 5 | 7 | 2 | 8 | 6 |
|---|---|---|---|---|---|---|---|---|
| giá trị | 0 | 1 | 1 | 1 | 0 | 1 | 1 | 1 |

→ **Bản mã C = 01110111**. ✓ khớp chương trình.

## 3. Giải mã

Dùng cùng thuật toán nhưng **đảo thứ tự khóa**: vòng 1 dùng K2, vòng 2 dùng K1. Từ `C = 01110111` chương trình cho lại `01110010` = P. ✓

```text
python sdes_cli.py dec --alg sdes --keys 1010000010 --data 01110111
```

Ví dụ thứ hai trong giáo trình (cùng khóa): `P = 10010111 → C = 00111000`.

## 4. 2S-DES và 3S-DES với cùng ví dụ

Cùng bản rõ `P = 01110010`.

**2S-DES**, `C = E_K2(E_K1(P))` với `K1 = 1010000010`, `K2 = 0110111001`:

- `X = E_K1(P) = 01110111` (chính là kết quả mục 2 ở trên)
- `C = E_K2(X) = 01011010`

```text
python sdes_cli.py enc --alg 2sdes --keys 1010000010 0110111001 --data 01110010 --verbose
```

**3S-DES (EDE)**, `C = E_K3(D_K2(E_K1(P)))` với `K1 = 1010000010`, `K2 = 0110111001`, `K3 = 0011010101`:

- `A = E_K1(P) = 01110111`
- `B = D_K2(A) = 10000010`
- `C = E_K3(B) = 00110000`

```text
python sdes_cli.py enc --alg 3sdes --keys 1010000010 0110111001 0011010101 --data 01110010 --verbose
```

**Kiểm tra 3S-DES một khóa:** `python sdes_cli.py enc --alg 3sdes --keys 1010000010 --data 01110010` cho `01110111`, giống hệt S-DES đơn vì `E(D(E(P))) = E(P)`.

## 5. Ví dụ tính tay tấn công MITM

Với 2S-DES, MITM thật phải tra 1024 khóa mỗi phía nên không tính tay hết được; chương trình chạy trực tiếp (`python mitm_demo.py sdes`). Để **tính tay trọn vẹn**, nhóm dùng bộ số nhỏ 4 bit trong `core/mitm_toy.py` (`python mitm_demo.py toy`): mã đồ chơi `E_k(x) = S[x ⊕ k]` với khối và khóa 4 bit, chỉ 16 mục mỗi bảng. Đây chỉ là minh họa nguyên lý MITM, **không phải hệ mã thứ hai**.

## 6. Cách đối chiếu khi viết báo cáo

| Mục | Giá trị tính tay | Lệnh để chương trình xác nhận |
|---|---|---|
| K1, K2 | 10100100, 01000011 | `sdes_cli.py enc --alg sdes ... --verbose` (đầu ra) |
| Sau IP | 10101001 | dòng `IP` |
| Sau vòng 1 | L = 1101, R = 1001 | dòng `sau fK` đầu tiên |
| Sau SW | L = 1001, R = 1101 | dòng `SW` |
| Sau vòng 2 | L = 1110, R = 1101 | dòng `sau fK` thứ hai |
| Bản mã | 01110111 | dòng cuối `Ban ma` |

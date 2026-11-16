# Ví dụ tính tay trên TinyDES (phiên bản thu nhỏ của DES mà lớp đã học)

TinyDES là hệ mã Feistel thu nhỏ trong bài giảng ATBMTT (chương 2, mục 3.2): **3 vòng, khối 8 bit, khóa 8 bit, khóa con 6 bit**.
Tài liệu này gồm hai ví dụ, **mỗi dòng đều khớp với chương trình** (`python tinydes_cli.py enc ... --verbose`) và khớp với tài liệu của lớp:

* Ví dụ 1: ví dụ trên lớp (bài giảng, trang 65): `P = 5C`, `K = 9A` → `C = 92`.
* Ví dụ 2: Bài 9 trong file bài tập: `P = 53`, `K = BB` → `C = 8E` (kèm giải mã và câu hỏi về khóa đảo thứ tự).

**Quy ước.** Các bit đánh số từ trái sang phải, bắt đầu từ 0. Với 4 bit `b0 b1 b2 b3` thì `b0` là bit trái nhất.

| Hàm | Quy tắc |
|---|---|
| Expand (4 → 6 bit) | `b0b1b2b3` → `b2 b3 b1 b2 b1 b0`. Ví dụ `0110` → `101110` |
| S-box (6 → 4 bit) | `b0b1b2b3b4b5`: hàng = `b0b5`, cột = `b1b2b3b4`; tra bảng bên dưới |
| P-box (4 → 4 bit) | `b0b1b2b3` → `b2 b0 b3 b1` |
| Compress (8 → 6 bit) | `k0…k7` → `k5 k1 k3 k2 k7 k0` |
| Vòng Feistel | `L_i = R_{i-1}`;  `R_i = L_{i-1} ⊕ F(R_{i-1}, K_i)`;  `F = P-box(S-box(Expand(R) ⊕ K))` |
| Khóa con | `K = KL0 KR0` (mỗi nửa 4 bit). Vòng 1 dịch trái 1 bit, vòng 2 dịch tiếp 2 bit, vòng 3 dịch tiếp 1 bit; `K_i = Compress(KL_i KR_i)` |
| Bản mã | `C = L3 R3` (không đổi chỗ hai nửa ở cuối) |

Bảng S-box (hệ 16, hàng `b0b5`, cột `b1b2b3b4`):

```text
cột      0 1 2 3 4 5 6 7 8 9 A B C D E F
hàng 00: E 4 D 1 2 F B 8 3 A 6 C 5 9 0 7
hàng 01: 0 F 7 4 E 2 D 1 A 6 C B 9 5 3 8
hàng 10: 4 1 E 8 D 6 2 B F C 9 7 3 A 5 0
hàng 11: F C 8 2 4 9 1 7 5 B 3 E A 0 6 D
```

---

## Ví dụ 1 (ví dụ trên lớp): P = 01011100 (5C), K = 10011010 (9A)

```text
python tinydes_cli.py enc --alg tinydes --keys 10011010 --data 01011100 --verbose
```

**Sinh khóa con.** `KL0 = 1001`, `KR0 = 1010`.

| Vòng | Dịch thêm | KL | KR | K = Compress(KL KR) |
|---|---|---|---|---|
| 1 | 1 | 0011 | 0101 | `00110101` → k5 k1 k3 k2 k7 k0 = **101110** |
| 2 | 2 | 1100 | 0101 | `11000101` → **110011** |
| 3 | 1 | 1001 | 1010 | `10011010` → **001001** |

**Mã hóa.** `L0 = 0101`, `R0 = 1100`.

| Vòng | Expand(R) | Expand(R) ⊕ K | S-box | F = P-box | L | R |
|---|---|---|---|---|---|---|
| 1 | 001011 | 100101 | 1000 | 0100 | L1 = 1100 | R1 = 0101 ⊕ 0100 = **0001** |
| 2 | 010000 | 100011 | 1100 | 0101 | L2 = 0001 | R2 = 1100 ⊕ 0101 = **1001** |
| 3 | 010001 | 011000 | 0101 | 0011 | L3 = 1001 | R3 = 0001 ⊕ 0011 = **0010** |

**Bản mã** `C = L3 R3 = 1001 0010 = 92` (hệ 16). Khớp bài giảng.

**Giải mã** `C = 92` với khóa K = 9A, khóa con theo thứ tự K3, K2, K1: `R_{i-1} = L_i`, `L_{i-1} = R_i ⊕ F(R_{i-1}, K_i)`.
Kết quả trở về `L0 R0 = 0101 1100 = 5C`:

```text
python tinydes_cli.py dec --alg tinydes --keys 10011010 --data 10010010 --verbose
```

---

## Ví dụ 2 (Bài 9, file bài tập): P = 01010011 (53), K = 10111011 (BB)

```text
python tinydes_cli.py enc --alg tinydes --keys 10111011 --data 01010011 --verbose
```

**(1) Sinh khóa con.** `KL0 = 1011`, `KR0 = 1011`.

| Vòng | Dịch thêm | KL | KR | K |
|---|---|---|---|---|
| 1 | 1 | 0111 | 0111 | `01110111` → **111110** |
| 2 | 2 | 1101 | 1101 | `11011101` → **111011** |
| 3 | 1 | 1011 | 1011 | `10111011` → **001111** |

**(2) Mã hóa.** `L0 = 0101`, `R0 = 0011`.

| Vòng | Expand(R) | Expand(R) ⊕ K | S-box | F | L | R |
|---|---|---|---|---|---|---|
| 1 | 110100 | 001010 | 1111 | 1111 | L1 = 0011 | R1 = 0101 ⊕ 1111 = **1010** |
| 2 | 100101 | 011110 | 0111 | 1011 | L2 = 1010 | R2 = 0011 ⊕ 1011 = **1000** |
| 3 | 000001 | 001110 | 1000 | 0100 | L3 = 1000 | R3 = 1010 ⊕ 0100 = **1110** |

**Bản mã** `C = 1000 1110 = 8E`. Khớp đáp án của file bài tập.

**(3) Giải mã** (khóa con theo thứ tự K3, K2, K1):

| Vòng | R_{i-1} = L_i | F(R_{i-1}, K_i) | L_{i-1} = R_i ⊕ F |
|---|---|---|---|
| 3 | R2 = 1000 | 0100 | L2 = 1110 ⊕ 0100 = 1010 |
| 2 | R1 = 1010 | 1011 | L1 = 1000 ⊕ 1011 = 0011 |
| 1 | R0 = 0011 | 1111 | L0 = 1010 ⊕ 1111 = 0101 |

Kết quả `L0 R0 = 0101 0011 = 53`: **trở về đúng bản rõ**.

**(4) Chạy lại sơ đồ mã hóa trên `C` với khóa con đảo thứ tự K3, K2, K1** cho `01110100`, **khác** bản rõ `01010011`.
Lý do: giải mã Feistel đi ngược chiều (`R_{i-1} = L_i`, `L_{i-1} = R_i ⊕ F`), còn cách này vẫn đi xuôi (`L_i = R_{i-1}`, `R_i = L_{i-1} ⊕ F`), nên thiếu bước **đổi chỗ hai nửa** ở đầu vào và đầu ra.
Chương trình kiểm tra điều này trong `tests/test_tinydes.py` (`test_reversed_keys_in_encryption_circuit_is_wrong`).

---

## 2TinyDES và 3TinyDES

Ghép như 2DES, 3DES (xem `core/tinydes_multi.py`): `C = E_K2(E_K1(P))` và `C = E_K3(D_K2(E_K1(P)))`.
Bài giảng trình bày 3DES với **2 khóa** (`K3 = K1`): `C = E_K1(D_K2(E_K1(M)))`. Chương trình hỗ trợ 1, 2 và 3 khóa.
Vì khóa chỉ 8 bit nên 2TinyDES có không gian khóa 2^16 = 65 536 cặp; tấn công gặp nhau ở giữa chạy thật được:
`python mitm_demo.py tinydes --brute` (MITM 512 phép so với vét cạn 131 072 phép).

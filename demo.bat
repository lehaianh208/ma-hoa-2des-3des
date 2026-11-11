@echo off
chcp 65001 >nul
cd /d "%~dp0"
REM ---- Sua dong duoi neu Python cua ban nam o cho khac ----
set PY=C:\Users\admin\PycharmProjects\des_project\.venv\Scripts\python.exe
if not exist "%PY%" set PY=python

echo ============================================================
echo  1. S-DES (ban thu nho): ma hoa co in tung buoc
echo ============================================================
%PY% sdes_cli.py enc --alg sdes --keys 1010000010 --data 01110010 --verbose
echo.
echo --- giai ma lai ---
%PY% sdes_cli.py dec --alg sdes --keys 1010000010 --data 01110111
pause

echo ============================================================
echo  2. DES day du: ma hoa co in tung buoc (vi du kinh dien)
echo ============================================================
%PY% cli.py enc --alg des --keys 133457799BBCDFF1 --data 0123456789ABCDEF --verbose
echo.
echo --- giai ma lai ---
%PY% cli.py dec --alg des --keys 133457799BBCDFF1 --data 85E813540F0AB405
pause

echo ============================================================
echo  3. 2DES va 3DES
echo ============================================================
%PY% cli.py enc --alg 2des --keys 133457799BBCDFF1 0123456789ABCDEF --data 0123456789ABCDEF
%PY% cli.py dec --alg 2des --keys 133457799BBCDFF1 0123456789ABCDEF --data 8D0AAB998757B0AF
%PY% cli.py enc --alg 3des --keys 133457799BBCDFF1 0123456789ABCDEF FEDCBA9876543210 --data 0123456789ABCDEF
%PY% cli.py dec --alg 3des --keys 133457799BBCDFF1 0123456789ABCDEF FEDCBA9876543210 --data EB2EF3D233BBEB25
pause

echo ============================================================
echo  4. Ma hoa tep that (CBC) roi giai ma lai
echo ============================================================
%PY% filecrypt.py demo --alg 3des --mode cbc --keys 133457799BBCDFF1 0123456789ABCDEF FEDCBA9876543210 --in samples\sample.txt --save demo_out
pause

echo ============================================================
echo  5. Tan cong gap nhau o giua (MITM) len 2S-DES, co vet can de so sanh
echo ============================================================
%PY% mitm_demo.py sdes --brute
pause

echo ============================================================
echo  6. MITM o quy mo that: 2DES khoa day du
echo ============================================================
%PY% mitm_demo.py des --bits 12
pause

echo ============================================================
echo  7. Bo kiem thu va doi chieu voi thu vien chuan
echo ============================================================
%PY% -m unittest discover tests
%PY% tests\test_des.py --compare
pause

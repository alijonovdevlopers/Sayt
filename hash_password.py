#!/usr/bin/env python3
"""Administrator parolidan ADMIN_PASSWORD_HASH qiymatini yasaydi.

Standart rejim: saytning O'ZINING security.pin_hash funksiyasidan foydalanadi, ya'ni hash
saytdagi tekshiruv (security.pin_verify) bilan aynan bir xil formatda bo'ladi. Format taxmin
qilinmaydi. Chop etishdan oldin skript hashni pin_verify bilan tekshiradi; o'tmasa, hech narsa chiqarmaydi.

security.py repo ildizidagi tg_userbot_mcp_railway.zip ichidan vaqtinchalik papkaga ochiladi
(yoki --app-dir bilan ochilgan papka ko'rsatiladi). Kerak bo'lsa avval:
    pip install -r requirements.lock.txt   (zip ichidagi fayl)

  python3 hash_password.py                 # sayt formati (main bilan mos)
  python3 hash_password.py --app-dir PATH  # ochilgan tg_userbot_mcp papkasi
  python3 hash_password.py --scrypt        # overrides/owner_password.py formati; faqat
                                           # owner-login-hardening yamog'i deploy bo'lgandan keyin ishlaydi

Parol ekranga chiqmaydi va hech qayerga yozilmaydi (kamida 12 belgi).
"""
import argparse
import getpass
import importlib
import sys
import tempfile
import zipfile
from pathlib import Path

MIN_LENGTH = 12
HERE = Path(__file__).resolve().parent


def find_security_dir(app_dir, tmp):
    for base in ([Path(app_dir)] if app_dir else [Path.cwd() / 'tg_userbot_mcp', HERE / 'tg_userbot_mcp']):
        if (base / 'security.py').is_file():
            return base
    archive = HERE / 'tg_userbot_mcp_railway.zip'
    if not app_dir and archive.is_file():
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmp)
        for hit in Path(tmp).rglob('security.py'):
            return hit.parent
    sys.exit('security.py topilmadi. --app-dir bilan ochilgan tg_userbot_mcp papkasini ko‘rsating.')


def site_functions(app_dir, tmp):
    path = find_security_dir(app_dir, tmp)
    sys.path.insert(0, str(path))
    try:
        module = importlib.import_module('security')
        return module.pin_hash, module.pin_verify
    except Exception as error:  # parol bu yerda hali yo'q; faqat xato turi chiqariladi
        sys.exit(f'security.py ni yuklab bo‘lmadi ({type(error).__name__}). '
                 'Avval: pip install -r requirements.lock.txt')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--app-dir')
    ap.add_argument('--scrypt', action='store_true')
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        if args.scrypt:
            sys.path.insert(0, str(HERE / 'overrides'))
            from owner_password import hash_password as make, verify_password as check
        else:
            make, check = site_functions(args.app_dir, tmp)
        first = getpass.getpass(f'Yangi parol (kamida {MIN_LENGTH} belgi): ')
        if len(first) < MIN_LENGTH:
            sys.exit(f'Parol juda qisqa: kamida {MIN_LENGTH} belgi kerak.')
        if getpass.getpass('Parolni takrorlang: ') != first:
            sys.exit('Parollar mos kelmadi.')
        stored = make(first)
        if not isinstance(stored, str) or not check(first, stored) or check(first + 'x', stored):
            sys.exit('Hash tekshiruvdan o‘tmadi. Hech narsa chiqarilmadi.')
    print('\nRailway > Variables > ADMIN_PASSWORD_HASH ga shu qiymatni qo‘ying:\n')
    print(stored)
    print('\nParolning o‘zini hech kimga va hech qayerga yozmang.')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Administrator parolidan scrypt hash yasaydi. Parol ekranga chiqmaydi va hech qayerga yozilmaydi.

Ishlatish (egasi o'zi, o'z terminalida):  python3 hash_password.py
Natijadagi qatorni Railway'da ADMIN_PASSWORD_HASH o'zgaruvchisiga qo'ying.
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / 'overrides'))
from owner_password import MIN_LENGTH, hash_password, verify_password


def main():
    first = getpass.getpass(f'Yangi parol (kamida {MIN_LENGTH} belgi): ')
    if len(first) < MIN_LENGTH:
        sys.exit(f'Parol juda qisqa: kamida {MIN_LENGTH} belgi kerak.')
    if getpass.getpass('Parolni takrorlang: ') != first:
        sys.exit('Parollar mos kelmadi.')
    stored = hash_password(first)
    if not verify_password(first, stored):
        sys.exit('Ichki xato: hash tekshiruvdan o‘tmadi.')
    print('\nRailway > tg-mcp > Variables > ADMIN_PASSWORD_HASH ga shu qiymatni qo‘ying:\n')
    print(stored)
    print('\nParolning o‘zini hech kimga va hech qayerga yozmang.')


if __name__ == '__main__':
    main()

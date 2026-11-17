"""Birinchi marta ishlatiladigan mahalliy sozlash; paket o‘rnatuvchisi emas."""
import os
from pathlib import Path
import secrets
from cryptography.fernet import Fernet
from security import SafeError, private_write


def main():
    os.umask(0o077)
    path = Path('.env')
    text = ('# Bu faylni boshqalarga yubormang.\n'
            'API_ID=\nAPI_HASH=\n'
            f'MCP_SECRET={secrets.token_urlsafe(32)}\n'
            f'ENC_KEY={Fernet.generate_key().decode()}\n'
            'DATA_DIR=data\nPUBLIC_URL=https://localhost\nMAX_LIMIT=30\nMAX_TEXT=500\n')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise SafeError('.env ruxsatini 600 qiling.')
        old = path.read_text()
        keys = {x.split('=', 1)[0].strip() for x in old.splitlines() if '=' in x and not x.lstrip().startswith('#')}
        missing = [line for line in text.splitlines() if '=' in line and line.split('=', 1)[0] not in keys]
        if missing:
            private_write(path, (old.rstrip('\n') + '\n' + '\n'.join(missing) + '\n').encode())
            print('Eski qiymatlar saqlandi; yetishmagan sozlamalar qo‘shildi.')
        else:
            print('.env allaqachon to‘liq; o‘zgartirilmadi.')
        return
    with os.fdopen(fd, 'w') as output:
        output.write(text)
    print('.env yaratildi. Kalitlar ekranga chiqarilmadi.')


if __name__ == '__main__':
    main()

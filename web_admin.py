"""Faqat terminaldan birinchi sayt egasini tayinlash."""
import argparse
import asyncio
from getpass import getpass

from config import config
from security import SafeError, Vault
from storage import Store
from web_store import WebStore


async def main():
    parser = argparse.ArgumentParser(description='Birinchi sayt egasini belgilang.')
    parser.add_argument('user_id', help='login.py yoki migrate_v1.py bergan foydalanuvchi ID')
    args = parser.parse_args()
    settings = config()
    store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
    try:
        web = WebStore(store)
        web.index_existing(Vault(settings.data_dir, settings.enc_key))
        await web.verify_pin(args.user_id, getpass('Sayt PINi: '), 'mahalliy_admin')
        web.bootstrap_admin(args.user_id)
        print('Sayt egasi belgilandi. Saytga kirib Boshqaruv bo‘limidan taklif yarating.')
    except SafeError as error:
        print(str(error))
    finally:
        store.close()


if __name__ == '__main__':
    asyncio.run(main())

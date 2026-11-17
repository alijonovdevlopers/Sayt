"""v1 SQLite sessiyasini faqat mahalliy shifrlangan saqlashga ko‘chirish."""
import asyncio
from getpass import getpass
import os
from pathlib import Path
import sqlite3

from config import config
from security import SafeError, Vault, pin_hash
from server import quiet_logs
from storage import Store


async def main():
    from telethon import TelegramClient
    from telethon.crypto import AuthKey
    from telethon.sessions import StringSession
    os.umask(0o077)
    quiet_logs()
    settings = config()
    path = Path(os.getenv('SESSION_PATH', 'data/tg_session'))
    if path.suffix != '.session':
        path = Path(str(path) + '.session')
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise SafeError('Eski sessiya fayli topilmadi yoki uning ruxsati 600 emas.')
    pin = getpass('Yangi sayt PIN (kamida 6 belgi): ')
    pin_hash(pin)
    if pin != getpass('PINni qaytaring: '):
        raise SafeError('PINlar mos emas.')
    with sqlite3.connect(path.absolute().as_uri() + '?mode=ro', uri=True) as old:
        row = old.execute('SELECT dc_id,server_address,port,auth_key FROM sessions').fetchone()
    if not row or not row[3]:
        raise SafeError('Eski sessiya bo‘sh.')
    session = StringSession()
    session.set_dc(row[0], row[1], row[2])
    session.auth_key = AuthKey(row[3])
    api_id = int(os.environ['API_ID'])
    api_hash = os.environ['API_HASH']
    client = TelegramClient(session, api_id, api_hash, receive_updates=False, flood_sleep_threshold=0, request_retries=0)
    store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            raise SafeError('Eski sessiya yaroqsiz; login.py orqali qayta kiring.')
        me = await client.get_me()
        uid, token = store.create_user(pin, me.id)
        try:
            Vault(settings.data_dir, settings.enc_key).save(uid, api_id=api_id, api_hash=api_hash, session=client.session.save())
        except Exception:
            store.set_blocked(uid, True)
            raise
        print('Shifrlangan akkaunt yaratildi. Foydalanuvchi ID:', uid)
        print('Faqat bir marta ko‘rsatiladigan MCP manzili:')
        print(settings.public_url + '/mcp/' + token)
        print('Eski sessiya fayli o‘zgartirilmadi. Yangisi ishlaganini tekshirgach eski ochiq nusxani o‘zingiz olib tashlang.')
    finally:
        await client.disconnect()
        store.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except SafeError as error:
        print(str(error))
    except KeyboardInterrupt:
        print('Bekor qilindi.')
    except Exception:
        print('Ko‘chirish bajarilmadi; sozlama va eski sessiyani tekshiring. Sirlar chiqarilmadi.')

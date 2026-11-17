"""1-bosqich: faqat server egasi terminalidan akkaunt ulash."""
import asyncio
from getpass import getpass
import os
import re
import sqlite3

from config import config
from security import SafeError, Vault, pin_hash
from storage import Store
from server import quiet_logs


async def main():
    from telethon import TelegramClient
    from telethon.errors import SessionPasswordNeededError
    from telethon.sessions import StringSession
    os.umask(0o077)
    quiet_logs()
    settings = config()
    raw_id = os.getenv('API_ID') or input('O‘zingizning API ID: ').strip()
    api_hash = os.getenv('API_HASH') or getpass('O‘zingizning API hash (yashirin): ').strip()
    if not raw_id.isdigit() or not 0 < int(raw_id) < 2**31 or not re.fullmatch('[a-fA-F0-9]{32}', api_hash):
        raise SafeError('API ID yoki API hash formati noto‘g‘ri.')
    pin = getpass('Yangi sayt PIN (kamida 6 belgi): ')
    pin_hash(pin)
    if pin != getpass('PINni qaytaring: '):
        raise SafeError('PINlar mos emas.')
    phone = getpass('Telegram telefon raqami (+998..., yashirin): ').strip()
    client = TelegramClient(StringSession(), int(raw_id), api_hash, receive_updates=False,
                            flood_sleep_threshold=0, request_retries=0)
    store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
    try:
        await client.connect()
        sent = await client.send_code_request(phone)
        try:
            await client.sign_in(phone=phone, code=getpass('Telegram kodi (yashirin): ').strip(),
                                 phone_code_hash=sent.phone_code_hash)
        except SessionPasswordNeededError:
            await client.sign_in(password=getpass('Telegram ikki bosqichli paroli (yashirin): '))
        me = await client.get_me()
        uid, token = store.create_user(pin, me.id)
        try:
            Vault(settings.data_dir, settings.enc_key).save(
                uid, api_id=int(raw_id), api_hash=api_hash, session=client.session.save())
        except Exception:
            store.set_blocked(uid, True)
            raise
        print('Akkaunt ulandi. Foydalanuvchi ID:', uid)
        print('MCP manzili FAQAT HOZIR ko‘rsatiladi; uni sir saqlang:')
        print(settings.public_url + '/mcp/' + token)
        print('PUBLIC_URL keyin o‘zgarsa, manzildagi domenni almashtiring; maxfiy qism o‘sha qoladi.')
    finally:
        await client.disconnect()
        store.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except SafeError as error:
        print(str(error))
    except sqlite3.IntegrityError:
        print('Bu Telegram akkaunti avval ulangan. Yangi foydalanuvchi yaratilmadi.')
    except KeyboardInterrupt:
        print('Bekor qilindi.')
    except Exception:
        print('Ulash bajarilmadi. Kod, parol, API ma’lumotlari va ulanishni tekshiring. Sirlar jurnalga yozilmadi.')

"""Egasi ko‘rib tasdiqlaydi. Bu jarayon Telegramga ULANMAYDI."""
import argparse
from getpass import getpass
import json

from actions import public_details
from config import config
from queue_store import QueueStore
from security import SafeError, pin_verify
from storage import Store


def visible(data):
    text = json.dumps(data, ensure_ascii=False, indent=2)
    return ''.join('\\u%04x' % ord(c) if 0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 else c for c in text)


def main():
    parser = argparse.ArgumentParser(description='Aniq amalni ko‘rib tasdiqlash yoki rad etish')
    parser.add_argument('id', help='Amal ID yoki list')
    parser.add_argument('--user', help='Foydalanuvchi ID; berilmasa so‘raladi')
    args = parser.parse_args()
    settings = config()
    store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
    try:
        uid = args.user or input('Foydalanuvchi ID: ').strip()
        user = store.user(uid)
        if store.auth_blocked(uid, 'local_approval'):
            raise SafeError('5 ta xato PIN: 15 daqiqadan keyin qayta urining.')
        if not pin_verify(getpass('Sayt PIN (yashirin): '), user['pin_hash']):
            store.auth_fail(uid, 'local_approval')
            raise SafeError('PIN noto‘g‘ri.')
        queue = QueueStore(store)
        if args.id == 'list':
            print(visible([{k: row[k] for k in ('id', 'tool', 'status', 'expires', 'done')} for row in queue.list(uid)]))
            return
        row = queue.get(uid, args.id)
        if row['status'] != 'pending':
            print(visible({'id': row['id'], 'status': row['status'], 'bajarilgan': row['done'], 'result': json.loads(row['result']),
                           'qadam_natijalari': queue.step_results(uid, row['id'])}))
            return
        print(visible(public_details(row)))
        answer = input('Aynan shu amalga RUXSAT yoki RAD deb yozing: ').strip()
        if answer not in ('RUXSAT', 'RAD'):
            print('Qaror berilmadi; amal kutishda qoldi.')
            return
        bulk = False
        if answer == 'RUXSAT' and row['bulk']:
            expected = 'OMMAVIY ' + row['id']
            print('OGOHLANTIRISH: 10 tadan ko‘p xabar/a’zoga ta’sir qiladi.')
            bulk = input('Alohida tasdiq uchun ' + expected + ' deb yozing: ').strip() == expected
            if not bulk:
                print('Ommaviy tasdiq berilmadi; bajarilmadi.')
                return
        queue.decide(uid, row['id'], row['digest'], answer == 'RUXSAT', bulk)
        print('Tasdiq saqlandi. Ishlayotgan server navbatni bajaradi.' if answer == 'RUXSAT' else 'Amal rad etildi.')
    finally:
        store.close()


if __name__ == '__main__':
    try:
        main()
    except SafeError as error:
        print(str(error))
    except (KeyboardInterrupt, EOFError):
        print('Tasdiq berilmadi.')
    except Exception:
        print('Qaror saqlanmadi; sozlama va bazani tekshiring.')

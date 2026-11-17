"""Faqat mahalliy terminal: jurnal va favqulodda to‘xtatish."""
import argparse
import json
from config import config
from security import SafeError
from storage import Store


def main():
    parser = argparse.ArgumentParser(description='Mahalliy yadro nazorati')
    parser.add_argument('amal', choices=['jurnal', 'toxtatish', 'holat'])
    parser.add_argument('user_id')
    args = parser.parse_args()
    settings = config()
    store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
    try:
        if args.amal == 'jurnal':
            print(json.dumps(store.events(args.user_id), ensure_ascii=False, indent=2))
        elif args.amal == 'toxtatish':
            store.stop(args.user_id)
            print('HAMMASI TO‘XTATILDI. Qayta yoqish paneli 3-bosqichda qo‘shiladi.')
        else:
            user = store.user(args.user_id)
            print(json.dumps({key: user[key] for key in ('user_id', 'stopped', 'blocked')}, ensure_ascii=False))
    finally:
        store.close()


if __name__ == '__main__':
    try:
        main()
    except SafeError as error:
        print(str(error))

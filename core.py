"""MCP va kelajakdagi panel uchun yagona himoya chegarasi."""
import asyncio
from contextlib import aclosing
import os
from pathlib import Path
import time
import uuid

from security import READ_TOOLS, WRITE_TOOLS, NOTICE, SafeError, check_tool, user_path
from telegram_adapter import WaitRequired

SERVICE_ID = 777000


def allowed_message(message):
    return all(message.get(k) != SERVICE_ID for k in ('chat_id', 'sender_id', 'forwarded_from_id'))


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise SafeError('Sonli parametr ruxsat etilgan chegaradan tashqarida.')
    return value


class Core:
    def __init__(self, store, pool, data_dir, max_file=20 * 1024**2, quota=100 * 1024**2, timeout=120):
        self.store, self.pool = store, pool
        self.data_dir = Path(data_dir)
        self.max_file, self.quota, self.timeout = max_file, quota, timeout
        self.locks = {}
        self.actions = None

    async def call(self, uid, name, params=None):
        params = params or {}
        try:
            self.store.user(uid)
        except SafeError:
            return {'ok': False, 'xato': 'Foydalanuvchi aniqlanmadi.'}
        if self.actions and (name in WRITE_TOOLS or name == 'action_status'):
            return await self.actions.call(uid, name, params)
        known = name in READ_TOOLS or name in WRITE_TOOLS
        label = name if known else 'noma_lum_vosita'
        level = 'A' if name in READ_TOOLS else 'B' if name in WRITE_TOOLS else 'rad'
        event = self.store.audit(uid, label, params, 'boshlandi', level)
        try:
            check_tool(name)
            self.store.assert_active(uid)
            async with asyncio.timeout(self.timeout):
                async with self.locks.setdefault(uid, asyncio.Lock()):
                    for attempt in range(2):
                        await self.wait_cooldown(uid)
                        try:
                            adapter = await self.pool.get(uid)
                            self.store.assert_active(uid)
                            result = await self.execute(uid, adapter, name, params)
                            self.store.assert_active(uid)
                            break
                        except WaitRequired as error:
                            self.store.cooldown(uid, error.seconds)
                            self.store.audit(uid, label, {'seconds': error.seconds}, 'flood_kutilmoqda', level)
                            if attempt:
                                raise SafeError('Telegram kutishni so‘radi; keyinroq qayta urinib ko‘ring.')
                    else:
                        raise SafeError('Amal bajarilmadi.')
            self.store.finish_event(uid, event, 'tayyor')
            answer = {'ok': True, 'data': result, 'eslatma': NOTICE}
            # v1 ishlatgan o‘zbekcha maydonlarni ham saqlaymiz.
            if name == 'whoami':
                answer.update(id=result.get('id'), ism=result.get('first_name'), username=result.get('username'))
            elif name == 'list_chats':
                answer['chatlar'] = [{'id': x['id'], 'nom': x.get('title', ''), 'tur': x.get('tur', 'shaxsiy'),
                                      'oqilmagan': x['unread_count']} for x in result['items']]
            elif name == 'read_messages':
                from v1_compat import short
                answer['xabarlar'] = [{'id': x['id'], 'sana': x.get('date'), 'kim': 'men' if x.get('out') else x['sender_id'],
                                      'matn': short(x['text']), 'media_bor': x.get('has_media', False)} for x in result]
            return answer
        except asyncio.CancelledError:
            self.store.finish_event(uid, event, 'bekor')
            raise
        except SafeError as error:
            self.store.finish_event(uid, event, 'rad')
            return {'ok': False, 'xato': str(error), 'event_id': event}
        except TimeoutError:
            self.store.finish_event(uid, event, 'vaqt_tugadi')
            return {'ok': False, 'xato': 'Kutish muddati tugadi. Keyinroq qayta urinib ko‘ring.', 'event_id': event}
        except Exception:
            # Telegram/Python xatolarining matni sirlar yoki xabarlarni saqlashi mumkin.
            self.store.finish_event(uid, event, 'xato')
            return {'ok': False, 'xato': 'Amal bajarilmadi; akkaunt, ruxsat va ulanishni tekshiring.', 'event_id': event}

    async def wait_cooldown(self, uid):
        while True:
            user = self.store.assert_active(uid)
            remaining = user['cooldown'] - time.time()
            if remaining <= 0:
                return
            await asyncio.sleep(min(0.25, remaining))

    async def resolve_chat(self, adapter, value):
        if type(value) not in (str, int) or isinstance(value, str) and not 1 <= len(value) <= 128:
            raise SafeError('Chat ID yoki username noto‘g‘ri.')
        if str(value).strip().lstrip('+') == str(SERVICE_ID):
            raise SafeError('Telegram xizmat chatiga kirish taqiqlangan.')
        info = await adapter.resolve(value)
        if info['id'] == SERVICE_ID:
            raise SafeError('Telegram xizmat chatiga kirish taqiqlangan.')
        return info

    async def execute(self, uid, adapter, name, p):
        permitted = {
            'whoami': set(), 'list_chats': {'limit'}, 'get_unread': {'limit'},
            'get_chat_info': {'chat'}, 'list_members': {'chat', 'limit'},
            'read_messages': {'chat', 'limit', 'offset_id'},
            'search_messages': {'chat', 'query', 'limit'},
            'download_media': {'chat', 'message_id'},
        }
        if p.keys() - permitted[name]:
            raise SafeError('Ortiqcha parametrga ruxsat yo‘q.')
        limit = integer(p.get('limit', 30), 1, 100)
        from v1_compat import clamp
        limit = min(limit, clamp(os.getenv('MAX_LIMIT', '30'), 30, 100))
        if name == 'whoami':
            return await adapter.whoami()
        if name in ('list_chats', 'get_unread'):
            rows = await adapter.dialogs(limit)
            rows = [d for d in rows if d['id'] != SERVICE_ID]
            if name == 'get_unread':
                rows = [d for d in rows if d['unread_count'] > 0]
            return {'items': rows, 'scanned_limit': limit, 'toliq_royxat': False}
        chat = p.get('chat')
        info = None
        if chat is not None:
            info = await self.resolve_chat(adapter, chat)
            chat = info['id']
        elif name != 'search_messages':
            raise SafeError('Chat ko‘rsatilishi kerak.')
        self.store.assert_active(uid)
        if name == 'get_chat_info':
            return info
        if name == 'list_members':
            return [u for u in await adapter.members(chat, limit) if u['id'] != SERVICE_ID]
        if name in ('read_messages', 'search_messages'):
            query = p.get('query')
            if name == 'search_messages' and (not isinstance(query, str) or not 1 <= len(query.strip()) <= 256):
                raise SafeError('Qidiruv 1–256 belgidan iborat bo‘lsin.')
            offset = integer(p.get('offset_id', 0), 0, 2**31 - 1)
            rows = await adapter.messages(chat, limit, offset, query)
            return [m for m in rows if allowed_message(m)]
        if name == 'download_media':
            return await self.download(uid, adapter, chat, integer(p.get('message_id'), 1, 2**31 - 1))
        raise SafeError('Bu vositaga ruxsat yo‘q.')

    async def download(self, uid, adapter, chat, message_id):
        info, media = await adapter.media(chat, message_id)
        if not allowed_message(info):
            raise SafeError('Telegram xizmat xabarini yuklab bo‘lmaydi.')
        size = info.get('size')
        if type(size) is not int or not 0 <= size <= self.max_file:
            raise SafeError('Fayl hajmi noma’lum yoki chegaradan katta.')
        directory = user_path(self.data_dir / 'downloads', uid)
        used = sum(p.stat().st_size for p in directory.iterdir() if p.is_file() and not p.is_symlink())
        if used + size > self.quota:
            raise SafeError('Yuklamalar uchun ajratilgan joy tugagan.')
        file_id = uuid.uuid4().hex
        filename = file_id + '.bin'
        path = directory / filename
        total = 0
        success = False
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as target:
                async with aclosing(adapter.chunks(media)) as chunks:
                    async for chunk in chunks:
                        self.store.assert_active(uid)
                        total += len(chunk)
                        if total > self.max_file or used + total > self.quota or total > size:
                            raise SafeError('Yuklama hajmi chegaradan oshdi.')
                        target.write(chunk)
            self.store.assert_active(uid)
            if total != size:
                raise SafeError('Fayl to‘liq yuklanmadi.')
            self.store.add_download(uid, file_id, filename, total)
            success = True
            return {'file_id': file_id, 'filename': filename, 'bytes': total,
                    'relative_path': f'downloads/{uid}/{filename}'}
        finally:
            if not success:
                path.unlink(missing_ok=True)

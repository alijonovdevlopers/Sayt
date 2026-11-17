"""Faqat haqiqiy Telethon 1.x o‘qish usullarini chaqiruvchi adapter."""
import asyncio

from security import SafeError


class WaitRequired(Exception):
    def __init__(self, seconds):
        self.seconds = seconds


class TelegramAdapter:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def public_user(user):
        return {key: getattr(user, key, None) for key in ('id', 'username', 'first_name', 'last_name', 'bot')}

    @staticmethod
    def public_chat(entity):
        from telethon import utils
        return {
            'id': utils.get_peer_id(entity),
            'title': getattr(entity, 'title', None) or getattr(entity, 'first_name', ''),
            'username': getattr(entity, 'username', None),
            'type': type(entity).__name__,
        }

    @staticmethod
    def public_message(message):
        from telethon import utils
        forwarded = getattr(getattr(message, 'fwd_from', None), 'from_id', None)
        return {
            'id': message.id,
            'chat_id': message.chat_id,
            'sender_id': message.sender_id,
            'forwarded_from_id': utils.get_peer_id(forwarded) if forwarded else None,
            'text': message.raw_text or '',
            'date': message.date.isoformat() if message.date else None,
            'has_media': bool(message.photo or message.document),
            'out': bool(message.out),
        }

    async def guarded(self, coroutine):
        from telethon.errors import FloodWaitError
        try:
            return await coroutine
        except FloodWaitError as error:
            raise WaitRequired(error.seconds) from None

    async def whoami(self):
        return self.public_user(await self.guarded(self.client.get_me()))

    async def resolve(self, chat):
        if isinstance(chat, str) and chat.lstrip('-').isdigit():
            chat = int(chat)
        return self.public_chat(await self.guarded(self.client.get_entity(chat)))

    async def dialogs(self, limit):
        async def collect():
            return [dict(self.public_chat(d.entity), unread_count=d.unread_count,
                         tur='kanal' if d.is_channel and not d.is_group else 'guruh' if d.is_group else 'shaxsiy')
                    async for d in self.client.iter_dialogs(limit=limit)]
        return await self.guarded(collect())

    async def messages(self, chat, limit, offset_id=0, query=None):
        async def collect():
            return [self.public_message(m) async for m in self.client.iter_messages(
                chat, limit=limit, offset_id=offset_id, search=query)]
        return await self.guarded(collect())

    async def members(self, chat, limit):
        async def collect():
            return [self.public_user(p) async for p in self.client.iter_participants(chat, limit=limit)]
        return await self.guarded(collect())

    async def media(self, chat, message_id):
        message = await self.guarded(self.client.get_messages(chat, ids=message_id))
        if not message or not (message.photo or message.document):
            raise SafeError('Yuklab olinadigan rasm yoki fayl topilmadi.')
        info = self.public_message(message)
        info['size'] = getattr(message.file, 'size', None)
        return info, message

    async def chunks(self, message):
        from telethon.errors import FloodWaitError
        iterator = self.client.iter_download(message.media, request_size=64 * 1024)
        try:
            async with iterator:
                async for chunk in iterator:
                    yield chunk
        except FloodWaitError as error:
            raise WaitRequired(error.seconds) from None


class ClientPool:
    """Har akkaunt uchun bitta mijoz; panel va MCP shu poolni bo‘lishadi."""
    def __init__(self, vault, store):
        self.vault, self.store = vault, store
        self.clients, self.locks = {}, {}

    def adopt(self, uid, client):
        if uid in self.clients:
            raise SafeError('Akkaunt mijozi mavjud.')
        self.clients[uid] = TelegramAdapter(client)

    async def drop(self, uid):
        async with self.locks.setdefault(uid, asyncio.Lock()):
            adapter = self.clients.pop(uid, None)
            if adapter:
                await adapter.client.disconnect()

    async def get(self, uid):
        from telethon import TelegramClient
        from telethon.errors import FloodWaitError
        from telethon.sessions import StringSession
        self.store.assert_active(uid)
        async with self.locks.setdefault(uid, asyncio.Lock()):
            self.store.assert_active(uid)
            if uid not in self.clients:
                credentials = self.vault.load(uid)
                client = TelegramClient(StringSession(credentials['session']), credentials['api_id'],
                                        credentials['api_hash'], receive_updates=False,
                                        flood_sleep_threshold=0, request_retries=0)
                try:
                    await client.connect()
                    if not await client.is_user_authorized():
                        raise SafeError('Telegramga qayta kirish kerak.')
                    me = await client.get_me()
                    if me.id != self.store.user(uid)['telegram_id']:
                        raise SafeError('Akkaunt egasi mos kelmadi.')
                    self.store.assert_active(uid)
                except FloodWaitError as error:
                    await client.disconnect()
                    raise WaitRequired(error.seconds) from None
                except BaseException:
                    await client.disconnect()
                    raise
                self.clients[uid] = TelegramAdapter(client)
            return self.clients[uid]

    async def close(self):
        for uid, adapter in list(self.clients.items()):
            try:
                # DC almashsa, yangilangan sessiya ham faqat shifrlangan holda qoladi.
                saved = self.vault.load(uid)
                self.vault.save(uid, api_id=saved['api_id'], api_hash=saved['api_hash'],
                                session=adapter.client.session.save())
            except Exception:
                self.store.audit(uid, 'ulanishni_yopish', {}, 'sessiyani_saqlash_xatosi', 'mahalliy')
            finally:
                try:
                    await adapter.client.disconnect()
                except Exception:
                    self.store.audit(uid, 'ulanishni_yopish', {}, 'uzilish_xatosi', 'mahalliy')
                finally:
                    self.clients.pop(uid, None)

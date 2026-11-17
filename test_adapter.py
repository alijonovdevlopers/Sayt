"""Haqiqiy Telethon turlari, tarmoqqa chiqmaydigan mijoz."""
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from telethon import types
from telethon.errors import FloodWaitError
from telegram_adapter import TelegramAdapter, WaitRequired


class DownloadIterator:
    def __init__(self):
        self.closed = False
        self.sent = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.sent:
            raise StopAsyncIteration
        self.sent = True
        return b'ab'


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_user_projection_excludes_phone_and_access_hash(self):
        user = types.User(id=42, first_name='Sinov', phone='998901234567', access_hash=987654321)
        result = TelegramAdapter.public_user(user)
        self.assertNotIn('phone', result)
        self.assertNotIn('access_hash', result)
        self.assertNotIn('998901234567', str(result))

    def test_marked_peer_ids_match_telethon(self):
        user = types.User(id=42, first_name='Sinov')
        channel = types.Channel(id=123, title='Sinov', photo=types.ChatPhotoEmpty(), date=datetime.now(timezone.utc))
        self.assertEqual(TelegramAdapter.public_chat(user)['id'], 42)
        self.assertEqual(TelegramAdapter.public_chat(channel)['id'], -1000000000123)

    def test_message_projection_marks_forwarded_service_message(self):
        message = types.Message(id=1, peer_id=types.PeerUser(42), from_id=types.PeerUser(42),
            date=datetime.now(timezone.utc), message='Sinov',
            fwd_from=types.MessageFwdHeader(date=datetime.now(timezone.utc), from_id=types.PeerUser(777000)))
        result = TelegramAdapter.public_message(message)
        self.assertEqual(result['forwarded_from_id'], 777000)
        self.assertEqual(result['chat_id'], 42)

    async def test_real_flood_error_converted(self):
        async def fail():
            raise FloodWaitError(request=None, capture=17)
        with self.assertRaises(WaitRequired) as result:
            await TelegramAdapter(None).guarded(fail())
        self.assertEqual(result.exception.seconds, 17)

    async def test_download_iterator_closed(self):
        iterator = DownloadIterator()
        client = SimpleNamespace(iter_download=lambda media, request_size: iterator)
        chunks = [chunk async for chunk in TelegramAdapter(client).chunks(SimpleNamespace(media=object()))]
        self.assertEqual(chunks, [b'ab'])
        self.assertTrue(iterator.closed)

    async def test_download_iterator_closed_when_cancelled_by_consumer(self):
        iterator = DownloadIterator()
        client = SimpleNamespace(iter_download=lambda media, request_size: iterator)
        stream = TelegramAdapter(client).chunks(SimpleNamespace(media=object()))
        await anext(stream)
        await stream.aclose()
        self.assertTrue(iterator.closed)

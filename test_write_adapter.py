"""Haqiqiy Telethon TL so‘rovlari va usul imzolari, tarmoqqa chiqmaydi."""
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock
from telethon import types, functions
from telethon.errors import FloodWaitError
from telegram_adapter import TelegramAdapter, WaitRequired
from write_adapter import WriteAdapter
from security import SafeError


class Client:
    def __init__(self):
        self.requests = []
        self.sent = []
        for name in ('send_message', 'edit_message', 'delete_messages', 'forward_messages', 'send_file',
                     'pin_message', 'unpin_message', 'send_read_acknowledge', 'edit_folder', 'kick_participant'):
            setattr(self, name, AsyncMock(return_value=None))

    async def __call__(self, req):
        # TL serializatsiyasi noto‘g‘ri tur/maydon bo‘lsa haqiqiy SDK xato beradi.
        bytes(req)
        self.requests.append(req)
        return None


class WriteAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.c = Client()
        self.adapter = WriteAdapter(TelegramAdapter(self.c))
        self.user = {'id': 42, 'raw_id': 42, 'kind': 'user', 'access_hash': 123, 'label': 'Sinov'}
        self.chat = {'id': -12, 'raw_id': 12, 'kind': 'chat', 'access_hash': None, 'label': 'Guruh'}
        self.channel = {'id': -1000000000023, 'raw_id': 23, 'kind': 'channel', 'access_hash': 234, 'label': 'Kanal'}

    def bundle(self, params, chat=None):
        return {'params': params, 'peers': {'chat': chat or self.channel, 'from_chat': self.channel,
                                         'user': self.user, 'users': [self.user]}, 'random_id': 456}

    async def test_all_twenty_four_dispatch_branches_use_real_sdk(self):
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        cases = {
            'send_message': {'text': '**literal**'}, 'reply': {'message_id': 1, 'text': 'Salom'},
            'edit_message': {'message_id': 1, 'text': 'Yangi'}, 'delete_messages': {'message_ids': [1], 'revoke': True},
            'forward_messages': {'message_ids': [1]}, 'send_file': {'filename': 'a.txt', 'caption': 'Izoh'},
            'react': {'message_id': 1, 'emoji': '👍'}, 'pin': {'message_id': 1, 'notify': False},
            'unpin': {'message_id': 1}, 'mark_read': {'max_id': 1}, 'join_chat': {}, 'leave_chat': {},
            'create_group': {'title': 'Guruh'}, 'create_channel': {'title': 'Kanal', 'about': '', 'megagroup': False},
            'add_member': {}, 'remove_member': {}, 'set_title': {'title': 'Yangi'}, 'set_about': {'about': 'Izoh'},
            'block': {}, 'unblock': {}, 'archive': {'archived': True}, 'mute': {'muted': True, 'hours': 24},
            'schedule_message': {'text': 'Keyin', 'when': future},
            'send_poll': {'question': 'Qaysi?', 'options': ['A', 'B'], 'anonymous': True, 'multiple': False},
        }
        from actions import SPECS
        self.assertEqual(set(cases), set(SPECS))
        for name, params in cases.items():
            with self.subTest(tool=name):
                await self.adapter.perform(name, self.bundle(params), file_bytes=b'abc')
        self.assertIsNone(self.c.send_message.call_args_list[0].kwargs['parse_mode'])
        self.assertFalse(self.c.send_message.call_args_list[0].kwargs['link_preview'])
        self.assertEqual(self.c.send_file.call_args.args[1].getvalue(), b'abc')
        self.assertEqual(self.c.forward_messages.call_args.args[1], [1])
        self.assertIsInstance(self.c.requests[-1], functions.messages.SendMediaRequest)
        self.assertEqual(self.c.requests[-1].media.poll.question.text, 'Qaysi?')

    async def test_basic_group_variants(self):
        for name, params in [('leave_chat', {}), ('set_title', {'title': 'Yangi'}), ('add_member', {})]:
            await self.adapter.perform(name, self.bundle(params, self.chat))
        self.assertIsInstance(self.c.requests[0], functions.messages.DeleteChatUserRequest)
        self.assertIsInstance(self.c.requests[1], functions.messages.EditChatTitleRequest)
        self.assertIsInstance(self.c.requests[2], functions.messages.AddChatUserRequest)

    async def test_invite_reaction_clear_unmute_unarchive(self):
        bundle = self.bundle({})
        bundle['invite_hash'] = 'ABCDEFGH'
        await self.adapter.perform('join_chat', bundle)
        await self.adapter.perform('react', self.bundle({'message_id': 1, 'emoji': ''}))
        await self.adapter.perform('mute', self.bundle({'muted': False, 'hours': 24}))
        await self.adapter.perform('archive', self.bundle({'archived': False}))
        self.assertIsInstance(self.c.requests[0], functions.messages.ImportChatInviteRequest)
        self.assertEqual(self.c.requests[1].reaction, [])
        self.assertEqual(self.c.requests[2].settings.mute_until.timestamp(), 0)
        self.assertEqual(self.c.edit_folder.call_args.kwargs['folder'], 0)

    async def test_nonchannel_message_ids_cannot_delete_foreign_chat(self):
        m = types.Message(id=1, peer_id=types.PeerUser(99), from_id=types.PeerUser(99), date=datetime.now(timezone.utc), message='Secret')
        self.c.get_messages = AsyncMock(return_value=[m])
        with self.assertRaises(SafeError):
            await self.adapter.snapshots(self.user, [1])

    async def test_snapshot_and_resolved_service_peer_rejected(self):
        self.c.get_entity = AsyncMock(return_value=types.User(id=777000, first_name='Telegram', access_hash=1))
        with self.assertRaises(SafeError):
            await self.adapter.freeze('@telegram')

    async def test_saved_messages_self_peer_is_supported(self):
        self.c.get_entity = AsyncMock(return_value=types.User(id=42, is_self=True, first_name='Men'))
        ref = await self.adapter.freeze('me')
        self.assertEqual(ref['id'], 42)
        self.assertEqual(ref['kind'], 'user')
        self.assertIsInstance(self.adapter.peer(ref), types.InputPeerSelf)

    async def test_floodwait_translated_without_sending_twice(self):
        self.c.send_message.side_effect = FloodWaitError(request=None, capture=7)
        with self.assertRaises(WaitRequired) as result:
            await self.adapter.perform('send_message', self.bundle({'text': 'X'}))
        self.assertEqual(result.exception.seconds, 7)
        self.assertEqual(self.c.send_message.await_count, 1)

    async def test_kick_partial_exception_never_treated_as_safe_retry(self):
        from write_adapter import OutcomeUnknown
        self.c.kick_participant.side_effect = FloodWaitError(request=None, capture=7)
        with self.assertRaises(OutcomeUnknown) as result:
            await self.adapter.perform('remove_member', self.bundle({}))
        self.assertEqual(result.exception.seconds, 7)

    async def test_existing_ban_is_not_silently_removed(self):
        async def response(req):
            return SimpleNamespace(participant=types.ChannelParticipantLeft(types.PeerUser(42)))
        class ReplyClient:
            async def __call__(self, req):
                return await response(req)
        self.adapter.client = ReplyClient()
        with self.assertRaises(SafeError):
            await self.adapter.member_present(self.channel, self.user)

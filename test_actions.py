import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from action_service import ActionService
from actions import SPECS, public_details, validate, read_outbox
from core import Core
from queue_store import QueueStore
from security import SafeError, user_path
from storage import Store
from telegram_adapter import WaitRequired
from test_core import FakeAdapter, FakePool
from write_adapter import OutcomeUnknown


class FakeWrites:
    def __init__(self):
        self.calls = []
        self.revision = 'original'
        self.failure = None
        self.on_perform = None
        self.alias_id = 42

    async def freeze(self, value):
        value = self.alias_id if value == '@alias' else int(value)
        if value == 777000:
            raise SafeError('Xizmat chati yopiq.')
        return {'id': value, 'raw_id': abs(value), 'kind': 'user' if value > 0 else 'chat', 'access_hash': 123, 'label': 'Sinov'}

    async def snapshots(self, ref, ids):
        return [{'id': mid, 'digest': self.revision, 'preview': 'Xabar namunasi'} for mid in ids]

    async def member_present(self, chat, user):
        pass

    async def invite_preview(self, invite_hash):
        return 'Taklifdagi chat'

    async def perform(self, name, bundle, step=0, file_bytes=None):
        self.calls.append((name, bundle, step, file_bytes))
        if self.on_perform:
            self.on_perform()
        if self.failure:
            exc, self.failure = self.failure, None
            raise exc
        return {'message_ids': [100 + step]}


class ActionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'p' * 43)
        self.a, self.ta = self.store.create_user('PIN123', 101)
        self.b, self.tb = self.store.create_user('PIN456', 102)
        self.core = Core(self.store, FakePool({self.a: FakeAdapter(101), self.b: FakeAdapter(102)}), self.root)
        self.writer = FakeWrites()
        self.service = ActionService(self.core, lambda _: self.writer)
        self.core.actions = self.service
        self.q = self.service.queue
        self.now = 1000.0
        self.q.clock = lambda: self.now

        async def virtual_sleep(seconds):
            self.now += max(seconds, 0.01)
            await asyncio.sleep(0)
        self.service.sleep = virtual_sleep

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    async def enqueue(self, name='send_message', p=None, uid=None):
        result = await self.core.call(uid or self.a, name, p or {'chat': 42, 'text': 'Aniq matn **bold**'})
        self.assertTrue(result['ok'], result)
        return result['id']

    def approve(self, action_id, uid=None, bulk=False):
        uid = uid or self.a
        row = self.q.get(uid, action_id)
        self.q.decide(uid, action_id, row['digest'], True, bulk)

    async def test_proposal_does_not_send(self):
        action_id = await self.enqueue()
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'pending')
        self.assertEqual(self.writer.calls, [])

    async def test_executor_cannot_run_pending(self):
        action_id = await self.enqueue()
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'pending')

    async def test_approve_executes_exact_text_once(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        await self.service.execute_one(self.a, action_id)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(len(self.writer.calls), 1)
        self.assertEqual(self.writer.calls[0][1]['params']['text'], 'Aniq matn **bold**')
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'done')

    async def test_concurrent_executors_only_one_sends(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        await asyncio.gather(self.service.execute_one(self.a, action_id), self.service.execute_one(self.a, action_id))
        self.assertEqual(len(self.writer.calls), 1)

    async def test_rejected_never_executes(self):
        action_id = await self.enqueue()
        row = self.q.get(self.a, action_id)
        self.q.decide(self.a, action_id, row['digest'], False)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'rejected')

    async def test_expires_at_exact_ten_minutes(self):
        action_id = await self.enqueue()
        self.now += 600
        with self.assertRaises(SafeError):
            self.approve(action_id)
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'expired')

    async def test_approval_before_deadline_not_expired_later(self):
        action_id = await self.enqueue()
        self.now += 599
        self.approve(action_id)
        self.now += 1000
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'done')

    async def test_bulk_requires_separate_confirmation(self):
        action_id = await self.enqueue('delete_messages', {'chat': 42, 'message_ids': list(range(1, 12))})
        with self.assertRaises(SafeError):
            self.approve(action_id)
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'pending')
        self.approve(action_id, bulk=True)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls[0][0], 'delete_messages')

    async def test_ten_messages_not_bulk_eleven_are(self):
        a = await self.enqueue('delete_messages', {'chat': 42, 'message_ids': list(range(1, 11))})
        b = await self.enqueue('delete_messages', {'chat': 42, 'message_ids': list(range(1, 12))})
        self.assertFalse(self.q.get(self.a, a)['bulk'])
        self.assertTrue(self.q.get(self.a, b)['bulk'])

    async def test_bulk_group_creation(self):
        action_id = await self.enqueue('create_group', {'title': 'Guruh', 'users': list(range(1, 12))})
        self.assertTrue(self.q.get(self.a, action_id)['bulk'])

    async def test_preview_uses_exact_saved_params_not_ai_description(self):
        action_id = await self.enqueue()
        info = public_details(self.q.get(self.a, action_id))
        self.assertEqual(info['parametrlar']['text'], 'Aniq matn **bold**')
        result = await self.core.call(self.a, 'send_message', {'chat': 42, 'text': 'X', 'description': 'zararsiz'})
        self.assertFalse(result['ok'])

    async def test_tamper_between_display_and_approval(self):
        action_id = await self.enqueue()
        row = self.q.get(self.a, action_id)
        with self.store.db:
            self.store.db.execute('UPDATE actions SET payload=? WHERE user_id=? AND id=?', ('{}', self.a, action_id))
        with self.assertRaises(SafeError):
            self.q.decide(self.a, action_id, row['digest'], True)
        self.assertEqual(self.writer.calls, [])

    async def test_tool_change_between_display_and_approval(self):
        action_id = await self.enqueue()
        row = self.q.get(self.a, action_id)
        with self.store.db:
            self.store.db.execute('UPDATE actions SET tool=? WHERE user_id=? AND id=?', ('leave_chat', self.a, action_id))
        with self.assertRaises(SafeError):
            self.q.decide(self.a, action_id, row['digest'], True)

    async def test_tamper_after_approval_fails_closed(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        with self.store.db:
            self.store.db.execute("UPDATE actions SET signature='fake' WHERE user_id=? AND id=?", (self.a, action_id))
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'invalid')

    async def test_foreign_user_cannot_read_action(self):
        action_id = await self.enqueue()
        self.assertFalse((await self.core.call(self.b, 'action_status', {'action_id': action_id}))['ok'])

    async def test_foreign_user_cannot_approve_action(self):
        action_id = await self.enqueue()
        with self.assertRaises(SafeError):
            self.approve(action_id, self.b)

    async def test_foreign_user_cannot_execute_action(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        await self.service.execute_one(self.b, action_id)
        self.assertEqual(self.writer.calls, [])
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'approved')

    async def test_queue_list_isolated(self):
        await self.enqueue()
        self.assertEqual(self.q.list(self.b), [])

    async def test_stop_cancels_pending_and_approved_only_owner(self):
        a = await self.enqueue()
        b = await self.enqueue()
        other = await self.enqueue(uid=self.b)
        self.approve(b)
        self.store.stop(self.a)
        self.assertEqual(self.q.get(self.a, a)['status'], 'cancelled')
        self.assertEqual(self.q.get(self.a, b)['status'], 'cancelled')
        self.assertEqual(self.q.get(self.b, other)['status'], 'pending')
        await self.service.execute_one(self.a, b)
        self.assertEqual(self.writer.calls, [])

    async def test_block_cancels_queue(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        self.store.set_blocked(self.a, True)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])

    async def test_status_does_not_expose_params_or_peer_access_hash(self):
        action_id = await self.enqueue()
        status = await self.core.call(self.a, 'action_status', {'action_id': action_id})
        self.assertNotIn('access_hash', str(status))
        self.assertNotIn('Aniq matn', str(status))

    async def test_frozen_username_not_resolved_again(self):
        action_id = await self.enqueue(p={'chat': '@alias', 'text': 'Salom'})
        self.writer.alias_id = 999
        self.approve(action_id)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls[0][1]['params']['chat'], 42)

    async def test_changed_message_does_not_execute(self):
        action_id = await self.enqueue('edit_message', {'chat': 42, 'message_id': 1, 'text': 'Yangi'})
        self.approve(action_id)
        self.writer.revision = 'edited'
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])

    async def test_file_snapshot_changed_does_not_send(self):
        folder = user_path(self.root / 'outbox', self.a)
        (folder / 'a.txt').write_bytes(b'old')
        action_id = await self.enqueue('send_file', {'chat': 42, 'filename': 'a.txt'})
        self.approve(action_id)
        (folder / 'a.txt').write_bytes(b'new')
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])

    async def test_file_bytes_sent_from_verified_memory(self):
        folder = user_path(self.root / 'outbox', self.a)
        (folder / 'a.txt').write_bytes(b'content')
        action_id = await self.enqueue('send_file', {'chat': 42, 'filename': 'a.txt'})
        self.approve(action_id)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls[0][3], b'content')

    def test_outbox_other_user_path_and_symlink_denied(self):
        folder = user_path(self.root / 'outbox', self.a)
        (folder / 'secret.txt').symlink_to(self.root / 'state.sqlite3')
        for filename in ('../' + self.b + '/x', '/etc/passwd', 'secret.txt'):
            with self.assertRaises(SafeError):
                read_outbox(self.root, self.a, filename)

    async def test_queue_limit_twenty_per_user(self):
        for _ in range(20):
            await self.enqueue()
        self.assertFalse((await self.core.call(self.a, 'send_message', {'chat': 42, 'text': 'x'}))['ok'])
        await self.enqueue(uid=self.b)

    async def test_all_write_specs_have_registered_policy_names(self):
        from security import WRITE_TOOLS
        self.assertEqual(set(SPECS), WRITE_TOOLS)

    async def test_service_chat_denied_for_writes(self):
        for name, params in [('send_message', {'chat': 777000, 'text': 'x'}),
                             ('forward_messages', {'chat': 42, 'from_chat': 777000, 'message_ids': [1]}),
                             ('block', {'user': 777000})]:
            self.assertFalse((await self.core.call(self.a, name, params))['ok'])
        self.assertEqual(self.q.list(self.a), [])

    async def test_worker_restarts_do_not_repeat_inflight_action(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        self.q.claim(self.a, action_id)
        self.q.begin_step(self.a, action_id, 0)
        self.q.recover()
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'uncertain')
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(self.writer.calls, [])

    async def test_ambiguous_network_error_not_retried(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        self.writer.failure = ConnectionError('PRIVATE secret')
        await self.service.execute_one(self.a, action_id)
        await self.service.execute_one(self.a, action_id)
        row = self.q.get(self.a, action_id)
        self.assertEqual(len(self.writer.calls), 1)
        self.assertEqual(row['status'], 'uncertain')
        self.assertNotIn('PRIVATE', row['result'] + str(self.store.events(self.a)))

    async def test_known_floodwait_waits_and_retries(self):
        action_id = await self.enqueue()
        self.approve(action_id)
        self.writer.failure = WaitRequired(0)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(len(self.writer.calls), 2)
        self.assertEqual(self.q.get(self.a, action_id)['status'], 'done')

    async def test_forward_steps_spaced_and_counted(self):
        action_id = await self.enqueue('forward_messages', {'chat': 42, 'from_chat': 43, 'message_ids': [1, 2]})
        self.approve(action_id)
        start = self.now
        await self.service.execute_one(self.a, action_id)
        self.assertGreaterEqual(self.now - start, 2)
        self.assertEqual([x[2] for x in self.writer.calls], [0, 1])
        self.assertEqual(self.q.get(self.a, action_id)['done'], 2)

    async def test_stop_between_forward_steps(self):
        action_id = await self.enqueue('forward_messages', {'chat': 42, 'from_chat': 43, 'message_ids': [1, 2]})
        self.approve(action_id)
        self.writer.on_perform = lambda: self.store.stop(self.a)
        await self.service.execute_one(self.a, action_id)
        self.assertEqual(len(self.writer.calls), 1)
        row = self.q.get(self.a, action_id)
        self.assertEqual(row['status'], 'partial')
        self.assertEqual(row['done'], 1)

    def test_persistent_thirty_per_hour_and_two_second_limits(self):
        for i in range(30):
            self.assertEqual(self.q.reserve_send(self.a, str(i)), 0)
            self.assertGreater(self.q.reserve_send(self.a, 'too-soon'), 0)
            self.now += 2
        self.assertGreater(self.q.reserve_send(self.a, '31'), 3000)
        self.assertEqual(self.q.reserve_send(self.b, 'own'), 0)
        reopened = Store(self.root / 'state.sqlite3', 'p' * 43)
        try:
            q2 = QueueStore(reopened, lambda: self.now)
            self.assertGreater(q2.reserve_send(self.a, 'restart'), 0)
        finally:
            reopened.close()
        self.now = 4600.0
        self.assertEqual(self.q.reserve_send(self.a, 'after-hour'), 0)

    def test_send_completion_time_defines_next_gap(self):
        self.q.reserve_send(self.a, 'upload')
        self.now += 50
        self.q.touch_slot(self.a, 'upload')
        self.assertEqual(self.q.reserve_send(self.a, 'next'), 2)

    def test_validation_rejects_dangerous_or_ambiguous_parameters(self):
        cases = [('delete_messages', {'chat': 42, 'message_ids': [1, 1]}),
                 ('send_message', {'chat': 42, 'text': '😀' * 3000}),
                 ('schedule_message', {'chat': 42, 'text': 'x', 'when': '2026-01-01'}),
                 ('send_poll', {'chat': 42, 'question': 'Q?', 'options': ['x', 'x']}),
                 ('mute', {'chat': 42, 'hours': True}),
                 ('arbitrary_rpc', {})]
        for name, p in cases:
            with self.subTest(name=name), self.assertRaises(SafeError):
                validate(name, p)

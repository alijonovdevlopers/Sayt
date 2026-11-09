"""Haqiqiy HTTP formalar; Telegram faqat soxta mijoz bilan."""
import asyncio
from html import unescape
import json
from pathlib import Path
import re
import tempfile
import time
from types import SimpleNamespace
import unittest

import httpx
from cryptography.fernet import Fernet
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, FloodWaitError

from core import Core
from security import SafeError, Vault, pin_verify
from server import build_app
from storage import Store
from telegram_adapter import ClientPool
from test_core import FakeAdapter
from test_actions import FakeWrites
from web import SESSION, GUEST


def value(html, name):
    match = re.search('name="' + name + '" value="([^"]*)"', html)
    assert match, name
    return unescape(match[1])


class FakeLogin:
    def __init__(self):
        self.calls, self.disconnected = [], False
        self.need_password = False
        self.failure = None
        self.owner = 303
        self.session = SimpleNamespace(save=lambda: 'SECRET-TG-SESSION-303')

    async def connect(self):
        self.calls.append('connect')

    async def disconnect(self):
        self.disconnected = True

    async def send_code_request(self, phone):
        self.calls.append(('send_code', phone))
        if self.failure:
            raise self.failure
        return SimpleNamespace(phone_code_hash='SENSITIVE-CODE-HASH')

    async def sign_in(self, **kwargs):
        self.calls.append(('sign_in', kwargs))
        if self.failure:
            raise self.failure
        if 'code' in kwargs and kwargs['code'] != '12345':
            raise PhoneCodeInvalidError(None)
        if self.need_password and 'password' not in kwargs:
            raise SessionPasswordNeededError(None)
        if 'password' in kwargs and kwargs['password'] != 'MY-2FA-SECRET':
            raise ValueError('MY-2FA-SECRET')

    async def get_me(self):
        return SimpleNamespace(id=self.owner, bot=False, first_name='Yangi', last_name='Foydalanuvchi')


class PanelTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'p' * 43)
        self.a, self.ta = self.store.create_user('PIN123', 101)
        self.b, self.tb = self.store.create_user('PIN456', 102)
        self.vault = Vault(self.root, Fernet.generate_key().decode())
        self.vault.save(self.a, api_id=11, api_hash='a'*32, session='A-SECRET')
        self.vault.save(self.b, api_id=22, api_hash='b'*32, session='B-SECRET')
        self.pool = ClientPool(self.vault, self.store)
        self.pool.clients = {self.a: FakeAdapter(101), self.b: FakeAdapter(102)}
        self.core = Core(self.store, self.pool, self.root)
        self.fake = FakeLogin()
        self.app = build_app(self.core, 'https://example.test', enable_writes=True, vault=self.vault, client_factory=lambda *_: self.fake)
        self.panel, self.web = self.app.panel, self.app.panel.web
        self.web.add_profile(self.a, 11, 'a'*32, 'Alijonov')
        self.web.add_profile(self.b, 22, 'b'*32, 'BOSHQA-FOYDALANUVCHI')
        self.web.bootstrap_admin(self.a)
        self.writer = FakeWrites()
        self.core.actions.adapter_factory = lambda _: self.writer
        self.q = self.core.actions.queue
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url='https://example.test')

    async def asyncTearDown(self):
        await self.panel.registration.close()
        await self.client.aclose()
        self.store.close()
        self.tmp.cleanup()

    def signin(self, uid=None):
        token = self.web.create_session(uid or self.a)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION, token, domain='example.test', path='/')
        return token

    async def post(self, path, data=None, token=None, origin='https://example.test'):
        token = token or self.client.cookies.get(SESSION) or self.client.cookies.get(GUEST)
        fields = {'csrf': self.web.csrf(token), **(data or {})}
        return await self.client.post(path, data=fields, headers={'Origin': origin})

    async def enqueue(self, uid=None, name='send_message', params=None):
        result = await self.core.call(uid or self.a, name, params or {'chat': 42, 'text': 'Aniq matn <script>alert(1)</script> & "sinov"'})
        self.assertTrue(result['ok'], result)
        return self.q.get(uid or self.a, result['id'])

    async def registration_start(self):
        self.client.cookies.clear()
        await self.client.get('/register')
        self.invite = self.web.create_invite(self.a)
        r = await self.post('/register', {'invite': self.invite, 'api_id': '33', 'api_hash': 'c'*32,
            'phone': '+998901234567', 'pin': 'NEWPIN123', 'confirm': 'NEWPIN123'})
        self.assertEqual(r.status_code, 303, r.text)

    async def test_public_navigation_accepts_external_and_null_origins(self):
        for origin in ('https://chatgpt.com', 'null', 'https://other.test'):
            for path in ('/', '/login', '/register'):
                r = await self.client.get(path, headers={'Origin': origin})
                self.assertIn(r.status_code, (200, 303), (path, r.text))
                self.assertNotIn('access-control-allow-origin', r.headers)

    async def test_external_origin_cannot_submit_login_or_stop(self):
        await self.client.get('/login')
        r = await self.post('/login', {'api_id': '11', 'api_hash': 'a'*32,
                                     'pin': 'PIN123'}, origin='https://chatgpt.com')
        self.assertEqual(r.status_code, 403)
        self.assertFalse(self.client.cookies.get(SESSION))
        self.signin()
        r = await self.post('/stop', origin='null')
        self.assertEqual(r.status_code, 403)

    async def test_private_and_mcp_routes_still_reject_foreign_origin(self):
        self.signin()
        for path in ('/settings', '/pending', '/logs', '/mcp/' + self.ta):
            r = await self.client.get(path, headers={'Origin': 'https://chatgpt.com'})
            self.assertEqual(r.status_code, 403)

    async def test_public_navigation_keeps_host_and_https_checks(self):
        r = await self.client.get('/login', headers={'Origin': 'null', 'Host': 'evil.test'})
        self.assertEqual(r.status_code, 421)
        r = await self.client.get('http://example.test/login', headers={'Origin': 'null'})
        self.assertEqual(r.status_code, 400)

    async def test_login_cookie_csrf_headers_and_private_secret_hashing(self):
        r = await self.client.get('/login')
        cookie = r.headers['set-cookie']
        for flag in ('HttpOnly', 'Secure', 'SameSite=strict', 'Path=/'):
            self.assertIn(flag, cookie)
        self.assertIn("frame-ancestors 'none'", r.headers['content-security-policy'])
        r = await self.post('/login', {'api_id': '11', 'api_hash': 'a'*32, 'pin': 'PIN123'})
        self.assertEqual(r.status_code, 303)
        token = self.client.cookies.get(SESSION)
        self.assertEqual(self.web.resolve_session(token)['user_id'], self.a)
        raw = self.store.db.execute('SELECT session_hash FROM web_sessions WHERE user_id=?', (self.a,)).fetchone()[0]
        self.assertNotEqual(raw, token)
        self.assertNotIn('a'*32, r.text)
        self.assertNotIn('PIN123', r.text)

    async def test_login_needs_pin_even_with_valid_api_hash(self):
        await self.client.get('/login')
        r = await self.post('/login', {'api_id': '11', 'api_hash': 'a'*32, 'pin': ''})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.client.cookies.get(SESSION))

    async def test_ip_and_user_lock_after_five_failures(self):
        for _ in range(5):
            with self.assertRaises(SafeError):
                await self.web.login('11', 'a'*32, 'WRONG', '10.0.0.1')
        with self.assertRaisesRegex(SafeError, '15 daqiqa'):
            await self.web.login('11', 'a'*32, 'PIN123', '10.0.0.2')
        with self.assertRaisesRegex(SafeError, '15 daqiqa'):
            await self.web.login('22', 'b'*32, 'PIN456', '10.0.0.1')
        self.assertTrue(await self.web.login('22', 'b'*32, 'PIN456', '10.0.0.3'))
        with self.store.db:
            self.store.db.execute('UPDATE auth_failures SET until=?', (time.time()-1,))
        self.assertTrue(await self.web.login('11', 'a'*32, 'PIN123', '10.0.0.1'))

    async def test_twelve_hour_session_absolute_expiry(self):
        now = self.web.clock()
        self.web.clock = lambda: now
        token = self.signin()
        self.web.clock = lambda: now+43199
        self.assertIsNotNone(self.web.resolve_session(token))
        self.web.clock = lambda: now+43200
        self.assertIsNone(self.web.resolve_session(token))
        self.assertEqual((await self.client.get('/')).status_code, 303)

    async def test_logout_revokes_cookie_and_server_session(self):
        token = self.signin()
        self.assertEqual((await self.post('/logout')).status_code, 303)
        self.assertIsNone(self.web.resolve_session(token))
        self.assertFalse(self.client.cookies.get(SESSION))

    async def test_csrf_missing_wrong_and_other_session_rejected(self):
        self.signin()
        other = self.web.create_session(self.a)
        for csrf in ('', 'wrong', self.web.csrf(other)):
            r = await self.client.post('/settings/stop', data={'csrf': csrf}, headers={'Origin': 'https://example.test'})
            self.assertEqual(r.status_code, 400)
            self.assertFalse(self.store.user(self.a)['stopped'])

    async def test_origin_host_and_https_required(self):
        self.signin()
        for headers in ({}, {'Origin': 'https://evil.test'}):
            r = await self.client.post('/settings/stop', data={'csrf': self.web.csrf(self.client.cookies.get(SESSION))}, headers=headers)
            self.assertIn(r.status_code, (400, 403))
        self.assertEqual((await self.client.get('/', headers={'Host': 'evil.test'})).status_code, 421)
        self.assertEqual((await self.client.get('http://example.test/')).status_code, 400)
        self.assertFalse(self.store.user(self.a)['stopped'])

    async def test_post_only_mutations_and_duplicate_form_fields_rejected(self):
        token = self.signin()
        self.assertEqual((await self.client.get('/settings/stop')).status_code, 404)
        r = await self.client.post('/settings/stop', content='csrf='+self.web.csrf(token)+'&csrf=x',
            headers={'Origin': 'https://example.test', 'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.store.user(self.a)['stopped'])

    async def test_body_size_and_json_rejected(self):
        self.signin()
        self.assertEqual((await self.post('/settings/stop', {'padding': 'x'*33000})).status_code, 400)
        self.assertEqual((await self.client.post('/settings/stop', json={}, headers={'Origin': 'https://example.test'})).status_code, 400)

    async def test_own_exact_parameters_escaped_and_access_hash_hidden(self):
        row = await self.enqueue()
        self.signin()
        r = await self.client.get('/actions/'+row['id'])
        self.assertEqual(r.status_code, 200)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', r.text)
        self.assertNotIn('<script>alert', r.text)
        self.assertNotIn('access_hash', r.text)
        self.assertIn('42', r.text)

    async def test_isolation_foreign_action_page(self):
        row = await self.enqueue(self.b)
        self.signin()
        r = await self.client.get('/actions/'+row['id'])
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('Aniq matn', r.text)

    async def test_isolation_foreign_action_approve_and_reject(self):
        row = await self.enqueue(self.b)
        self.signin()
        for decision in ('approve', 'reject'):
            r = await self.post('/actions/'+row['id']+'/'+decision, {'digest': row['digest']})
            self.assertEqual(r.status_code, 400)
        self.assertEqual(self.q.get(self.b, row['id'])['status'], 'pending')

    async def test_isolation_foreign_pending_list_and_logs(self):
        row = await self.enqueue(self.b)
        self.store.audit(self.b, 'FOREIGN-LOG-MARKER', {}, 'xato', 'B')
        self.signin()
        self.assertNotIn(row['id'], (await self.client.get('/pending?user_id='+self.b)).text)
        self.assertNotIn('FOREIGN-LOG-MARKER', (await self.client.get('/logs?filter=all&user_id='+self.b)).text)

    async def test_isolation_foreign_profile_and_mcp_secret_absent(self):
        self.signin(self.b)
        for path in ('/', '/settings', '/pending', '/logs'):
            r = await self.client.get(path+'?user_id='+self.a)
            self.assertNotIn(self.a, r.text)
            self.assertNotIn(self.ta, r.text)
            self.assertNotIn('A-SECRET', r.text)
        self.assertEqual((await self.client.get('/data/users/'+self.a+'/credentials.enc')).status_code, 404)

    async def test_isolation_other_user_cannot_stop_or_resume(self):
        self.signin(self.b)
        await self.post('/settings/stop', {'user_id': self.a})
        self.assertFalse(self.store.user(self.a)['stopped'])
        self.assertTrue(self.store.user(self.b)['stopped'])
        r = await self.post('/settings/resume', {'user_id': self.a, 'pin': 'PIN123'})
        self.assertEqual(r.status_code, 400)
        self.assertTrue(self.store.user(self.b)['stopped'])

    async def test_isolation_admin_routes_denied_for_regular_user(self):
        self.signin(self.b)
        self.assertEqual((await self.client.get('/admin')).status_code, 400)
        for path in ('/admin/invite', '/admin/user/'+self.a+'/block', '/admin/user/'+self.a+'/delete'):
            self.assertEqual((await self.post(path, {'pin': 'PIN456', 'confirm': self.a})).status_code, 400)
        self.assertFalse(self.store.user(self.a)['blocked'])

    async def test_isolation_pin_change_targets_only_cookie_user(self):
        old = self.signin(self.b)
        second = self.web.create_session(self.b)
        r = await self.post('/settings/pin', {'user_id': self.a, 'current': 'PIN456', 'new': 'NEWPIN', 'confirm': 'NEWPIN'})
        self.assertEqual(r.status_code, 303)
        self.assertTrue(pin_verify('PIN123', self.store.user(self.a)['pin_hash']))
        self.assertTrue(pin_verify('NEWPIN', self.store.user(self.b)['pin_hash']))
        self.assertIsNone(self.web.resolve_session(old))
        self.assertIsNone(self.web.resolve_session(second))
        self.assertIsNotNone(self.web.resolve_session(self.client.cookies.get(SESSION)))

    async def test_approval_then_worker_once_reject_and_repeat_safe(self):
        row = await self.enqueue()
        self.signin()
        route = '/actions/'+row['id']+'/approve'
        self.assertEqual((await self.post(route, {'digest': row['digest']})).status_code, 303)
        self.assertEqual(self.writer.calls, [])
        await self.core.actions.execute_one(self.a, row['id'])
        self.assertEqual(len(self.writer.calls), 1)
        self.assertEqual((await self.post(route, {'digest': row['digest']})).status_code, 400)
        other = await self.enqueue()
        await self.post('/actions/'+other['id']+'/reject', {'digest': other['digest']})
        await self.core.actions.execute_one(self.a, other['id'])
        self.assertEqual(len(self.writer.calls), 1)

    async def test_bulk_requires_second_signed_confirmation(self):
        row = await self.enqueue(name='delete_messages', params={'chat': 42, 'message_ids': list(range(1, 12))})
        self.signin()
        path = '/actions/'+row['id']+'/approve'
        r = await self.post(path, {'digest': row['digest'], 'bulk_confirm': 'yes'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.q.get(self.a, row['id'])['status'], 'pending')
        ticket = value(r.text, 'bulk_ticket')
        r = await self.post(path, {'digest': row['digest'], 'bulk_ticket': ticket})
        self.assertEqual(r.status_code, 400)
        r = await self.post(path, {'digest': row['digest'], 'bulk_ticket': ticket, 'bulk_confirm': 'yes'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.q.get(self.a, row['id'])['status'], 'approved')

    async def test_bulk_ticket_wrong_action_and_expired_denied(self):
        row = await self.enqueue(name='delete_messages', params={'chat': 42, 'message_ids': list(range(1, 12))})
        self.signin()
        now = self.web.clock()
        self.web.clock = lambda: now
        ticket = self.web.bulk_ticket(self.a, row['id'], row['digest'])
        self.web.clock = lambda: now+121
        self.assertFalse(self.web.bulk_valid(self.a, row['id'], row['digest'], ticket))
        self.web.clock = lambda: now
        self.assertFalse(self.web.bulk_valid(self.b, row['id'], row['digest'], ticket))
        self.assertFalse(self.web.bulk_valid(self.a, 'wrong', row['digest'], ticket))

    async def test_modified_payload_and_expired_action_cannot_approve(self):
        self.signin()
        row = await self.enqueue()
        with self.store.db:
            self.store.db.execute("UPDATE actions SET payload='{}' WHERE user_id=? AND id=?", (self.a, row['id']))
        r = await self.post('/actions/'+row['id']+'/approve', {'digest': row['digest']})
        self.assertEqual(r.status_code, 400)
        row = await self.enqueue()
        self.q.clock = lambda: row['expires']+1
        r = await self.post('/actions/'+row['id']+'/approve', {'digest': row['digest']})
        self.assertEqual(r.status_code, 400)

    async def test_stop_cancels_own_pending_read_write_and_resume_pin_only(self):
        row, other = await self.enqueue(), await self.enqueue(self.b)
        self.signin()
        await self.post('/settings/stop')
        self.assertEqual(self.q.get(self.a, row['id'])['status'], 'cancelled')
        self.assertEqual(self.q.get(self.b, other['id'])['status'], 'pending')
        self.assertFalse((await self.core.call(self.a, 'whoami'))['ok'])
        self.assertFalse((await self.core.call(self.a, 'send_message', {'chat': 42, 'text': 'no'}))['ok'])
        self.assertEqual((await self.post('/settings/resume', {'pin': 'wrong'})).status_code, 400)
        self.assertEqual((await self.post('/settings/resume', {'pin': 'PIN123'})).status_code, 303)
        self.assertTrue((await self.core.call(self.a, 'whoami'))['ok'])
        self.assertEqual(self.q.get(self.a, row['id'])['status'], 'cancelled')

    async def test_pin_minimum_confirmation_and_old_pin_required(self):
        self.signin()
        for fields in ({'current':'wrong', 'new':'NEWPIN', 'confirm':'NEWPIN'}, {'current':'PIN123','new':'short','confirm':'short'}, {'current':'PIN123','new':'NEWPIN','confirm':'DIFFERENT'}):
            self.assertEqual((await self.post('/settings/pin', fields)).status_code, 400)
        self.assertTrue(pin_verify('PIN123', self.store.user(self.a)['pin_hash']))

    async def test_mcp_rotation_own_only_one_time_and_pin(self):
        self.signin(self.b)
        self.assertEqual((await self.post('/settings/mcp', {'pin': 'wrong'})).status_code, 400)
        r = await self.post('/settings/mcp', {'pin': 'PIN456', 'user_id': self.a})
        token = re.search('/mcp/([A-Za-z0-9_-]{43})', r.text)[1]
        self.assertEqual(self.store.authenticate(token), self.b)
        self.assertIsNone(self.store.authenticate(self.tb))
        self.assertEqual(self.store.authenticate(self.ta), self.a)
        self.assertNotIn(token, (await self.client.get('/settings')).text)

    async def test_log_filters_and_secrets_redacted(self):
        self.signin()
        self.store.audit(self.a, 'ERRMARK', {'text':'SECRETTEXT', 'api_hash':'a'*32, 'pin':'PIN123'}, 'xato', 'B')
        self.store.audit(self.a, 'GOODMARK', {}, 'tayyor', 'A')
        r = await self.client.get('/logs?filter=error')
        self.assertIn('ERRMARK', r.text)
        self.assertNotIn('GOODMARK', r.text)
        for secret in ('SECRETTEXT', 'a'*32, 'PIN123'):
            self.assertNotIn(secret, r.text)
        r = await self.client.get('/logs?filter=B')
        self.assertIn('ERRMARK', r.text)
        self.assertNotIn('GOODMARK', r.text)

    async def test_admin_invite_one_time_display_and_revoke(self):
        self.signin()
        r = await self.post('/admin/invite')
        code = re.search('id="invite-code">([^<]+)', r.text)[1]
        self.assertNotIn(code, (await self.client.get('/admin')).text)
        invite = self.web.invites(self.a)[0]
        self.assertNotEqual(invite['id'], code)
        await self.post('/admin/revoke', {'invite': invite['id']})
        with self.assertRaises(SafeError):
            self.web.reserve_invite(code, 'test')

    async def test_admin_block_revokes_sessions_tokens_and_pending(self):
        row = await self.enqueue(self.b)
        bt = self.web.create_session(self.b)
        self.signin()
        await self.post('/admin/user/'+self.b+'/block')
        self.assertIsNone(self.web.resolve_session(bt))
        self.assertIsNone(self.store.authenticate(self.tb))
        self.assertEqual(self.q.get(self.b, row['id'])['status'], 'cancelled')
        await self.post('/admin/user/'+self.b+'/unblock')
        self.assertEqual(self.store.authenticate(self.tb), self.b)
        self.assertIsNone(self.web.resolve_session(bt))

    async def test_admin_cannot_delete_or_block_self(self):
        self.signin()
        for action in ('block', 'delete'):
            r = await self.post('/admin/user/'+self.a+'/'+action, {'pin':'PIN123', 'confirm':self.a})
            self.assertEqual(r.status_code, 400)

    async def test_delete_requires_pin_removes_all_owned_data_disconnects_only(self):
        self.pool.clients.pop(self.b)
        self.pool.adopt(self.b, self.fake)
        await self.enqueue(self.b)
        bt = self.web.create_session(self.b)
        for name in ('outbox','downloads'):
            path = self.root / name / self.b
            path.mkdir(parents=True)
            (path/'file.txt').write_text('PRIVATE')
        self.signin()
        path = '/admin/user/'+self.b+'/delete'
        self.assertEqual((await self.post(path, {'pin':'wrong','confirm':self.b})).status_code, 400)
        r = await self.post(path, {'pin':'PIN123','confirm':self.b})
        self.assertEqual(r.status_code, 303, r.text)
        self.assertTrue(self.fake.disconnected)
        self.assertIsNone(self.web.resolve_session(bt))
        self.assertIsNone(self.store.authenticate(self.tb))
        for table in ('users','audit','actions','web_accounts','web_sessions'):
            self.assertIsNone(self.store.db.execute('SELECT 1 FROM '+table+' WHERE user_id=?', (self.b,)).fetchone())
        for name in ('users','outbox','downloads'):
            self.assertFalse((self.root/name/self.b).exists())
        self.assertTrue((self.root/'users'/self.a).exists())
        self.assertFalse((await self.core.call(self.b, 'whoami'))['ok'])

    async def test_delete_waits_for_active_core_operation(self):
        self.pool.clients.pop(self.b)
        self.pool.adopt(self.b, self.fake)
        lock = self.core.locks.setdefault(self.b, asyncio.Lock())
        await lock.acquire()
        task = asyncio.create_task(self.panel.delete_user(self.b))
        await asyncio.sleep(.01)
        self.assertTrue(self.store.user(self.b)['blocked'])
        self.assertFalse(task.done())
        lock.release()
        await task
        self.assertTrue(self.fake.disconnected)

    async def test_bootstrap_admin_only_once(self):
        with self.assertRaises(SafeError):
            self.web.bootstrap_admin(self.b)

    async def test_delete_cancels_running_worker_before_removing_database(self):
        row = await self.enqueue(self.b)
        self.q.decide(self.b, row['id'], row['digest'], True)
        entered = asyncio.Event()
        async def blocked_perform(*args):
            entered.set()
            await asyncio.Event().wait()
        self.writer.perform = blocked_perform
        task = asyncio.create_task(self.core.actions.execute_one(self.b, row['id']))
        self.core.actions.tasks[self.b] = task
        await asyncio.wait_for(entered.wait(), 1)
        self.pool.clients.pop(self.b)
        self.pool.adopt(self.b, self.fake)
        await self.panel.delete_user(self.b)
        self.assertTrue(task.done())
        self.assertTrue(task.cancelled())
        self.assertNotIn(self.b, self.core.actions.tasks)
        self.assertIsNone(self.store.db.execute('SELECT 1 FROM users WHERE user_id=?', (self.b,)).fetchone())

    async def test_all_pages_and_static_assets_valid_forms(self):
        from html.parser import HTMLParser
        class Forms(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms, self.current, self.titles = [], None, 0
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'form':
                    self.current = {'method':attrs.get('method'), 'action':attrs.get('action'), 'csrf':False}
                if tag == 'input' and self.current is not None and attrs.get('name') == 'csrf':
                    self.current['csrf'] = bool(attrs.get('value'))
                if tag == 'h1':
                    self.titles += 1
            def handle_endtag(self, tag):
                if tag == 'form':
                    self.forms.append(self.current)
                    self.current = None
        self.signin()
        row = await self.enqueue()
        for path in ('/', '/pending', '/logs', '/logs?filter=error', '/settings', '/admin', '/admin/delete/'+self.b, '/actions/'+row['id']):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            html = Forms();html.feed(response.text)
            self.assertEqual(html.titles, 1, path)
            for f in html.forms:
                self.assertEqual(f['method'], 'post')
                self.assertTrue(f['csrf'])
                self.assertTrue(f['action'].startswith('/'))
        for name, kind in [('panel.css','text/css'), ('panel.js','application/javascript')]:
            r = await self.client.get('/assets/'+name)
            self.assertEqual(r.status_code, 200)
            self.assertIn(kind, r.headers['content-type'])
        self.assertEqual((await self.client.get('/assets/security.py')).status_code, 404)

    async def test_http_panel_approval_with_real_server_worker_lifecycle(self):
        row = await self.enqueue()
        self.signin()
        async with self.app.downstream.router.lifespan_context(self.app.downstream):
            r = await self.post('/actions/'+row['id']+'/approve', {'digest':row['digest']})
            self.assertEqual(r.status_code, 303)
            for _ in range(100):
                if self.q.get(self.a, row['id'])['status'] == 'done':
                    break
                await asyncio.sleep(.01)
            page = await self.client.get('/actions/'+row['id'])
            self.assertIn('Bajarildi', page.text)
            self.assertEqual(len(self.writer.calls), 1)

    async def test_registration_requires_invite_before_telegram(self):
        await self.client.get('/register')
        r = await self.post('/register', {'invite':'bad','api_id':'33','api_hash':'c'*32,'phone':'+998901234567','pin':'NEWPIN','confirm':'NEWPIN'})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.fake.calls, [])

    async def test_registration_code_encrypted_save_single_shared_client_and_invite_consumption(self):
        await self.registration_start()
        r = await self.post('/register/code', {'value':'12345'})
        self.assertEqual(r.status_code, 200, r.text)
        p = self.web.resolve_session(self.client.cookies.get(SESSION))
        self.assertEqual(p['telegram_id'], 303)
        self.assertFalse(p['is_admin'])
        uid = p['user_id']
        self.assertIs(self.pool.clients[uid].client, self.fake)
        saved = self.vault.load(uid)
        self.assertEqual(saved['session'], 'SECRET-TG-SESSION-303')
        blob = (self.root/'users'/uid/'credentials.enc').read_bytes()
        self.assertNotIn(b'SECRET-TG-SESSION', blob)
        self.assertNotIn(b'c'*32, blob)
        for secret in ('c'*32, 'NEWPIN123', '+998901234567', 'SENSITIVE-CODE-HASH', 'SECRET-TG-SESSION'):
            self.assertNotIn(secret, r.text)
        self.assertEqual(self.web.invites(self.a)[0]['used'], 1)
        with self.assertRaises(SafeError):
            self.web.reserve_invite(self.invite, 'different')
        self.assertEqual(self.panel.registration.flows, {})

    async def test_registration_2fa_and_wrong_secret_not_echoed(self):
        self.fake.need_password = True
        await self.registration_start()
        r = await self.post('/register/code', {'value':'12345'})
        self.assertEqual(r.status_code, 303)
        self.assertIn('2FA', (await self.client.get('/register/verify')).text)
        r = await self.post('/register/password', {'value':'WRONG-SECRET'})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('WRONG-SECRET', r.text)
        self.assertNotIn('MY-2FA-SECRET', r.text)
        r = await self.post('/register/password', {'value':'MY-2FA-SECRET'})
        self.assertEqual(r.status_code, 200)
        disk = (self.root/'state.sqlite3').read_bytes()
        self.assertNotIn(b'MY-2FA-SECRET', disk)

    async def test_registration_five_wrong_codes_disconnect_and_rate_limit(self):
        await self.registration_start()
        for _ in range(5):
            self.assertEqual((await self.post('/register/code', {'value':'99999'})).status_code, 400)
        self.assertTrue(self.fake.disconnected)
        self.assertEqual(self.panel.registration.flows, {})
        with self.assertRaisesRegex(SafeError, '15 daqiqa'):
            self.web.rate_check(self.web.rate_keys('127.0.0.1'))

    async def test_registration_expiry_cancel_and_invite_release(self):
        await self.registration_start()
        guest = self.client.cookies.get(GUEST)
        flow = self.panel.registration.state(guest)
        flow['expires'] = self.web.clock()-1
        self.assertEqual((await self.post('/register/code', {'value':'12345'})).status_code, 400)
        await self.post('/register/cancel')
        self.assertTrue(self.fake.disconnected)
        self.assertEqual(self.web.invites(self.a)[0]['reserved_until'], 0)
        self.assertTrue(self.web.reserve_invite(self.invite, 'new'))

    async def test_revoked_invite_during_login_cannot_finish_or_save_credentials(self):
        await self.registration_start()
        self.web.revoke_invite(self.a, self.web.invites(self.a)[0]['id'])
        r = await self.post('/register/code', {'value':'12345'})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.store.db.execute('SELECT 1 FROM users WHERE telegram_id=303').fetchone())
        self.assertEqual(len(list((self.root/'users').iterdir())), 2)
        self.assertTrue(self.fake.disconnected)

    async def test_invite_cannot_be_reserved_twice_and_expires(self):
        code = self.web.create_invite(self.a)
        owner, invite = self.web.reserve_invite(code, 'one')
        with self.assertRaises(SafeError):
            self.web.reserve_invite(code, 'two')
        self.web.release_invite(owner, invite, 'one')
        with self.store.db:
            self.store.db.execute('UPDATE web_invites SET expires=0 WHERE user_id=?', (self.a,))
        with self.assertRaises(SafeError):
            self.web.reserve_invite(code, 'two')

    async def test_duplicate_telegram_identity_rejected_without_overwriting(self):
        await self.registration_start()
        self.fake.owner = 101
        self.assertEqual((await self.post('/register/code', {'value':'12345'})).status_code, 400)
        self.assertEqual(self.vault.load(self.a)['session'], 'A-SECRET')
        self.assertFalse(self.fake is self.pool.clients[self.a])

    async def test_registration_flood_wait_sanitized_and_releases_invite(self):
        self.fake.failure = FloodWaitError(None, capture=20)
        await self.client.get('/register')
        code = self.web.create_invite(self.a)
        r = await self.post('/register', {'invite':code,'api_id':'33','api_hash':'c'*32,'phone':'+998901234567','pin':'NEWPIN','confirm':'NEWPIN'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('20 soniya', r.text)
        self.assertTrue(self.fake.disconnected)
        self.assertEqual(self.web.invites(self.a)[0]['reserved_until'], 0)

    async def test_legacy_profile_index_and_ambiguous_api_requires_uid(self):
        self.web.add_profile(self.b, 11, 'a'*32, 'Ikkinchi')
        with self.assertRaises(SafeError):
            await self.web.login('11', 'a'*32, 'PIN123', 'one')
        session = await self.web.login('11', 'a'*32, 'PIN123', 'one', self.a)
        self.assertEqual(self.web.resolve_session(session)['user_id'], self.a)


if __name__ == '__main__':
    unittest.main(verbosity=2)

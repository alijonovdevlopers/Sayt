"""Instagram: panel sahifalari va MCP vositalari (haqiqiy Gateway/FastMCP, soxta Instagram). Cloud Shell'da ishga tushiriladi."""
import asyncio
import json
from pathlib import Path
import re
import tempfile
import unittest

import httpx
from cryptography.fernet import Fernet

from core import Core
from instagram import IGService
from security import Vault
from server import build_app
from storage import Store
from telegram_adapter import ClientPool
from test_actions import FakeWrites
from test_core import FakeAdapter, FakePool
from test_instagram import FakeGraph, TOKEN, PEER
from test_web import FakeLogin
from web import SESSION

ORIGIN = 'https://example.test'


class InstagramPanelTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'p' * 43)
        self.a, self.ta = self.store.create_user('PIN123', 101)
        self.b, self.tb = self.store.create_user('PIN456', 102)
        self.vault = Vault(self.root, Fernet.generate_key().decode())
        self.vault.save(self.a, api_id=11, api_hash='a' * 32, session='A-SECRET')
        self.vault.save(self.b, api_id=22, api_hash='b' * 32, session='B-SECRET')
        self.pool = ClientPool(self.vault, self.store)
        self.pool.clients = {self.a: FakeAdapter(101), self.b: FakeAdapter(102)}
        self.core = Core(self.store, self.pool, self.root)
        self.graph = FakeGraph()
        self.ig = IGService(self.store, self.vault.fernet, client=self.graph)
        self.app = build_app(self.core, ORIGIN, enable_writes=True, vault=self.vault,
                             client_factory=lambda *_: FakeLogin(), instagram=self.ig)
        self.panel, self.web = self.app.panel, self.app.panel.web
        self.web.add_profile(self.a, 11, 'a' * 32, 'Alijonov')
        self.web.add_profile(self.b, 22, 'b' * 32, 'Boshqa')
        self.web.bootstrap_admin(self.a)
        self.core.actions.adapter_factory = lambda _: FakeWrites()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url=ORIGIN)

    async def asyncTearDown(self):
        await self.panel.registration.close()
        await self.client.aclose()
        self.store.close()
        self.tmp.cleanup()

    def signin(self, uid):
        token = self.web.create_session(uid)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION, token, domain='example.test', path='/')
        return token

    async def post(self, path, data, token):
        return await self.client.post(path, data={'csrf': self.web.csrf(token), **data}, headers={'Origin': ORIGIN})

    async def connect(self, token, uid_pin='PIN123'):
        return await self.post('/instagram/connect', {'token': TOKEN, 'pin': uid_pin}, token)

    def draft(self, text='Salom, bu sinov', uid=None):
        self.ig.draft(uid or self.a, PEER, text)
        return self.ig.drafts(uid or self.a)[-1]

    # ---- sinovlar -----------------------------------------------------------
    async def test_page_needs_login_and_disabled_means_404(self):
        self.client.cookies.clear()
        self.assertEqual((await self.client.get('/instagram')).status_code, 303)
        self.signin(self.a)
        self.assertEqual((await self.client.get('/instagram')).status_code, 200)
        self.panel.instagram = None
        self.assertEqual((await self.client.get('/instagram')).status_code, 404)
        self.assertNotIn('/instagram', (await self.client.get('/settings')).text)

    async def test_settings_links_to_instagram_page(self):
        self.signin(self.a)
        self.assertIn('href="/instagram"', (await self.client.get('/settings')).text)

    async def test_connect_needs_pin_and_valid_token_and_never_shows_token(self):
        token = self.signin(self.a)
        form = await self.client.get('/instagram')
        self.assertIn('Instagram ulash', form.text)
        r = await self.connect(token, 'NOTOGRI')
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.ig.status(self.a))
        r = await self.post('/instagram/connect', {'token': 'qisqa', 'pin': 'PIN123'}, token)
        self.assertEqual(r.status_code, 400)
        r = await self.connect(token)
        self.assertEqual(r.status_code, 303, r.text)
        page = await self.client.get('/instagram')
        self.assertIn('@davlat', page.text)
        self.assertIn('Ulangan', page.text)
        self.assertNotIn(TOKEN, page.text + (await self.client.get('/settings')).text)

    async def test_pending_draft_shows_escaped_exact_text_and_approve_sends_once(self):
        token = self.signin(self.a)
        await self.connect(token)
        draft = self.draft('<script>alert(1)</script> & salom')
        page = (await self.client.get('/instagram')).text
        self.assertIn(PEER, page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt; &amp; salom', page)
        self.assertNotIn('<script>alert', page)
        data = {'draft': draft['id'], 'digest': draft['digest']}
        r = await self.post('/instagram/approve', data, token)
        self.assertEqual(r.status_code, 303, r.text)
        self.assertEqual(self.graph.sent, [('17841400000000001', PEER, '<script>alert(1)</script> & salom')])
        self.assertIn('Yuborildi', (await self.client.get('/instagram')).text)
        r = await self.post('/instagram/approve', data, token)  # ikkinchi marta
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self.graph.sent), 1)

    async def test_approve_rejects_tampered_digest_other_user_and_missing_csrf(self):
        token = self.signin(self.a)
        await self.connect(token)
        draft = self.draft()
        r = await self.post('/instagram/approve', {'draft': draft['id'], 'digest': 'x' * 64}, token)
        self.assertEqual(r.status_code, 400)
        r = await self.client.post('/instagram/approve', data={'draft': draft['id'], 'digest': draft['digest']},
                                   headers={'Origin': ORIGIN})
        self.assertIn(r.status_code, (400, 403))
        r = await self.client.post('/instagram/approve', data={'csrf': self.web.csrf(token), 'draft': draft['id'], 'digest': draft['digest']},
                                   headers={'Origin': 'https://evil.test'})
        self.assertIn(r.status_code, (400, 403))
        token_b = self.signin(self.b)
        r = await self.post('/instagram/approve', {'draft': draft['id'], 'digest': draft['digest']}, token_b)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.graph.sent, [])
        self.assertEqual(len(self.ig.drafts(self.a)), 1)

    async def test_reject_and_failed_send_are_shown(self):
        token = self.signin(self.a)
        await self.connect(token)
        first = self.draft('Rad etiladi')
        r = await self.post('/instagram/reject', {'draft': first['id'], 'digest': first['digest']}, token)
        self.assertEqual(r.status_code, 303)
        self.assertIn('Rad etildi', (await self.client.get('/instagram')).text)
        second = self.draft('Xatoga uchraydi')
        from instagram import InstagramError
        self.graph.fail_send = InstagramError('Instagram javob oynasi (24 soat) yopilgan: odam avval yozishi kerak.')
        r = await self.post('/instagram/approve', {'draft': second['id'], 'digest': second['digest']}, token)
        self.assertEqual(r.status_code, 400)
        self.assertIn('24 soat', r.text)
        page = (await self.client.get('/instagram')).text
        self.assertIn('Xato', page)
        self.assertEqual(self.graph.sent, [])

    async def test_stopped_account_cannot_approve(self):
        token = self.signin(self.a)
        await self.connect(token)
        draft = self.draft()
        self.store.stop(self.a)
        r = await self.post('/instagram/approve', {'draft': draft['id'], 'digest': draft['digest']}, token)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.graph.sent, [])

    async def test_disconnect_needs_pin_and_cancels_pending(self):
        token = self.signin(self.a)
        await self.connect(token)
        self.draft()
        r = await self.post('/instagram/disconnect', {'pin': 'NOTOGRI'}, token)
        self.assertEqual(r.status_code, 400)
        self.assertIsNotNone(self.ig.status(self.a))
        r = await self.post('/instagram/disconnect', {'pin': 'PIN123'}, token)
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.ig.status(self.a))
        self.assertEqual(self.ig.drafts(self.a), [])
        self.assertIn('Instagram ulash', (await self.client.get('/instagram')).text)

    async def test_each_user_has_own_instagram(self):
        token_a = self.signin(self.a)
        await self.connect(token_a)
        token_b = self.signin(self.b)
        page = (await self.client.get('/instagram')).text
        self.assertIn('Instagram ulash', page)
        self.assertNotIn('@davlat', page)
        self.draft('A uchun', self.a)
        self.assertNotIn('A uchun', (await self.client.get('/instagram')).text)

    async def test_account_deletion_forgets_instagram(self):
        token = self.signin(self.a)
        await self.connect(token)
        await self.panel.delete_user(self.a)
        self.assertIsNone(self.ig.status(self.a))


class InstagramMCPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'x' * 43)
        self.a, self.ta = self.store.create_user('PIN_A_123', 1001)
        self.b, self.tb = self.store.create_user('PIN_B_123', 1002)
        self.core = Core(self.store, FakePool({self.a: FakeAdapter(1001), self.b: FakeAdapter(1002)}), self.root)
        self.graph = FakeGraph()
        self.ig = IGService(self.store, Fernet(Fernet.generate_key()), client=self.graph)
        await self.ig.connect(self.a, TOKEN)
        self.app = build_app(self.core, ORIGIN, instagram=self.ig)
        self.started, self.finished = asyncio.Event(), asyncio.Event()

        async def serve_lifespan():
            async with self.app.downstream.router.lifespan_context(self.app.downstream):
                self.started.set()
                await self.finished.wait()

        self.lifespan_task = asyncio.create_task(serve_lifespan())
        await self.started.wait()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url=ORIGIN,
                                        headers={'Accept': 'application/json, text/event-stream',
                                                 'MCP-Protocol-Version': '2025-11-25'})

    async def asyncTearDown(self):
        await self.client.aclose()
        self.finished.set()
        await self.lifespan_task
        self.store.close()
        self.tmp.cleanup()

    async def rpc(self, token, method, params=None):
        return await self.client.post('/mcp/' + token, json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

    def payload(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()['result']
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])

    async def call(self, token, name, arguments):
        return self.payload(await self.rpc(token, 'tools/call', {'name': name, 'arguments': arguments}))

    async def test_tools_are_listed(self):
        tools = (await self.rpc(self.ta, 'tools/list')).json()['result']['tools']
        names = {t['name'] for t in tools}
        self.assertTrue({'ig_conversations', 'ig_messages', 'ig_send_message'} <= names)
        read_only = {t['name']: t['annotations'].get('readOnlyHint') for t in tools}
        self.assertTrue(read_only['ig_conversations'])
        self.assertFalse(read_only['ig_send_message'])

    async def test_read_tools_work_for_connected_user_only(self):
        data = await self.call(self.ta, 'ig_conversations', {'limit': 5})
        self.assertTrue(data['ok'], data)
        self.assertEqual([x['id'] for x in data['data']['items']], ['conv_AAA', 'conv_BBB'])
        data = await self.call(self.ta, 'ig_messages', {'conversation_id': 'conv_AAA', 'limit': 2})
        self.assertEqual([x['kim'] for x in data['data']['items']], ['boshqa', 'men'])
        other = await self.call(self.tb, 'ig_conversations', {})
        self.assertFalse(other['ok'])
        self.assertIn('ulanmagan', other['xato'])

    async def test_send_tool_only_creates_draft(self):
        data = await self.call(self.ta, 'ig_send_message', {'recipient_id': PEER, 'text': 'Salom'})
        self.assertTrue(data['ok'], data)
        self.assertIn('Yuborilmadi', data['navbat'])
        self.assertEqual(self.graph.sent, [])
        self.assertEqual(len(self.ig.drafts(self.a)), 1)
        bad = await self.call(self.ta, 'ig_send_message', {'recipient_id': 'ali', 'text': 'Salom'})
        self.assertFalse(bad['ok'])

    async def test_bad_arguments_give_generic_error(self):
        response = await self.rpc(self.ta, 'tools/call', {'name': 'ig_messages', 'arguments': {'conversation_id': 5, 'limit': 'x'}})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['result'].get('isError'))
        self.assertNotIn(TOKEN, response.text)

    async def test_stop_applies_to_instagram_tools(self):
        self.store.stop(self.a)
        data = await self.call(self.ta, 'ig_conversations', {})
        self.assertFalse(data['ok'])
        self.assertIn('TO‘XTATILGAN', data['xato'])

    async def test_gateway_audit_labels_instagram_tools(self):
        await self.call(self.ta, 'ig_conversations', {})
        rows = [dict(r) for r in self.store.db.execute('SELECT tool,level,status FROM audit WHERE user_id=?', (self.a,))]
        transport = [r for r in rows if r['status'] == 'mcp_chaqiruv']
        self.assertTrue(any(r['tool'] == 'ig_conversations' and r['level'] == 'A' for r in transport), rows)
        self.assertFalse(any(r['tool'] == 'noma_lum_vosita' for r in rows), rows)


if __name__ == '__main__':
    unittest.main()

"""MCP OAuth HTTP sinovlari (haqiqiy Gateway/FastMCP/panel, soxta Telegram). Cloud Shell'da ishga tushiriladi."""
import asyncio
import html
import json
from pathlib import Path
import re
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.fernet import Fernet

from core import Core
from oauth_server import OAuthServer, s256
from security import Vault
from server import build_app
from storage import Store
from telegram_adapter import ClientPool
from test_actions import FakeWrites
from test_core import FakeAdapter, FakePool
from test_web import FakeLogin
from web import SESSION

ORIGIN = 'https://example.test'
CLAUDE = 'https://claude.ai/api/mcp/auth_callback'
VERIFIER = 'v' * 50


def link_in(page, needle):
    for href in re.findall(r'href="([^"]+)"', page):
        href = html.unescape(href)
        if needle in href:
            return href
    raise AssertionError('havola topilmadi: ' + needle)


class OAuthMCPTests(unittest.IsolatedAsyncioTestCase):
    """Gateway: metadata, 401 challenge, Bearer orqali MCP, token oxirgi nuqtalari."""

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'x' * 43)
        self.a, self.ta = self.store.create_user('PIN_A_123', 1001)
        self.b, self.tb = self.store.create_user('PIN_B_123', 1002)
        self.pool = FakePool({self.a: FakeAdapter(1001), self.b: FakeAdapter(1002)})
        self.core = Core(self.store, self.pool, self.root)
        self.oauth = OAuthServer(self.store.db, self.store.pepper, ORIGIN)
        self.app = build_app(self.core, ORIGIN, oauth=self.oauth)
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

    # ---- yordamchilar ----------------------------------------------------
    async def register(self, **extra):
        r = await self.client.post('/oauth/register', json={'client_name': 'Claude', 'redirect_uris': [CLAUDE], **extra})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    async def tokens_for(self, uid):
        client = await self.register()
        req = self.oauth.validate_authorize({'client_id': client['client_id'], 'redirect_uri': CLAUDE, 'response_type': 'code',
                                             'code_challenge': s256(VERIFIER), 'code_challenge_method': 'S256'})
        code = parse_qs(urlparse(self.oauth.approve(req, uid)).query)['code'][0]
        r = await self.client.post('/oauth/token', data={'grant_type': 'authorization_code', 'code': code,
                                                         'client_id': client['client_id'], 'redirect_uri': CLAUDE,
                                                         'code_verifier': VERIFIER})
        self.assertEqual(r.status_code, 200, r.text)
        return client, r.json()

    async def rpc(self, bearer, method='tools/call', params=None):
        headers = {'Authorization': 'Bearer ' + bearer} if bearer else {}
        return await self.client.post('/mcp', headers=headers, json={
            'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {'name': 'whoami', 'arguments': {}}})

    def payload(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()['result']
        self.assertFalse(result.get('isError'), str(result))
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])

    def who(self, response):
        return self.payload(response)['data']['id']

    # ---- sinovlar -----------------------------------------------------------
    async def test_metadata_documents_are_served(self):
        for path in ('/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'):
            r = await self.client.get(path)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['resource'], ORIGIN + '/mcp')
            self.assertEqual(r.json()['authorization_servers'], [ORIGIN])
        r = await self.client.get('/.well-known/oauth-authorization-server')
        meta = r.json()
        self.assertEqual(meta['token_endpoint'], ORIGIN + '/oauth/token')
        self.assertEqual(meta['code_challenge_methods_supported'], ['S256'])

    async def test_mcp_without_token_gets_401_challenge_and_is_not_counted_as_failure(self):
        for _ in range(8):
            r = await self.rpc(None, 'tools/list', {})
            self.assertEqual(r.status_code, 401)
        challenge = r.headers['www-authenticate']
        self.assertIn('resource_metadata="' + ORIGIN + '/.well-known/oauth-protected-resource"', challenge)
        self.assertNotIn('invalid_token', challenge)
        # maxfiy URL hali ham ishlaydi (IP bloklanmagan)
        self.assertEqual(self.who(await self.client.post('/mcp/' + self.ta, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'whoami', 'arguments': {}}})), 1001)

    async def test_invalid_bearer_gets_invalid_token_challenge(self):
        for bad in ('mcpa_' + 'z' * 43, 'garbage', self.ta):
            r = await self.rpc(bad, 'tools/list', {})
            self.assertEqual(r.status_code, 401)
            self.assertIn('error="invalid_token"', r.headers['www-authenticate'])

    async def test_bearer_reaches_the_right_user_only(self):
        _, a = await self.tokens_for(self.a)
        _, b = await self.tokens_for(self.b)
        self.assertEqual(self.who(await self.rpc(a['access_token'])), 1001)
        self.assertEqual(self.who(await self.rpc(b['access_token'])), 1002)

    async def test_refresh_token_is_not_accepted_as_bearer(self):
        _, tokens = await self.tokens_for(self.a)
        self.assertEqual((await self.rpc(tokens['refresh_token'], 'tools/list', {})).status_code, 401)

    async def test_refresh_over_http_rotates_and_old_one_dies(self):
        client, tokens = await self.tokens_for(self.a)
        form = {'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'], 'client_id': client['client_id']}
        r = await self.client.post('/oauth/token', data=form)
        self.assertEqual(r.status_code, 200, r.text)
        new = r.json()
        self.assertEqual(self.who(await self.rpc(new['access_token'])), 1001)
        again = await self.client.post('/oauth/token', data=form)  # eski refresh qayta ishlatildi
        self.assertEqual(again.status_code, 400)
        self.assertEqual(again.json()['error'], 'invalid_grant')
        self.assertEqual((await self.rpc(new['access_token'], 'tools/list', {})).status_code, 401)

    async def test_revoke_endpoint_kills_access(self):
        _, tokens = await self.tokens_for(self.a)
        r = await self.client.post('/oauth/revoke', data={'token': tokens['refresh_token']})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((await self.rpc(tokens['access_token'], 'tools/list', {})).status_code, 401)
        self.assertEqual((await self.client.post('/oauth/revoke', data={'token': 'hech-narsa'})).status_code, 200)

    async def test_emergency_stop_still_applies_to_bearer(self):
        _, a = await self.tokens_for(self.a)
        _, b = await self.tokens_for(self.b)
        self.store.stop(self.a)
        self.assertFalse(self.payload(await self.rpc(a['access_token']))['ok'])
        self.assertTrue(self.payload(await self.rpc(b['access_token']))['ok'])

    async def test_blocked_user_bearer_rejected(self):
        _, tokens = await self.tokens_for(self.a)
        self.store.set_blocked(self.a, True)
        self.assertEqual((await self.rpc(tokens['access_token'], 'tools/list', {})).status_code, 401)

    async def test_register_endpoint_validation(self):
        r = await self.client.post('/oauth/register', json={'redirect_uris': ['https://evil.example/cb']})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()['error'], 'invalid_redirect_uri')
        r = await self.client.post('/oauth/register', content=b'{yomon', headers={'Content-Type': 'application/json'})
        self.assertEqual(r.status_code, 400)
        r = await self.client.post('/oauth/register', data={'redirect_uris': CLAUDE})  # JSON emas
        self.assertEqual(r.status_code, 400)
        self.assertEqual((await self.client.get('/oauth/register')).status_code, 405)

    async def test_token_endpoint_input_validation(self):
        self.assertEqual((await self.client.get('/oauth/token')).status_code, 405)
        r = await self.client.post('/oauth/token', json={'grant_type': 'authorization_code'})
        self.assertEqual(r.status_code, 400)
        r = await self.client.post('/oauth/token', data={'grant_type': 'password', 'username': 'a', 'password': 'b'})
        self.assertEqual(r.json()['error'], 'unsupported_grant_type')
        r = await self.client.post('/oauth/token', content=b'grant_type=refresh_token&grant_type=authorization_code',
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(r.status_code, 400)
        r = await self.client.post('/oauth/token', content=b'x=' + b'a' * 20000,
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(r.status_code, 413)
        r = await self.client.post('/oauth/token', data={'grant_type': 'authorization_code', 'code': 'x',
                                                         'code_verifier': 'v' * 50, 'client_id': 'yoq', 'redirect_uri': CLAUDE})
        self.assertEqual(r.json()['error'], 'invalid_grant')
        self.assertEqual(r.headers['cache-control'], 'no-store')

    async def test_secret_url_still_works_when_oauth_enabled(self):
        r = await self.client.post('/mcp/' + self.tb, json={
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'whoami', 'arguments': {}}})
        self.assertEqual(self.who(r), 1002)
        self.assertEqual((await self.client.post('/mcp/' + 'A' * 43, json={})).status_code, 404)


class OAuthPanelTests(unittest.IsolatedAsyncioTestCase):
    """Panel: ruxsat sahifasi, cross-site oraliq sahifa, sozlamalarda ulangan ilovalar."""

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
        self.oauth = OAuthServer(self.store.db, self.store.pepper, ORIGIN)
        self.app = build_app(self.core, ORIGIN, enable_writes=True, vault=self.vault,
                             client_factory=lambda *_: FakeLogin(), oauth=self.oauth)
        self.panel, self.web = self.app.panel, self.app.panel.web
        self.web.add_profile(self.a, 11, 'a' * 32, 'Alijonov')
        self.web.add_profile(self.b, 22, 'b' * 32, 'Boshqa')
        self.web.bootstrap_admin(self.a)
        self.core.actions.adapter_factory = lambda _: FakeWrites()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url=ORIGIN)
        self.registered = self.oauth.register({'client_name': 'Claude', 'redirect_uris': [CLAUDE]})

    async def asyncTearDown(self):
        await self.panel.registration.close()
        await self.client.aclose()
        self.store.close()
        self.tmp.cleanup()

    def params(self, **over):
        q = {'client_id': self.registered['client_id'], 'redirect_uri': CLAUDE, 'response_type': 'code',
             'code_challenge': s256(VERIFIER), 'code_challenge_method': 'S256', 'state': 'ST1', 'resource': ORIGIN + '/mcp'}
        q.update(over)
        return q

    def signin(self, uid):
        token = self.web.create_session(uid)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION, token, domain='example.test', path='/')
        return token

    async def post(self, path, data, token):
        return await self.client.post(path, data={'csrf': self.web.csrf(token), **data}, headers={'Origin': ORIGIN})

    async def approve(self, token, decision='approve', **over):
        return await self.post('/oauth/authorize', {**self.params(**over), 'decision': decision}, token)

    async def test_cross_site_navigation_shows_click_through_even_when_signed_in(self):
        self.signin(self.a)
        r = await self.client.get('/oauth/authorize', params=self.params(), headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn('Davom etish', r.text)
        self.assertIn('Claude', r.text)
        self.assertNotIn('Ruxsat berish', r.text)
        self.assertIn('client_id=', link_in(r.text, '/oauth/authorize?'))

    async def test_same_site_without_session_goes_to_login(self):
        self.client.cookies.clear()
        r = await self.client.get('/oauth/authorize', params=self.params(), headers={'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers['location'], '/login')

    async def test_signed_in_sees_consent_with_account_name(self):
        self.signin(self.a)
        r = await self.client.get('/oauth/authorize', params=self.params(), headers={'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(r.status_code, 200, r.text)
        for text in ('Claude', 'Alijonov', 'Ruxsat berish', 'Rad etish'):
            self.assertIn(text, r.text)

    async def test_invalid_requests_show_error_and_never_redirect(self):
        self.signin(self.a)
        for over in ({'redirect_uri': 'https://evil.example/cb'}, {'client_id': 'yoq'}, {'code_challenge_method': 'plain'},
                     {'response_type': 'token'}, {'resource': 'https://boshqa.app/mcp'}):
            r = await self.client.get('/oauth/authorize', params=self.params(**over), headers={'Sec-Fetch-Site': 'same-origin'})
            self.assertEqual(r.status_code, 400, repr(over))
            self.assertNotIn('location', r.headers)
        r = await self.client.get('/oauth/authorize', params=self.params(redirect_uri='https://evil.example/cb'),
                                  headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(r.status_code, 400)

    async def test_approve_returns_code_link_and_full_token_flow_works(self):
        token = self.signin(self.a)
        r = await self.approve(token)
        self.assertEqual(r.status_code, 200, r.text)
        back = link_in(r.text, CLAUDE)
        query = parse_qs(urlparse(back).query)
        self.assertEqual(query['state'], ['ST1'])
        self.assertEqual(query['iss'], [ORIGIN])
        t = await self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'code': query['code'][0], 'client_id': self.registered['client_id'],
            'redirect_uri': CLAUDE, 'code_verifier': VERIFIER})
        self.assertEqual(t.status_code, 200, t.text)
        self.assertEqual(self.oauth.authenticate(t.json()['access_token']), self.a)

    async def test_deny_returns_error_link(self):
        token = self.signin(self.a)
        r = await self.approve(token, 'deny')
        query = parse_qs(urlparse(link_in(r.text, CLAUDE)).query)
        self.assertEqual(query['error'], ['access_denied'])
        self.assertNotIn('code', query)
        self.assertEqual(self.oauth.grants(self.a), [])

    async def test_post_needs_session_csrf_and_valid_request(self):
        token = self.signin(self.a)
        r = await self.client.post('/oauth/authorize', data={**self.params(), 'decision': 'approve'}, headers={'Origin': ORIGIN})
        self.assertIn(r.status_code, (400, 403))
        self.client.cookies.clear()
        r = await self.post('/oauth/authorize', {**self.params(), 'decision': 'approve'}, token)
        self.assertEqual(r.status_code, 303)  # sessiyasiz: kirishga
        token = self.signin(self.a)
        r = await self.approve(token, redirect_uri='https://evil.example/cb')
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('evil.example', r.headers.get('location', ''))

    async def test_settings_lists_and_revokes_connected_apps_per_user(self):
        token = self.signin(self.a)
        r = await self.approve(token)
        code = parse_qs(urlparse(link_in(r.text, CLAUDE)).query)['code'][0]
        t = (await self.client.post('/oauth/token', data={
            'grant_type': 'authorization_code', 'code': code, 'client_id': self.registered['client_id'],
            'redirect_uri': CLAUDE, 'code_verifier': VERIFIER})).json()
        page = await self.client.get('/settings')
        self.assertIn('Ulangan ilovalar', page.text)
        self.assertIn('Claude', page.text)
        grant = self.oauth.grants(self.a)[0]['id']
        token_b = self.signin(self.b)  # boshqa foydalanuvchi bekor qila olmaydi
        await self.post('/settings/oauth/revoke', {'grant': grant}, token_b)
        self.assertEqual(self.oauth.authenticate(t['access_token']), self.a)
        token = self.signin(self.a)
        r = await self.post('/settings/oauth/revoke', {'grant': grant}, token)
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.oauth.authenticate(t['access_token']))
        self.assertIn('Hozircha ulangan ilova yo‘q', (await self.client.get('/settings')).text)

    async def test_revoke_all_and_account_deletion_revoke_oauth(self):
        for uid in (self.a, self.b):
            req = self.oauth.validate_authorize(self.params())
            code = parse_qs(urlparse(self.oauth.approve(req, uid)).query)['code'][0]
            self.oauth.token({'grant_type': 'authorization_code', 'code': code, 'client_id': self.registered['client_id'],
                              'redirect_uri': CLAUDE, 'code_verifier': VERIFIER})
        token = self.signin(self.a)
        await self.post('/settings/oauth/revoke-all', {}, token)
        self.assertEqual(self.oauth.grants(self.a), [])
        self.assertEqual(len(self.oauth.grants(self.b)), 1)
        await self.panel.delete_user(self.b)
        self.assertEqual(self.oauth.grants(self.b), [])


if __name__ == '__main__':
    unittest.main()

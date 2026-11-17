"""Google bilan kirishning HTTP sinovlari. Google va Telegram soxta; haqiqiy forma/cookie oqimi."""
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.fernet import Fernet

from core import Core
from google_auth import GoogleAuth
from security import Vault
from server import build_app
from storage import Store
from telegram_adapter import ClientPool
from test_actions import FakeWrites
from test_core import FakeAdapter
from test_google_auth import FakeHttp
from test_web import FakeLogin
from web import SESSION, GUEST, GFLOW, GID

ADMIN = 'owner@gmail.com'
ORIGIN = 'https://example.test'


class GoogleWebTests(unittest.IsolatedAsyncioTestCase):
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
        self.fake = FakeLogin()
        self.http = FakeHttp(email=ADMIN, sub='S-OWNER')
        self.google = GoogleAuth(self.store.db, self.store.pepper, client_id='cid', client_secret='SECRET-VALUE',
                                 public_url=ORIGIN, admin_email=ADMIN, http=self.http)
        self.app = build_app(self.core, ORIGIN, enable_writes=True, vault=self.vault,
                             client_factory=lambda *_: self.fake, google=self.google)
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

    # ---- yordamchilar ------------------------------------------------
    async def google_login(self, email=None, sub=None, clear=True):
        if clear:
            self.client.cookies.clear()
        if email:
            self.http.info.update(email=email, sub=sub or 'S-' + email)
        r = await self.client.get('/auth/google')
        self.assertEqual(r.status_code, 303, r.text)
        state = parse_qs(urlparse(r.headers['location']).query)['state'][0]
        return await self.client.get('/auth/google/callback', params={'state': state, 'code': 'code-1234567890'})

    async def post(self, path, data=None, token=None):
        token = token or self.client.cookies.get(SESSION) or self.client.cookies.get(GUEST)
        return await self.client.post(path, data={'csrf': self.web.csrf(token), **(data or {})},
                                      headers={'Origin': ORIGIN})

    def signin(self, uid):
        token = self.web.create_session(uid)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION, token, domain='example.test', path='/')
        return token

    def row(self, email):
        return next((r for r in self.google.listing() if r['email'] == email), None)

    # ---- sinovlar ----------------------------------------------------
    async def test_login_page_has_google_button_and_pin_login_still_works(self):
        r = await self.client.get('/login')
        self.assertIn('href="/auth/google"', r.text)
        r = await self.post('/login', {'api_id': '11', 'api_hash': 'a' * 32, 'pin': 'PIN123'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.web.resolve_session(self.client.cookies.get(SESSION))['user_id'], self.a)

    async def test_google_disabled_hides_button_and_routes(self):
        self.panel.google = None
        self.assertNotIn('/auth/google', (await self.client.get('/login')).text)
        self.assertEqual((await self.client.get('/auth/google')).status_code, 404)
        self.assertEqual((await self.client.get('/auth/google/callback')).status_code, 404)

    async def test_begin_redirects_to_google_with_lax_flow_cookie(self):
        r = await self.client.get('/auth/google')
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers['location'].startswith('https://accounts.google.com/'))
        query = parse_qs(urlparse(r.headers['location']).query)
        self.assertEqual(query['redirect_uri'], [ORIGIN + '/auth/google/callback'])
        self.assertNotIn('SECRET-VALUE', r.headers['location'])
        flow = next(c for c in r.headers.get_list('set-cookie') if c.startswith(GFLOW + '='))
        for flag in ('HttpOnly', 'Secure', 'SameSite=lax', 'Path=/'):
            self.assertIn(flag, flow)

    async def test_owner_email_logs_in_links_admin_and_shows_click_through_page(self):
        r = await self.google_login(ADMIN)
        self.assertEqual(r.status_code, 200, r.text)  # yo‘naltirish emas: Strict cookie zanjirda yo‘qoladi
        self.assertIn('href="/"', r.text)
        session = self.client.cookies.get(SESSION)
        self.assertEqual(self.web.resolve_session(session)['user_id'], self.a)
        self.assertEqual(self.row(ADMIN)['user_id'], self.a)
        cookie = next(c for c in r.headers.get_list('set-cookie') if c.startswith(SESSION + '='))
        self.assertIn('SameSite=strict', cookie)
        self.assertEqual((await self.client.get('/')).status_code, 200)

    async def test_second_google_login_uses_stored_link(self):
        await self.google_login(ADMIN)
        r = await self.google_login(ADMIN)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.web.resolve_session(self.client.cookies.get(SESSION))['user_id'], self.a)

    async def test_stranger_and_bad_callbacks_are_rejected_without_session(self):
        r = await self.google_login('stranger@gmail.com')
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.client.cookies.get(SESSION))
        self.assertIsNone(self.row('stranger@gmail.com'))
        await self.client.get('/auth/google')
        for params in ({'state': 'boshqa', 'code': 'code-1234567890'}, {'error': 'access_denied'}, {}):
            r = await self.client.get('/auth/google/callback', params=params)
            self.assertEqual(r.status_code, 400)
            self.assertFalse(self.client.cookies.get(SESSION))
        self.client.cookies.clear()
        r = await self.client.get('/auth/google/callback', params={'state': 'x', 'code': 'code-1234567890'})
        self.assertEqual(r.status_code, 400)

    async def test_wrong_google_account_for_same_email_rejected(self):
        await self.google_login(ADMIN, sub='S-OWNER')
        r = await self.google_login(ADMIN, sub='BOSHQA-SUB')
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.client.cookies.get(SESSION))

    async def test_allowed_new_user_registers_without_invite_and_gets_linked(self):
        self.google.allow('new@gmail.com', ADMIN)
        r = await self.google_login('new@gmail.com')
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn('href="/register"', r.text)
        self.assertFalse(self.client.cookies.get(SESSION))
        page = await self.client.get('/register')
        self.assertNotIn('name="invite"', page.text)
        self.assertIn('new@gmail.com', page.text)
        r = await self.post('/register', {'api_id': '33', 'api_hash': 'c' * 32, 'phone': '+998901234567',
                                          'pin': 'NEWPIN123', 'confirm': 'NEWPIN123'})
        self.assertEqual(r.status_code, 303, r.text)
        r = await self.post('/register/code', {'value': '12345'})
        self.assertEqual(r.status_code, 200, r.text)
        uid = self.store.db.execute('SELECT user_id FROM users WHERE telegram_id=303').fetchone()[0]
        self.assertEqual(self.row('new@gmail.com')['user_id'], uid)
        # keyingi Google kirishi shu akkauntga olib boradi
        r = await self.google_login('new@gmail.com')
        self.assertEqual(self.web.resolve_session(self.client.cookies.get(SESSION))['user_id'], uid)

    async def test_register_without_google_ticket_still_needs_invite(self):
        self.client.cookies.clear()
        await self.client.get('/register')
        r = await self.post('/register', {'api_id': '33', 'api_hash': 'c' * 32, 'phone': '+998901234567',
                                          'pin': 'NEWPIN123', 'confirm': 'NEWPIN123'})
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.store.db.execute('SELECT 1 FROM users WHERE telegram_id=303').fetchone())

    async def test_removed_email_loses_ticket_and_cannot_register(self):
        self.google.allow('gone@gmail.com', ADMIN)
        await self.google_login('gone@gmail.com')
        self.google.remove('gone@gmail.com')
        page = await self.client.get('/register')
        self.assertIn('name="invite"', page.text)

    async def test_pin_login_links_existing_account_to_google_email(self):
        self.google.allow('bee@gmail.com', ADMIN)
        await self.google_login('bee@gmail.com')
        r = await self.post('/login', {'api_id': '22', 'api_hash': 'b' * 32, 'pin': 'PIN456'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.row('bee@gmail.com')['user_id'], self.b)
        r = await self.google_login('bee@gmail.com')
        self.assertEqual(self.web.resolve_session(self.client.cookies.get(SESSION))['user_id'], self.b)

    async def test_other_email_cannot_be_linked_to_owner_account(self):
        self.google.allow('bee@gmail.com', ADMIN)
        await self.google_login('bee@gmail.com')
        r = await self.post('/login', {'api_id': '11', 'api_hash': 'a' * 32, 'pin': 'PIN123'})
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.row('bee@gmail.com')['user_id'])

    async def test_deleted_account_unlinks_instead_of_breaking_login(self):
        self.google.allow('bee@gmail.com', ADMIN)
        await self.google_login('bee@gmail.com')
        await self.post('/login', {'api_id': '22', 'api_hash': 'b' * 32, 'pin': 'PIN456'})
        await self.panel.delete_user(self.b)
        r = await self.google_login('bee@gmail.com')
        self.assertEqual(r.status_code, 200)
        self.assertIn('href="/register"', r.text)
        self.assertIsNone(self.row('bee@gmail.com')['user_id'])

    async def test_admin_adds_and_removes_emails_non_admin_cannot(self):
        token = self.signin(self.a)
        page = await self.client.get('/admin')
        self.assertIn('Google emaillar', page.text)
        r = await self.post('/admin/email', {'email': 'Ali@Gmail.com'}, token)
        self.assertEqual(r.status_code, 303, r.text)
        self.assertIn('ali@gmail.com', (await self.client.get('/admin')).text)
        r = await self.post('/admin/email', {'email': 'yomon'}, token)
        self.assertEqual(r.status_code, 400)
        r = await self.post('/admin/email/remove', {'email': 'ali@gmail.com'}, token)
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.row('ali@gmail.com'))
        r = await self.post('/admin/email/remove', {'email': ADMIN}, token)
        self.assertEqual(r.status_code, 400)
        token_b = self.signin(self.b)
        r = await self.post('/admin/email', {'email': 'hack@gmail.com'}, token_b)
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.row('hack@gmail.com'))

    async def test_get_cannot_change_emails(self):
        self.signin(self.a)
        self.assertEqual((await self.client.get('/admin/email')).status_code, 404)
        self.assertEqual((await self.client.get('/admin/email/remove')).status_code, 404)

    async def test_secrets_never_reach_pages_or_cookies(self):
        r = await self.google_login(ADMIN)
        blob = r.text + ' '.join(r.headers.get_list('set-cookie'))
        self.assertNotIn('SECRET-VALUE', blob)
        self.assertNotIn('S-OWNER', blob)


if __name__ == '__main__':
    unittest.main()

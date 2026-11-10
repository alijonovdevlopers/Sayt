import os
import unittest
from unittest.mock import patch
import test_web
from security import pin_hash, SafeError
from web import SESSION, ADMIN_SETUP

class OwnerLoginTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_web.PanelTests.asyncSetUp
    asyncTearDown = test_web.PanelTests.asyncTearDown
    post = test_web.PanelTests.post
    signin = test_web.PanelTests.signin

    def settings(self, tg='101', api='11'):
        return patch.dict(os.environ, {'ADMIN_LOGIN_USER':'OwnerTest',
            'ADMIN_PASSWORD_HASH':pin_hash('test-owner-password'),
            'ADMIN_TELEGRAM_ID':tg, 'ADMIN_API_ID':api,
            'INITIAL_OWNER_INVITE_CODE':'b'*43})

    async def login(self, password='test-owner-password'):
        await self.client.get('/login')
        return await self.post('/login', {'username':'OwnerTest','password':password})

    async def test_existing_owner_login_and_admin_access(self):
        with self.settings():
            r = await self.login()
            self.assertEqual(r.status_code,303)
            self.assertEqual(self.web.resolve_session(self.client.cookies.get(SESSION))['user_id'],self.a)
            self.assertEqual((await self.client.get('/admin')).status_code,200)

    async def test_wrong_password_does_not_create_session(self):
        with self.settings():
            self.assertEqual((await self.login('wrong')).status_code,400)
            self.assertFalse(self.client.cookies.get(SESSION))
            self.assertFalse(self.client.cookies.get(ADMIN_SETUP))

    async def test_owner_must_match_configured_identity(self):
        with self.settings(tg='999'):
            self.assertEqual((await self.login()).status_code,400)
            self.assertFalse(self.client.cookies.get(SESSION))

    async def test_rate_limit_is_shared_across_ips_for_owner(self):
        with self.settings():
            for i in range(5):
                await self.login('wrong')
            with self.assertRaises(SafeError):
                self.web.rate_check(self.web.rate_keys('different-ip', credential='configured-owner'))

    async def setup_registration(self, tg):
        with self.store.db:
            self.store.db.execute("DELETE FROM users WHERE user_id!='__system__'")
        self.cfg=self.settings(tg=tg,api='33');self.cfg.start()
        self.addCleanup(self.cfg.stop)
        r=await self.login()
        self.assertEqual(r.status_code,303)
        self.assertEqual(r.headers['location'],'/register')
        self.assertTrue(self.client.cookies.get(ADMIN_SETUP))
        r=await self.client.get('/register')
        self.assertNotIn('name="invite"',r.text)
        r=await self.post('/register', {'api_id':'33','api_hash':'c'*32,
            'phone':'+998901234567','pin':'NEWPIN123','confirm':'NEWPIN123'})
        self.assertEqual(r.status_code,303,r.text)

    async def test_first_owner_verified_id_becomes_admin(self):
        await self.setup_registration('303')
        r=await self.post('/register/code',{'value':'12345'})
        self.assertEqual(r.status_code,200,r.text)
        p=self.web.resolve_session(self.client.cookies.get(SESSION))
        self.assertTrue(p['is_admin'])
        self.assertEqual(p['telegram_id'],303)
        self.assertEqual(p['api_id'],33)

    async def test_wrong_telegram_identity_cannot_claim_admin(self):
        await self.setup_registration('999')
        r=await self.post('/register/code',{'value':'12345'})
        self.assertEqual(r.status_code,400)
        self.assertFalse(self.store.db.execute('SELECT 1 FROM web_accounts').fetchone())
        self.assertFalse(self.client.cookies.get(SESSION))

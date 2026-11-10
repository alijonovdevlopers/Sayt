import os
import unittest
from unittest.mock import patch
import test_web
from owner_password import hash_password
from web import SESSION


class OwnerHardeningTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_web.PanelTests.asyncSetUp
    asyncTearDown = test_web.PanelTests.asyncTearDown
    post = test_web.PanelTests.post

    def env(self, **extra):
        base = {'ADMIN_LOGIN_USER': 'OwnerTest', 'ADMIN_PASSWORD_HASH': hash_password('test-owner-password'),
                'ADMIN_TELEGRAM_ID': '101', 'ADMIN_API_ID': '11', 'INITIAL_OWNER_INVITE_CODE': 'b' * 43}
        base.update(extra)
        return patch.dict(os.environ, base)

    async def test_scrypt_hash_logs_owner_in(self):
        with self.env():
            await self.client.get('/login')
            r = await self.post('/login', {'username': 'OwnerTest', 'password': 'test-owner-password'})
            self.assertEqual(r.status_code, 303)
            self.assertTrue(self.client.cookies.get(SESSION))

    async def test_scrypt_hash_rejects_wrong_password(self):
        with self.env():
            await self.client.get('/login')
            r = await self.post('/login', {'username': 'OwnerTest', 'password': 'wrong-password-1'})
            self.assertEqual(r.status_code, 400)
            self.assertFalse(self.client.cookies.get(SESSION))

    async def test_registration_closed_by_default(self):
        with self.env():
            os.environ.pop('REGISTRATION_ENABLED', None)
            r = await self.client.get('/register')
            self.assertNotEqual(r.status_code, 200)
            self.assertIn('o‘chirilgan', r.text)

    async def test_registration_can_be_enabled_explicitly(self):
        with self.env(REGISTRATION_ENABLED='1'):
            r = await self.client.get('/register')
            self.assertNotIn('o‘chirilgan', r.text)


if __name__ == '__main__':
    unittest.main()

"""Browser form policy and unchanged CSRF/Origin boundaries."""
import unittest
import test_web
from web import SESSION

class FormPolicyTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_web.PanelTests.asyncSetUp
    asyncTearDown = test_web.PanelTests.asyncTearDown
    post = test_web.PanelTests.post

    async def test_form_pages_preserve_same_origin(self):
        for path in ('/login', '/login/telegram', '/register'):
            r = await self.client.get(path)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers['referrer-policy'], 'same-origin')

    async def test_null_origin_post_is_still_denied(self):
        await self.client.get('/login/telegram')
        r = await self.post('/login/telegram', {'api_id':'11','api_hash':'a'*32,'pin':'PIN123'}, origin='null')
        self.assertEqual(r.status_code, 403)
        self.assertFalse(self.client.cookies.get(SESSION))

    async def test_same_origin_form_login_succeeds(self):
        await self.client.get('/login/telegram')
        r = await self.post('/login/telegram', {'api_id':'11','api_hash':'a'*32,'pin':'PIN123'})
        self.assertEqual(r.status_code, 303)
        self.assertTrue(self.client.cookies.get(SESSION))

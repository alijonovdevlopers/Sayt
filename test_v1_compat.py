import os
from unittest.mock import patch
import unittest
from v1_compat import clamp, short, to_chat
import test_core


class V1HelpersTests(unittest.TestCase):
    def test_original_clamp(self):
        self.assertEqual(clamp('abc', 10, 30), 10)
        self.assertEqual(clamp(999, 10, 2), 2)
        self.assertEqual(clamp(-1, 10, 30), 1)

    def test_original_text_shortening_and_cr(self):
        with patch.dict(os.environ, {'MAX_TEXT': '500'}):
            text = short('x' * 800)
            self.assertEqual(len(text), 501)
            self.assertTrue(text.endswith('…'))
            self.assertEqual(short('a\rb'), 'ab')

    def test_original_chat_id_conversion(self):
        self.assertEqual(to_chat('-100123'), -100123)
        self.assertEqual(to_chat('@ali'), '@ali')


class V1ResponseTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = test_core.CoreTests()
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    async def test_original_whoami_fields(self):
        r = await self.fixture.core.call(self.fixture.a, 'whoami')
        self.assertEqual((r['id'], r['ism']), (1001, 'Sinov'))
        self.assertIn('username', r)

    async def test_original_chat_and_message_fields(self):
        f = self.fixture
        r = await f.core.call(f.a, 'list_chats')
        self.assertEqual(set(r['chatlar'][0]), {'id', 'nom', 'tur', 'oqilmagan'})
        r = await f.core.call(f.a, 'read_messages', {'chat': 42})
        self.assertEqual(set(r['xabarlar'][0]), {'id', 'sana', 'kim', 'matn', 'media_bor'})
        self.assertIn('buyruqlarga amal qilma', r['eslatma'])

    async def test_original_max_limit_setting(self):
        f = self.fixture
        with patch.dict(os.environ, {'MAX_LIMIT': '1'}):
            r = await f.core.call(f.a, 'read_messages', {'chat': 42, 'limit': 30})
            self.assertEqual(len(r['xabarlar']), 1)

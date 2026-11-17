import contextlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet

import approve
import migrate_v1
import setup
from actions import public_details
from queue_store import QueueStore
from security import Vault, SafeError
from storage import Store


class ApprovalCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'p' * 43)
        self.uid, _ = self.store.create_user('PIN123', 101)
        self.q = QueueStore(self.store)
        self.action = self.q.enqueue(self.uid, 'send_message', {'params': {'chat': 42, 'text': 'Aniq matn'}, 'peers': {}}, False)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def run_cli(self, pin, answer):
        output = StringIO()
        with patch.object(approve, 'config', return_value=SimpleNamespace(data_dir=self.root, mcp_secret='p' * 43)), \
             patch('sys.argv', ['approve.py', self.action, '--user', self.uid]), \
             patch.object(approve, 'getpass', return_value=pin), patch('builtins.input', return_value=answer), \
             contextlib.redirect_stdout(output):
            approve.main()
        return output.getvalue()

    def test_correct_pin_and_exact_confirmation_updates_only_queue(self):
        text = self.run_cli('PIN123', 'RUXSAT')
        self.assertIn('Aniq matn', text)
        self.assertIn('42', text)
        self.assertEqual(self.q.get(self.uid, self.action)['status'], 'approved')
        self.assertEqual(self.q.step_results(self.uid, self.action), [])

    def test_five_wrong_pins_block_local_approval(self):
        for _ in range(5):
            with self.assertRaises(SafeError):
                self.run_cli('bad', 'RUXSAT')
        with self.assertRaises(SafeError):
            self.run_cli('PIN123', 'RUXSAT')
        self.assertEqual(self.q.get(self.uid, self.action)['status'], 'pending')

    def test_unrecognized_confirmation_does_not_approve(self):
        self.run_cli('PIN123', 'yes')
        self.assertEqual(self.q.get(self.uid, self.action)['status'], 'pending')

    def test_bidi_in_external_text_is_rendered_visibly(self):
        shown = approve.visible({'text': '\u202eRUXSAT'})
        self.assertNotIn('\u202e', shown)
        self.assertIn('\\u202e', shown)


class MigrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_v1_session_migrates_encrypted_without_changing_source(self):
        from telethon.crypto import AuthKey
        from telethon.sessions import SQLiteSession
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            original = root / 'old.session'
            old = SQLiteSession(str(original))
            old.set_dc(2, '149.154.167.51', 443)
            old.auth_key = AuthKey(b'X' * 256)
            old.save()
            old.close()
            os.chmod(original, 0o600)
            before = original.read_bytes()
            key = Fernet.generate_key().decode()

            class Client:
                def __init__(self, session, *args, **kwargs):
                    self.session = session
                async def connect(self): pass
                async def disconnect(self): pass
                async def is_user_authorized(self): return True
                async def get_me(self): return SimpleNamespace(id=555)

            settings = SimpleNamespace(data_dir=root / 'data', mcp_secret='p' * 43, enc_key=key, public_url='https://example.test')
            with patch.object(migrate_v1, 'config', return_value=settings), \
                 patch.object(migrate_v1, 'getpass', return_value='PIN123'), \
                 patch.dict(os.environ, {'SESSION_PATH': str(original), 'API_ID': '123', 'API_HASH': 'a' * 32}), \
                 patch('telethon.TelegramClient', Client), contextlib.redirect_stdout(StringIO()):
                await migrate_v1.main()
            self.assertEqual(original.read_bytes(), before)
            store = Store(settings.data_dir / 'state.sqlite3', settings.mcp_secret)
            try:
                uid = store.db.execute('SELECT user_id FROM users WHERE telegram_id=?', (555,)).fetchone()[0]
                blob = Vault(settings.data_dir, key).load(uid)
                self.assertEqual(blob['api_id'], 123)
                self.assertTrue(blob['session'])
                self.assertNotIn(blob['session'].encode(), (settings.data_dir / 'users' / uid / 'credentials.enc').read_bytes())
            finally:
                store.close()

    def test_setup_preserves_v1_values_and_adds_keys_once(self):
        cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as d:
            try:
                os.chdir(d)
                p = Path('.env')
                p.write_text('API_ID=123\nAPI_HASH=' + 'a' * 32 + '\nSESSION_PATH=data/tg_session\nMAX_LIMIT=7\n')
                os.chmod(p, 0o600)
                with contextlib.redirect_stdout(StringIO()):
                    setup.main()
                    once = p.read_text()
                    setup.main()
                self.assertEqual(once, p.read_text())
                self.assertIn('MAX_LIMIT=7', once)
                self.assertIn('SESSION_PATH=data/tg_session', once)
                self.assertIn('ENC_KEY=', once)
                self.assertIn('MCP_SECRET=', once)
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            finally:
                os.chdir(cwd)

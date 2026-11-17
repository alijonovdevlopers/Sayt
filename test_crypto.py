import tempfile
from pathlib import Path
import unittest
from cryptography.fernet import Fernet
from security import Vault, SafeError


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a, self.b = 'a' * 32, 'b' * 32
        self.vault = Vault(self.root, Fernet.generate_key().decode())

    def tearDown(self):
        self.tmp.cleanup()

    def test_ciphertext_at_rest_permissions_and_user_isolation(self):
        self.vault.save(self.a, api_id=1, api_hash='hash-A-secret', session='session-A-secret')
        self.vault.save(self.b, api_id=2, api_hash='hash-B-secret', session='session-B-secret')
        path = self.root / 'users' / self.a / 'credentials.enc'
        self.assertNotIn(b'session-A-secret', path.read_bytes())
        self.assertNotIn(b'hash-A-secret', path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.vault.load(self.a)['session'], 'session-A-secret')
        self.assertEqual(self.vault.load(self.b)['session'], 'session-B-secret')

    def test_tampering_fails_closed(self):
        self.vault.save(self.a, api_id=1, api_hash='hash', session='session')
        path = self.root / 'users' / self.a / 'credentials.enc'
        path.write_bytes(path.read_bytes()[:-10] + b'corrupted!')
        with self.assertRaises(SafeError):
            self.vault.load(self.a)

    def test_other_users_ciphertext_cannot_be_reassigned(self):
        self.vault.save(self.a, api_id=1, api_hash='a', session='A')
        self.vault.save(self.b, api_id=2, api_hash='b', session='B')
        a = self.root / 'users' / self.a / 'credentials.enc'
        b = self.root / 'users' / self.b / 'credentials.enc'
        a.write_bytes(b.read_bytes())
        with self.assertRaises(SafeError):
            self.vault.load(self.a)

    def test_path_traversal_rejected(self):
        with self.assertRaises(SafeError):
            self.vault.load('../' + self.b)

    def test_wrong_key_fails_closed(self):
        self.vault.save(self.a, api_id=1, api_hash='hash', session='session')
        other = Vault(self.root, Fernet.generate_key().decode())
        with self.assertRaises(SafeError):
            other.load(self.a)

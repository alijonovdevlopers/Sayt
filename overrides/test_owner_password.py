import unittest
from owner_password import hash_password, verify_password, MIN_LENGTH


class OwnerPasswordTests(unittest.TestCase):
    def test_roundtrip(self):
        h = hash_password('correct horse battery')
        self.assertTrue(h.startswith('scrypt$'))
        self.assertTrue(verify_password('correct horse battery', h))

    def test_wrong_password(self):
        h = hash_password('correct horse battery')
        self.assertFalse(verify_password('correct horse batterx', h))
        self.assertFalse(verify_password('', h))

    def test_short_password_refused(self):
        with self.assertRaises(ValueError):
            hash_password('a' * (MIN_LENGTH - 1))
        hash_password('a' * MIN_LENGTH)

    def test_salt_is_random(self):
        self.assertNotEqual(hash_password('same password 123'), hash_password('same password 123'))

    def test_malformed_values_fail_closed(self):
        for bad in ('', 'scrypt$', 'scrypt$1$1$1$a$b', 'scrypt$32768$8$1$!!$@@', None, 5):
            self.assertFalse(verify_password('correct horse battery', bad))
        self.assertFalse(verify_password(None, hash_password('correct horse battery')))

    def test_oversized_cost_rejected(self):
        h = hash_password('correct horse battery').split('$')
        h[1] = str(2 ** 24)
        self.assertFalse(verify_password('correct horse battery', '$'.join(h)))


if __name__ == '__main__':
    unittest.main()

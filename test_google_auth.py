import asyncio
import base64
import hashlib
import json
import sqlite3
import unittest
from urllib.parse import parse_qs, urlparse

import google_auth
from google_auth import GoogleAuth, normalize_email
from security import SafeError

ADMIN = 'davlatbek.skar@gmail.com'


class FakeHttp:
    def __init__(self, email='ali@gmail.com', sub='111', verified=True, fail=None, token='tok'):
        self.info = {'email': email, 'sub': sub, 'email_verified': verified}
        self.fail, self.token, self.posts, self.gets = fail, token, [], []

    async def post_form(self, url, data):
        self.posts.append((url, data))
        if self.fail == 'post':
            raise SafeError('Google kirishni qabul qilmadi. Qayta urining.')
        if self.fail == 'boom':
            raise RuntimeError('ichki xato: client_secret=XYZ')
        return {'access_token': self.token} if self.token else {}

    async def get_json(self, url, access_token):
        self.gets.append((url, access_token))
        return self.info


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def run(coro):
    return asyncio.run(coro)


class GoogleAuthTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        google_auth.schema(self.db)
        self.clock = Clock()
        self.http = FakeHttp()
        self.auth = self.make()

    def make(self, http=None):
        return GoogleAuth(self.db, 'pepper-1', client_id='cid', client_secret='SECRET-VALUE',
                          public_url='https://site.up.railway.app/', admin_email=ADMIN.upper(),
                          clock=self.clock, http=http or self.http)

    def login(self, auth=None):
        auth = auth or self.auth
        url, cookie = auth.begin()
        state = parse_qs(urlparse(url).query)['state'][0]
        return run(auth.finish(cookie, state, 'code-' * 4)), (url, cookie, state)

    # ---- email -----------------------------------------------------
    def test_normalize_email(self):
        self.assertEqual(normalize_email('  Ali@Gmail.COM '), 'ali@gmail.com')
        for bad in ['', 'ali', 'a@b', '@gmail.com', 'a b@gmail.com', 'a@@gmail.com', None, 5, 'x' * 300 + '@a.com']:
            with self.assertRaises(SafeError):
                normalize_email(bad)

    # ---- begin -----------------------------------------------------
    def test_begin_url_has_pkce_state_and_no_secret(self):
        url, cookie = self.auth.begin()
        query = parse_qs(urlparse(url).query)
        self.assertEqual(query['response_type'], ['code'])
        self.assertEqual(query['scope'], ['openid email'])
        self.assertEqual(query['code_challenge_method'], ['S256'])
        self.assertEqual(query['redirect_uri'], ['https://site.up.railway.app/auth/google/callback'])
        flow = json.loads(base64.urlsafe_b64decode(cookie.split('.')[0] + '=='))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(flow['v'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(query['code_challenge'], [challenge])
        self.assertEqual(query['state'], [flow['s']])
        self.assertNotIn('SECRET-VALUE', url + cookie)

    def test_each_begin_is_unique(self):
        self.assertNotEqual(self.auth.begin()[1], self.auth.begin()[1])

    # ---- finish ----------------------------------------------------
    def test_finish_success_sends_verifier_and_secret_server_side(self):
        (email, sub), (url, cookie, state) = self.login()
        self.assertEqual((email, sub), ('ali@gmail.com', '111'))
        post_url, data = self.http.posts[0]
        self.assertEqual(post_url, google_auth.TOKEN_URL)
        self.assertEqual(data['client_secret'], 'SECRET-VALUE')
        flow = json.loads(base64.urlsafe_b64decode(cookie.split('.')[0] + '=='))
        self.assertEqual(data['code_verifier'], flow['v'])
        self.assertEqual(self.http.gets[0], (google_auth.USERINFO_URL, 'tok'))

    def test_state_mismatch_rejected(self):
        url, cookie = self.auth.begin()
        with self.assertRaises(SafeError):
            run(self.auth.finish(cookie, 'boshqa-state', 'code-' * 4))
        self.assertEqual(self.http.posts, [])

    def test_tampered_or_foreign_cookie_rejected(self):
        url, cookie = self.auth.begin()
        state = parse_qs(urlparse(url).query)['state'][0]
        body, sig = cookie.split('.')
        other = json.dumps({'s': state, 'v': 'x', 'e': 9e9}).encode()
        forged = base64.urlsafe_b64encode(other).rstrip(b'=').decode() + '.' + sig
        for bad in [forged, body + '.' + 'a' * len(sig), 'nuqtasiz', '', None, body + '.' + sig + '.x']:
            with self.assertRaises(SafeError):
                run(self.auth.finish(bad, state, 'code-' * 4))
        # boshqa pepper bilan imzolangan cookie
        foreign = GoogleAuth(self.db, 'pepper-2', client_id='c', client_secret='s',
                             public_url='https://x.app', admin_email=ADMIN, clock=self.clock, http=self.http)
        with self.assertRaises(SafeError):
            run(foreign.finish(cookie, state, 'code-' * 4))

    def test_expired_flow_rejected(self):
        url, cookie = self.auth.begin()
        state = parse_qs(urlparse(url).query)['state'][0]
        self.clock.now += google_auth.FLOW_SECONDS + 1
        with self.assertRaises(SafeError):
            run(self.auth.finish(cookie, state, 'code-' * 4))

    def test_bad_code_rejected(self):
        url, cookie = self.auth.begin()
        state = parse_qs(urlparse(url).query)['state'][0]
        for code in [None, '', 'qisqa', 'x' * 3000, 12345]:
            with self.assertRaises(SafeError):
                run(self.auth.finish(cookie, state, code))
        self.assertEqual(self.http.posts, [])

    def test_unverified_email_rejected(self):
        self.http.info['email_verified'] = False
        with self.assertRaises(SafeError):
            self.login()
        self.http.info['email_verified'] = 'true'  # satr emas, aynan True kerak
        with self.assertRaises(SafeError):
            self.login()

    def test_bad_identity_fields_rejected(self):
        for patch in [{'email': None}, {'email': 'notemail'}, {'sub': None}, {'sub': 'a b'}, {'sub': ''}]:
            self.http.info = {'email': 'ali@gmail.com', 'sub': '111', 'email_verified': True, **patch}
            with self.assertRaises(SafeError):
                self.login()

    def test_google_failures_are_safe_messages(self):
        for fail in ['post', 'boom']:
            self.http.fail = fail
            with self.assertRaises(SafeError) as cm:
                self.login()
            self.assertNotIn('SECRET', str(cm.exception))
            self.assertNotIn('XYZ', str(cm.exception))
        self.http.fail, self.http.token = None, None
        with self.assertRaises(SafeError):
            self.login()

    # ---- ruxsat ro‘yxati --------------------------------------------
    def test_admin_email_admitted_case_insensitive_and_flagged(self):
        result = self.auth.admit('Davlatbek.Skar@Gmail.com', 'S1')
        self.assertTrue(result['is_admin'])
        self.assertEqual(result['email'], ADMIN)

    def test_stranger_rejected_listed_admitted_removed_rejected(self):
        with self.assertRaises(SafeError):
            self.auth.admit('ali@gmail.com', 'A1')
        self.auth.allow('Ali@gmail.com', ADMIN)
        result = self.auth.admit('ali@gmail.com', 'A1')
        self.assertFalse(result['is_admin'])
        self.auth.remove('ali@gmail.com')
        with self.assertRaises(SafeError):
            self.auth.admit('ali@gmail.com', 'A1')

    def test_sub_is_bound_on_first_login(self):
        self.auth.allow('ali@gmail.com', ADMIN)
        self.auth.admit('ali@gmail.com', 'A1')
        self.auth.admit('ali@gmail.com', 'A1')
        with self.assertRaises(SafeError):
            self.auth.admit('ali@gmail.com', 'BOSHQA')

    def test_blocked_user_rejected_and_unblocked_again(self):
        self.auth.allow('ali@gmail.com', ADMIN)
        self.auth.set_blocked('ali@gmail.com', True)
        with self.assertRaises(SafeError):
            self.auth.admit('ali@gmail.com', 'A1')
        self.auth.set_blocked('ali@gmail.com', False)
        self.auth.admit('ali@gmail.com', 'A1')

    def test_admin_cannot_be_removed_or_blocked(self):
        self.auth.admit(ADMIN, 'S1')
        with self.assertRaises(SafeError):
            self.auth.remove(ADMIN)
        with self.assertRaises(SafeError):
            self.auth.set_blocked(ADMIN, True)

    def test_user_limit_is_50_including_admin(self):
        self.auth.admit(ADMIN, 'S1')
        for i in range(49):
            self.auth.allow('u%d@gmail.com' % i, ADMIN)
        with self.assertRaises(SafeError):
            self.auth.allow('qoshimcha@gmail.com', ADMIN)
        self.auth.allow('u0@gmail.com', ADMIN)  # mavjud email — chegara tegmaydi
        self.assertEqual(len(self.auth.listing()), 50)

    def test_link_and_listing(self):
        self.auth.allow('ali@gmail.com', ADMIN)
        self.auth.link('ali@gmail.com', 'user-1')
        self.assertEqual(self.auth.admit('ali@gmail.com', 'A1')['user_id'], 'user-1')
        self.assertEqual([r['email'] for r in self.auth.listing()], ['ali@gmail.com'])

    def test_ticket_roundtrip_expiry_tamper_and_removal(self):
        self.auth.allow('ali@gmail.com', ADMIN)
        ticket = self.auth.ticket('ALI@gmail.com')
        self.assertEqual(self.auth.ticket_email(ticket), 'ali@gmail.com')
        body, sig = ticket.split('.')
        for bad in [body + '.' + 'a' * len(sig), 'x', '', None, ticket + '.z']:
            self.assertIsNone(self.auth.ticket_email(bad))
        self.auth.set_blocked('ali@gmail.com', True)
        self.assertIsNone(self.auth.ticket_email(ticket))
        self.auth.set_blocked('ali@gmail.com', False)
        self.assertEqual(self.auth.ticket_email(ticket), 'ali@gmail.com')
        self.auth.remove('ali@gmail.com')
        self.assertIsNone(self.auth.ticket_email(ticket))
        self.auth.allow('ali@gmail.com', ADMIN)
        self.clock.now += google_auth.TICKET_SECONDS + 1
        self.assertIsNone(self.auth.ticket_email(ticket))

    def test_ticket_of_other_pepper_rejected(self):
        self.auth.allow('ali@gmail.com', ADMIN)
        foreign = GoogleAuth(self.db, 'pepper-2', client_id='c', client_secret='s',
                             public_url='https://x.app', admin_email=ADMIN, clock=self.clock, http=self.http)
        self.assertIsNone(self.auth.ticket_email(foreign.ticket('ali@gmail.com')))

    def test_linked_admin_uid_needs_exactly_one_admin(self):
        self.db.executescript('''CREATE TABLE web_accounts(user_id TEXT, api_id INTEGER, credential_hash TEXT,
                              display_name TEXT, is_admin INTEGER);''')
        self.assertIsNone(self.auth.linked_admin_uid())
        self.db.execute("INSERT INTO web_accounts VALUES('u1',1,'h1','A',1)")
        self.assertEqual(self.auth.linked_admin_uid(), 'u1')
        self.db.execute("INSERT INTO web_accounts VALUES('u2',2,'h2','B',1)")
        self.assertIsNone(self.auth.linked_admin_uid())

    def test_bad_admin_email_config_fails_fast(self):
        with self.assertRaises(SafeError):
            GoogleAuth(self.db, 'p', client_id='c', client_secret='s', public_url='https://x',
                       admin_email='', http=self.http)

    def test_full_flow_unlisted_google_user_denied(self):
        self.http.info['email'] = 'begona@gmail.com'
        (email, sub), _ = self.login()
        with self.assertRaises(SafeError):
            self.auth.admit(email, sub)


if __name__ == '__main__':
    unittest.main()

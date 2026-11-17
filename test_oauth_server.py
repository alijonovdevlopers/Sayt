import sqlite3
import unittest
from urllib.parse import parse_qs, urlsplit

import oauth_server
from oauth_server import OAuthError, OAuthServer, s256
from security import SafeError

URL = 'https://site.example.app'
CLAUDE = 'https://claude.ai/api/mcp/auth_callback'
VERIFIER = 'v' * 50


class Clock:
    def __init__(self):
        self.now = 10_000.0

    def __call__(self):
        return self.now


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.executescript('CREATE TABLE users(user_id TEXT PRIMARY KEY, blocked INTEGER NOT NULL DEFAULT 0);'
                              "INSERT INTO users(user_id) VALUES('u1'),('u2');")
        self.clock = Clock()
        self.srv = OAuthServer(self.db, 'pepper', URL + '/', clock=self.clock)

    # ---- yordamchilar ----------------------------------------------
    def register(self, **extra):
        return self.srv.register({'client_name': 'Claude', 'redirect_uris': [CLAUDE], **extra})

    def request(self, client, **over):
        q = {'client_id': client['client_id'], 'redirect_uri': CLAUDE, 'response_type': 'code',
             'code_challenge': s256(VERIFIER), 'code_challenge_method': 'S256', 'state': 'ST', 'resource': URL + '/mcp'}
        q.update(over)
        return self.srv.validate_authorize(q)

    def code_for(self, client, uid='u1'):
        location = self.srv.approve(self.request(client), uid)
        query = parse_qs(urlsplit(location).query)
        self.assertEqual(query['state'], ['ST'])
        self.assertEqual(query['iss'], [URL])
        return query['code'][0]

    def exchange(self, client, issued, **over):
        form = {'grant_type': 'authorization_code', 'code': issued, 'client_id': client['client_id'],
                'redirect_uri': CLAUDE, 'code_verifier': VERIFIER}
        form.update(over)
        return self.srv.token(form)

    def tokens(self, uid='u1'):
        client = self.register()
        return client, self.exchange(client, self.code_for(client, uid))

    # ---- metadata ---------------------------------------------------
    def test_metadata_documents(self):
        resource = self.srv.protected_resource_metadata()
        self.assertEqual(resource['resource'], URL + '/mcp')
        self.assertEqual(resource['authorization_servers'], [URL])
        meta = self.srv.authorization_server_metadata()
        self.assertEqual(meta['issuer'], URL)
        self.assertEqual(meta['code_challenge_methods_supported'], ['S256'])
        self.assertEqual(meta['token_endpoint_auth_methods_supported'], ['none'])
        self.assertEqual(meta['token_endpoint'], URL + '/oauth/token')
        self.assertTrue(meta['authorization_response_iss_parameter_supported'])

    # ---- ro‘yxatdan o‘tkazish -----------------------------------------
    def test_register_ok_returns_public_client_without_secret(self):
        client = self.register()
        self.assertEqual(client['token_endpoint_auth_method'], 'none')
        self.assertNotIn('client_secret', client)
        self.assertEqual(client['redirect_uris'], [CLAUDE])

    def test_register_redirect_allowlist_and_loopback(self):
        good = [CLAUDE, 'https://claude.com/api/mcp/auth_callback', 'http://127.0.0.1:3333/callback',
                'http://localhost:8080/cb', 'http://[::1]:5000/cb']
        for uri in good:
            self.srv.register({'redirect_uris': [uri]})
        bad = ['https://evil.example/cb', 'http://claude.ai/api/mcp/auth_callback', 'http://evil.com:80/cb',
               'https://claude.ai/api/mcp/auth_callback#x', 'http://127.0.0.1:99999/cb', 'javascript:alert(1)',
               'http://user:pw@127.0.0.1:3000/cb', 'http://127.0.0.1:3000', '', 'x' * 600, 5, None,
               'https://claude.ai/api/mcp/auth_callback ', 'http://127.0.0.1:3000/a b']
        for uri in bad:
            with self.assertRaises(OAuthError, msg=repr(uri)) as cm:
                self.srv.register({'redirect_uris': [uri]})
            self.assertEqual(cm.exception.code, 'invalid_redirect_uri')

    def test_register_rejects_bad_bodies(self):
        for body in [None, [], 'x', {}, {'redirect_uris': []}, {'redirect_uris': 'x'},
                     {'redirect_uris': [CLAUDE] * 6}, {'redirect_uris': [CLAUDE], 'grant_types': ['client_credentials']},
                     {'redirect_uris': [CLAUDE], 'grant_types': 'authorization_code'}]:
            with self.assertRaises(OAuthError, msg=repr(body)):
                self.srv.register(body)

    def test_register_name_is_cleaned(self):
        client = self.srv.register({'client_name': 'A\x00B\n' + 'x' * 300, 'redirect_uris': [CLAUDE]})
        self.assertNotIn('\x00', client['client_name'])
        self.assertLessEqual(len(client['client_name']), 100)
        self.assertEqual(self.srv.register({'client_name': 5, 'redirect_uris': [CLAUDE]})['client_name'], 'Noma’lum ilova')

    def test_client_cap_prunes_old_unused_clients_but_not_active_ones(self):
        first = self.register()
        active, _ = self.tokens()  # faol ruxsatli mijoz
        for _ in range(oauth_server.MAX_CLIENTS - 2):
            self.register()
        with self.assertRaises(OAuthError):
            self.register()
        self.clock.now += oauth_server.CLIENT_TTL + 1
        self.register()  # eski, ishlatilmagan mijozlar tozalandi
        with self.assertRaises(OAuthError):
            self.srv.client(first['client_id'])
        self.assertEqual(self.srv.client(active['client_id'])['client_id'], active['client_id'])

    # ---- ruxsat so‘rovi -------------------------------------------------
    def test_authorize_validation_errors(self):
        client = self.register()
        cases = [{'client_id': 'yoq'}, {'client_id': None}, {'redirect_uri': 'https://claude.com/api/mcp/auth_callback'},
                 {'redirect_uri': None}, {'response_type': 'token'}, {'code_challenge_method': 'plain'},
                 {'code_challenge': 'qisqa'}, {'code_challenge': None}, {'resource': 'https://boshqa.app/mcp'},
                 {'state': 's' * 600}]
        for over in cases:
            with self.assertRaises(SafeError, msg=repr(over)):
                self.request(client, **over)

    def test_authorize_without_resource_or_state_is_ok(self):
        client = self.register()
        req = self.request(client, state='')
        del_q = self.srv.validate_authorize({'client_id': client['client_id'], 'redirect_uri': CLAUDE, 'response_type': 'code',
                                             'code_challenge': s256(VERIFIER), 'code_challenge_method': 'S256'})
        self.assertEqual(del_q['state'], '')
        self.assertNotIn('state=', self.srv.approve(req, 'u1'))

    def test_deny_redirects_with_error_and_state(self):
        req = self.request(self.register())
        query = parse_qs(urlsplit(self.srv.deny(req)).query)
        self.assertEqual(query['error'], ['access_denied'])
        self.assertEqual(query['state'], ['ST'])
        self.assertNotIn('code', query)

    def test_redirect_keeps_existing_query_and_drops_fragment(self):
        client = self.srv.register({'redirect_uris': ['http://127.0.0.1:3000/cb?app=1']})
        req = self.srv.validate_authorize({'client_id': client['client_id'], 'redirect_uri': 'http://127.0.0.1:3000/cb?app=1',
                                           'response_type': 'code', 'code_challenge': s256(VERIFIER),
                                           'code_challenge_method': 'S256', 'state': 'a b&c=d'})
        parts = urlsplit(self.srv.approve(req, 'u1'))
        query = parse_qs(parts.query)
        self.assertEqual(query['app'], ['1'])
        self.assertEqual(query['state'], ['a b&c=d'])
        self.assertEqual(parts.fragment, '')

    # ---- kodni almashtirish -------------------------------------------
    def test_full_flow_issues_tokens_bound_to_user(self):
        client, tokens = self.tokens('u2')
        self.assertTrue(tokens['access_token'].startswith('mcpa_'))
        self.assertTrue(tokens['refresh_token'].startswith('mcpr_'))
        self.assertEqual(tokens['token_type'], 'Bearer')
        self.assertEqual(self.srv.authenticate(tokens['access_token']), 'u2')

    def test_tokens_and_codes_are_stored_hashed_only(self):
        client = self.register()
        code = self.code_for(client)
        tokens = self.exchange(client, code)
        dump = repr(list(map(tuple, self.db.execute('SELECT * FROM oauth_tokens')))) + \
            repr(list(map(tuple, self.db.execute('SELECT * FROM oauth_codes'))))
        for secret in (code, tokens['access_token'], tokens['refresh_token'], VERIFIER):
            self.assertNotIn(secret, dump)

    def test_wrong_verifier_redirect_client_rejected_and_code_still_single_use(self):
        client = self.register()
        other = self.register()
        code = self.code_for(client)
        for over in [{'code_verifier': 'w' * 50}, {'code_verifier': 'qisqa'}, {'redirect_uri': 'https://claude.com/api/mcp/auth_callback'},
                     {'client_id': other['client_id']}, {'client_id': 'yoq'}, {'code': 'boshqa'}, {'code': ''}]:
            with self.assertRaises(OAuthError, msg=repr(over)):
                self.exchange(client, code, **over)
        self.assertIn('access_token', self.exchange(client, code))  # noto‘g‘ri urinishlar kodni yoqmadi

    def test_non_ascii_inputs_do_not_crash(self):
        client = self.register()
        code = self.code_for(client)
        with self.assertRaises(OAuthError):
            self.exchange(client, code, client_id='ñandú', redirect_uri='é')
        self.assertIn('access_token', self.exchange(client, code))
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': 'mcpr_é', 'client_id': 'ñ'})

    def test_expired_code_rejected(self):
        client = self.register()
        code = self.code_for(client)
        self.clock.now += oauth_server.CODE_SECONDS + 1
        with self.assertRaises(OAuthError):
            self.exchange(client, code)

    def test_code_reuse_revokes_tokens_from_first_use(self):
        client = self.register()
        code = self.code_for(client)
        tokens = self.exchange(client, code)
        self.assertEqual(self.srv.authenticate(tokens['access_token']), 'u1')
        with self.assertRaises(OAuthError):
            self.exchange(client, code)
        self.assertIsNone(self.srv.authenticate(tokens['access_token']))

    def test_resource_mismatch_and_bad_grant_type(self):
        client = self.register()
        with self.assertRaises(OAuthError) as cm:
            self.exchange(client, self.code_for(client), resource='https://boshqa.app/mcp')
        self.assertEqual(cm.exception.code, 'invalid_target')
        for form in [{}, {'grant_type': 'password'}, {'grant_type': 'client_credentials'}, {'grant_type': None}]:
            with self.assertRaises(OAuthError):
                self.srv.token(form)

    # ---- access token --------------------------------------------------
    def test_access_token_expiry_block_and_garbage(self):
        client, tokens = self.tokens()
        access = tokens['access_token']
        self.assertEqual(self.srv.authenticate(access), 'u1')
        for bad in [None, '', 'x', 5, 'mcpa_' + 'z' * 43, tokens['refresh_token'], 'mcpa_' + 'a' * 500]:
            self.assertIsNone(self.srv.authenticate(bad))
        self.db.execute("UPDATE users SET blocked=1 WHERE user_id='u1'")
        self.assertIsNone(self.srv.authenticate(access))
        self.db.execute("UPDATE users SET blocked=0 WHERE user_id='u1'")
        self.assertEqual(self.srv.authenticate(access), 'u1')
        self.clock.now += oauth_server.ACCESS_SECONDS + 1
        self.assertIsNone(self.srv.authenticate(access))

    def test_deleted_user_loses_access(self):
        client, tokens = self.tokens()
        self.db.execute("DELETE FROM users WHERE user_id='u1'")
        self.assertIsNone(self.srv.authenticate(tokens['access_token']))

    def test_other_users_tokens_are_independent(self):
        _, a = self.tokens('u1')
        _, b = self.tokens('u2')
        self.assertEqual(self.srv.authenticate(a['access_token']), 'u1')
        self.assertEqual(self.srv.authenticate(b['access_token']), 'u2')

    # ---- refresh ---------------------------------------------------------
    def test_refresh_rotates_and_old_refresh_reuse_revokes_everything(self):
        client, first = self.tokens()
        second = self.srv.token({'grant_type': 'refresh_token', 'refresh_token': first['refresh_token'],
                                 'client_id': client['client_id']})
        self.assertNotEqual(first['refresh_token'], second['refresh_token'])
        self.assertEqual(self.srv.authenticate(second['access_token']), 'u1')
        with self.assertRaises(OAuthError):  # eski refresh qayta ishlatildi
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': first['refresh_token'],
                            'client_id': client['client_id']})
        self.assertIsNone(self.srv.authenticate(second['access_token']))
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': second['refresh_token'],
                            'client_id': client['client_id']})

    def test_refresh_needs_same_client_and_unexpired(self):
        client, tokens = self.tokens()
        other = self.register()
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
                            'client_id': other['client_id']})
        self.clock.now += oauth_server.REFRESH_SECONDS + 1
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
                            'client_id': client['client_id']})

    def test_access_token_cannot_be_used_as_refresh(self):
        client, tokens = self.tokens()
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': tokens['access_token'],
                            'client_id': client['client_id']})

    # ---- bekor qilish -----------------------------------------------------
    def test_revoke_token_kills_grant_and_unknown_token_is_silent(self):
        client, tokens = self.tokens()
        self.srv.revoke_token('mcpr_hech-narsa')
        self.srv.revoke_token(None)
        self.assertEqual(self.srv.authenticate(tokens['access_token']), 'u1')
        self.srv.revoke_token(tokens['refresh_token'])
        self.assertIsNone(self.srv.authenticate(tokens['access_token']))
        with self.assertRaises(OAuthError):
            self.srv.token({'grant_type': 'refresh_token', 'refresh_token': tokens['refresh_token'],
                            'client_id': client['client_id']})

    def test_revoke_by_access_token_works_too(self):
        client, tokens = self.tokens()
        self.srv.revoke_token(tokens['access_token'])
        self.assertIsNone(self.srv.authenticate(tokens['access_token']))

    def test_grants_listing_revoke_grant_and_revoke_all_are_per_user(self):
        _, a = self.tokens('u1')
        _, b = self.tokens('u2')
        listing = self.srv.grants('u1')
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]['name'], 'Claude')
        self.srv.revoke_grant('u2', listing[0]['id'])  # boshqa foydalanuvchi bekor qila olmaydi
        self.assertEqual(self.srv.authenticate(a['access_token']), 'u1')
        self.srv.revoke_grant('u1', listing[0]['id'])
        self.assertIsNone(self.srv.authenticate(a['access_token']))
        self.assertEqual(self.srv.grants('u1'), [])
        self.srv.revoke_all('u2')
        self.assertIsNone(self.srv.authenticate(b['access_token']))

    def test_expired_rows_are_pruned_on_exchange(self):
        client = self.register()
        self.code_for(client)
        self.clock.now += 7200
        self.exchange(client, self.code_for(client))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM oauth_codes WHERE used=0').fetchone()[0], 0)

    def test_errors_never_leak_secrets(self):
        client = self.register()
        code = self.code_for(client)
        with self.assertRaises(OAuthError) as cm:
            self.exchange(client, code, code_verifier='w' * 50)
        for secret in (code, VERIFIER, client['client_id']):
            self.assertNotIn(secret, str(cm.exception))


if __name__ == '__main__':
    unittest.main()

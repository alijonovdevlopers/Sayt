import asyncio
import unittest
from unittest.mock import patch

import httpx

from google_auth import Http, TOKEN_ERRORS, TOKEN_URL
from security import SafeError


class GoogleHttpTests(unittest.TestCase):
    def post(self, response):
        transport = httpx.MockTransport(lambda request: response)
        real_client = httpx.AsyncClient
        def factory(**kwargs):
            return real_client(transport=transport, **kwargs)
        with patch('httpx.AsyncClient', side_effect=factory):
            return asyncio.run(Http().post_form(TOKEN_URL, {'code': 'PRIVATE-CODE'}))

    def test_success_still_returns_token(self):
        self.assertEqual(self.post(httpx.Response(200, json={'access_token': 'test-token'})),
                         {'access_token': 'test-token'})

    def test_known_errors_identified_without_leaking_response(self):
        for code in TOKEN_ERRORS:
            with self.subTest(code=code), self.assertLogs('google_auth', level='WARNING') as logs:
                with self.assertRaises(SafeError) as error:
                    self.post(httpx.Response(400, json={
                        'error': code, 'error_description': 'PRIVATE-SECRET PRIVATE-CODE',
                        'access_token': 'PRIVATE-TOKEN'}))
                combined = str(error.exception) + str(logs.output)
                self.assertIn(code, combined)
                self.assertIn('HTTP 400', str(error.exception))
                self.assertNotIn('PRIVATE-', combined)

    def test_untrusted_unknown_and_malformed_errors_are_hidden(self):
        responses = [httpx.Response(502, text='PRIVATE-SECRET'),
                     httpx.Response(400, json={'error': 'PRIVATE-SECRET'}),
                     httpx.Response(400, json={'error': ['PRIVATE-SECRET']}),
                     httpx.Response(400, json=['PRIVATE-SECRET'])]
        for response in responses:
            with self.subTest(response=response), self.assertLogs('google_auth', level='WARNING') as logs:
                with self.assertRaises(SafeError) as error:
                    self.post(response)
                combined = str(error.exception) + str(logs.output)
                self.assertIn('unknown', combined)
                self.assertNotIn('PRIVATE-', combined)


if __name__ == '__main__':
    unittest.main()

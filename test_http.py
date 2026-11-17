"""Haqiqiy FastMCP/Starlette HTTP protokoli, soxta Telegram bilan."""
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
import httpx

from core import Core
from security import READ_TOOLS, SYSTEM
from server import build_app
from storage import Store
from test_core import FakeAdapter, FakePool


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'state.sqlite3', 'x' * 43)
        self.a, self.ta = self.store.create_user('PIN_A_123', 1001)
        self.b, self.tb = self.store.create_user('PIN_B_123', 1002)
        self.pool = FakePool({self.a: FakeAdapter(1001), self.b: FakeAdapter(1002)})
        self.core = Core(self.store, self.pool, self.root)
        self.app = build_app(self.core, 'https://example.test')
        self.started, self.finished = asyncio.Event(), asyncio.Event()

        async def serve_lifespan():
            async with self.app.downstream.router.lifespan_context(self.app.downstream):
                self.started.set()
                await self.finished.wait()

        self.lifespan_task = asyncio.create_task(serve_lifespan())
        await self.started.wait()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='https://example.test',
            headers={'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'})

    async def asyncTearDown(self):
        await self.client.aclose()
        self.finished.set()
        await self.lifespan_task
        self.store.close()
        self.tmp.cleanup()

    async def rpc(self, token, method='tools/call', params=None, **kwargs):
        return await self.client.post('/mcp/' + token,
            json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {'name': 'whoami', 'arguments': {}}}, **kwargs)

    def result(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()['result']
        self.assertFalse(result.get('isError'), str(result))
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])

    async def test_initialize_handshake(self):
        response = await self.rpc(self.ta, 'initialize', {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'Sinov', 'version': '1.0'}})
        self.assertEqual(response.status_code, 200)
        self.assertIn('serverInfo', response.json()['result'])

    async def test_official_mcp_client_end_to_end(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        async with streamable_http_client('https://example.test/mcp/' + self.ta,
                                          http_client=self.client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                self.assertEqual({t.name for t in listed.tools}, READ_TOOLS)
                result = await session.call_tool('whoami', {})
                self.assertFalse(result.isError)
                payload = result.structuredContent or json.loads(result.content[0].text)
                self.assertEqual(payload['data']['id'], 1001)

    async def test_exactly_eight_read_tools_no_identity_parameter(self):
        response = await self.rpc(self.ta, 'tools/list', {})
        names = response.json()['result']['tools']
        self.assertEqual({t['name'] for t in names}, READ_TOOLS)
        for tool in names:
            self.assertNotIn('user_id', tool['inputSchema'].get('properties', {}))

    async def test_http_concurrent_identity_isolation(self):
        rows = await asyncio.gather(*[self.rpc(self.ta if i % 2 == 0 else self.tb) for i in range(12)])
        for i, row in enumerate(rows):
            self.assertEqual(self.result(row)['data']['id'], 1001 if i % 2 == 0 else 1002)

    async def test_foreign_session_header_does_not_change_owner(self):
        row = await self.rpc(self.ta, headers={'Mcp-Session-Id': self.tb})
        self.assertEqual(self.result(row)['data']['id'], 1001)

    async def test_unknown_token_404_and_redacted_log(self):
        token = 'z' * 43
        response = await self.rpc(token)
        self.assertEqual(response.status_code, 404)
        rows = self.store.db.execute('SELECT * FROM audit WHERE user_id=?', (SYSTEM,)).fetchall()
        self.assertTrue(rows)
        self.assertNotIn(token, str([dict(x) for x in rows]))

    async def test_five_bad_attempts_block_ip(self):
        for _ in range(5):
            self.assertEqual((await self.rpc('z' * 43)).status_code, 404)
        self.assertEqual((await self.rpc('z' * 43)).status_code, 429)

    async def test_expired_ip_block_allows_requests_again(self):
        for _ in range(5):
            await self.rpc('z' * 43)
        with self.store.db:
            self.store.db.execute('UPDATE auth_failures SET until=0 WHERE user_id=?', (SYSTEM,))
        self.assertTrue(self.result(await self.rpc(self.ta))['ok'])

    async def test_http_without_https_rejected(self):
        response = await self.client.post('http://example.test/mcp/' + self.ta, json={})
        self.assertEqual(response.status_code, 400)

    async def test_wrong_host_rejected(self):
        self.assertEqual((await self.rpc(self.ta, headers={'Host': 'evil.test'})).status_code, 421)

    async def test_cross_origin_rejected(self):
        self.assertEqual((await self.rpc(self.ta, headers={'Origin': 'https://evil.test'})).status_code, 403)

    async def test_stop_is_per_user_over_http(self):
        self.store.stop(self.a)
        self.assertFalse(self.result(await self.rpc(self.ta))['ok'])
        self.assertTrue(self.result(await self.rpc(self.tb))['ok'])

    async def test_blocked_token_is_404(self):
        self.store.set_blocked(self.a, True)
        self.assertEqual((await self.rpc(self.ta)).status_code, 404)
        self.assertTrue(self.result(await self.rpc(self.tb))['ok'])

    async def test_request_body_limit(self):
        response = await self.client.post('/mcp/' + self.ta, content=b'x' * 65537,
                                          headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 413)

    async def test_error_validation_does_not_expose_secret_argument(self):
        response = await self.rpc(self.ta, params={'name': 'list_chats', 'arguments': {'limit': 'VERY_SECRET'}})
        self.assertEqual(response.status_code, 200)
        # SDK xatolari ham kirish ma’lumotini javobda oshkor qilmasin.
        self.assertNotIn('VERY_SECRET', response.text)

    async def test_write_and_unknown_tool_unavailable(self):
        for name in ('send_message', 'arbitrary_rpc'):
            response = await self.rpc(self.ta, params={'name': name, 'arguments': {}})
            self.assertTrue(response.json()['result']['isError'])
        self.assertEqual(self.pool.calls, [])

    async def test_no_endpoint_for_audit_or_credentials(self):
        for path in ('/users/' + self.b, '/data/state.sqlite3', '/data/users/' + self.b + '/credentials.enc'):
            self.assertEqual((await self.client.get(path)).status_code, 404)

    async def test_no_cache_or_referrer(self):
        response = await self.rpc(self.ta)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.headers['referrer-policy'], 'no-referrer')


if __name__ == '__main__':
    unittest.main(verbosity=2)

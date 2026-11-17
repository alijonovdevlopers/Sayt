import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import tempfile
import unittest
import httpx

from actions import SPECS
from core import Core
from security import READ_TOOLS
from server import build_app
from storage import Store
from test_actions import FakeWrites
from test_core import FakeAdapter, FakePool


class WriteHTTPTests(unittest.IsolatedAsyncioTestCase):
    @asynccontextmanager
    async def running(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(Path(d) / 'state.sqlite3', 'p' * 43)
            a, ta = store.create_user('PIN123', 101)
            b, tb = store.create_user('PIN456', 102)
            core = Core(store, FakePool({a: FakeAdapter(101), b: FakeAdapter(102)}), d)
            app = build_app(core, 'https://example.test', enable_writes=True)
            writer = FakeWrites()
            core.actions.adapter_factory = lambda _: writer
            try:
                async with app.downstream.router.lifespan_context(app.downstream):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://example.test',
                        headers={'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'}) as client:
                        yield client, core, writer, a, ta, b, tb
            finally:
                store.close()

    async def rpc(self, client, token, name, arguments):
        response = await client.post('/mcp/' + token, json={'jsonrpc': '2.0', 'id': 1,
            'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()['result']
        return result, result.get('structuredContent') or json.loads(result['content'][0]['text']) if not result.get('isError') else None

    async def test_http_propose_approve_worker_status_full_flow(self):
        async with self.running() as (client, core, writer, a, ta, b, tb):
            _, result = await self.rpc(client, ta, 'send_message', {'chat': 42, 'text': 'Tasdiq kerak'})
            self.assertEqual(result['status'], 'pending')
            self.assertEqual(writer.calls, [])
            q = core.actions.queue
            row = q.get(a, result['id'])
            q.decide(a, row['id'], row['digest'], True)
            for _ in range(100):
                if q.get(a, row['id'])['status'] == 'done':
                    break
                await asyncio.sleep(0.02)
            _, status = await self.rpc(client, ta, 'action_status', {'action_id': row['id']})
            self.assertEqual(status['status'], 'done')
            self.assertEqual(len(writer.calls), 1)
            _, other = await self.rpc(client, tb, 'action_status', {'action_id': row['id']})
            self.assertFalse(other['ok'])

    async def test_no_remote_approval_tool_and_exact_registry(self):
        async with self.running() as (client, core, writer, a, ta, b, tb):
            response = await client.post('/mcp/' + ta, json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}})
            names = {x['name'] for x in response.json()['result']['tools']}
            self.assertEqual(names, READ_TOOLS | set(SPECS) | {'action_status'})
            for name in ('approve', 'decide', 'execute', 'arbitrary_rpc'):
                result, _ = await self.rpc(client, ta, name, {})
                self.assertTrue(result['isError'])
            self.assertEqual(writer.calls, [])

    async def test_foreign_identity_parameter_cannot_choose_owner(self):
        async with self.running() as (client, core, writer, a, ta, b, tb):
            _, result = await self.rpc(client, ta, 'send_message', {'chat': 42, 'text': 'X', 'user_id': b})
            # SDK ortiqcha parametrni rad etsa ham, tashlab yuborsa ham egasi faqat URLdan.
            if result and result.get('ok'):
                self.assertEqual(core.actions.queue.get(a, result['id'])['user_id'], a)
            self.assertEqual(core.actions.queue.list(b), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)

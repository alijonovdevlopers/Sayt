"""Taklif qilish, tekshirish va server ichidagi tasdiqlangan ishchi."""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
import time

from actions import SEND_TOOLS, SPECS, read_outbox, validate
from queue_store import QueueStore
from security import SafeError
from telegram_adapter import WaitRequired
from write_adapter import OutcomeUnknown, WriteAdapter


class ActionService:
    def __init__(self, core, adapter_factory=WriteAdapter):
        self.core, self.store = core, core.store
        self.queue = QueueStore(self.store)
        self.adapter_factory = adapter_factory
        self.sleep = asyncio.sleep
        self.tasks = {}

    async def prepare(self, uid, name, raw):
        p = validate(name, raw)
        adapter = self.adapter_factory(await self.core.pool.get(uid))
        bundle = {'params': p, 'peers': {}, 'previews': [], 'random_id': secrets.randbits(63)}
        refs = bundle['peers']
        for key in ('chat', 'from_chat', 'user'):
            if key not in p:
                continue
            invite = re.fullmatch(r'https://t\.me/(?:\+|joinchat/)([A-Za-z0-9_-]{8,128})', str(p[key]))
            if name == 'join_chat' and key == 'chat' and invite:
                bundle['invite_hash'] = invite[1]
                bundle['previews'] = [{'taklif_nomi': await adapter.invite_preview(invite[1])}]
                continue
            refs[key] = await adapter.freeze(p[key])
            p[key] = refs[key]['id']
        if 'users' in p:
            refs['users'] = [await adapter.freeze(u) for u in p['users']]
            p['users'] = [u['id'] for u in refs['users']]
            if len(set(p['users'])) != len(p['users']):
                raise SafeError('Bir a’zo ikki marta ko‘rsatilgan.')
        for ref in ([refs['user']] if 'user' in refs else []) + refs.get('users', []):
            if ref['kind'] != 'user':
                raise SafeError('A’zo sifatida faqat foydalanuvchi tanlanadi.')
        if name in ('leave_chat', 'set_title', 'set_about', 'add_member', 'remove_member') and refs['chat']['kind'] not in ('chat', 'channel'):
            raise SafeError('Bu amal guruh yoki kanal uchun.')
        if name == 'join_chat' and 'invite_hash' not in bundle and refs['chat']['kind'] != 'channel':
            raise SafeError('Ochiq kanal/superguruh yoki Telegram taklif havolasini ko‘rsating.')
        ids = p.get('message_ids') or ([p['message_id']] if 'message_id' in p else [p['max_id']] if 'max_id' in p else [])
        if ids:
            ref = refs['from_chat'] if name == 'forward_messages' else refs['chat']
            bundle['previews'] = await adapter.snapshots(ref, ids)
        if name == 'remove_member':
            await adapter.member_present(refs['chat'], refs['user'])
        if name == 'send_file':
            data = read_outbox(self.core.data_dir, uid, p['filename'])
            bundle['file'] = {'filename': p['filename'], 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        self.store.assert_active(uid)
        return bundle

    async def call(self, uid, name, params):
        event = self.store.audit(uid, name, params, 'boshlandi', 'B' if name != 'action_status' else 'A')
        try:
            self.store.assert_active(uid)
            if name == 'action_status':
                if set(params) != {'action_id'} or not isinstance(params['action_id'], str):
                    raise SafeError('Amal ID noto‘g‘ri.')
                row = self.queue.get(uid, params['action_id'])
                result = {'ok': True, 'id': row['id'], 'status': row['status'], 'bajarilgan_qism': row['done'],
                          'result': json.loads(row['result']), 'qadam_natijalari': self.queue.step_results(uid, row['id'])}
            else:
                async with asyncio.timeout(120):
                    async with self.core.locks.setdefault(uid, asyncio.Lock()):
                        await self.core.wait_cooldown(uid)
                        bundle = await self.prepare(uid, name, params)
                        p = bundle['params']
                        bulk = len(p.get('message_ids', [])) > 10 or len(p.get('users', [])) > 10
                        action_id = self.queue.enqueue(uid, name, bundle, bulk)
                result = {'ok': True, 'id': action_id, 'status': 'pending', 'xabar': 'Kutilmoqda. Egasi tasdiqlamaguncha bajarilmaydi.',
                          'ommaviy_tasdiq_kerak': bulk, 'muddati_soniya': 600}
            self.store.finish_event(uid, event, 'tayyor')
            return result
        except WaitRequired as error:
            self.store.cooldown(uid, error.seconds)
            self.store.finish_event(uid, event, 'flood_kutilmoqda')
            return {'ok': False, 'xato': 'Telegram kutishni so‘radi. Keyinroq qayta urining.', 'seconds': error.seconds}
        except SafeError as error:
            self.store.finish_event(uid, event, 'rad')
            return {'ok': False, 'xato': str(error)}
        except Exception:
            self.store.finish_event(uid, event, 'xato')
            return {'ok': False, 'xato': 'Amal navbatga qo‘shilmadi; parametrlar va ruxsatlarni tekshiring.'}

    async def check_unchanged(self, uid, adapter, row, bundle, step):
        p, refs, name = bundle['params'], bundle['peers'], row['tool']
        self.store.assert_active(uid)
        if bundle['previews'] and 'invite_hash' not in bundle:
            previous = bundle['previews']
            if name == 'forward_messages':
                previous = [previous[step]]
            ref = refs['from_chat'] if name == 'forward_messages' else refs['chat']
            current = await adapter.snapshots(ref, [s['id'] for s in previous])
            if [(x['id'], x['digest']) for x in current] != [(x['id'], x['digest']) for x in previous]:
                raise SafeError('Tasdiqlangan xabar o‘zgargan. Yangi amal taklif qiling.')
        if name == 'remove_member':
            await adapter.member_present(refs['chat'], refs['user'])
        if name == 'schedule_message' and (datetime.fromisoformat(p['when']) - datetime.now(timezone.utc)).total_seconds() < 60:
            raise SafeError('Rejalashtirilgan vaqt juda yaqin yoki o‘tgan; kamida 1 daqiqa qolsin.')
        if name == 'send_file':
            data = read_outbox(self.core.data_dir, uid, p['filename'])
            if hashlib.sha256(data).hexdigest() != bundle['file']['sha256']:
                raise SafeError('Tasdiqlangan fayl o‘zgargan. Yangi amal taklif qiling.')
            return data

    async def execute_one(self, uid, action_id):
        async with self.core.locks.setdefault(uid, asyncio.Lock()):
            try:
                row = self.queue.claim(uid, action_id)
            except SafeError:
                self.queue.invalidate(uid, action_id)
                return
            bundle = json.loads(row['payload'])
            name = row['tool']
            total = len(bundle['params']['message_ids']) if name == 'forward_messages' else 1
            entered = False
            event = self.store.audit(uid, name, {}, 'bajarilmoqda', 'B')
            try:
                for attempt in range(3):
                    try:
                        adapter = self.adapter_factory(await self.core.pool.get(uid))
                        break
                    except WaitRequired as error:
                        self.store.cooldown(uid, error.seconds)
                        self.store.audit(uid, name, {'seconds': error.seconds}, 'flood_kutilmoqda', 'B')
                        if attempt == 2:
                            raise SafeError('Ulanishda Telegram kutishni so‘radi; keyinroq yangi amal taklif qiling.')
                        await self.core.wait_cooldown(uid)
                for step in range(total):
                    for attempt in range(3):
                        entered = False
                        await self.core.wait_cooldown(uid)
                        slot = action_id + ':' + str(step)
                        if name in SEND_TOOLS:
                            while True:
                                wait = self.queue.reserve_send(uid, slot)
                                if not wait:
                                    break
                                self.store.assert_active(uid)
                                await self.sleep(min(wait, 0.25))
                        try:
                            data = await self.check_unchanged(uid, adapter, row, bundle, step)
                            self.store.assert_active(uid)
                            self.queue.begin_step(uid, action_id, step)
                            entered = True
                            try:
                                result = await asyncio.wait_for(adapter.perform(name, bundle, step, data), timeout=120)
                            finally:
                                if name in SEND_TOOLS:
                                    self.queue.touch_slot(uid, slot)
                            self.queue.finish_step(uid, action_id, step, result)
                            entered = False
                            break
                        except WaitRequired as error:
                            self.store.cooldown(uid, error.seconds)
                            self.store.audit(uid, name, {'seconds': error.seconds}, 'flood_kutilmoqda', 'B')
                            if name in SEND_TOOLS:
                                self.queue.release_slot(uid, slot)
                            self.queue.retry_step(uid, action_id, step)
                            entered = False
                            if attempt == 2:
                                raise SafeError('Telegram bir necha marta kutishni so‘radi; amal to‘xtadi.')
                    self.store.assert_active(uid)
                self.queue.finish(uid, action_id, 'done', {'xabar': 'Tasdiqlangan amal bajarildi.', 'qismlar': total})
                self.store.finish_event(uid, event, 'bajarildi')
            except (OutcomeUnknown, TimeoutError) as error:
                seconds = getattr(error, 'seconds', None)
                if seconds is not None:
                    self.store.cooldown(uid, seconds)
                    self.store.audit(uid, name, {'seconds': seconds}, 'flood_natija_noaniq', 'B')
                self.queue.finish(uid, action_id, 'uncertain', {'xabar': 'Natija noaniq. Telegramda tekshiring; avtomatik takrorlanmaydi.'})
                self.store.finish_event(uid, event, 'natija_noaniq')
            except asyncio.CancelledError:
                self.queue.finish(uid, action_id, 'uncertain' if entered else 'cancelled', {'xabar': 'Ishchi to‘xtadi; bajarilgan qismlar Telegramda qolishi mumkin.'})
                self.store.finish_event(uid, event, 'uzilgan')
                raise
            except SafeError as error:
                current = self.queue.get(uid, action_id)
                self.queue.finish(uid, action_id, 'partial' if current['done'] else 'cancelled', {'xabar': str(error)})
                self.store.finish_event(uid, event, 'toxtadi')
            except Exception:
                self.queue.finish(uid, action_id, 'uncertain' if entered else 'failed', {'xabar': 'Amal tugamadi. Telegramda natijani tekshiring.'})
                self.store.finish_event(uid, event, 'xato')

    async def cancel_user(self, uid):
        task = self.tasks.pop(uid, None)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def worker(self):
        self.queue.recover()
        tasks = self.tasks
        try:
            while True:
                for uid in self.queue.worker_users():
                    if uid in tasks:
                        if not tasks[uid].done():
                            continue
                        try:
                            tasks.pop(uid).result()
                        except Exception:
                            self.store.audit(uid, 'navbat_ishchisi', {}, 'xato', 'B')
                    user = self.store.user(uid)
                    if user['stopped'] or user['blocked']:
                        continue
                    action_id = self.queue.next_approved(uid)
                    if action_id:
                        tasks[uid] = asyncio.create_task(self.execute_one(uid, action_id))
                await asyncio.sleep(0.25)
        finally:
            for task in tasks.values():
                task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)

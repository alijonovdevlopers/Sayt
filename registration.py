"""Taklif bilan Telegram kirishi. Kod, telefon va 2FA paroli diskka yozilmaydi."""
import asyncio
import re
import secrets
import shutil
import uuid

from security import SafeError, SYSTEM, pin_hash, fingerprint


def telegram_client(api_id, api_hash):
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    return TelegramClient(StringSession(), api_id, api_hash, receive_updates=False,
                          flood_sleep_threshold=0, request_retries=0)


class Registration:
    def __init__(self, web, vault, pool, factory=telegram_client):
        self.web, self.vault, self.pool, self.factory = web, vault, pool, factory
        self.flows, self.locks = {}, {}

    def identity(self, guest):
        if not self.web.guest_valid(guest):
            raise SafeError('Ro‘yxatdan o‘tish oynasi eskirgan. Qayta boshlang.')
        return self.web.key('flow:' + guest)

    def state(self, guest):
        identity = self.identity(guest)
        flow = self.flows.get(identity)
        if not flow or flow['expires'] <= self.web.clock():
            raise SafeError('Kirish muddati tugagan. Ro‘yxatdan o‘tishni qayta boshlang.')
        return flow

    async def discard(self, identity):
        flow = self.flows.pop(identity, None)
        if flow:
            self.web.release_invite(flow['owner'], flow['invite'], identity)
            try:
                await asyncio.wait_for(flow['client'].disconnect(), 10)
            except Exception:
                pass

    async def start(self, guest, fields, ip):
        from telethon.errors import SessionPasswordNeededError
        identity = self.identity(guest)
        async with self.locks.setdefault(identity, asyncio.Lock()):
            keys = self.web.rate_keys(ip)
            self.web.rate_check(keys)
            if identity in self.flows:
                raise SafeError('Kirish boshlangan. Avval uni yakunlang yoki bekor qiling.')
            if len(self.flows) >= 32 or sum(f['ip'] == ip for f in self.flows.values()) >= 2:
                raise SafeError('Kirish oynalari band. Birozdan keyin urining.')
            lookup = self.web.credential(fields.get('api_id', ''), fields.get('api_hash', ''))
            if self.web.db.execute('SELECT 1 FROM web_accounts WHERE credential_hash=?', (lookup,)).fetchone():
                raise SafeError('Bu API ma’lumotlari bilan akkaunt mavjud. Kirish sahifasidan foydalaning.')
            phone = fields.get('phone', '').replace(' ', '')
            if not re.fullmatch(r'\+[1-9][0-9]{6,14}', phone):
                raise SafeError('Telefonni xalqaro shaklda kiriting: +998…')
            if fields.get('pin') != fields.get('confirm'):
                raise SafeError('PINlar mos emas.')
            hashed = await asyncio.to_thread(pin_hash, fields.get('pin', ''))
            try:
                owner, invite = self.web.reserve_invite(fields.get('invite', ''), identity)
            except SafeError:
                self.web.rate_fail(keys)
                raise
            client = None
            try:
                api_id, api_hash = int(fields['api_id']), fields['api_hash'].lower()
                client = self.factory(api_id, api_hash)
                flow = dict(owner=owner, invite=invite, client=client, api_id=api_id, api_hash=api_hash,
                            pin_hash=hashed, phone=phone, ip=ip, expires=self.web.clock() + 600,
                            step='code', code_hash=None, attempts=0)
                self.flows[identity] = flow
                await asyncio.wait_for(client.connect(), 30)
                try:
                    sent = await asyncio.wait_for(client.send_code_request(phone), 45)
                    flow['code_hash'] = sent.phone_code_hash
                except SessionPasswordNeededError:
                    flow['step'] = 'password'
            except Exception as error:
                await self.discard(identity)
                if not client:
                    self.web.release_invite(owner, invite, identity)
                self.web.rate_fail(keys)
                raise self.safe_error(error) from None

    @staticmethod
    def safe_error(error):
        from telethon.errors import FloodWaitError, PhoneCodeExpiredError
        if isinstance(error, FloodWaitError):
            return SafeError('Telegram kutishni so‘radi: ' + str(max(0, error.seconds)) + ' soniya. Keyin qayta boshlang.')
        if isinstance(error, PhoneCodeExpiredError):
            return SafeError('Telegram kodi eskirgan. Kirishni qayta boshlang.')
        return SafeError('Telegramga kirish tugamadi. Ma’lumotlarni tekshirib qayta urining.')

    async def verify(self, guest, value, step, ip):
        from telethon.errors import SessionPasswordNeededError, FloodWaitError, PhoneCodeExpiredError
        identity = self.identity(guest)
        async with self.locks.setdefault(identity, asyncio.Lock()):
            flow = self.state(guest)
            keys = self.web.rate_keys(ip)
            self.web.rate_check(keys)
            if flow['step'] != step:
                raise SafeError('Kirish bosqichi o‘zgargan. Sahifani yangilang.')
            try:
                if step == 'code':
                    if not re.fullmatch('[0-9]{4,8}', value):
                        raise ValueError('code')
                    await asyncio.wait_for(flow['client'].sign_in(phone=flow['phone'], code=value,
                                                                 phone_code_hash=flow['code_hash']), 45)
                elif step == 'password':
                    if not value or len(value) > 256:
                        raise ValueError('password')
                    await asyncio.wait_for(flow['client'].sign_in(password=value), 45)
                else:
                    raise ValueError('step')
            except SessionPasswordNeededError:
                flow['step'] = 'password'
                return None
            except Exception as error:
                flow['attempts'] += 1
                self.web.rate_fail(keys)
                if flow['attempts'] >= 5 or isinstance(error, (FloodWaitError, PhoneCodeExpiredError)):
                    await self.discard(identity)
                raise self.safe_error(error) from None
            try:
                me = await asyncio.wait_for(flow['client'].get_me(), 30)
                if not me or getattr(me, 'bot', False):
                    raise SafeError('Shaxsiy Telegram akkaunti kerak.')
                return self.finish(identity, flow, me)
            except Exception as error:
                await self.discard(identity)
                if isinstance(error, SafeError):
                    raise
                raise SafeError('Akkauntni saqlash tugamadi. Qayta boshlang.') from None

    def finish(self, identity, flow, me):
        uid, token, now = uuid.uuid4().hex, secrets.token_urlsafe(32), self.web.clock()
        db = self.web.db
        if db.execute('SELECT 1 FROM users WHERE telegram_id=?', (me.id,)).fetchone():
            raise SafeError('Bu Telegram akkaunti ro‘yxatdan o‘tgan. Kirish sahifasidan foydalaning.')
        try:
            self.vault.save(uid, api_id=flow['api_id'], api_hash=flow['api_hash'], session=flow['client'].session.save())
            with db:
                db.execute('BEGIN IMMEDIATE')
                invite = db.execute('SELECT * FROM web_invites WHERE user_id=? AND id=?', (flow['owner'], flow['invite'])).fetchone()
                if (not invite or invite['used'] or invite['revoked'] or invite['expires'] <= now or
                        invite['reserved_until'] <= now or invite['reserved_by'] != identity or not self.web.is_admin(flow['owner'])):
                    raise SafeError('Taklifning muddati tugagan yoki u bekor qilingan.')
                lookup = self.web.credential(flow['api_id'], flow['api_hash'])
                if db.execute('SELECT 1 FROM web_accounts WHERE credential_hash=?', (lookup,)).fetchone():
                    raise SafeError('Bu API ma’lumotlari bilan akkaunt mavjud.')
                db.execute('INSERT INTO users(user_id,token_hash,pin_hash,telegram_id,created) VALUES(?,?,?,?,?)',
                           (uid, fingerprint(self.web.store.pepper, token), flow['pin_hash'], me.id, now))
                name = ' '.join(filter(None, [getattr(me, 'first_name', ''), getattr(me, 'last_name', '')]))[:80]
                db.execute('INSERT INTO web_accounts VALUES(?,?,?,?,0)', (uid, flow['api_id'], lookup, name or 'Telegram akkaunti'))
                db.execute('UPDATE web_invites SET used=1,used_by=?,reserved_by=NULL,reserved_until=0 WHERE user_id=? AND id=?',
                           (uid, flow['owner'], flow['invite']))
        except BaseException:
            shutil.rmtree(self.vault.root / 'users' / uid, ignore_errors=True)
            raise
        self.pool.adopt(uid, flow['client'])
        self.flows.pop(identity, None)
        session = self.web.create_session(uid)
        self.web.store.audit(uid, 'royxatdan_otish', {}, 'tayyor', 'himoya')
        return uid, session, token

    async def cancel(self, guest):
        identity = self.identity(guest)
        async with self.locks.setdefault(identity, asyncio.Lock()):
            await self.discard(identity)

    async def reaper(self):
        while True:
            await asyncio.sleep(30)
            for identity, flow in list(self.flows.items()):
                if flow['expires'] <= self.web.clock():
                    async with self.locks.setdefault(identity, asyncio.Lock()):
                        await self.discard(identity)
            for identity, lock in list(self.locks.items()):
                if identity not in self.flows and not lock.locked():
                    self.locks.pop(identity, None)

    async def close(self):
        for identity in list(self.flows):
            await self.discard(identity)

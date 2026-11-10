"""Link Telegram to an authenticated website identity; keep legacy tools unchanged."""
import asyncio
import re
import secrets
import shutil

from registration import Registration
from security import SafeError, pin_hash, fingerprint


class TelegramLink(Registration):
    async def start_link(self, uid, guest, fields, ip):
        from telethon.errors import SessionPasswordNeededError
        self.web.store.assert_active(uid)
        if self.web.profile(uid)['telegram_id']:
            raise SafeError('Telegram allaqachon ulangan.')
        identity = self.identity(guest)
        async with self.locks.setdefault(identity, asyncio.Lock()):
            keys = self.web.rate_keys(ip, uid)
            self.web.rate_check(keys)
            if identity in self.flows or any(f.get('target_uid') == uid for f in self.flows.values()):
                raise SafeError('Kirish boshlangan. Uni yakunlang yoki bekor qiling.')
            if len(self.flows) >= 32:
                raise SafeError('Kirish oynalari band. Keyinroq urining.')
            self.web.credential(fields.get('api_id', ''), fields.get('api_hash', ''))
            phone = fields.get('phone', '').replace(' ', '')
            if not re.fullmatch(r'\+[1-9][0-9]{6,14}', phone):
                raise SafeError('Telefonni xalqaro shaklda kiriting: +998…')
            if fields.get('pin') != fields.get('confirm'):
                raise SafeError('PINlar mos emas.')
            hashed = await asyncio.to_thread(pin_hash, fields.get('pin', ''))
            client = self.factory(int(fields['api_id']), fields['api_hash'].lower())
            flow = dict(target_uid=uid, owner='__link__', invite='', client=client,
                        api_id=int(fields['api_id']), api_hash=fields['api_hash'].lower(),
                        pin_hash=hashed, phone=phone, ip=ip, expires=self.web.clock() + 600,
                        step='code', code_hash=None, attempts=0)
            self.flows[identity] = flow
            try:
                await asyncio.wait_for(client.connect(), 30)
                try:
                    sent = await asyncio.wait_for(client.send_code_request(phone), 45)
                    flow['code_hash'] = sent.phone_code_hash
                except SessionPasswordNeededError:
                    flow['step'] = 'password'
            except Exception as error:
                await self.discard(identity)
                self.web.rate_fail(keys)
                raise self.safe_error(error) from None

    def finish(self, identity, flow, me):
        uid = flow['target_uid']
        self.web.store.assert_active(uid)
        if self.web.profile(uid)['telegram_id']:
            raise SafeError('Telegram allaqachon ulangan.')
        if self.web.db.execute('SELECT 1 FROM users WHERE telegram_id=?', (me.id,)).fetchone():
            raise SafeError('Bu Telegram boshqa hisobga ulangan. Avval o‘sha hisobga kiring.')
        token = secrets.token_urlsafe(32)
        try:
            self.vault.save(uid, api_id=flow['api_id'], api_hash=flow['api_hash'], session=flow['client'].session.save())
            with self.web.db:
                self.web.db.execute('BEGIN IMMEDIATE')
                self.web.db.execute('UPDATE users SET telegram_id=?,pin_hash=?,token_hash=? WHERE user_id=? AND telegram_id IS NULL',
                                    (me.id, flow['pin_hash'], fingerprint(self.web.store.pepper, token), uid))
                self.web.db.execute('UPDATE web_accounts SET api_id=?,credential_hash=? WHERE user_id=?',
                                    (flow['api_id'], self.web.credential(flow['api_id'], flow['api_hash']), uid))
        except BaseException:
            shutil.rmtree(self.vault.root / 'users' / uid, ignore_errors=True)
            raise
        self.pool.adopt(uid, flow['client'])
        self.flows.pop(identity, None)
        self.web.store.audit(uid, 'telegram_ulash', {}, 'tayyor', 'himoya')
        return uid, self.web.create_session(uid), token

"""Sayt sessiyalari, takliflar va akkaunt profillari; sirlar faqat iz bilan."""
import asyncio
from datetime import datetime
import hmac
import json
import re
import secrets
import time
from zoneinfo import ZoneInfo

from security import SYSTEM, SafeError, fingerprint, pin_hash, pin_verify


def schema(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS web_accounts (
      user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
      api_id INTEGER NOT NULL, credential_hash TEXT NOT NULL,
      display_name TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS web_credential ON web_accounts(credential_hash);
    CREATE TABLE IF NOT EXISTS web_sessions (
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      session_hash TEXT NOT NULL UNIQUE, created REAL NOT NULL, expires REAL NOT NULL,
      PRIMARY KEY(user_id,session_hash)
    );
    CREATE TABLE IF NOT EXISTS web_invites (
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      id TEXT NOT NULL UNIQUE, created REAL NOT NULL, expires REAL NOT NULL,
      used INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
      reserved_by TEXT, reserved_until REAL NOT NULL DEFAULT 0,
      used_by TEXT REFERENCES users(user_id) ON DELETE SET NULL,
      PRIMARY KEY(user_id,id)
    );
    ''')


class WebStore:
    def __init__(self, store, clock=time.time):
        self.store, self.db, self.clock = store, store.db, clock

    def key(self, text):
        return fingerprint(self.store.pepper, text)

    def credential(self, api_id, api_hash):
        if not str(api_id).isdigit() or not 0 < int(api_id) < 2**31 or not re.fullmatch('[a-fA-F0-9]{32}', str(api_hash)):
            raise SafeError('API ID va API hash formatini tekshiring.')
        return self.key('credential:' + str(int(api_id)) + ':' + api_hash.lower())

    def add_profile(self, uid, api_id, api_hash, name):
        self.store.user(uid)
        with self.db:
            self.db.execute('''INSERT INTO web_accounts(user_id,api_id,credential_hash,display_name)
              VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET api_id=excluded.api_id,
              credential_hash=excluded.credential_hash,display_name=excluded.display_name''',
                            (uid, int(api_id), self.credential(api_id, api_hash), str(name or 'Telegram akkaunti')[:80]))

    def index_existing(self, vault):
        # Faqat mahalliy migratsiya: v1/v2 akkauntlari saytga kira olishi uchun.
        ids = [r[0] for r in self.db.execute("SELECT user_id FROM users WHERE user_id!='__system__'")]
        for uid in ids:
            if self.db.execute('SELECT 1 FROM web_accounts WHERE user_id=?', (uid,)).fetchone():
                continue
            try:
                saved = vault.load(uid)
                self.add_profile(uid, saved['api_id'], saved['api_hash'], 'Telegram ' + str(self.store.user(uid)['telegram_id']))
            except Exception:
                self.store.audit(uid, 'sayt_profili', {}, 'profil_ochilmadi', 'himoya')

    def profile(self, uid):
        row = self.db.execute('''SELECT u.user_id,u.telegram_id,u.stopped,u.blocked,w.api_id,w.display_name,w.is_admin
          FROM users u JOIN web_accounts w ON u.user_id=w.user_id WHERE u.user_id=?''', (uid,)).fetchone()
        if not row:
            raise SafeError('Akkaunt topilmadi.')
        return dict(row)

    def is_admin(self, uid):
        p = self.profile(uid)
        return bool(p['is_admin'] and not p['blocked'])

    def require_admin(self, uid):
        if not self.is_admin(uid):
            raise SafeError('Bu sahifa faqat sayt egasi uchun.')

    def bootstrap_admin(self, uid):
        self.profile(uid)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if self.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone():
                raise SafeError('Sayt egasi allaqachon belgilangan.')
            self.db.execute('UPDATE web_accounts SET is_admin=1 WHERE user_id=?', (uid,))

    def create_session(self, uid):
        p = self.profile(uid)
        if p['blocked']:
            raise SafeError('Kirish ma’lumotlari noto‘g‘ri yoki akkaunt yopilgan.')
        token, now = secrets.token_urlsafe(32), self.clock()
        with self.db:
            self.db.execute('DELETE FROM web_sessions WHERE user_id=? AND expires<=?', (uid, now))
            self.db.execute('INSERT INTO web_sessions VALUES(?,?,?,?)', (uid, self.key('session:' + token), now, now + 43200))
        return token

    def resolve_session(self, token):
        if not isinstance(token, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', token):
            return None
        row = self.db.execute('SELECT user_id,expires FROM web_sessions WHERE session_hash=?', (self.key('session:' + token),)).fetchone()
        if not row:
            return None
        if row['expires'] <= self.clock():
            self.logout(row['user_id'], token)
            return None
        p = self.profile(row['user_id'])
        return None if p['blocked'] else p

    def logout(self, uid, token):
        with self.db:
            self.db.execute('DELETE FROM web_sessions WHERE user_id=? AND session_hash=?', (uid, self.key('session:' + token)))

    def revoke_sessions(self, uid):
        with self.db:
            self.db.execute('DELETE FROM web_sessions WHERE user_id=?', (uid,))

    def csrf(self, token):
        return self.key('csrf:' + token)

    def csrf_valid(self, token, given):
        return bool(token and isinstance(given, str) and hmac.compare_digest(self.csrf(token), given))

    def guest_token(self):
        raw = str(int(self.clock())) + '.' + secrets.token_urlsafe(24)
        return raw + '.' + self.key('guest:' + raw)

    def guest_valid(self, token):
        if not isinstance(token, str) or len(token) > 160:
            return False
        try:
            issued, nonce, sig = token.split('.')
            return (0 <= self.clock() - int(issued) < 1200 and len(nonce) == 32 and
                    hmac.compare_digest(sig, self.key('guest:' + issued + '.' + nonce)))
        except (ValueError, TypeError):
            return False

    def bulk_ticket(self, uid, action_id, digest):
        body = str(int(self.clock()) + 120)
        return body + '.' + self.key('bulk:' + ':'.join([uid, action_id, digest, body]))

    def bulk_valid(self, uid, action_id, digest, token):
        try:
            deadline, sig = token.split('.')
            return (0 < int(deadline) - self.clock() <= 120 and
                    hmac.compare_digest(sig, self.key('bulk:' + ':'.join([uid, action_id, digest, deadline]))))
        except (ValueError, AttributeError):
            return False

    def rate_keys(self, ip, uid=None, credential=None):
        keys = [(SYSTEM, self.key('web-ip:' + ip))]
        if uid:
            keys.append((uid, 'web-auth'))
        if credential:
            keys.append((SYSTEM, self.key('web-account:' + credential)))
        return keys

    def rate_check(self, keys):
        if any(self.store.auth_blocked(uid, subject) for uid, subject in keys):
            raise SafeError('5 ta xato urinish. 15 daqiqadan keyin qayta urining.')

    def rate_fail(self, keys):
        for uid, subject in keys:
            self.store.auth_fail(uid, subject)

    async def login(self, api_id, api_hash, pin, ip, uid_hint=''):
        keys = self.rate_keys(ip)
        self.rate_check(keys)
        try:
            lookup = self.credential(api_id, api_hash)
        except SafeError:
            self.rate_fail(keys)
            raise SafeError('Kirish ma’lumotlarini tekshiring.') from None
        rows = self.db.execute('SELECT user_id FROM web_accounts WHERE credential_hash=?', (lookup,)).fetchall()
        candidates = [r[0] for r in rows if not uid_hint or r[0] == uid_hint]
        uid = candidates[0] if len(candidates) == 1 else None
        keys = self.rate_keys(ip, uid, lookup)
        self.rate_check(keys)
        encoded = self.store.user(uid)['pin_hash'] if uid else '00' * 16 + ':' + '00' * 32
        valid = await asyncio.to_thread(pin_verify, pin, encoded)
        self.rate_check(keys)
        if not valid or not uid or self.store.user(uid)['blocked']:
            self.rate_fail(keys)
            self.store.audit(uid or SYSTEM, 'sayt_kirish', {}, 'rad', 'himoya')
            raise SafeError('Kirish ma’lumotlari noto‘g‘ri yoki akkaunt yopilgan. Zarur bo‘lsa foydalanuvchi IDni kiriting.')
        token = self.create_session(uid)
        self.store.audit(uid, 'sayt_kirish', {}, 'tayyor', 'himoya')
        return token

    async def verify_pin(self, uid, pin, ip):
        keys = self.rate_keys(ip, uid)
        self.rate_check(keys)
        valid = await asyncio.to_thread(pin_verify, pin, self.store.user(uid)['pin_hash'])
        self.rate_check(keys)
        if not valid:
            self.rate_fail(keys)
            raise SafeError('PIN noto‘g‘ri.')
        if self.store.user(uid)['blocked']:
            raise SafeError('Akkaunt bloklangan.')

    async def change_pin(self, uid, current, new, confirm, ip):
        await self.verify_pin(uid, current, ip)
        if new != confirm:
            raise SafeError('Yangi PINlar mos emas.')
        hashed = await asyncio.to_thread(pin_hash, new)
        with self.db:
            self.db.execute('UPDATE users SET pin_hash=? WHERE user_id=?', (hashed, uid))
            self.db.execute('DELETE FROM web_sessions WHERE user_id=?', (uid,))
        self.store.audit(uid, 'pin_almashtirish', {}, 'tayyor', 'himoya')
        return self.create_session(uid)

    async def resume(self, uid, pin, ip):
        await self.verify_pin(uid, pin, ip)
        with self.db:
            self.db.execute('UPDATE users SET stopped=0 WHERE user_id=? AND blocked=0', (uid,))
        self.store.audit(uid, 'saytdan_yoqish', {}, 'tayyor', 'himoya')

    def rotate_mcp(self, uid):
        token = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('UPDATE users SET token_hash=? WHERE user_id=? AND blocked=0', (fingerprint(self.store.pepper, token), uid))
        self.store.audit(uid, 'mcp_yangilash', {}, 'tayyor', 'himoya')
        return token

    def create_invite(self, uid):
        self.require_admin(uid)
        code, now = secrets.token_urlsafe(24), self.clock()
        with self.db:
            self.db.execute('INSERT INTO web_invites(user_id,id,created,expires) VALUES(?,?,?,?)',
                            (uid, self.key('invite:' + code), now, now + 86400))
        return code

    def invites(self, uid):
        self.require_admin(uid)
        return [dict(r) for r in self.db.execute('SELECT * FROM web_invites WHERE user_id=? ORDER BY created DESC LIMIT 50', (uid,))]

    def revoke_invite(self, uid, invite_id):
        self.require_admin(uid)
        with self.db:
            self.db.execute('UPDATE web_invites SET revoked=1 WHERE user_id=? AND id=?', (uid, invite_id))

    def reserve_invite(self, code, flow):
        identity, now = self.key('invite:' + code), self.clock()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT * FROM web_invites WHERE id=?', (identity,)).fetchone()
            if not row or row['used'] or row['revoked'] or row['expires'] <= now or row['reserved_until'] > now:
                raise SafeError('Taklif kodi yaroqsiz, band yoki muddati tugagan.')
            self.db.execute('UPDATE web_invites SET reserved_by=?,reserved_until=? WHERE user_id=? AND id=?',
                            (flow, now + 600, row['user_id'], identity))
        return row['user_id'], identity

    def release_invite(self, owner, identity, flow):
        with self.db:
            self.db.execute('UPDATE web_invites SET reserved_by=NULL,reserved_until=0 WHERE user_id=? AND id=? AND reserved_by=?',
                            (owner, identity, flow))

    def admin_users(self, uid):
        self.require_admin(uid)
        # Egaga faqat boshqarish uchun zarur profil/holat; boshqa jurnal, sessiya va MCP sirlari yo‘q.
        return [self.profile(r[0]) for r in self.db.execute('SELECT user_id FROM web_accounts ORDER BY display_name')]

    def logs(self, uid, which):
        self.store.user(uid)
        sql, params = 'SELECT * FROM audit WHERE user_id=?', [uid]
        if which == 'today':
            start = datetime.now(ZoneInfo('Asia/Tashkent')).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            sql += ' AND created>=?'
            params.append(start)
        elif which == 'error':
            sql += " AND status IN ('xato','rad','vaqt_tugadi','natija_noaniq','flood_natija_noaniq','profil_ochilmadi','toxtadi','uzilgan','sessiyani_saqlash_xatosi','uzilish_xatosi')"
        elif which == 'B':
            sql += " AND level='B'"
        return [dict(r) for r in self.db.execute(sql + ' ORDER BY created DESC LIMIT 100', params)]

"""Public website identities, independent of Telegram and Instagram credentials."""
import asyncio
import os
import re
import secrets
import sqlite3
import time
import uuid

from admin_service import BlockedAccountError
from security import SafeError, SYSTEM, pin_hash, pin_verify


class SiteAccounts:
    def __init__(self, web):
        self.web, self.db = web, web.db
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS site_logins (
          user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS site_signup_limits (
          subject TEXT PRIMARY KEY, count INTEGER NOT NULL, reset REAL NOT NULL
        );
        ''')
        self.hash_slots = asyncio.Semaphore(2)

    def username(self, value):
        value = value.strip()
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{2,31}', value):
            raise SafeError('Login 3–32 belgi: lotin harflari, raqam, nuqta, _ yoki - ishlating.')
        return value

    async def hash_password(self, password, confirm):
        if password != confirm:
            raise SafeError('Parollar mos emas.')
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            raise SafeError('Parol 8–128 belgidan iborat bo‘lsin.')
        async with self.hash_slots:
            return await asyncio.to_thread(pin_hash, password)

    async def register(self, username, password, confirm, ip):
        username = self.username(username)
        if username.casefold() == os.getenv('ADMIN_LOGIN_USER', '').casefold():
            raise SafeError('Bu login band. Boshqa login tanlang.')
        key, now = self.web.key('signup:' + ip), time.time()
        row = self.db.execute('SELECT * FROM site_signup_limits WHERE subject=?', (key,)).fetchone()
        if row and row['reset'] > now and row['count'] >= 5:
            raise SafeError('Hisob yaratish chegarasiga yetildi. Bir soatdan keyin urining.')
        if self.db.execute('SELECT 1 FROM site_logins WHERE username=?', (username,)).fetchone():
            raise SafeError('Bu login band. Boshqa login tanlang.')
        hashed = await self.hash_password(password, confirm)
        uid = uuid.uuid4().hex
        try:
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                # Recheck after expensive password hashing / concurrent requests.
                row = self.db.execute('SELECT * FROM site_signup_limits WHERE subject=?', (key,)).fetchone()
                if row and row['reset'] > time.time() and row['count'] >= 5:
                    raise SafeError('Hisob yaratish chegarasiga yetildi. Bir soatdan keyin urining.')
                self.db.execute('INSERT INTO users(user_id,pin_hash,created) VALUES(?,?,?)', (uid, hashed, now))
                self.db.execute('INSERT INTO web_accounts VALUES(?,?,?,?,0)',
                                (uid, 0, self.web.key('unlinked:' + uid), username))
                self.db.execute('INSERT INTO site_logins VALUES(?,?,?,?)', (uid, username, hashed, now))
                self.db.execute('DELETE FROM site_signup_limits WHERE reset<=?', (now,))
                self.db.execute('INSERT INTO site_signup_limits VALUES(?,1,?) ON CONFLICT(subject) DO UPDATE SET count=count+1', (key, now + 3600))
        except sqlite3.IntegrityError:
            raise SafeError('Bu login band. Boshqa login tanlang.') from None
        self.web.store.audit(uid, 'hisob_yaratish', {}, 'tayyor', 'himoya')
        return uid

    async def login(self, username, password, ip):
        username = str(username).strip()[:128]
        keys = self.web.rate_keys(ip, credential='site:' + username.casefold())
        self.web.rate_check(keys)
        row = self.db.execute('SELECT * FROM site_logins WHERE username=?', (username,)).fetchone()
        encoded = row['password_hash'] if row else '00' * 16 + ':' + '00' * 32
        async with self.hash_slots:
            valid = await asyncio.to_thread(pin_verify, password, encoded)
        self.web.rate_check(keys)
        if not valid or not row:
            self.web.rate_fail(keys)
            if row and self.web.store.user(row['user_id'])['blocked']:
                raise BlockedAccountError(row['user_id'])
            raise SafeError('Login yoki parol noto‘g‘ri yoki hisob yopilgan.')
        if self.web.store.user(row['user_id'])['blocked']:
            raise BlockedAccountError(row['user_id'])
        return self.web.create_session(row['user_id'])

    async def change(self, uid, current, password, confirm, ip):
        row = self.db.execute('SELECT * FROM site_logins WHERE user_id=?', (uid,)).fetchone()
        if not row:
            raise SafeError('Bu eski hisob: mavjud administrator yoki Telegram kirishidan foydalaning.')
        session = await self.login(row['username'], current, ip)
        self.web.logout(uid, session)
        hashed = await self.hash_password(password, confirm)
        with self.db:
            self.db.execute('UPDATE site_logins SET password_hash=? WHERE user_id=?', (hashed, uid))
            self.db.execute('DELETE FROM web_sessions WHERE user_id=?', (uid,))
        return self.web.create_session(uid)

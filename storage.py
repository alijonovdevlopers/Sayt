"""Har bir egaga tegishli yozuv user_id bilan saqlanadi."""
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
import uuid

from security import SYSTEM, SafeError, fingerprint, pin_hash, safe_params


class Store:
    def __init__(self, path, pepper):
        path = Path(path)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(path.parent, 0o700)
        if path.is_symlink():
            raise SafeError('Baza fayli xavfsiz emas.')
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        self.pepper = pepper
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          user_id TEXT PRIMARY KEY,
          token_hash TEXT UNIQUE,
          pin_hash TEXT NOT NULL,
          telegram_id INTEGER UNIQUE,
          stopped INTEGER NOT NULL DEFAULT 0 CHECK(stopped IN (0,1)),
          blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0,1)),
          cooldown REAL NOT NULL DEFAULT 0,
          created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          id TEXT NOT NULL,
          created REAL NOT NULL,
          tool TEXT NOT NULL,
          level TEXT NOT NULL,
          params TEXT NOT NULL,
          status TEXT NOT NULL,
          PRIMARY KEY (user_id,id)
        );
        CREATE INDEX IF NOT EXISTS audit_time ON audit(user_id,created);
        CREATE TABLE IF NOT EXISTS downloads (
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          id TEXT NOT NULL,
          filename TEXT NOT NULL,
          size INTEGER NOT NULL,
          created REAL NOT NULL,
          PRIMARY KEY (user_id,id)
        );
        CREATE TABLE IF NOT EXISTS auth_failures (
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          subject TEXT NOT NULL,
          count INTEGER NOT NULL,
          until REAL NOT NULL,
          PRIMARY KEY (user_id,subject)
        );
        ''')
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO users(user_id,pin_hash,blocked,created) VALUES(?,?,1,?)',
                            (SYSTEM, '', time.time()))
        from queue_store import schema
        schema(self.db)
        from web_store import schema as web_schema
        web_schema(self.db)

    def create_user(self, pin, telegram_id):
        uid, token = uuid.uuid4().hex, secrets.token_urlsafe(32)
        hashed_pin = pin_hash(pin)
        with self.db:
            self.db.execute('INSERT INTO users(user_id,token_hash,pin_hash,telegram_id,created) VALUES(?,?,?,?,?)',
                            (uid, fingerprint(self.pepper, token), hashed_pin, telegram_id, time.time()))
        return uid, token

    def authenticate(self, token):
        # Faqat autentifikatsiya chegarasida user_id token orqali aniqlanadi.
        row = self.db.execute('SELECT user_id FROM users WHERE token_hash=? AND blocked=0',
                              (fingerprint(self.pepper, token),)).fetchone()
        return row['user_id'] if row else None

    def user(self, uid):
        row = self.db.execute('SELECT * FROM users WHERE user_id=?', (uid,)).fetchone()
        if row is None or uid == SYSTEM:
            raise SafeError('Foydalanuvchi aniqlanmadi.')
        return dict(row)

    def assert_active(self, uid):
        user = self.user(uid)
        if user['blocked']:
            raise SafeError('Foydalanuvchi bloklangan.')
        if user['stopped']:
            raise SafeError('HAMMASI TO‘XTATILGAN.')
        return user

    def stop(self, uid):
        self.user(uid)
        with self.db:
            self.db.execute('UPDATE users SET stopped=1 WHERE user_id=?', (uid,))
            self.db.execute("UPDATE actions SET status='cancelled' WHERE user_id=? AND status IN ('pending','approved')", (uid,))
        self.audit(uid, 'toxtatish', {}, 'toxtatilgan', level='mahalliy')

    def set_blocked(self, uid, blocked):
        self.user(uid)
        with self.db:
            self.db.execute('UPDATE users SET blocked=? WHERE user_id=?', (int(blocked), uid))
            if blocked:
                self.db.execute("UPDATE actions SET status='cancelled' WHERE user_id=? AND status IN ('pending','approved')", (uid,))

    def cooldown(self, uid, seconds):
        self.user(uid)
        with self.db:
            self.db.execute('UPDATE users SET cooldown=MAX(cooldown,?) WHERE user_id=?',
                            (time.time() + max(0, seconds), uid))

    def audit(self, uid, tool, params, status, level='A'):
        event_id = uuid.uuid4().hex
        with self.db:
            self.db.execute('INSERT INTO audit VALUES(?,?,?,?,?,?,?)',
                            (uid, event_id, time.time(), tool, level, safe_params(params), status))
        return event_id

    def events(self, uid, limit=50):
        self.user(uid)
        return [dict(row) for row in self.db.execute(
            'SELECT * FROM audit WHERE user_id=? ORDER BY created DESC LIMIT ?', (uid, max(1, min(100, limit))))]

    def finish_event(self, uid, event_id, status):
        with self.db:
            self.db.execute('UPDATE audit SET status=? WHERE user_id=? AND id=?', (status, uid, event_id))

    def event(self, uid, event_id):
        self.user(uid)
        row = self.db.execute('SELECT * FROM audit WHERE user_id=? AND id=?', (uid, event_id)).fetchone()
        return dict(row) if row else None

    def add_download(self, uid, file_id, filename, size):
        self.assert_active(uid)
        with self.db:
            self.db.execute('INSERT INTO downloads VALUES(?,?,?,?,?)', (uid, file_id, filename, size, time.time()))

    def download(self, uid, file_id):
        self.user(uid)
        row = self.db.execute('SELECT * FROM downloads WHERE user_id=? AND id=?', (uid, file_id)).fetchone()
        return dict(row) if row else None

    def auth_blocked(self, uid, subject):
        row = self.db.execute('SELECT count,until FROM auth_failures WHERE user_id=? AND subject=?',
                              (uid, subject)).fetchone()
        return bool(row and row['count'] >= 5 and row['until'] > time.time())

    def auth_fail(self, uid, subject):
        now = time.time()
        with self.db:
            self.db.execute('''INSERT INTO auth_failures VALUES(?,?,1,?)
            ON CONFLICT(user_id,subject) DO UPDATE SET
              count=CASE WHEN until<? THEN 1 ELSE count+1 END,
              until=CASE WHEN until<? OR count>=4 THEN excluded.until ELSE until END''',
                            (uid, subject, now + 900, now, now))

    def close(self):
        self.db.close()

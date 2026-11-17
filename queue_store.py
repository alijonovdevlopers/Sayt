"""Tasdiq, bir martalik bajarish holati va diskda saqlanadigan limitlar."""
import json
import time
import uuid

from actions import canonical, action_digest
from security import SafeError, fingerprint


def schema(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS actions (
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      id TEXT NOT NULL, tool TEXT NOT NULL, payload TEXT NOT NULL, digest TEXT NOT NULL,
      status TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
      bulk INTEGER NOT NULL, approved REAL, signature TEXT, done INTEGER NOT NULL DEFAULT 0,
      result TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(user_id,id)
    );
    CREATE INDEX IF NOT EXISTS action_state ON actions(user_id,status,created);
    CREATE TABLE IF NOT EXISTS action_steps (
      user_id TEXT NOT NULL, action_id TEXT NOT NULL, step INTEGER NOT NULL,
      status TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}',
      PRIMARY KEY(user_id,action_id,step),
      FOREIGN KEY(user_id,action_id) REFERENCES actions(user_id,id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS send_slots (
      user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      id TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(user_id,id)
    );
    CREATE INDEX IF NOT EXISTS send_time ON send_slots(user_id,created);
    ''')


class QueueStore:
    def __init__(self, store, clock=time.time):
        self.store, self.db, self.clock = store, store.db, clock

    def expire(self, uid):
        with self.db:
            self.db.execute("UPDATE actions SET status='expired' WHERE user_id=? AND status='pending' AND expires<=?",
                            (uid, self.clock()))

    def enqueue(self, uid, tool, bundle, bulk):
        self.store.assert_active(uid)
        self.expire(uid)
        action_id, now = uuid.uuid4().hex, self.clock()
        row = dict(user_id=uid, id=action_id, tool=tool, payload=canonical(bundle), created=now, expires=now + 600, bulk=int(bulk))
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.store.assert_active(uid)
            count = self.db.execute("SELECT count(*) FROM actions WHERE user_id=? AND status IN ('pending','approved','running')", (uid,)).fetchone()[0]
            if count >= 20:
                raise SafeError('Navbat to‘la: avval kutayotgan amallarni ko‘rib chiqing.')
            self.db.execute('''INSERT INTO actions(user_id,id,tool,payload,digest,status,created,expires,bulk)
              VALUES(?,?,?,?,?,'pending',?,?,?)''',
                            (uid, action_id, tool, row['payload'], action_digest(row), now, now + 600, int(bulk)))
        return action_id

    def get(self, uid, action_id):
        self.store.user(uid)
        self.expire(uid)
        return self._row(uid, action_id)

    def _row(self, uid, action_id):
        row = self.db.execute('SELECT * FROM actions WHERE user_id=? AND id=?', (uid, action_id)).fetchone()
        if row is None:
            raise SafeError('Amal topilmadi.')
        return dict(row)

    def list(self, uid):
        self.store.user(uid)
        self.expire(uid)
        return [dict(row) for row in self.db.execute('SELECT * FROM actions WHERE user_id=? ORDER BY created DESC LIMIT 100', (uid,))]

    def signature(self, row):
        return fingerprint(self.store.pepper, canonical([
            row['user_id'], row['id'], row['tool'], row['digest'], row['approved'], row['bulk']]))

    def decide(self, uid, action_id, reviewed_digest, approve, bulk_confirm=False):
        self.expire(uid)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.store.assert_active(uid)
            row = self._row(uid, action_id)
            if row['status'] != 'pending' or row['expires'] <= self.clock():
                raise SafeError('Amal endi tasdiq kutmayapti yoki muddati tugagan.')
            if row['digest'] != reviewed_digest or action_digest(row) != reviewed_digest:
                raise SafeError('Ko‘rsatilgan amal o‘zgargan; tasdiqlanmadi.')
            if approve and row['bulk'] and not bulk_confirm:
                raise SafeError('Ommaviy amalga alohida tasdiq kerak.')
            row['approved'] = self.clock()
            self.db.execute('UPDATE actions SET status=?,approved=?,signature=? WHERE user_id=? AND id=? AND status=?',
                            ('approved' if approve else 'rejected', row['approved'], self.signature(row) if approve else None,
                             uid, action_id, 'pending'))
        self.store.audit(uid, row['tool'], {}, 'tasdiqlandi' if approve else 'rad_etildi', 'B')

    def claim(self, uid, action_id):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.store.assert_active(uid)
            row = self._row(uid, action_id)
            if row['status'] != 'approved':
                raise SafeError('Amal bajarishga tasdiqlanmagan.')
            import hmac
            if action_digest(row) != row['digest'] or not hmac.compare_digest(row['signature'] or '', self.signature(row)):
                raise SafeError('Tasdiqning yaxlitligi buzilgan.')
            self.db.execute("UPDATE actions SET status='running' WHERE user_id=? AND id=? AND status='approved'", (uid, action_id))
        return row

    def finish(self, uid, action_id, status, result=None):
        with self.db:
            self.db.execute("UPDATE actions SET status=?,result=? WHERE user_id=? AND id=? AND status='running'",
                            (status, canonical(result or {}), uid, action_id))

    def begin_step(self, uid, action_id, step):
        self.store.assert_active(uid)
        with self.db:
            self.db.execute('INSERT INTO action_steps VALUES(?,?,?,\'running\',\'{}\')', (uid, action_id, step))

    def finish_step(self, uid, action_id, step, result):
        with self.db:
            self.db.execute("UPDATE action_steps SET status='done',result=? WHERE user_id=? AND action_id=? AND step=?",
                            (canonical(result), uid, action_id, step))
            self.db.execute('UPDATE actions SET done=done+1 WHERE user_id=? AND id=?', (uid, action_id))

    def retry_step(self, uid, action_id, step):
        # Faqat aniq FloodWait rad javobidan keyin; noaniq tarmoq xatosida EMAS.
        with self.db:
            self.db.execute("DELETE FROM action_steps WHERE user_id=? AND action_id=? AND step=? AND status='running'",
                            (uid, action_id, step))

    def step_results(self, uid, action_id):
        self.store.user(uid)
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT result FROM action_steps WHERE user_id=? AND action_id=? AND status='done' ORDER BY step", (uid, action_id))]

    def reserve_send(self, uid, slot_id):
        now = self.clock()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.store.assert_active(uid)
            times = [r[0] for r in self.db.execute('SELECT created FROM send_slots WHERE user_id=? AND created>? ORDER BY created',
                                                  (uid, now - 3600))]
            wait = max(0, times[-1] + 2 - now) if times else 0
            if len(times) >= 30:
                wait = max(wait, times[-30] + 3600 - now)
            if wait > 0:
                return wait
            self.db.execute('INSERT INTO send_slots VALUES(?,?,?)', (uid, slot_id, now))
            self.db.execute('DELETE FROM send_slots WHERE user_id=? AND created<=?', (uid, now - 3600))
        return 0

    def release_slot(self, uid, slot_id):
        with self.db:
            self.db.execute('DELETE FROM send_slots WHERE user_id=? AND id=?', (uid, slot_id))

    def touch_slot(self, uid, slot_id):
        with self.db:
            self.db.execute('UPDATE send_slots SET created=? WHERE user_id=? AND id=?', (self.clock(), uid, slot_id))

    def invalidate(self, uid, action_id):
        with self.db:
            self.db.execute("UPDATE actions SET status='invalid' WHERE user_id=? AND id=? AND status='approved'", (uid, action_id))

    def worker_users(self):
        # Faqat mahalliy ishchi rejalashtiruvchi; bu ro‘yxat MCPga chiqarilmaydi.
        return [r[0] for r in self.db.execute("SELECT user_id FROM users WHERE user_id!='__system__'")]

    def next_approved(self, uid):
        self.expire(uid)
        row = self.db.execute("SELECT id FROM actions WHERE user_id=? AND status='approved' ORDER BY created LIMIT 1", (uid,)).fetchone()
        return row[0] if row else None

    def recover(self):
        for uid in self.worker_users():
            with self.db:
                self.db.execute("UPDATE actions SET status='uncertain',result=? WHERE user_id=? AND status='running'",
                                (canonical({'xabar': 'Server uzilgan. Telegramda tekshiring; avtomatik takrorlanmaydi.'}), uid))

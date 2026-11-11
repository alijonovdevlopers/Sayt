"""Admin statistics, user blocking with blocked screen state, and in-app messaging."""
import hmac
import re
import time
import uuid

from security import SafeError, pin_verify


class BlockedAccountError(SafeError):
    def __init__(self, user_id):
        super().__init__('Siz saytga kira olmaysiz, iltimos adminga murojaat qiling.')
        self.user_id = user_id


class AdminService:
    def __init__(self, web, core):
        self.web, self.db, self.core = web, web.db, core
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS blocked_sessions (
          session_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_messages (
          id TEXT PRIMARY KEY,
          sender_id TEXT NOT NULL,
          target_user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          body TEXT NOT NULL,
          created REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS admin_messages_target ON admin_messages(target_user_id, created DESC);
        CREATE TABLE IF NOT EXISTS admin_message_reads (
          message_id TEXT NOT NULL REFERENCES admin_messages(id) ON DELETE CASCADE,
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          read_at REAL NOT NULL,
          PRIMARY KEY(message_id, user_id)
        );
        ''')

    def blocked_token(self, uid):
        return uid + '.' + self.web.key('blocked-cookie:' + uid)

    def resolve_blocked_cookie(self, cookie):
        if not isinstance(cookie, str) or '.' not in cookie:
            return None
        uid, sig = cookie.split('.', 1)
        if not re.fullmatch(r'[a-f0-9]{32}', uid):
            return None
        if not hmac.compare_digest(sig, self.web.key('blocked-cookie:' + uid)):
            return None
        row = self.db.execute('SELECT blocked FROM users WHERE user_id=?', (uid,)).fetchone()
        return uid if row and row['blocked'] else None

    def is_blocked_session(self, session):
        if not isinstance(session, str) or not session:
            return None
        shash = self.web.key('session:' + session)
        row = self.db.execute(
            '''SELECT b.user_id FROM blocked_sessions b
               JOIN users u ON u.user_id = b.user_id
               WHERE b.session_hash = ? AND u.blocked = 1''',
            (shash,)
        ).fetchone()
        return row['user_id'] if row else None

    def check_blocked_telegram_login(self, api_id, pin):
        if not str(api_id).isdigit() or not pin:
            return None
        rows = self.db.execute(
            '''SELECT u.user_id, u.pin_hash, u.blocked FROM users u
               JOIN web_accounts w ON w.user_id = u.user_id
               WHERE w.api_id = ? AND u.blocked = 1''',
            (int(api_id),)
        ).fetchall()
        for row in rows:
            if row['pin_hash'] and pin_verify(str(pin), row['pin_hash']):
                return row['user_id']
        return None

    def block_user(self, admin_uid, target_uid):
        if admin_uid == target_uid:
            raise SafeError('O‘zingizni bloklay olmaysiz.')
        target = self.db.execute(
            '''SELECT u.user_id, COALESCE(w.is_admin, 0) AS is_admin
               FROM users u LEFT JOIN web_accounts w ON w.user_id = u.user_id
               WHERE u.user_id = ? AND u.user_id != '__system__' ''',
            (target_uid,)
        ).fetchone()
        if not target or target['is_admin']:
            raise SafeError('Foydalanuvchi topilmadi yoki uni bloklab bo‘lmaydi.')
        now = time.time()
        with self.db:
            sessions = self.db.execute('SELECT session_hash FROM web_sessions WHERE user_id=?', (target_uid,)).fetchall()
            for s in sessions:
                self.db.execute(
                    'INSERT OR REPLACE INTO blocked_sessions(session_hash, user_id, created) VALUES(?,?,?)',
                    (s['session_hash'], target_uid, now)
                )
            self.db.execute("UPDATE instagram_actions SET status='rejected' WHERE user_id=? AND status='pending'", (target_uid,))
        self.web.store.set_blocked(target_uid, True)
        with self.db:
            self.db.execute('DELETE FROM web_sessions WHERE user_id=?', (target_uid,))
            self.db.execute("UPDATE actions SET status='cancelled' WHERE user_id=? AND status IN ('pending','approved')", (target_uid,))
        self.web.store.audit(admin_uid, 'admin_block', {'target': target_uid}, 'tayyor', 'himoya')

    def unblock_user(self, admin_uid, target_uid):
        if admin_uid == target_uid:
            raise SafeError('Amal noto‘g‘ri.')
        target = self.db.execute(
            "SELECT user_id FROM users WHERE user_id=? AND user_id!='__system__'",
            (target_uid,)
        ).fetchone()
        if not target:
            raise SafeError('Foydalanuvchi topilmadi.')
        self.web.store.set_blocked(target_uid, False)
        with self.db:
            self.db.execute('DELETE FROM blocked_sessions WHERE user_id=?', (target_uid,))
        self.web.store.audit(admin_uid, 'admin_unblock', {'target': target_uid}, 'tayyor', 'himoya')

    def stats(self):
        q = lambda sql, args=(): self.db.execute(sql, args).fetchone()[0]
        total_users = q("SELECT COUNT(*) FROM users WHERE user_id != '__system__'")
        blocked_users = q("SELECT COUNT(*) FROM users WHERE user_id != '__system__' AND blocked = 1")
        active_users = total_users - blocked_users
        site_accounts = q('SELECT COUNT(*) FROM site_logins')
        telegram_connected = q("SELECT COUNT(*) FROM users WHERE user_id != '__system__' AND telegram_id IS NOT NULL")
        instagram_connected = q('SELECT COUNT(*) FROM instagram_accounts')
        tg_mcp = q("SELECT COUNT(*) FROM users WHERE user_id != '__system__' AND token_hash IS NOT NULL AND token_hash != '' AND blocked = 0")
        ig_mcp = q('SELECT COUNT(*) FROM instagram_mcp m JOIN users u ON u.user_id = m.user_id WHERE u.blocked = 0')
        pending_tg = q("SELECT COUNT(*) FROM actions WHERE status IN ('pending', 'approved')")
        pending_ig = q("SELECT COUNT(*) FROM instagram_actions WHERE status = 'pending'")
        done_tg = q("SELECT COUNT(*) FROM actions WHERE status = 'done'")
        done_ig = q("SELECT COUNT(*) FROM instagram_actions WHERE status = 'done'")
        sent_messages = q('SELECT COUNT(*) FROM admin_messages')
        return {
            'total_users': total_users,
            'active_users': active_users,
            'blocked_users': blocked_users,
            'site_accounts': site_accounts,
            'telegram_connected': telegram_connected,
            'instagram_connected': instagram_connected,
            'active_mcp_keys': tg_mcp + ig_mcp,
            'pending_actions': pending_tg + pending_ig,
            'completed_actions': done_tg + done_ig,
            'sent_messages': sent_messages,
        }

    def users_list(self):
        rows = self.db.execute('''
            SELECT u.user_id, u.telegram_id, u.blocked, u.stopped, u.created,
                   u.token_hash AS tg_token,
                   COALESCE(w.display_name, '') AS display_name,
                   COALESCE(w.is_admin, 0) AS is_admin,
                   s.username AS site_username,
                   ig.username AS ig_username,
                   ig.instagram_id AS ig_id,
                   im.token_hash AS ig_token
            FROM users u
            LEFT JOIN web_accounts w ON w.user_id = u.user_id
            LEFT JOIN site_logins s ON s.user_id = u.user_id
            LEFT JOIN instagram_accounts ig ON ig.user_id = u.user_id
            LEFT JOIN instagram_mcp im ON im.user_id = u.user_id
            WHERE u.user_id != '__system__'
            ORDER BY COALESCE(w.is_admin, 0) DESC, u.created DESC
        ''').fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d['label'] = d['site_username'] or d['display_name'] or ('ID:' + d['user_id'][:8])
            result.append(d)
        return result

    def send_message(self, admin_uid, target, title, body):
        title = (title or '').strip()
        body = (body or '').strip()
        target = (target or 'all').strip()
        if not 1 <= len(title) <= 120:
            raise SafeError('Xabar sarlavhasi 1–120 belgidan iborat bo‘lsin.')
        if not 1 <= len(body) <= 2000:
            raise SafeError('Xabar matni 1–2000 belgidan iborat bo‘lsin.')
        target_uid = None
        if target.lower() not in ('', 'all', 'broadcast'):
            clean = target.lstrip('@')
            row = self.db.execute(
                '''SELECT u.user_id FROM users u
                   LEFT JOIN site_logins s ON s.user_id = u.user_id
                   WHERE u.user_id != '__system__' AND (u.user_id = ? OR LOWER(s.username) = LOWER(?))''',
                (target, clean)
            ).fetchone()
            if not row:
                raise SafeError('Qabul qiluvchi foydalanuvchi topilmadi.')
            target_uid = row['user_id']
        mid = uuid.uuid4().hex
        now = time.time()
        with self.db:
            self.db.execute(
                'INSERT INTO admin_messages(id, sender_id, target_user_id, title, body, created) VALUES(?,?,?,?,?,?)',
                (mid, admin_uid, target_uid, title, body, now)
            )
        self.web.store.audit(admin_uid, 'admin_xabar', {'target': target_uid or 'all'}, 'tayyor', 'himoya')
        return mid

    def delete_message(self, admin_uid, msg_id):
        if not re.fullmatch(r'[a-f0-9]{32}', msg_id or ''):
            raise SafeError('Xabar topilmadi.')
        with self.db:
            cur = self.db.execute('DELETE FROM admin_messages WHERE id=?', (msg_id,))
            if cur.rowcount == 0:
                raise SafeError('Xabar topilmadi.')
        self.web.store.audit(admin_uid, 'admin_xabar_ochirish', {'id': msg_id}, 'tayyor', 'himoya')

    def list_sent_messages(self, limit=30):
        rows = self.db.execute('''
            SELECT m.id, m.target_user_id, m.title, m.body, m.created,
                   s.username AS target_username, w.display_name AS target_display,
                   (SELECT COUNT(*) FROM admin_message_reads r WHERE r.message_id = m.id) AS read_count
            FROM admin_messages m
            LEFT JOIN site_logins s ON s.user_id = m.target_user_id
            LEFT JOIN web_accounts w ON w.user_id = m.target_user_id
            ORDER BY m.created DESC LIMIT ?
        ''', (limit,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d['target_user_id']:
                d['target_label'] = '@' + d['target_username'] if d['target_username'] else (d['target_display'] or d['target_user_id'][:8])
            else:
                d['target_label'] = 'Barcha foydalanuvchilar (Umumiy e’lon)'
            result.append(d)
        return result

    def user_messages(self, uid, unread_only=False):
        sql = '''
            SELECT m.id, m.target_user_id, m.title, m.body, m.created,
                   r.read_at
            FROM admin_messages m
            LEFT JOIN admin_message_reads r ON r.message_id = m.id AND r.user_id = ?
            WHERE (m.target_user_id IS NULL OR m.target_user_id = ?)
        '''
        if unread_only:
            sql += ' AND r.read_at IS NULL'
        sql += ' ORDER BY m.created DESC LIMIT 50'
        rows = self.db.execute(sql, (uid, uid)).fetchall()
        return [dict(r, is_read=bool(r['read_at'])) for r in rows]

    def unread_count(self, uid):
        return self.db.execute('''
            SELECT COUNT(*) FROM admin_messages m
            LEFT JOIN admin_message_reads r ON r.message_id = m.id AND r.user_id = ?
            WHERE (m.target_user_id IS NULL OR m.target_user_id = ?) AND r.read_at IS NULL
        ''', (uid, uid)).fetchone()[0]

    def mark_read(self, uid, msg_id):
        if not re.fullmatch(r'[a-f0-9]{32}', msg_id or ''):
            raise SafeError('Xabar topilmadi.')
        row = self.db.execute(
            'SELECT 1 FROM admin_messages WHERE id=? AND (target_user_id IS NULL OR target_user_id=?)',
            (msg_id, uid)
        ).fetchone()
        if not row:
            raise SafeError('Xabar topilmadi.')
        with self.db:
            self.db.execute(
                'INSERT OR IGNORE INTO admin_message_reads(message_id, user_id, read_at) VALUES(?,?,?)',
                (msg_id, uid, time.time())
            )

    def mark_all_read(self, uid):
        now = time.time()
        rows = self.user_messages(uid, unread_only=True)
        with self.db:
            for r in rows:
                self.db.execute(
                    'INSERT OR IGNORE INTO admin_message_reads(message_id, user_id, read_at) VALUES(?,?,?)',
                    (r['id'], uid, now)
                )

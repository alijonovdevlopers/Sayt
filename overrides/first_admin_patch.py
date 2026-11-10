"""One-time first-owner registration, applied to the pinned ZIP at image build."""
from pathlib import Path

def replace_once(file, before, after):
    path = Path(file)
    source = path.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{file}: expected one matching block; found {count}")
    path.write_text(source.replace(before, after), encoding="utf-8")

replace_once("web_store.py", "import json\n", "import json\nimport os\n")
replace_once("web_store.py", """    def reserve_invite(self, code, flow):
        identity, now = self.key('invite:' + code), self.clock()
""", """    def reserve_invite(self, code, flow):
        # Only the first Telegram account may use this environment-only secret.
        initial = os.environ.get('INITIAL_OWNER_INVITE_CODE', '')
        if len(initial) >= 32 and hmac.compare_digest(str(code), initial):
            if (self.db.execute('SELECT 1 FROM web_accounts LIMIT 1').fetchone()
                    or self.db.execute("SELECT 1 FROM users WHERE user_id!='__system__' LIMIT 1").fetchone()):
                raise SafeError('Dastlabki kirish kodi endi amal qilmaydi.')
            return '__bootstrap__', self.key('bootstrap:' + initial)
        identity, now = self.key('invite:' + code), self.clock()
""")
replace_once("web_store.py", """    def release_invite(self, owner, identity, flow):
        with self.db:
""", """    def release_invite(self, owner, identity, flow):
        if owner == '__bootstrap__':
            return
        with self.db:
""")
replace_once("registration.py", "import asyncio\n", "import asyncio\nimport os\n")
replace_once("registration.py", """                invite = db.execute('SELECT * FROM web_invites WHERE user_id=? AND id=?', (flow['owner'], flow['invite'])).fetchone()
                if (not invite or invite['used'] or invite['revoked'] or invite['expires'] <= now or
                        invite['reserved_until'] <= now or invite['reserved_by'] != identity or not self.web.is_admin(flow['owner'])):
                    raise SafeError('Taklifning muddati tugagan yoki u bekor qilingan.')
""", """                first_owner = flow['owner'] == '__bootstrap__'
                if first_owner:
                    expected_tg = os.environ.get('ADMIN_TELEGRAM_ID', '')
                    expected_api = os.environ.get('ADMIN_API_ID', '')
                    if (not expected_tg.isdigit() or not expected_api.isdigit()
                            or me.id != int(expected_tg) or flow['api_id'] != int(expected_api)):
                        raise SafeError('Bu Telegram akkaunti administrator uchun belgilanmagan.')
                    initial = os.environ.get('INITIAL_OWNER_INVITE_CODE', '')
                    if (len(initial) < 32 or self.web.key('bootstrap:' + initial) != flow['invite']
                            or db.execute('SELECT 1 FROM web_accounts LIMIT 1').fetchone()
                            or db.execute("SELECT 1 FROM users WHERE user_id!='__system__' LIMIT 1").fetchone()):
                        raise SafeError('Dastlabki kirish kodi endi amal qilmaydi.')
                else:
                    invite = db.execute('SELECT * FROM web_invites WHERE user_id=? AND id=?', (flow['owner'], flow['invite'])).fetchone()
                    if (not invite or invite['used'] or invite['revoked'] or invite['expires'] <= now or
                            invite['reserved_until'] <= now or invite['reserved_by'] != identity or not self.web.is_admin(flow['owner'])):
                        raise SafeError('Taklifning muddati tugagan yoki u bekor qilingan.')
""")
replace_once("registration.py", """                db.execute('INSERT INTO web_accounts VALUES(?,?,?,?,0)', (uid, flow['api_id'], lookup, name or 'Telegram akkaunti'))
                db.execute('UPDATE web_invites SET used=1,used_by=?,reserved_by=NULL,reserved_until=0 WHERE user_id=? AND id=?',
                           (uid, flow['owner'], flow['invite']))
""", """                db.execute('INSERT INTO web_accounts VALUES(?,?,?,?,?)',
                           (uid, flow['api_id'], lookup, name or 'Telegram akkaunti', int(first_owner)))
                if not first_owner:
                    db.execute('UPDATE web_invites SET used=1,used_by=?,reserved_by=NULL,reserved_until=0 WHERE user_id=? AND id=?',
                               (uid, flow['owner'], flow['invite']))
""")
print("First-owner bootstrap patch applied")


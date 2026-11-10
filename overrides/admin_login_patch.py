"""Configure password-only owner login, followed by Telegram setup on first use."""
from pathlib import Path
def ch(path,old,new):
 p=Path(path); s=p.read_text(encoding='utf-8'); n=s.count(old)
 if n!=1: raise RuntimeError(f'{path}: expected 1 match, got {n}: {old[:80]}')
 p.write_text(s.replace(old,new),encoding='utf-8')
ch('web.py','import asyncio\n','import asyncio\nimport os\nimport hmac\nimport hashlib\n')
ch('web.py',"GUEST = '__Host-tg_guest'","GUEST = '__Host-tg_guest'\nADMIN_SETUP = '__Host-admin_setup'")
ch('web.py',"public = path in ('/login', '/register', '/register/verify', '/register/code', '/register/password', '/register/cancel')","public = path in ('/login', '/login/telegram', '/register', '/register/verify', '/register/code', '/register/password', '/register/cancel')")
ch('web.py','response = await self.public(path, post, values, guest, csrf, ip)',"response = await self.public(path, post, values, guest, csrf, ip, request.cookies.get(ADMIN_SETUP, ''))")
ch('web.py',"return card(form('/login', csrf, body, 'Kirish →')) + '<p class=\"center muted\">Hali akkaunt yo‘qmi? <a href=\"/register\">Taklif bilan qo‘shilish</a></p>'","return card(form('/login/telegram', csrf, body, 'Kirish →')) + '<p class=\"center muted\"><a href=\"/login\">Administrator kirishi</a></p>'")
ch('web.py',"    async def public(self, path, post, values, guest, csrf, ip):\n        if path == '/login':\n","""    def owner_credentials_valid(self, username, password):
        user = os.environ.get('ADMIN_LOGIN_USER', '')
        pwd = os.environ.get('ADMIN_PASSWORD_HASH', '')
        if not user or not pwd: return False
        ok_user = hmac.compare_digest(str(username).encode(), user.encode())
        from security import pin_verify
        ok_pwd = pin_verify(password, pwd)
        return ok_user and ok_pwd

    def first_setup_valid(self, guest, cookie):
        return bool(self.web.guest_valid(guest) and isinstance(cookie, str) and
                    hmac.compare_digest(cookie, self.web.key('owner-setup:' + guest)))

    async def public(self, path, post, values, guest, csrf, ip, setup_cookie=''):
        if path == '/login':
            if post:
                keys = self.web.rate_keys(ip, credential='configured-owner')
                self.web.rate_check(keys)
                valid = await asyncio.to_thread(self.owner_credentials_valid, values.get('username',''), values.get('password',''))
                self.web.rate_check(keys)
                if not valid:
                    self.web.rate_fail(keys)
                    raise SafeError('Login yoki parol noto‘g‘ri.')
                row = self.web.db.execute('SELECT w.user_id FROM web_accounts w JOIN users u ON u.user_id=w.user_id WHERE w.is_admin=1 AND u.telegram_id=? AND w.api_id=?', (os.environ.get('ADMIN_TELEGRAM_ID', ''), os.environ.get('ADMIN_API_ID', ''))).fetchone()
                if row:
                    session = self.web.create_session(row['user_id'])
                    response = self.cookie(self.redirect('/'), SESSION, session, 43200)
                    self.cookie(response, GUEST, '', 0)
                    self.cookie(response, ADMIN_SETUP, '', 0)
                    return response
                if self.web.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone():
                    raise SafeError('Administrator akkaunti belgilangan ID bilan mos emas.')
                response = self.redirect('/register')
                self.cookie(response, ADMIN_SETUP, self.web.key('owner-setup:' + guest), 600)
                return response
            body = '<p class="muted">Administrator hisobiga kiring.</p>'
            body += field('username', 'Login', attrs='autocomplete="username" maxlength="80"')
            body += field('password', 'Parol', 'password', attrs='autocomplete="current-password" maxlength="256"')
            return self.page('Administrator kirishi', card(form('/login', csrf, body, 'Kirish →')) + '<p class="center muted"><a href="/login/telegram">Telegram akkaunt orqali kirish</a></p>')
        if path == '/login/telegram':
""")
ch('web.py',"        if path == '/register':\n            if post:\n                await self.registration.start(guest, values, ip)\n","""        if path == '/register':
            first_setup = self.first_setup_valid(guest, setup_cookie) and not self.web.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone()
            if post:
                if first_setup:
                    values = dict(values, invite=os.environ.get('INITIAL_OWNER_INVITE_CODE', ''))
                await self.registration.start(guest, values, ip)
""")
ch('web.py',"            body = '<p class=\"muted\">Sayt egasidan olingan bir martalik taklif kodini kiriting.</p>'","            body = '<p class=\"muted\">Telegram API ma’lumotlarini kiriting.</p>' if first_setup else '<p class=\"muted\">Sayt egasidan olingan bir martalik taklif kodini kiriting.</p>'")
ch('web.py',"            body += field('invite', 'Taklif kodi', attrs='autocomplete=\"off\" maxlength=\"64\"')","            if not first_setup:\n                body += field('invite', 'Taklif kodi', attrs='autocomplete=\"off\" maxlength=\"64\"')")
ch('web.py',"                self.cookie(response, GUEST, '', 0)\n                return self.cookie(response, SESSION, session, 43200)","                self.cookie(response, GUEST, '', 0)\n                self.cookie(response, ADMIN_SETUP, '', 0)\n                return self.cookie(response, SESSION, session, 43200)")

# Update the legacy endpoint tests as a file transformation, not a single-match patch.
p = Path('test_web.py')
p.write_text(p.read_text().replace("'/login'", "'/login/telegram'"), encoding='utf-8')
print('admin login patch applied')

# Preserve same-origin form Origin while suppressing referrers to other sites.
ch('web.py', "'Referrer-Policy': 'no-referrer'", "'Referrer-Policy': 'same-origin'")

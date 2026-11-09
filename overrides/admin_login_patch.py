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
        pwd = os.environ.get('ADMIN_LOGIN_PASSWORD', '')
        if not user or len(pwd) < 12: return False
        ok_user = hmac.compare_digest(str(username).encode(), user.encode())
        ok_pwd = hmac.compare_digest(hashlib.sha256(str(password).encode()).digest(), hashlib.sha256(pwd.encode()).digest())
        return ok_user and ok_pwd

    def first_setup_valid(self, guest, cookie):
        return bool(self.web.guest_valid(guest) and isinstance(cookie, str) and
                    hmac.compare_digest(cookie, self.web.key('owner-setup:' + guest)))

    async def public(self, path, post, values, guest, csrf, ip, setup_cookie=''):
        if path == '/login':
            if post:
                keys = self.web.rate_keys(ip)
                self.web.rate_check(keys)
                if not self.owner_credentials_valid(values.get('username',''), values.get('password','')):
                    self.web.rate_fail(keys)
                    raise SafeError('Login yoki parol noto‘g‘ri.')
                row = self.web.db.execute('SELECT user_id FROM web_accounts WHERE is_admin=1 LIMIT 1').fetchone()
                if row:
                    session = self.web.create_session(row['user_id'])
                    response = self.cookie(self.redirect('/'), SESSION, session, 43200)
                    self.cookie(response, GUEST, '', 0)
                    self.cookie(response, ADMIN_SETUP, '', 0)
                    return response
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
# Run existing API/PIN tests against the preserved legacy login endpoint.
ch('test_web.py',"r = await self.client.get('/login')","r = await self.client.get('/login/telegram')")
ch('test_web.py',"await self.client.get('/login')","await self.client.get('/login/telegram')")
ch('test_web.py',"r = await self.post('/login', {'api_id': '11', 'api_hash': 'a'*32, 'pin': 'PIN123'})","r = await self.post('/login/telegram', {'api_id': '11', 'api_hash': 'a'*32, 'pin': 'PIN123'})")
ch('test_web.py',"r = await self.post('/login', {'api_id': '11', 'api_hash': 'a'*32, 'pin': ''})","r = await self.post('/login/telegram', {'api_id': '11', 'api_hash': 'a'*32, 'pin': ''})")
print('admin login patch applied')
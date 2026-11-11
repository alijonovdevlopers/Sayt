"""Official Meta Unified Login / Instagram Graph API, encrypted per-tenant tokens and approvals."""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from urllib.parse import urlencode

import httpx
from security import SafeError, SYSTEM

SCOPES = ('instagram_business_basic', 'instagram_business_manage_messages', 'instagram_business_manage_comments')


class InstagramService:
    def __init__(self, web, vault, public_url, transport=None):
        self.web, self.db, self.vault, self.public_url = web, web.db, vault, public_url
        self.transport = transport
        self.locks = {}
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS instagram_accounts (
          user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
          instagram_id TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
          token_enc BLOB NOT NULL, expires REAL NOT NULL, refreshed REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instagram_auth (
          user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
          mode TEXT NOT NULL, subject_id TEXT NOT NULL, config_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instagram_mcp (
          user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
          token_hash TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instagram_oauth (
          state_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          session_hash TEXT NOT NULL, expires REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS instagram_resources (
          user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          kind TEXT NOT NULL, resource_id TEXT NOT NULL, expires REAL NOT NULL,
          PRIMARY KEY(user_id,kind,resource_id)
        );
        CREATE TABLE IF NOT EXISTS instagram_actions (
          id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
          instagram_id TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL,
          text_enc BLOB NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS instagram_action_user ON instagram_actions(user_id,created);
        CREATE TABLE IF NOT EXISTS instagram_deletions (
          receipt_hash TEXT PRIMARY KEY, created REAL NOT NULL
        );
        ''')
        # A process may have stopped after Meta accepted a write. Never retry it automatically.
        with self.db:
            self.db.execute("UPDATE instagram_actions SET status='uncertain' WHERE status='running'")

    @property
    def configured(self):
        return bool(os.getenv('INSTAGRAM_APP_ID') and os.getenv('INSTAGRAM_APP_SECRET')
                    and (self.login_mode == 'instagram' or os.getenv('INSTAGRAM_CONFIG_ID')))

    @property
    def login_mode(self):
        mode = os.getenv('INSTAGRAM_LOGIN_MODE', 'unified')
        if mode not in ('unified', 'instagram'):
            raise SafeError('Instagram kirish usuli noto‘g‘ri sozlangan.')
        return mode

    def account_mode(self, uid):
        row = self.db.execute('SELECT mode FROM instagram_auth WHERE user_id=?', (uid,)).fetchone()
        # Existing connections predate Unified Login and retain their original host.
        return row['mode'] if row else 'instagram'

    @property
    def callback(self):
        return self.public_url + '/instagram/callback'

    @property
    def version(self):
        version = os.getenv('INSTAGRAM_GRAPH_VERSION', 'v25.0')
        if not re.fullmatch(r'v[0-9]{2}\.0', version):
            raise SafeError('Instagram API versiyasi sozlanmagan.')
        return version

    def account(self, uid):
        row = self.db.execute('SELECT instagram_id,username,expires,refreshed FROM instagram_accounts WHERE user_id=?', (uid,)).fetchone()
        return dict(row) if row else None

    def begin(self, uid, session):
        self.web.store.assert_active(uid)
        if not self.configured:
            raise SafeError('Instagram ulanishi hali sozlanmoqda. Sayt egasi Meta ilovasini ulashi kerak.')
        state = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('DELETE FROM instagram_oauth WHERE user_id=? OR expires<=?', (uid, time.time()))
            self.db.execute('INSERT INTO instagram_oauth VALUES(?,?,?,?)',
                            (self.web.key('ig-state:' + state), uid, self.web.key('session:' + session), time.time()+600))
        if self.login_mode == 'unified':
            return 'https://www.facebook.com/dialog/oauth?' + urlencode(dict(
                client_id=os.environ['INSTAGRAM_APP_ID'], config_id=os.environ['INSTAGRAM_CONFIG_ID'],
                override_default_response_type='true', redirect_uri=self.callback,
                response_type='code', state=state, prompt='login'))
        return 'https://www.instagram.com/oauth/authorize?' + urlencode(dict(
            client_id=os.environ['INSTAGRAM_APP_ID'], redirect_uri=self.callback,
            response_type='code', scope=','.join(SCOPES), state=state, enable_fb_login='0', force_authentication='1'))

    async def http(self, method, url, **kwargs):
        try:
            async with httpx.AsyncClient(timeout=25, follow_redirects=False, transport=self.transport) as client:
                response = await client.request(method, url, **kwargs)
            data = response.json()
            if not isinstance(data, dict) or response.status_code >= 400 or 'error' in data:
                code = data.get('error', {}).get('code') if isinstance(data, dict) and isinstance(data.get('error'), dict) else None
                if code == 190:
                    raise SafeError('Instagram ruxsati eskirgan yoki bekor qilingan. Akkauntni qayta ulang.')
                if response.status_code == 429 or code in (4, 17, 32, 613):
                    raise SafeError('Instagram so‘rovlar chegarasiga yetildi. Keyinroq urining.')
                raise SafeError('Instagram so‘rovni qabul qilmadi. Ruxsatlar va xabarga javob berish muddatini tekshiring.')
            return data
        except SafeError:
            raise
        except Exception:
            # Do not expose response bodies, token-bearing URLs or message contents.
            raise SafeError('Instagram bilan aloqa tugamadi. Keyinroq urining.') from None

    async def complete(self, state, code, session):
        p = self.web.resolve_session(session)
        if not p or not re.fullmatch(r'[A-Za-z0-9_-]{43}', state or ''):
            raise SafeError('Instagram ulash oynasi eskirgan. Hisobga kirib qayta ulang.')
        uid = p['user_id']
        self.web.store.assert_active(uid)
        with self.db:
            row = self.db.execute('SELECT * FROM instagram_oauth WHERE state_hash=?', (self.web.key('ig-state:' + state),)).fetchone()
            if (not row or row['user_id'] != uid or row['expires'] < time.time()
                    or not hmac.compare_digest(row['session_hash'], self.web.key('session:' + session))):
                raise SafeError('Instagram ulash tasdig‘i noto‘g‘ri yoki eskirgan.')
            self.db.execute('DELETE FROM instagram_oauth WHERE state_hash=?', (row['state_hash'],))
        if not code or len(code) > 4096:
            raise SafeError('Instagram ruxsati berilmadi. Qayta ulashingiz mumkin.')
        async with self.locks.setdefault(uid, asyncio.Lock()):
            mode = self.login_mode
            subject = ''
            if mode == 'unified':
                access, expires, profile, subject = await self.exchange_unified(uid, code)
            else:
                short = await self.http('POST', 'https://api.instagram.com/oauth/access_token', data=dict(
                    client_id=os.environ['INSTAGRAM_APP_ID'], client_secret=os.environ['INSTAGRAM_APP_SECRET'],
                    grant_type='authorization_code', redirect_uri=self.callback, code=code))
                short = short.get('data', [short])[0]
                access = short.get('access_token')
                if not access:
                    raise SafeError('Instagram kirish kalitini bermadi. Qayta ulang.')
                long = await self.http('GET', 'https://graph.instagram.com/access_token', params=dict(
                    grant_type='ig_exchange_token', client_secret=os.environ['INSTAGRAM_APP_SECRET'], access_token=access))
                access = long.get('access_token')
                if not access:
                    raise SafeError('Instagram ulanishini saqlab bo‘lmadi. Qayta ulang.')
                profile = await self.http('GET', f'https://graph.instagram.com/{self.version}/me',
                                          params={'fields': 'user_id,username'}, headers={'Authorization': 'Bearer ' + access})
                expires = time.time()+min(int(long.get('expires_in', 5184000)), 5184000)
            igid, username = str(profile.get('user_id') or profile.get('id') or ''), profile.get('username')
            if not igid.isdigit() or not username:
                raise SafeError('Instagram professional akkaunti aniqlanmadi.')
            # Session must still exist after the external calls (logout/block revokes callback).
            if not self.web.resolve_session(session):
                raise SafeError('Sayt seansi yopilgan. Qayta kiring.')
            self.web.store.assert_active(uid)
            try:
                with self.db:
                    existing = self.account(uid)
                    if existing and existing['instagram_id'] != igid:
                        raise SafeError('Boshqa Instagram ulashdan oldin hozirgi akkauntni uzing.')
                    self.db.execute('''INSERT INTO instagram_accounts VALUES(?,?,?,?,?,?)
                      ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,token_enc=excluded.token_enc,
                      expires=excluded.expires,refreshed=excluded.refreshed''',
                        (uid, igid, str(username)[:100], self.vault.fernet.encrypt(access.encode()),
                         expires, time.time()))
                    self.db.execute('INSERT OR REPLACE INTO instagram_auth VALUES(?,?,?,?)',
                        (uid, mode, subject or igid, os.getenv('INSTAGRAM_CONFIG_ID', '') if mode == 'unified' else ''))
            except sqlite3.IntegrityError:
                raise SafeError('Bu Instagram boshqa sayt hisobiga ulangan.') from None
            self.web.store.audit(uid, 'instagram_ulash', {}, 'tayyor', 'himoya')
            return uid

    async def exchange_unified(self, uid, code):
        base = f'https://graph.facebook.com/{self.version}'
        result = await self.http('GET', base+'/oauth/access_token', params=dict(
            client_id=os.environ['INSTAGRAM_APP_ID'], client_secret=os.environ['INSTAGRAM_APP_SECRET'],
            redirect_uri=self.callback, code=code))
        access = result.get('access_token')
        if not isinstance(access, str) or not access:
            raise SafeError('Meta kirish kalitini bermadi. Qayta ulang.')
        lifetime = result.get('expires_in')
        if isinstance(lifetime, (int, float)) and lifetime > 0:
            expires = time.time() + lifetime
        elif os.getenv('INSTAGRAM_TOKEN_LIFETIME') == 'never':
            # Zero is an explicit non-expiring configuration, never a guessed 60-day TTL.
            expires = 0
        else:
            raise SafeError('Meta token muddati aniqlanmadi. Konfiguratsiya muddatini tekshiring.')
        headers = {'Authorization': 'Bearer ' + access}
        subject = await self.http('GET', base+'/me', params={'fields': 'id'}, headers=headers)
        subject_id = str(subject.get('id', ''))
        if not subject_id.isdigit():
            raise SafeError('Meta tizim foydalanuvchisi aniqlanmadi.')
        accounts, seen, after = {}, set(), None
        for _ in range(50):
            params = {'fields': 'id,username', 'limit': 100}
            if after:
                params['after'] = after
            page = await self.http('GET', base+'/me/assigned_instagram_accounts', params=params, headers=headers)
            rows = page.get('data')
            if not isinstance(rows, list):
                raise SafeError('Instagram akkauntlari ro‘yxati olinmadi.')
            for row in rows:
                ident = str(row.get('id', ''))
                if not ident.isdigit() or not row.get('username'):
                    raise SafeError('Instagram akkaunti aniqlanmadi.')
                accounts[ident] = row
            after = page.get('paging', {}).get('cursors', {}).get('after')
            if not rows or not after:
                break
            if not isinstance(after, str) or len(after) > 2048 or after in seen:
                raise SafeError('Instagram akkauntlari sahifasi takrorlandi. Qayta ulang.')
            seen.add(after)
        else:
            raise SafeError('Instagram akkauntlari juda ko‘p. Faqat kerakli akkauntni tanlang.')
        existing = self.account(uid)
        if existing and existing['instagram_id'] in accounts:
            profile = accounts[existing['instagram_id']]
        elif len(accounts) == 1:
            profile = next(iter(accounts.values()))
        elif not accounts:
            raise SafeError('Instagram professional akkaunti ulashilmadi. Meta oynasida akkauntga ruxsat bering.')
        else:
            raise SafeError('Bir nechta Instagram tanlangan. Qayta ulab, faqat kerakli bitta akkauntga ruxsat bering.')
        return access, expires, profile, subject_id

    async def token(self, uid):
        self.web.store.assert_active(uid)
        row = self.db.execute('SELECT * FROM instagram_accounts WHERE user_id=?', (uid,)).fetchone()
        if not row or (row['expires'] != 0 and row['expires'] <= time.time()):
            raise SafeError('Instagram akkauntingizni saytda ulang yoki qayta ulang.')
        token = self.vault.fernet.decrypt(row['token_enc']).decode()
        if self.account_mode(uid) == 'instagram' and row['expires'] - time.time() < 14*86400 and time.time() - row['refreshed'] > 86400:
            fresh = await self.http('GET', 'https://graph.instagram.com/refresh_access_token',
                                    params={'grant_type': 'ig_refresh_token', 'access_token': token})
            token = fresh['access_token']
            with self.db:
                self.db.execute('UPDATE instagram_accounts SET token_enc=?,expires=?,refreshed=? WHERE user_id=?',
                    (self.vault.fernet.encrypt(token.encode()), time.time()+min(int(fresh['expires_in']),5184000), time.time(), uid))
        return token

    async def graph(self, uid, path, *, method='GET', params=None, body=None):
        token = await self.token(uid)
        host = 'graph.instagram.com'
        if self.account_mode(uid) == 'unified':
            host = 'graph.facebook.com'
            if path == 'me' or path.startswith('me/'):
                path = self.account(uid)['instagram_id'] + path[2:]
        return await self.http(method, f'https://{host}/{self.version}/{path}',
                               params=params, json=body, headers={'Authorization': 'Bearer ' + token})

    def rotate(self, uid):
        self.web.store.assert_active(uid)
        if not self.account(uid):
            raise SafeError('Avval Instagram akkauntingizni ulang.')
        token = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('INSERT INTO instagram_mcp VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash',
                            (uid, self.web.key('ig-mcp:' + token)))
        return token

    def authenticate(self, token):
        row = self.db.execute('''SELECT t.user_id FROM instagram_mcp t JOIN users u ON u.user_id=t.user_id
          JOIN instagram_accounts a ON a.user_id=t.user_id WHERE t.token_hash=? AND u.blocked=0''',
                              (self.web.key('ig-mcp:' + token),)).fetchone()
        return row['user_id'] if row else None

    def disconnect(self, uid):
        with self.db:
            for table in ('instagram_mcp','instagram_oauth','instagram_resources','instagram_actions','instagram_auth','instagram_accounts'):
                self.db.execute(f'DELETE FROM {table} WHERE user_id=?', (uid,))

    def remember(self, uid, kind, ids):
        with self.db:
            self.db.execute('DELETE FROM instagram_resources WHERE expires<?', (time.time(),))
            for ident in ids:
                if ident and re.fullmatch(r'[A-Za-z0-9_:.=-]{1,300}', str(ident)):
                    self.db.execute('INSERT OR REPLACE INTO instagram_resources VALUES(?,?,?,?)',
                                    (uid, kind, str(ident), time.time()+86400))

    def require_resource(self, uid, kind, ident):
        if not isinstance(ident, str) or not self.db.execute('SELECT 1 FROM instagram_resources WHERE user_id=? AND kind=? AND resource_id=? AND expires>?', (uid, kind, ident, time.time())).fetchone():
            raise SafeError('Nishon ushbu hisob uchun topilmadi. Avval uning ro‘yxatini oling.')

    @staticmethod
    def pagination(data):
        def clean(value):
            if isinstance(value, list):
                return [clean(v) for v in value]
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if k not in ('paging', 'access_token')}
            return value
        return {'data': clean(data.get('data', [])), 'after': data.get('paging', {}).get('cursors', {}).get('after')}

    async def maintain(self):
        while True:
            now = time.time()
            with self.db:
                self.db.execute('DELETE FROM instagram_actions WHERE expires<? AND status!=?', (now-86400, 'running'))
                self.db.execute('DELETE FROM instagram_resources WHERE expires<?', (now,))
                self.db.execute('DELETE FROM instagram_oauth WHERE expires<?', (now,))
                self.db.execute('DELETE FROM web_sessions WHERE expires<?', (now,))
                self.db.execute('DELETE FROM site_signup_limits WHERE reset<?', (now,))
                self.db.execute('DELETE FROM instagram_deletions WHERE created<?', (now-30*86400,))
            await asyncio.sleep(60)


    @staticmethod
    def listing(limit, after):
        if type(limit) is not int or not 1 <= limit <= 50 or not isinstance(after, str) or len(after) > 2048 or (after and not re.fullmatch(r'[A-Za-z0-9_=-]+', after)):
            raise SafeError('Limit 1–50 bo‘lsin; sahifa kursori noto‘g‘ri.')
        return dict(limit=limit, **({'after': after} if after else {}))

    async def call(self, uid, tool, args):
        async with self.locks.setdefault(uid, asyncio.Lock()):
            self.web.store.assert_active(uid)
            if tool == 'instagram_profile':
                fields = 'id,username,name,media_count' if self.account_mode(uid) == 'unified' else 'user_id,username,name,account_type,media_count'
                return await self.graph(uid, 'me', params={'fields': fields})
            if tool in ('instagram_posts','instagram_conversations','instagram_comments','instagram_messages'):
                params = self.listing(args.get('limit',20), args.get('after',''))
                if tool == 'instagram_posts':
                    path, kind = 'me/media', 'media'
                    params['fields'] = 'id,caption,media_type,permalink,timestamp'
                elif tool == 'instagram_conversations':
                    path, kind = 'me/conversations', 'conversation'
                    params.update(platform='instagram', fields='id,updated_time,participants')
                elif tool == 'instagram_comments':
                    ident = args.get('media_id')
                    self.require_resource(uid, 'media', ident)
                    path, kind = ident+'/comments', 'comment'
                    params['fields'] = 'id,text,username,timestamp'
                else:
                    ident = args.get('conversation_id')
                    self.require_resource(uid, 'conversation', ident)
                    # Conversation messages edge returns IDs; expanded field supplies safe text details.
                    data = await self.graph(uid, ident, params={'fields': f"messages.limit({params['limit']})" +
                        ('.after(' + args['after'] + ')' if args.get('after') and re.fullmatch(r'[A-Za-z0-9_=-]+', args['after']) else '') + '{id,created_time,from,to,message}'})
                    data = data.get('messages', {})
                    return self.pagination(data)
                data = await self.graph(uid, path, params=params)
                self.remember(uid, kind, [r.get('id') for r in data.get('data', [])])
                return self.pagination(data)
            if tool in ('instagram_prepare_reply','instagram_prepare_comment_reply'):
                kind = 'message' if tool == 'instagram_prepare_reply' else 'comment'
                target = args.get('conversation_id') if kind == 'message' else args.get('comment_id')
                self.require_resource(uid, 'conversation' if kind == 'message' else 'comment', target)
                text = args.get('text')
                if not isinstance(text, str) or not 1 <= len(text.strip()) <= 1000:
                    raise SafeError('Javob matni 1–1000 belgi bo‘lsin.')
                if not self.account(uid):
                    raise SafeError('Avval Instagram akkauntingizni ulang.')
                now, aid = time.time(), uuid.uuid4().hex
                with self.db:
                    self.db.execute('DELETE FROM instagram_actions WHERE expires<?', (now-86400,))
                    if self.db.execute('SELECT COUNT(*) FROM instagram_actions WHERE user_id=? AND created>?', (uid, now-3600)).fetchone()[0] >= 30:
                        raise SafeError('Bir soatda 30 ta taklif chegarasi. Keyinroq urining.')
                    self.db.execute('INSERT INTO instagram_actions VALUES(?,?,?,?,?,?,?,?,?)',
                        (aid,uid,self.account(uid)['instagram_id'],kind,target,self.vault.fernet.encrypt(text.encode()),'pending',now,now+600))
                return {'status':'tasdiq_kutilmoqda','action_id':aid,'approval_url':self.public_url+'/instagram/actions/'+aid,
                        'notice':'Egasi saytda tasdiqlamaguncha hech qanday xabar yuborilmaydi.'}
            raise SafeError('Instagram vositasi topilmadi.')

    def action(self, uid, aid):
        row = self.db.execute('SELECT * FROM instagram_actions WHERE user_id=? AND id=?', (uid,aid)).fetchone()
        if not row:
            raise SafeError('Amal topilmadi.')
        result = dict(row)
        result['text'] = self.vault.fernet.decrypt(row['text_enc']).decode()
        return result

    async def decide(self, uid, aid, approve):
        async with self.locks.setdefault(uid, asyncio.Lock()):
            self.web.store.assert_active(uid)
            row = self.action(uid,aid)
            if row['status'] != 'pending' or row['expires'] <= time.time():
                raise SafeError('Amal muddati tugagan yoki ko‘rib chiqilgan.')
            if not self.account(uid) or self.account(uid)['instagram_id'] != row['instagram_id']:
                raise SafeError('Instagram akkaunti o‘zgargan. Amal bekor qilindi.')
            with self.db:
                self.db.execute('UPDATE instagram_actions SET status=? WHERE user_id=? AND id=?',
                                ('running' if approve else 'rejected',uid,aid))
            if not approve:
                return
            try:
                if row['kind'] == 'comment':
                    await self.graph(uid,row['target']+'/replies',method='POST',body={'message':row['text']})
                else:
                    details = await self.graph(uid,row['target'],params={'fields':'participants'})
                    own = row['instagram_id']
                    people = details.get('participants',{}).get('data',[])
                    ids = [str(p.get('id','')) for p in people]
                    others = [p for p in ids if p != own]
                    if own not in ids or len(others) != 1:
                        raise SafeError('Suhbat egasi tasdiqlanmadi.')
                    # Meta enforces its reply window; never use HUMAN_AGENT to bypass it.
                    await self.graph(uid, own+'/messages',method='POST',body={'recipient':{'id':others[0]},'message':{'text':row['text']}})
            except Exception:
                with self.db:
                    self.db.execute("UPDATE instagram_actions SET status='uncertain' WHERE user_id=? AND id=?", (uid,aid))
                raise SafeError('Natija tasdiqlanmadi. Qayta yuborishdan oldin Instagram’da tekshiring.') from None
            with self.db:
                self.db.execute("UPDATE instagram_actions SET status='done' WHERE user_id=? AND id=?", (uid,aid))
            self.web.store.audit(uid,'instagram_javob',{},'tayyor','B')

    def signed_user(self, signed):
        try:
            sig, body = signed.split('.')
            decode = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s)%4))
            expected = hmac.new(os.environ['INSTAGRAM_APP_SECRET'].encode(), body.encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, decode(sig)):
                raise ValueError()
            data = json.loads(decode(body))
            if data.get('algorithm','').upper() != 'HMAC-SHA256' or not str(data['user_id']).isdigit():
                raise ValueError()
            return str(data['user_id'])
        except Exception:
            raise SafeError('Instagram tasdig‘i yaroqsiz.') from None

"""Google orqali kirish: PKCE, imzolangan oqim cookiesi, email ruxsat ro‘yxati va admin emaili.

Bu modul faqat mantiq: Starlette/MCP/Telethonga bog‘liq emas, shuning uchun alohida sinaladi.
Google bilan faqat ‘kim ekanligi’ aniqlanadi (email + sub). Telegram sessiyasi alohida ulanadi.
"""
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from urllib.parse import urlencode

from security import SafeError, fingerprint

AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo'
EMAIL_RE = re.compile(r'[a-z0-9._%+\-]{1,64}@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,24}')
FLOW_SECONDS = 600
TICKET_SECONDS = 1800
MAX_USERS = 50
TOKEN_ERRORS = {
    'invalid_client': 'Google ilova kalitlarini qabul qilmadi. Client ID va Client secret juftligini tekshiring.',
    'invalid_grant': 'Google kirish kodi yaroqsiz yoki eskirgan. Kirish sahifasidan qayta boshlang.',
    'redirect_uri_mismatch': 'Google qaytish manzili mos emas. Authorized redirect URIs sozlamasini tekshiring.',
    'unauthorized_client': 'Bu Google ilovasiga ushbu kirish usuli uchun ruxsat berilmagan.',
    'invalid_request': 'Google kirish so‘rovi parametrlarini qabul qilmadi.',
    'deleted_client': 'Google OAuth ilovasi o‘chirilgan.',
}


def token_error(response):
    # Faqat tanilgan kodni chiqaramiz; javob matnida maxfiy qiymatlar bo‘lishi mumkin.
    try:
        payload = response.json()
    except ValueError:
        payload = None
    code = payload.get('error') if isinstance(payload, dict) else None
    code = code if isinstance(code, str) and code in TOKEN_ERRORS else 'unknown'
    logging.getLogger(__name__).warning(
        'Google token exchange failed: status=%s error=%s', response.status_code, code)
    message = TOKEN_ERRORS.get(code, 'Google kirishni qabul qilmadi. Qayta urining.')
    return SafeError(message + ' [Google: ' + code + '; HTTP ' + str(response.status_code) + ']')


def schema(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS web_google (
      email TEXT PRIMARY KEY, sub TEXT, user_id TEXT,
      blocked INTEGER NOT NULL DEFAULT 0, added REAL NOT NULL, added_by TEXT
    );
    ''')


def normalize_email(text):
    value = text.strip().lower() if isinstance(text, str) else ''
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise SafeError('Email formati noto‘g‘ri.')
    return value


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


class Http:
    """Google bilan HTTPS aloqa. Sinovlarda shu interfeysli soxta obyekt beriladi."""

    async def post_form(self, url, data):
        import httpx
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.post(url, data=data)
        if response.status_code != 200:
            raise token_error(response)
        return response.json()

    async def get_json(self, url, access_token):
        import httpx
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.get(url, headers={'Authorization': 'Bearer ' + access_token})
        if response.status_code != 200:
            raise SafeError('Google akkaunt ma’lumotini bermadi. Qayta urining.')
        return response.json()


class GoogleAuth:
    def __init__(self, db, pepper, *, client_id, client_secret, public_url, admin_email,
                 clock=time.time, http=None):
        self.db, self.pepper, self.clock = db, pepper, clock
        schema(db)
        self.client_id, self.client_secret = client_id, client_secret
        self.redirect_uri = public_url.rstrip('/') + '/auth/google/callback'
        self.admin_email = normalize_email(admin_email)
        self.http = http or Http()

    def key(self, text):
        return fingerprint(self.pepper, text)

    # ---- kirish oqimi -------------------------------------------------
    def begin(self):
        """Google sahifasiga URL va brauzerga qo‘yiladigan imzolangan cookie qiymatini qaytaradi."""
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        body = _b64(json.dumps({'s': state, 'v': verifier, 'e': int(self.clock()) + FLOW_SECONDS},
                               separators=(',', ':')).encode())
        cookie = body + '.' + self.key('gflow:' + body)
        url = AUTH_URL + '?' + urlencode({
            'client_id': self.client_id, 'redirect_uri': self.redirect_uri,
            'response_type': 'code', 'scope': 'openid email', 'state': state,
            'code_challenge': challenge, 'code_challenge_method': 'S256',
            'prompt': 'select_account', 'access_type': 'online'})
        return url, cookie

    def _open(self, cookie):
        try:
            body, sig = cookie.split('.')
            if not hmac.compare_digest(sig, self.key('gflow:' + body)):
                raise ValueError('imzo')
            flow = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
            if not isinstance(flow, dict) or int(flow['e']) <= self.clock():
                raise ValueError('muddat')
            return flow
        except (ValueError, TypeError, KeyError, AttributeError):
            raise SafeError('Kirish oynasi eskirgan. Google bilan qayta kiring.') from None

    async def finish(self, cookie, state, code):
        """Callback: Google identifikatsiyasini tekshiradi va (email, sub) qaytaradi."""
        flow = self._open(cookie)
        if not isinstance(state, str) or not hmac.compare_digest(state.encode(), flow['s'].encode()):
            raise SafeError('Kirish oynasi mos kelmadi. Google bilan qayta kiring.')
        if not isinstance(code, str) or not 10 <= len(code) <= 2048:
            raise SafeError('Google kodi noto‘g‘ri.')
        try:
            token = await self.http.post_form(TOKEN_URL, {
                'code': code, 'client_id': self.client_id, 'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri, 'grant_type': 'authorization_code',
                'code_verifier': flow['v']})
            access = token.get('access_token') if isinstance(token, dict) else None
            if not isinstance(access, str) or not access:
                raise SafeError('Google kirishni qabul qilmadi. Qayta urining.')
            info = await self.http.get_json(USERINFO_URL, access)
        except SafeError:
            raise
        except Exception:
            raise SafeError('Google bilan bog‘lanib bo‘lmadi. Qayta urining.') from None
        if not isinstance(info, dict) or info.get('email_verified') is not True:
            raise SafeError('Google emailingiz tasdiqlanmagan.')
        sub = info.get('sub')
        if not isinstance(sub, str) or not re.fullmatch(r'[0-9A-Za-z_.\-]{1,255}', sub):
            raise SafeError('Google akkauntini aniqlab bo‘lmadi.')
        return normalize_email(info.get('email')), sub

    # ---- Google bilan kirgan, lekin Telegram hali ulanmagan odam uchun chipta ----
    def ticket(self, email):
        body = _b64(json.dumps({'m': normalize_email(email), 'e': int(self.clock()) + TICKET_SECONDS},
                               separators=(',', ':')).encode())
        return body + '.' + self.key('gticket:' + body)

    def ticket_email(self, token):
        """Chipta yaroqli bo‘lsa va email hali ruxsat ro‘yxatida bo‘lsa emailni qaytaradi, aks holda None."""
        try:
            body, sig = token.split('.')
            if not hmac.compare_digest(sig, self.key('gticket:' + body)):
                return None
            data = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
            email = normalize_email(data['m'])
            if int(data['e']) <= self.clock():
                return None
        except (ValueError, TypeError, KeyError, AttributeError, SafeError):
            return None
        row = self.db.execute('SELECT blocked FROM web_google WHERE email=?', (email,)).fetchone()
        if not row or (row['blocked'] and email != self.admin_email):
            return None
        return email

    def linked_admin_uid(self):
        """Sayt egasi (is_admin) hisobining ID si; yo‘q bo‘lsa None."""
        row = self.db.execute('SELECT user_id FROM web_accounts WHERE is_admin=1 LIMIT 2').fetchall()
        return row[0]['user_id'] if len(row) == 1 else None

    # ---- ruxsat ro‘yxati ----------------------------------------------
    def admit(self, email, sub):
        """Email ro‘yxatda (yoki admin) bo‘lsa va sub mos kelsa kirishga ruxsat."""
        email = normalize_email(email)
        denied = SafeError('Bu email ruxsat ro‘yxatida yo‘q. Sayt egasiga murojaat qiling.')
        is_admin = email == self.admin_email
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT * FROM web_google WHERE email=?', (email,)).fetchone()
            if not row:
                if not is_admin:
                    raise denied
                self.db.execute('INSERT INTO web_google(email,sub,added,added_by) VALUES(?,?,?,?)',
                                (email, sub, self.clock(), 'admin_email'))
                row = self.db.execute('SELECT * FROM web_google WHERE email=?', (email,)).fetchone()
            if row['blocked'] and not is_admin:
                raise denied
            if row['sub'] is None:
                self.db.execute('UPDATE web_google SET sub=? WHERE email=?', (sub, email))
            elif not hmac.compare_digest(row['sub'].encode(), sub.encode()):
                raise SafeError('Bu email boshqa Google akkauntga bog‘langan. Sayt egasiga murojaat qiling.')
        return {'email': email, 'user_id': row['user_id'], 'is_admin': is_admin}

    def allow(self, email, added_by):
        email = normalize_email(email)
        if self.db.execute('SELECT COUNT(*) FROM web_google WHERE email!=?', (self.admin_email,)).fetchone()[0] >= MAX_USERS - 1 \
                and not self.db.execute('SELECT 1 FROM web_google WHERE email=?', (email,)).fetchone():
            raise SafeError('Foydalanuvchilar chegarasi (' + str(MAX_USERS) + ') to‘ldi.')
        with self.db:
            self.db.execute('INSERT INTO web_google(email,added,added_by) VALUES(?,?,?) '
                            'ON CONFLICT(email) DO UPDATE SET blocked=0', (email, self.clock(), added_by))

    def remove(self, email):
        email = normalize_email(email)
        if email == self.admin_email:
            raise SafeError('Sayt egasi emailini o‘chirib bo‘lmaydi.')
        with self.db:
            self.db.execute('DELETE FROM web_google WHERE email=?', (email,))

    def set_blocked(self, email, blocked):
        email = normalize_email(email)
        if email == self.admin_email:
            raise SafeError('Sayt egasini bloklab bo‘lmaydi.')
        with self.db:
            self.db.execute('UPDATE web_google SET blocked=? WHERE email=?', (int(bool(blocked)), email))

    def link(self, email, user_id):
        """Telegram ulanib bo‘lgach, emailni foydalanuvchi IDga bog‘lash."""
        with self.db:
            self.db.execute('UPDATE web_google SET user_id=? WHERE email=?', (user_id, normalize_email(email)))

    def listing(self):
        return [dict(r) for r in self.db.execute(
            'SELECT email,user_id,blocked,added FROM web_google ORDER BY added')]


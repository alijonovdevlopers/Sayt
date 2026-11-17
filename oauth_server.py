"""MCP uchun OAuth 2.1: mijozni ro‘yxatdan o‘tkazish, PKCE, bir martalik kod, aylanuvchi token.

Faqat mantiq: Starlette/MCPga bog‘liq emas. Tokenlar bazada faqat xesh holida saqlanadi.
Mijozlar ommaviy (public) va faqat PKCE S256 bilan ishlaydi.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from security import SafeError, fingerprint

ACCESS_SECONDS = 3600
REFRESH_SECONDS = 30 * 86400
CODE_SECONDS = 60
MAX_CLIENTS = 100
MAX_REDIRECTS = 5
CLIENT_TTL = 86400
ACCESS_PREFIX = 'mcpa_'
REFRESH_PREFIX = 'mcpr_'
VERIFIER_RE = re.compile(r'[A-Za-z0-9\-._~]{43,128}')
CHALLENGE_RE = re.compile(r'[A-Za-z0-9_-]{43}')
LOOPBACK = {'127.0.0.1', 'localhost', '::1'}
DEFAULT_REDIRECTS = ('https://claude.ai/api/mcp/auth_callback', 'https://claude.com/api/mcp/auth_callback')
GRANT_TYPES = {'authorization_code', 'refresh_token'}


class OAuthError(SafeError):
    """Token/ro‘yxat uchun standart OAuth xato kodi bilan."""

    def __init__(self, code, text):
        super().__init__(text)
        self.code = code


def schema(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY, name TEXT NOT NULL, redirect_uris TEXT NOT NULL, created REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_grants (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL, created REAL NOT NULL,
      last_used REAL NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
      challenge TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0, grant_id TEXT
    );
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      token_hash TEXT PRIMARY KEY, kind TEXT NOT NULL, grant_id TEXT NOT NULL,
      expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens(grant_id);
    CREATE INDEX IF NOT EXISTS oauth_grants_user ON oauth_grants(user_id);
    ''')


def same(a, b):
    """Doimiy vaqtli solishtirish; ASCII bo‘lmagan kirishda ham xato bermaydi."""
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


class OAuthServer:
    def __init__(self, db, pepper, public_url, *, redirects=DEFAULT_REDIRECTS, clock=time.time):
        self.db, self.pepper, self.clock = db, pepper, clock
        self.issuer = public_url.rstrip('/')
        self.resource = self.issuer + '/mcp'
        self.redirect_allow = frozenset(redirects)
        schema(db)

    def h(self, kind, value):
        return fingerprint(self.pepper, 'oauth-' + kind + ':' + value)

    # ---- metadata hujjatlari (RFC 9728, RFC 8414) -----------------------
    def protected_resource_metadata(self):
        return {'resource': self.resource, 'authorization_servers': [self.issuer],
                'bearer_methods_supported': ['header'], 'scopes_supported': ['mcp']}

    def authorization_server_metadata(self):
        return {'issuer': self.issuer,
                'authorization_endpoint': self.issuer + '/oauth/authorize',
                'token_endpoint': self.issuer + '/oauth/token',
                'registration_endpoint': self.issuer + '/oauth/register',
                'revocation_endpoint': self.issuer + '/oauth/revoke',
                'response_types_supported': ['code'],
                'grant_types_supported': sorted(GRANT_TYPES),
                'code_challenge_methods_supported': ['S256'],
                'token_endpoint_auth_methods_supported': ['none'],
                'scopes_supported': ['mcp'],
                'authorization_response_iss_parameter_supported': True}

    # ---- mijozni ro‘yxatdan o‘tkazish (RFC 7591) -------------------------
    def redirect_ok(self, uri):
        if not isinstance(uri, str) or not uri or len(uri) > 512 or any(c.isspace() or ord(c) < 32 for c in uri):
            return False
        if uri in self.redirect_allow:
            return True
        try:
            parts = urlsplit(uri)
            parts.port  # noto‘g‘ri port ValueError beradi
        except ValueError:
            return False
        return (parts.scheme == 'http' and parts.hostname in LOOPBACK and parts.path.startswith('/')
                and not parts.fragment and not parts.username and not parts.password)

    def register(self, body):
        bad = lambda text: OAuthError('invalid_client_metadata', text)
        if not isinstance(body, dict):
            raise bad('So‘rov formati noto‘g‘ri.')
        uris = body.get('redirect_uris')
        if not isinstance(uris, list) or not 1 <= len(uris) <= MAX_REDIRECTS or not all(self.redirect_ok(u) for u in uris):
            raise OAuthError('invalid_redirect_uri', 'Yo‘naltirish manzili ruxsat etilmagan.')
        grants = body.get('grant_types')
        if grants is not None and (not isinstance(grants, list) or not set(grants) <= GRANT_TYPES):
            raise bad('Bu grant turi qo‘llab-quvvatlanmaydi.')
        name = body.get('client_name')
        name = ''.join(c for c in name if c.isprintable())[:100].strip() if isinstance(name, str) else ''
        name = name or 'Noma’lum ilova'
        now = self.clock()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if self.db.execute('SELECT COUNT(*) FROM oauth_clients').fetchone()[0] >= MAX_CLIENTS:
                self.db.execute('''DELETE FROM oauth_clients WHERE created<? AND client_id NOT IN
                                   (SELECT client_id FROM oauth_grants WHERE revoked=0)''', (now - CLIENT_TTL,))
                if self.db.execute('SELECT COUNT(*) FROM oauth_clients').fetchone()[0] >= MAX_CLIENTS:
                    raise OAuthError('invalid_client_metadata', 'Ro‘yxatdan o‘tkazish chegarasi to‘ldi. Keyinroq urining.')
            client_id = secrets.token_urlsafe(18)
            self.db.execute('INSERT INTO oauth_clients VALUES(?,?,?,?)', (client_id, name, json.dumps(uris), now))
        return {'client_id': client_id, 'client_name': name, 'redirect_uris': uris,
                'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'],
                'token_endpoint_auth_method': 'none', 'client_id_issued_at': int(now)}

    def client(self, client_id):
        row = self.db.execute('SELECT * FROM oauth_clients WHERE client_id=?',
                              (client_id if isinstance(client_id, str) else '',)).fetchone()
        if not row:
            raise OAuthError('invalid_client', 'Ilova ro‘yxatdan o‘tmagan.')
        return {'client_id': row['client_id'], 'name': row['name'], 'redirect_uris': json.loads(row['redirect_uris'])}

    # ---- ruxsat so‘rovi -------------------------------------------------
    def validate_authorize(self, q):
        """Xato bo‘lsa SafeError: foydalanuvchi boshqa saytga YO‘NALTIRILMAYDI, sahifada ko‘rsatiladi."""
        q = {k: v for k, v in q.items() if isinstance(v, str)}
        client = self.client(q.get('client_id'))
        if q.get('redirect_uri') not in client['redirect_uris']:
            raise SafeError('Yo‘naltirish manzili ilova ro‘yxatiga mos kelmadi.')
        if q.get('response_type') != 'code':
            raise SafeError('So‘rov turi noto‘g‘ri.')
        if q.get('code_challenge_method') != 'S256' or not CHALLENGE_RE.fullmatch(q.get('code_challenge', '')):
            raise SafeError('PKCE (S256) majburiy.')
        if q.get('resource') and q['resource'] != self.resource:
            raise SafeError('resource manzili noto‘g‘ri.')
        state = q.get('state', '')
        if len(state) > 512:
            raise SafeError('state juda uzun.')
        return {'client_id': client['client_id'], 'client_name': client['name'], 'redirect_uri': q['redirect_uri'],
                'challenge': q['code_challenge'], 'state': state}

    def _redirect(self, req, params):
        parts = urlsplit(req['redirect_uri'])
        query = parse_qsl(parts.query, keep_blank_values=True)
        query += [(k, v) for k, v in params.items() if v]
        query.append(('iss', self.issuer))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ''))

    def approve(self, req, user_id):
        """Foydalanuvchi ruxsat berdi: bir martalik kod bilan qaytish manzilini beradi."""
        code = secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,challenge,expires) VALUES(?,?,?,?,?,?)',
                            (self.h('code', code), req['client_id'], user_id, req['redirect_uri'], req['challenge'],
                             self.clock() + CODE_SECONDS))
        return self._redirect(req, {'code': code, 'state': req['state']})

    def deny(self, req):
        return self._redirect(req, {'error': 'access_denied', 'state': req['state']})

    # ---- token oxirgi nuqtasi ------------------------------------------
    def _issue(self, grant_id):
        now, access, refresh = self.clock(), ACCESS_PREFIX + secrets.token_urlsafe(32), REFRESH_PREFIX + secrets.token_urlsafe(32)
        self.db.execute('INSERT INTO oauth_tokens(token_hash,kind,grant_id,expires) VALUES(?,?,?,?)',
                        (self.h('access', access), 'access', grant_id, now + ACCESS_SECONDS))
        self.db.execute('INSERT INTO oauth_tokens(token_hash,kind,grant_id,expires) VALUES(?,?,?,?)',
                        (self.h('refresh', refresh), 'refresh', grant_id, now + REFRESH_SECONDS))
        return {'access_token': access, 'token_type': 'Bearer', 'expires_in': ACCESS_SECONDS,
                'refresh_token': refresh, 'scope': 'mcp'}

    def _prune(self):
        now = self.clock()
        self.db.execute('DELETE FROM oauth_codes WHERE expires<?', (now - 3600,))
        self.db.execute('DELETE FROM oauth_tokens WHERE expires<?', (now - 86400,))

    def token(self, form):
        form = {k: v for k, v in form.items() if isinstance(v, str)}
        kind = form.get('grant_type')
        if kind == 'authorization_code':
            return self._exchange_code(form)
        if kind == 'refresh_token':
            return self._refresh(form)
        raise OAuthError('unsupported_grant_type', 'Bu grant turi qo‘llab-quvvatlanmaydi.')

    def _exchange_code(self, form):
        invalid = OAuthError('invalid_grant', 'Kod yaroqsiz yoki muddati tugagan.')
        code, verifier = form.get('code', ''), form.get('code_verifier', '')
        if not code or not VERIFIER_RE.fullmatch(verifier):
            raise OAuthError('invalid_request', 'code va code_verifier kerak.')
        if form.get('resource') and form['resource'] != self.resource:
            raise OAuthError('invalid_target', 'resource manzili noto‘g‘ri.')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT * FROM oauth_codes WHERE code_hash=?', (self.h('code', code),)).fetchone()
            if not row:
                raise invalid
            if row['used']:
                # Kod qayta ishlatildi: shu koddan chiqqan hamma tokenlar bekor qilinadi (OAuth 2.1).
                if row['grant_id']:
                    self.db.execute('UPDATE oauth_grants SET revoked=1 WHERE id=?', (row['grant_id'],))
                self.db.commit()
                raise invalid
            checks = (row['expires'] > self.clock(),
                      same(row['client_id'], form.get('client_id', '')),
                      same(row['redirect_uri'], form.get('redirect_uri', '')),
                      same(row['challenge'], s256(verifier)))
            if not all(checks):
                raise invalid
            grant = secrets.token_hex(16)
            self.db.execute('UPDATE oauth_codes SET used=1,grant_id=? WHERE code_hash=?', (grant, row['code_hash']))
            self.db.execute('INSERT INTO oauth_grants(id,user_id,client_id,created) VALUES(?,?,?,?)',
                            (grant, row['user_id'], row['client_id'], self.clock()))
            result = self._issue(grant)
            self._prune()
        return result

    def _refresh(self, form):
        invalid = OAuthError('invalid_grant', 'Refresh token yaroqsiz yoki muddati tugagan.')
        refresh = form.get('refresh_token', '')
        if not refresh.startswith(REFRESH_PREFIX) or len(refresh) > 200:
            raise invalid
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('''SELECT t.*, g.client_id, g.revoked FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id
                                     WHERE t.token_hash=? AND t.kind='refresh' ''', (self.h('refresh', refresh),)).fetchone()
            if not row or row['revoked']:
                raise invalid
            if not same(row['client_id'], form.get('client_id', '')):
                raise invalid
            if row['used']:
                # Eski refresh token qayta ishlatildi: o‘g‘irlangan bo‘lishi mumkin, butun ruxsat bekor qilinadi.
                self.db.execute('UPDATE oauth_grants SET revoked=1 WHERE id=?', (row['grant_id'],))
                self.db.commit()
                raise invalid
            if row['expires'] <= self.clock():
                raise invalid
            self.db.execute('UPDATE oauth_tokens SET used=1 WHERE token_hash=?', (row['token_hash'],))
            return self._issue(row['grant_id'])

    # ---- himoyalangan so‘rovlarda tekshirish -----------------------------
    def authenticate(self, access_token):
        """Yaroqli access token bo‘lsa foydalanuvchi ID, aks holda None."""
        if not isinstance(access_token, str) or not access_token.startswith(ACCESS_PREFIX) or len(access_token) > 200:
            return None
        now = self.clock()
        row = self.db.execute('''SELECT g.id, g.user_id, g.last_used FROM oauth_tokens t
            JOIN oauth_grants g ON g.id=t.grant_id JOIN users u ON u.user_id=g.user_id
            WHERE t.token_hash=? AND t.kind='access' AND t.expires>? AND g.revoked=0 AND u.blocked=0''',
                              (self.h('access', access_token), now)).fetchone()
        if not row:
            return None
        if now - row['last_used'] > 60:
            with self.db:
                self.db.execute('UPDATE oauth_grants SET last_used=? WHERE id=?', (now, row['id']))
        return row['user_id']

    # ---- bekor qilish va ro‘yxat --------------------------------------
    def revoke_token(self, token):
        """RFC 7009: token topilsa butun ruxsat bekor qilinadi; topilmasa ham xato yo‘q."""
        if not isinstance(token, str) or len(token) > 200:
            return
        for kind in ('access', 'refresh'):
            row = self.db.execute('SELECT grant_id FROM oauth_tokens WHERE token_hash=? AND kind=?',
                                  (self.h(kind, token), kind)).fetchone()
            if row:
                with self.db:
                    self.db.execute('UPDATE oauth_grants SET revoked=1 WHERE id=?', (row['grant_id'],))

    def revoke_grant(self, user_id, grant_id):
        with self.db:
            self.db.execute('UPDATE oauth_grants SET revoked=1 WHERE user_id=? AND id=?', (user_id, grant_id))

    def revoke_all(self, user_id):
        with self.db:
            self.db.execute('UPDATE oauth_grants SET revoked=1 WHERE user_id=?', (user_id,))

    def grants(self, user_id):
        return [dict(r) for r in self.db.execute('''SELECT g.id, c.name, g.created, g.last_used FROM oauth_grants g
            JOIN oauth_clients c ON c.client_id=g.client_id WHERE g.user_id=? AND g.revoked=0 ORDER BY g.created DESC''',
                                                 (user_id,))]

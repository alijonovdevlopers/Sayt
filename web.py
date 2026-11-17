"""Telefon uchun HTTPS paneli, CSRF va qat’iy foydalanuvchi chegarasi."""
import asyncio
import json
from pathlib import Path
import re
import shutil
from urllib.parse import parse_qs, urlencode

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from actions import public_details
from registration import Registration
from security import SafeError
from web_store import WebStore
from web_ui import e, when, field, hidden, form, card, note, dump, layout, action_row, LABELS, STATUS

LABELS.update({'ig_conversations': 'Instagram: suhbatlar', 'ig_messages': 'Instagram: xabarlar', 'ig_send_message': 'Instagram: yuborish',
               'instagram_ulandi': 'Instagram ulandi', 'instagram_uzildi': 'Instagram uzildi'})

SESSION = '__Host-tg_session'
GUEST = '__Host-tg_guest'
GFLOW = '__Host-tg_gflow'
GID = '__Host-tg_gid'
HEADERS = {'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
           'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
           'Strict-Transport-Security': 'max-age=31536000',
           'Content-Security-Policy': "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}


class Panel:
    def __init__(self, core, public_url, vault, client_factory=None, google=None, oauth=None, instagram=None):
        self.core, self.store, self.public_url, self.google, self.oauth = core, core.store, public_url, google, oauth
        self.instagram = instagram
        self.web = WebStore(self.store)
        self.web.index_existing(vault)
        self.registration = Registration(self.web, vault, core.pool, **({'factory': client_factory} if client_factory else {}))
        self.app = Starlette(routes=[Route('/assets/{name}', self.asset), Route('/{path:path}', self.handle, methods=['GET', 'POST'])])

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)

    def cookie(self, response, name, value, age):
        response.set_cookie(name, value, max_age=age, httponly=True, secure=True, samesite='strict', path='/')
        return response

    def lax_cookie(self, response, name, value, age):
        # Google sahifasidan qaytishda (boshqa sayt → bizning sayt) faqat Lax cookie yuboriladi.
        response.set_cookie(name, value, max_age=age, httponly=True, secure=True, samesite='lax', path='/')
        return response

    def google_email(self, request):
        if not self.google or request is None:
            return None
        return self.google.ticket_email(request.cookies.get(GID, ''))

    def google_invite(self):
        owner = self.google.linked_admin_uid()
        if not owner:
            raise SafeError('Sayt egasi hisobi hali yo‘q. Avval egasi kirishi kerak.')
        return self.web.create_invite(owner)

    def page(self, title, content, p=None, path='', csrf='', code=200):
        return HTMLResponse(layout(title, content, p, path, csrf), status_code=code, headers=HEADERS)

    def redirect(self, path):
        return RedirectResponse(path, status_code=303, headers=HEADERS)

    async def asset(self, request):
        name = request.path_params['name']
        if name not in ('panel.css', 'panel.js'):
            return Response(status_code=404, headers=HEADERS)
        return Response((Path(__file__).parent / 'assets' / name).read_bytes(),
                        media_type='text/css' if name.endswith('.css') else 'application/javascript', headers=HEADERS)

    async def fields(self, request, token):
        if request.headers.get('origin') != self.public_url:
            raise SafeError('So‘rov manbasi noto‘g‘ri. Saytdagi tugmadan foydalaning.')
        if request.headers.get('content-type', '').split(';')[0].strip() != 'application/x-www-form-urlencoded':
            raise SafeError('Forma formati noto‘g‘ri.')
        body = bytearray()
        async with asyncio.timeout(15):
            async for part in request.stream():
                body.extend(part)
                if len(body) > 32768:
                    raise SafeError('Forma juda katta.')
        try:
            parsed = parse_qs(body.decode('utf-8'), keep_blank_values=True, max_num_fields=32, strict_parsing=True)
            if any(len(v) != 1 for v in parsed.values()):
                raise ValueError('duplicate')
            values = {k: v[0] for k, v in parsed.items()}
        except (ValueError, UnicodeError):
            raise SafeError('Forma formati noto‘g‘ri.') from None
        if not self.web.csrf_valid(token, values.get('csrf')):
            raise SafeError('Sahifa eskirgan. Yangilang va qayta urining.')
        return values

    async def handle(self, request):
        path, post = request.url.path, request.method == 'POST'
        token = request.cookies.get(SESSION, '')
        p = self.web.resolve_session(token)
        guest = request.cookies.get(GUEST, '')
        guest_new = False
        public = path in ('/login', '/register', '/register/verify', '/register/code', '/register/password', '/register/cancel', '/auth/google', '/auth/google/callback')
        oauth_get = bool(self.oauth) and path == '/oauth/authorize' and not post
        if not p and not public and not oauth_get:
            return self.redirect('/login')
        if public and p:
            return self.redirect('/')
        if not p and not oauth_get:
            if not self.web.guest_valid(guest):
                if post:
                    return self.page('Sahifani yangilang', note('Kirish oynasi eskirgan. Qayta oching.', True) + '<a class="button" href="/login">Kirish</a>', code=403)
                guest, guest_new = self.web.guest_token(), True
            token = guest
        csrf = self.web.csrf(token)
        ip = request.client.host if request.client else 'noma_lum'
        try:
            values = await self.fields(request, token) if post else {}
            if oauth_get:
                response = self.oauth_page(request, p, csrf)
            elif not p:
                response = await self.public(path, post, values, guest, csrf, ip, request)
            elif post:
                response = await self.mutate(path, values, p, token, csrf, ip)
            else:
                response = self.view(path, request, p, csrf)
        except SafeError as error:
            back = ('/pending' if path.startswith('/actions/') else '/admin' if path.startswith('/admin/') else '/' if path.startswith('/oauth/') else '/instagram' if path.startswith('/instagram/') else '/settings') if p else ('/register/verify' if path.startswith('/register/') else '/register' if path == '/register' else '/login')
            response = self.page('Amal tugamadi', note(str(error), True) + '<a class="button secondary" href="' + back + '">Qaytish</a>', p, code=400)
        except Exception:
            # Xom Telethon/SQL xatosi, forma va sirlar javob/logga chiqmaydi.
            response = self.page('Qayta urinib ko‘ring', note('So‘rov tugamadi. Sahifani yangilang.', True) + '<a class="button" href="/">Bosh sahifa</a>', p, code=500)
        if guest_new:
            self.cookie(response, GUEST, guest, 1200)
        return response

    def oauth_page(self, request, p, csrf):
        """Claude/ChatGPT yo‘naltirgan ruxsat so‘rovi. Boshqa saytdan kelganda Strict cookie yuborilmaydi,
        shuning uchun avval bosiladigan havola ko‘rsatiladi, keyin (bir saytdan) ruxsat sahifasi ochiladi."""
        query = dict(request.query_params)
        req = self.oauth.validate_authorize(query)
        if request.headers.get('sec-fetch-site') == 'cross-site':
            here = '/oauth/authorize?' + urlencode(query)
            body = note('«' + req['client_name'] + '» ilovasi Telegram akkauntingizga ulanishni so‘rayapti.') + '<a class="button" href="' + e(here) + '">Davom etish</a>'
            return self.page('Ulanish so‘rovi', body)
        if not p:
            return self.redirect('/login')
        keys = ('client_id', 'redirect_uri', 'response_type', 'code_challenge', 'code_challenge_method', 'state', 'resource')
        hidden_fields = ''.join(hidden(key, query.get(key, '')) for key in keys)
        text = ('<p>«' + e(req['client_name']) + '» ilovasi <strong>' + e(p['display_name']) + '</strong> akkauntingizning o‘qish vositalaridan foydalana oladi. '
                'Xabar yuborish kabi yozish amallari baribir sizning tasdig‘ingizni kutadi.</p>'
                '<p class="muted">Bu so‘rovni siz boshlamagan bo‘lsangiz, Rad eting. Ruxsatni keyin Sozlamalar → Ulangan ilovalar bo‘limidan bekor qilasiz.</p>')
        body = card('<h2>Ulanishga ruxsat berasizmi?</h2>' + text
                    + form('/oauth/authorize', csrf, hidden_fields + hidden('decision', 'approve'), 'Ruxsat berish')
                    + form('/oauth/authorize', csrf, hidden_fields + hidden('decision', 'deny'), 'Rad etish', 'secondary'))
        return self.page('Ulanish so‘rovi', body, p, '/', csrf)

    def instagram_view(self, p, csrf):
        uid = p['user_id']
        state = self.instagram.status(uid)
        pin = field('pin', 'Sayt PINi', 'password', attrs='autocomplete="current-password" maxlength="128"')
        if not state:
            body = card('<h2>Instagram ulash</h2><p class="muted">Meta App Dashboard → Instagram → API setup with Instagram business login → Generate token. '
                        'Tokenni shu yerga qo‘ying: u shifrlangan holda saqlanadi va faqat sizning vositalaringiz uchun ishlatiladi.</p>'
                        + form('/instagram/connect', csrf, field('token', 'Instagram access token', 'password', attrs='autocomplete="off" maxlength="600"') + pin, 'Ulash'))
            return self.page('Instagram', body, p, '/instagram', csrf)
        body = card('<div class="split"><strong>@' + e(state['username']) + '</strong><span class="pill live">Ulangan</span></div>'
                    '<p class="muted">Token taxminan ' + str(state['days_left']) + ' kundan keyin tugaydi; tugashiga yaqin o‘zi yangilanishga urinadi. '
                    'Xabarlar faqat Claude so‘raganda o‘qiladi; yuborish esa shu yerda tasdiqlanadi.</p>'
                    + form('/instagram/disconnect', csrf, pin, 'Ulanishni uzish', 'danger'))
        drafts = self.instagram.drafts(uid)
        rows = ''
        for d in drafts:
            fields = hidden('draft', d['id']) + hidden('digest', d['digest'])
            rows += card('<p class="muted">Qabul qiluvchi (IGSID): ' + e(d['recipient_id']) + ' · ' + e(when(d['created'])) + '</p><pre>' + e(d['text']) + '</pre>'
                         '<p class="muted">Instagram faqat odam avval yozgan bo‘lsa va 24 soat ichida javob berishga ruxsat beradi.</p>'
                         + form('/instagram/approve', csrf, fields, 'Yuborishga ruxsat') + form('/instagram/reject', csrf, fields, 'Rad etish', 'secondary'))
        body += '<h2>Tasdiq kutayotgan xabarlar</h2>' + (rows or card('<div class="empty"><span>✓</span><h3>Kutayotgan xabar yo‘q</h3></div>'))
        recent = self.instagram.recent(uid)
        if recent:
            names = {'sent': 'Yuborildi', 'failed': 'Xato', 'rejected': 'Rad etildi', 'expired': 'Muddati tugadi', 'cancelled': 'Bekor qilindi', 'sending': 'Yuborilmoqda'}
            body += '<h2>So‘nggi holatlar</h2>' + card(''.join('<div class="split"><span>' + e(r['recipient_id']) + '</span><span class="pill">' + e(names.get(r['status'], r['status'])) + '</span></div>'
                                                             + ('<p class="muted">' + e(r['result']) + '</p>' if r['status'] == 'failed' and r['result'] else '') for r in recent))
        return self.page('Instagram', body, p, '/instagram', csrf)

    def login_form(self, csrf):
        body = '<p class="muted">O‘z API ma’lumotlaringiz va sayt PINingiz bilan kiring.</p>'
        body += field('api_id', 'API ID', attrs='inputmode="numeric" autocomplete="username" maxlength="10"')
        body += field('api_hash', 'API hash', 'password', attrs='maxlength="32" autocomplete="off"')
        body += field('pin', 'Sayt PINi', 'password', attrs='minlength="6" maxlength="128" autocomplete="current-password"')
        body += '<details><summary>Qo‘shimcha foydalanuvchi ID</summary>' + field('user_id', 'Foydalanuvchi ID', required=False, hint='Faqat bir API bilan bir nechta eski akkaunt mavjud bo‘lsa.', attrs='maxlength="32"') + '</details>'
        google = '<p class="center"><a class="button" href="/auth/google">Google bilan kirish</a></p>' if self.google else ''
        return google + card(form('/login', csrf, body, 'Kirish →')) + '<p class="center muted">Hali akkaunt yo‘qmi? <a href="/register">Taklif bilan qo‘shilish</a></p>'

    async def google_callback(self, request, ip):
        keys = self.web.rate_keys(ip)
        self.web.rate_check(keys)
        try:
            if request.query_params.get('error'):
                raise SafeError('Google kirishi bekor qilindi yoki rad etildi.')
            email, sub = await self.google.finish(request.cookies.get(GFLOW, ''), request.query_params.get('state'), request.query_params.get('code'))
            who = self.google.admit(email, sub)
        except SafeError:
            self.web.rate_fail(keys)
            raise
        uid = who['user_id']
        if uid:
            try:
                self.web.profile(uid)
            except SafeError:
                # Akkaunt saytdan o‘chirilgan: bog‘lanishni bekor qilamiz.
                self.google.link(email, None)
                uid = None
        if not uid and who['is_admin']:
            uid = self.google.linked_admin_uid()
            if uid:
                self.google.link(email, uid)
        # Google'dan qaytish boshqa saytdan kelgan so‘rov: Strict cookie shu zanjirda yuborilmaydi,
        # shuning uchun yo‘naltirish emas, foydalanuvchi bosadigan havola ko‘rsatiladi.
        if uid:
            session = self.web.create_session(uid)
            response = self.page('Google tasdiqlandi', note('Google orqali kirdingiz.') + '<a class="button" href="/">Panelga o‘tish</a>')
            self.cookie(response, SESSION, session, 43200)
            self.cookie(response, GID, '', 0)
        else:
            response = self.page('Google tasdiqlandi', note('Emailingiz ruxsat ro‘yxatida. Endi Telegram akkauntingizni ulang.') + '<a class="button" href="/register">Telegramni ulash</a>')
            self.cookie(response, GID, self.google.ticket(email), 1800)
        return self.cookie(response, GFLOW, '', 0)

    async def public(self, path, post, values, guest, csrf, ip, request=None):
        if path in ('/auth/google', '/auth/google/callback'):
            if not self.google or post:
                return self.page('Topilmadi', note('Bunday sahifa yo‘q.'), code=404)
            if path == '/auth/google':
                url, flow = self.google.begin()
                return self.lax_cookie(self.redirect(url), GFLOW, flow, 600)
            return await self.google_callback(request, ip)
        if path == '/login':
            if post:
                session = await self.web.login(values.get('api_id', ''), values.get('api_hash', ''), values.get('pin', ''), ip, values.get('user_id', ''))
                response = self.cookie(self.redirect('/'), SESSION, session, 43200)
                self.cookie(response, GUEST, '', 0)
                email = self.google_email(request)
                if email:
                    me = self.web.resolve_session(session)
                    # Eski (PIN) hisobni Google emailiga bog‘lash; egasi hisobi faqat egasi emailiga.
                    if me and (not me['is_admin'] or email == self.google.admin_email):
                        self.google.link(email, me['user_id'])
                    self.cookie(response, GID, '', 0)
                return response
            return self.page('Nazorat sizda.', self.login_form(csrf))
        if path == '/register':
            email = self.google_email(request)
            if post:
                if email:
                    values = dict(values, invite=self.google_invite())
                await self.registration.start(guest, values, ip)
                return self.redirect('/register/verify')
            if email:
                body = note('Google tasdiqlandi: ' + email) + '<p class="muted">Taklif kodi shart emas. Telegram ma’lumotlaringizni kiriting.</p>'
            else:
                body = '<p class="muted">Sayt egasidan olingan bir martalik taklif kodini kiriting.</p>'
                body += field('invite', 'Taklif kodi', attrs='autocomplete="off" maxlength="64"')
            body += field('api_id', 'API ID', attrs='inputmode="numeric" maxlength="10"')
            body += field('api_hash', 'API hash', 'password', attrs='maxlength="32" autocomplete="off"')
            body += '<p class="muted">API ma’lumotlaringizni <a href="https://my.telegram.org" rel="noreferrer" target="_blank">my.telegram.org</a> orqali oling.</p>'
            body += field('phone', 'Telegram telefon raqami', 'tel', attrs='placeholder="+998" autocomplete="tel" maxlength="20"')
            body += field('pin', 'Yangi sayt PINi', 'password', hint='Kamida 6 belgi. Bu Telegram 2FA parolidan alohida.', attrs='minlength="6" maxlength="128" autocomplete="new-password"')
            body += field('confirm', 'PINni takrorlang', 'password', attrs='minlength="6" maxlength="128" autocomplete="new-password"')
            return self.page('Hisob ochish', card(form(path, csrf, body, 'Telegram kodini olish')) + '<p class="center"><a href="/login">Kirishga qaytish</a></p>')
        if path == '/register/cancel' and post:
            await self.registration.cancel(guest)
            return self.redirect('/register')
        if path in ('/register/code', '/register/password') and post:
            result = await self.registration.verify(guest, values.get('value', ''), path.rsplit('/', 1)[1], ip)
            if result:
                uid, session, secret = result
                response = self.secret_page(self.web.profile(uid), self.web.csrf(session), secret, 'Hisob tayyor')
                self.cookie(response, GUEST, '', 0)
                email = self.google_email(request)
                if email:
                    self.google.link(email, uid)
                    self.cookie(response, GID, '', 0)
                return self.cookie(response, SESSION, session, 43200)
            return self.redirect('/register/verify')
        if path == '/register/verify' and not post:
            try:
                flow = self.registration.state(guest)
            except SafeError:
                return self.page('Kirishni boshlang', note('Kirish oynasi yo‘q yoki uning muddati tugagan.') + '<a class="button" href="/register">Qayta boshlash</a>')
            password = flow['step'] == 'password'
            title = 'Ikki bosqichli himoya' if password else 'Telegram kodi'
            body = '<p class="muted">' + ('Telegram akkauntingizning 2FA parolini kiriting.' if password else 'Telegram yuborgan kodni kiriting. Kirish oynasi 10 daqiqa ochiq turadi.') + '</p>'
            body += field('value', '2FA paroli' if password else 'Tasdiqlash kodi', 'password' if password else 'text', attrs='autocomplete="off" maxlength="256"' if password else 'inputmode="numeric" autocomplete="one-time-code" maxlength="8"')
            return self.page(title, card(form('/register/' + flow['step'], csrf, body, 'Tasdiqlash')) + form('/register/cancel', csrf, '', 'Bekor qilish', 'secondary'))
        return self.page('Topilmadi', note('Bunday sahifa yo‘q.'), code=404)

    def secret_page(self, p, csrf, secret, title='Yangi MCP manzili'):
        body = note('Bu maxfiy manzil faqat hozir ko‘rsatiladi. Ishonchli joyda saqlang.')
        body += card('<h2>Sizning MCP manzilingiz</h2><pre id="mcp-secret">' + e(self.public_url + '/mcp/' + secret) + '</pre><button type="button" data-copy="mcp-secret">Manzilni nusxalash</button><p class="muted">Manzil akkauntingizga kirish kalitidir. Boshqalarga ulashmang.</p>')
        body += '<a class="button secondary" href="/">Bosh sahifaga o‘tish</a>'
        return self.page(title, body, p, '/settings', csrf)

    def action_detail(self, row, csrf, p, ticket=None):
        details = public_details(row)
        title = LABELS.get(row['tool'], row['tool'])
        body = '<a class="back" href="/pending">← Amallarga qaytish</a>'
        body += note(details['eslatma'])
        body += card('<div class="split"><span class="pill">B DARAJA</span><span class="muted">' + e(STATUS.get(row['status'], row['status'])) + '</span></div><h2>' + e(title) + '</h2><p class="muted">Tasdiq muddati: ' + e(when(row['expires'])) + '</p><h3>Kimga / qayerga</h3>' + dump(details['nishonlar']) + '<h3>Aniq parametrlar</h3>' + dump(details['parametrlar']) + '<p>Xabarlar soni: <strong>' + e(details['xabarlar_soni']) + '</strong></p>' + ('<h3>Fayl</h3>' + dump(details['fayl']) if details['fayl'] else '') + ('<details><summary>Manba xabarlaridan namunalar</summary>' + dump(details['xabar_namunalari']) + '</details>' if details['xabar_namunalari'] else ''))
        if row['status'] == 'pending' and not p['stopped']:
            if row['bulk']:
                body += note('Ommaviy amal: 10 tadan ko‘p xabar yoki a’zoga ta’sir qiladi. Alohida tasdiq talab etiladi.', True)
            fields = hidden('digest', row['digest'])
            if ticket:
                fields += hidden('bulk_ticket', ticket) + '<label class="check"><input type="checkbox" name="bulk_confirm" value="yes" required>Ommaviy amal ko‘rsatilgan barcha nishonlarga ta’sir qilishini tasdiqlayman.</label>'
            body += '<div class="decision">' + form('/actions/' + row['id'] + '/approve', csrf, fields, 'Ommaviy amalga ruxsat' if ticket else 'Ruxsat', 'primary') + form('/actions/' + row['id'] + '/reject', csrf, hidden('digest', row['digest']), 'Rad', 'danger') + '</div>'
        elif row['status'] not in ('pending', 'approved'):
            body += card('<h3>Natija</h3>' + dump(json.loads(row['result'])))
        return self.page('Alohida tasdiq' if ticket else 'Amal tafsiloti', body, p, '/pending', csrf)

    def view(self, path, request, p, csrf):
        uid = p['user_id']
        if path == '/':
            rows = self.core.actions.queue.list(uid)
            pending = [r for r in rows if r['status'] == 'pending']
            state = 'To‘xtatilgan' if p['stopped'] else 'Ishlayapti'
            body = card('<div class="split"><span class="pill ' + ('paused' if p['stopped'] else 'live') + '">● ' + state + '</span><span class="muted">TELEGRAM AKKAUNTI</span></div><h2 class="account-name">' + e(p['display_name']) + '</h2><p class="muted">ID: ' + e(p['telegram_id']) + ' · Sessiya shifrlangan holda saqlangan</p>' + form('/connection-check', csrf, '', 'Ulanishni tekshirish', 'secondary'), 'account-card')
            body += '<div class="stats">' + card('<span class="muted">Tasdiq kutilmoqda</span><strong class="number">' + str(len(pending)) + '</strong><a href="/pending">Amallarni ko‘rish →</a>') + card('<span class="muted">Yuborish chegarasi</span><strong class="number">30<small>/ soat</small></strong><p class="muted">Har yuborish orasida 2 soniya</p>') + '</div>'
            body += '<div class="section-head"><h2>So‘nggi amallar</h2><a href="/pending">Barchasi →</a></div>' + card(''.join(action_row(r) for r in rows[:4]) or '<div class="empty"><span>✓</span><h3>Hozircha amallar yo‘q</h3><p class="muted">AI taklif qilgan o‘zgarishlar shu yerda ko‘rinadi.</p></div>')
            body += self.stop_form(csrf, p)
            return self.page('Boshqaruv paneli', body, p, path, csrf)
        if path == '/pending':
            rows = self.core.actions.queue.list(uid)
            pending = [r for r in rows if r['status'] == 'pending']
            body = '<p class="intro">Aniq matn va nishonni tekshiring. Siz ruxsat bermaguningizcha o‘zgarish bajarilmaydi.</p>'
            body += card(''.join(action_row(r) for r in pending) or '<div class="empty"><span>✓</span><h3>Kutayotgan amal yo‘q</h3><p class="muted">Barcha qarorlar sizning qo‘lingizda.</p></div>')
            others = [r for r in rows if r['status'] != 'pending']
            if others:
                body += '<h2>So‘nggi holatlar</h2>' + card(''.join(action_row(r) for r in others[:30]))
            return self.page('Kutilayotgan amallar', body, p, path, csrf)
        if re.fullmatch('/actions/[a-f0-9]{32}', path):
            return self.action_detail(self.core.actions.queue.get(uid, path.rsplit('/', 1)[1]), csrf, p)
        if path == '/logs':
            which = request.query_params.get('filter', 'today')
            if which not in ('today', 'error', 'B', 'all'):
                raise SafeError('Filtr noto‘g‘ri.')
            body = '<div class="filters">' + ''.join('<a href="/logs?filter=' + key + '" class="' + ('selected' if key == which else '') + '">' + label + '</a>' for key, label in [('today', 'Bugun'), ('error', 'Xatolar'), ('B', 'B daraja'), ('all', 'Barchasi')]) + '</div>'
            logs = self.web.logs(uid, which)
            body += card(''.join('<div class="log-row"><div class="split"><strong>' + e(LABELS.get(r['tool'], r['tool'])) + '</strong><time>' + e(when(r['created'])) + '</time></div><p>' + e(r['status']) + ' <span class="pill">' + e(r['level']) + '</span></p><details><summary>Parametrlar</summary>' + dump(json.loads(r['params'])) + '</details></div>' for r in logs) or '<div class="empty">Bu filtrda yozuvlar yo‘q.</div>')
            body += '<p class="muted">Oxirgi 100 yozuv. Maxfiy ma’lumot va xabar matnlari jurnalga chiqarilmaydi.</p>'
            return self.page('Amallar jurnali', body, p, path, csrf)
        if path == '/settings':
            body = self.stop_form(csrf, p)
            fields = field('current', 'Hozirgi PIN', 'password', attrs='autocomplete="current-password" maxlength="128"') + field('new', 'Yangi PIN', 'password', attrs='minlength="6" maxlength="128" autocomplete="new-password"') + field('confirm', 'Yangi PINni takrorlang', 'password', attrs='minlength="6" maxlength="128" autocomplete="new-password"')
            body += card('<h2>Sayt PINi</h2><p class="muted">O‘zgartirilganda boshqa sayt seanslari yopiladi.</p>' + form('/settings/pin', csrf, fields, 'PINni yangilash'))
            body += card('<h2>MCP manzili</h2><p class="muted">Yo‘qotgan bo‘lsangiz, yangi maxfiy manzil yarating. Eski manzil darhol yaroqsiz bo‘ladi.</p>' + form('/settings/mcp', csrf, field('pin', 'Sayt PINi', 'password', attrs='autocomplete="current-password" maxlength="128"'), 'Yangi manzil yaratish', 'secondary'))
            if self.oauth:
                grants = self.oauth.grants(uid)
                rows = ''.join('<div class="split"><strong>' + e(g['name']) + '</strong><span class="muted">' + e(when(g['created'])) + '</span></div>'
                               + form('/settings/oauth/revoke', csrf, hidden('grant', g['id']), 'Bekor qilish', 'secondary') for g in grants)
                body += card('<h2>Ulangan ilovalar</h2><p class="muted">OAuth orqali ulangan Claude/ChatGPT kabi ilovalar. Bekor qilingach, ular qayta ruxsat so‘rashi kerak.</p>'
                             + (rows or '<p class="muted">Hozircha ulangan ilova yo‘q.</p>')
                             + (form('/settings/oauth/revoke-all', csrf, '', 'Hammasini bekor qilish', 'danger') if grants else ''))
            if self.instagram:
                body += card('<h2>Instagram</h2><p class="muted">Claude uchun Instagram xabarlarini ulash va yuborishni tasdiqlash.</p><a class="button" href="/instagram">Instagram bo‘limi</a>')
            body += card('<h2>Hisob</h2><p class="muted">Foydalanuvchi ID</p><code>' + e(uid) + '</code>' + form('/logout', csrf, '', 'Saytdan chiqish', 'secondary'))
            return self.page('Sozlamalar', body, p, path, csrf)
        if self.instagram and path == '/instagram':
            return self.instagram_view(p, csrf)
        if path == '/admin':
            return self.admin_view(p, csrf)
        if re.fullmatch('/admin/delete/[a-f0-9]{32}', path):
            self.web.require_admin(uid)
            target = path.rsplit('/', 1)[1]
            victim = self.web.profile(target)
            if victim['is_admin']:
                raise SafeError('Sayt egasiga bu amal qo‘llanmaydi.')
            body = note('Saytdagi profil, shifrlangan sessiya va foydalanuvchi fayllari o‘chadi. Telegram akkauntining o‘zi o‘chirilmaydi.', True)
            body += card('<h2>' + e(victim['display_name']) + '</h2><p>Telegram ID: ' + e(victim['telegram_id']) + '</p>' + form('/admin/user/' + target + '/delete', csrf, hidden('confirm', target) + field('pin', 'Sayt egasining PINi', 'password', attrs='autocomplete="current-password" maxlength="128"'), 'Ha, saytdan o‘chirish', 'danger'))
            return self.page('O‘chirishni tasdiqlash', body + '<a href="/admin">Bekor qilish</a>', p, '/admin', csrf)
        return self.page('Topilmadi', note('Bunday sahifa yo‘q.'), p, code=404)

    def stop_form(self, csrf, p):
        if p['stopped']:
            return card('<h2>Barcha vositalar to‘xtatilgan</h2><p class="muted">Bekor qilingan amallar qayta ishga tushmaydi.</p>' + form('/settings/resume', csrf, field('pin', 'Qayta yoqish uchun PIN', 'password', attrs='autocomplete="current-password" maxlength="128"'), 'Qayta yoqish'), 'stop-card')
        return card('<h2>Favqulodda to‘xtatish</h2><p class="muted">O‘qish va yozish yopiladi, kutayotgan amallar bekor qilinadi. Telegramga yuborib bo‘lingan amallar ortga qaytmaydi.</p>' + form('/settings/stop', csrf, '', 'HAMMASINI TO‘XTATISH', 'danger'), 'stop-card')

    def admin_view(self, p, csrf, code=None):
        uid = p['user_id']
        self.web.require_admin(uid)
        body = '<p class="intro">Takliflar va foydalanuvchi holatini boshqaring.</p>'
        if code:
            body += note('Taklif kodi bir marta ko‘rsatiladi. 24 soat amal qiladi.') + card('<pre id="invite-code">' + e(code) + '</pre><button type="button" data-copy="invite-code">Kodni nusxalash</button>')
        body += card('<h2>Yangi taklif</h2>' + form('/admin/invite', csrf, '', 'Bir martalik kod yaratish'))
        for user in self.web.admin_users(uid):
            body += card('<div class="split"><h3>' + e(user['display_name']) + '</h3><span class="pill">' + ('Egasi' if user['is_admin'] else 'Bloklangan' if user['blocked'] else 'Faol') + '</span></div><p class="muted">Telegram ID: ' + e(user['telegram_id']) + '</p>' + ('' if user['is_admin'] else '<div class="decision">' + form('/admin/user/' + user['user_id'] + ('/unblock' if user['blocked'] else '/block'), csrf, '', 'Blokdan olish' if user['blocked'] else 'Bloklash', 'secondary') + '<a class="button danger" href="/admin/delete/' + user['user_id'] + '">Saytdan o‘chirish</a></div>'))
        if self.google:
            body += card('<h2>Google emaillar</h2><p class="muted">Faqat shu emaillar Google orqali kira oladi (jami 50 tagacha). Emailni olib tashlash akkauntni o‘chirmaydi, faqat Google orqali kirishni yopadi.</p>' + form('/admin/email', csrf, field('email', 'Email', 'email', attrs='autocomplete="off" maxlength="254"'), 'Emailni qo‘shish'))
            for row in self.google.listing():
                owner = row['email'] == self.google.admin_email
                status = 'Egasi' if owner else 'Bloklangan' if row['blocked'] else 'Ulangan' if row['user_id'] else 'Kutilmoqda'
                body += card('<div class="split"><strong>' + e(row['email']) + '</strong><span class="pill">' + status + '</span></div>' + ('' if owner else form('/admin/email/remove', csrf, hidden('email', row['email']), 'Olib tashlash', 'secondary')))
        body += '<h2>Takliflar</h2>'
        for invite in self.web.invites(uid):
            valid = not invite['used'] and not invite['revoked'] and invite['expires'] > self.web.clock()
            status = 'Ishlatilgan' if invite['used'] else 'Bekor qilingan' if invite['revoked'] else 'Muddati tugagan' if not valid else 'Kirish davom etmoqda' if invite['reserved_until'] > self.web.clock() else 'Tayyor'
            body += card('<div class="split"><strong>' + status + '</strong><span class="muted">' + e(when(invite['created'])) + '</span></div>' + (form('/admin/revoke', csrf, hidden('invite', invite['id']), 'Taklifni bekor qilish', 'secondary') if valid else ''))
        return self.page('Sayt boshqaruvi', body, p, '/admin', csrf)

    async def mutate(self, path, values, p, token, csrf, ip):
        uid = p['user_id']
        if path == '/logout':
            self.web.logout(uid, token)
            return self.cookie(self.redirect('/login'), SESSION, '', 0)
        if path == '/settings/stop':
            self.store.stop(uid)
            return self.redirect('/settings')
        if path == '/settings/resume':
            await self.web.resume(uid, values.get('pin', ''), ip)
            return self.redirect('/')
        if path == '/settings/pin':
            new_token = await self.web.change_pin(uid, values.get('current', ''), values.get('new', ''), values.get('confirm', ''), ip)
            return self.cookie(self.redirect('/settings'), SESSION, new_token, 43200)
        if path == '/settings/mcp':
            await self.web.verify_pin(uid, values.get('pin', ''), ip)
            return self.secret_page(p, csrf, self.web.rotate_mcp(uid))
        if self.instagram and path == '/instagram/connect':
            await self.web.verify_pin(uid, values.get('pin', ''), ip)
            await self.instagram.connect(uid, values.get('token', ''))
            self.store.audit(uid, 'instagram_ulandi', {}, 'tayyor', 'himoya')
            return self.redirect('/instagram')
        if self.instagram and path == '/instagram/disconnect':
            await self.web.verify_pin(uid, values.get('pin', ''), ip)
            self.instagram.forget(uid)
            self.store.audit(uid, 'instagram_uzildi', {}, 'tayyor', 'himoya')
            return self.redirect('/instagram')
        if self.instagram and path == '/instagram/approve':
            await self.instagram.approve(uid, values.get('draft', ''), values.get('digest', ''))
            return self.redirect('/instagram')
        if self.instagram and path == '/instagram/reject':
            self.instagram.reject(uid, values.get('draft', ''), values.get('digest', ''))
            return self.redirect('/instagram')
        if self.oauth and path == '/oauth/authorize':
            req = self.oauth.validate_authorize(values)
            if values.get('decision') == 'approve':
                target = self.oauth.approve(req, uid)
                self.store.audit(uid, 'oauth_ruxsat', {'ilova': req['client_name']}, 'tayyor', 'himoya')
                title, text = 'Ruxsat berildi', 'Ruxsat berildi. Ilovaga qaytish tugmasini bosing.'
            else:
                target = self.oauth.deny(req)
                self.store.audit(uid, 'oauth_rad', {'ilova': req['client_name']}, 'tayyor', 'himoya')
                title, text = 'Rad etildi', 'So‘rov rad etildi. Ilovaga qaytish tugmasini bosing.'
            # Redirect emas: forma yuborilgach CSP form-action boshqa saytga yo‘naltirishni to‘sadi.
            return self.page(title, note(text) + '<a class="button" href="' + e(target) + '" rel="noreferrer">Ilovaga qaytish</a>', p, '/', csrf)
        if self.oauth and path == '/settings/oauth/revoke':
            self.oauth.revoke_grant(uid, values.get('grant', ''))
            return self.redirect('/settings')
        if self.oauth and path == '/settings/oauth/revoke-all':
            self.oauth.revoke_all(uid)
            return self.redirect('/settings')
        if path == '/connection-check':
            result = await self.core.call(uid, 'whoami')
            if not result['ok']:
                raise SafeError(result['xato'])
            return self.page('Ulanish tekshirildi', note('Telegram javob berdi. Akkaunt ulangan.') + card(dump(result['data'])) + '<a class="button" href="/">Bosh sahifa</a>', p, '/', csrf)
        match = re.fullmatch('/actions/([a-f0-9]{32})/(approve|reject)', path)
        if match:
            action_id, decision = match.groups()
            row = self.core.actions.queue.get(uid, action_id)
            public_details(row)
            if row['digest'] != values.get('digest') or row['status'] != 'pending':
                raise SafeError('Amal o‘zgargan yoki endi tasdiq kutmayapti.')
            self.store.assert_active(uid)
            bulk = row['bulk'] and decision == 'approve'
            if bulk:
                ticket = values.get('bulk_ticket', '')
                if not ticket:
                    return self.action_detail(row, csrf, p, self.web.bulk_ticket(uid, action_id, row['digest']))
                if values.get('bulk_confirm') != 'yes' or not self.web.bulk_valid(uid, action_id, row['digest'], ticket):
                    raise SafeError('Ommaviy tasdiq eskirgan yoki belgilanmagan. Amalni qayta oching.')
            self.core.actions.queue.decide(uid, action_id, row['digest'], decision == 'approve', bulk_confirm=bool(bulk))
            return self.redirect('/actions/' + action_id)
        if path.startswith('/admin/'):
            self.web.require_admin(uid)
            if path == '/admin/invite':
                return self.admin_view(p, csrf, self.web.create_invite(uid))
            if self.google and path == '/admin/email':
                self.google.allow(values.get('email', ''), uid)
                self.store.audit(uid, 'google_email_qoshildi', {}, 'tayyor', 'himoya')
                return self.redirect('/admin')
            if self.google and path == '/admin/email/remove':
                self.google.remove(values.get('email', ''))
                self.store.audit(uid, 'google_email_olindi', {}, 'tayyor', 'himoya')
                return self.redirect('/admin')
            if path == '/admin/revoke':
                self.web.revoke_invite(uid, values.get('invite', ''))
                return self.redirect('/admin')
            match = re.fullmatch('/admin/user/([a-f0-9]{32})/(block|unblock|delete)', path)
            if match:
                target, action = match.groups()
                victim = self.web.profile(target)
                if victim['is_admin'] or target == uid:
                    raise SafeError('Sayt egasiga bu amal qo‘llanmaydi.')
                if action == 'delete':
                    await self.web.verify_pin(uid, values.get('pin', ''), ip)
                    if values.get('confirm') != target:
                        raise SafeError('O‘chirish tasdig‘i mos emas.')
                    await self.delete_user(target)
                else:
                    self.store.set_blocked(target, action == 'block')
                    if action == 'block':
                        self.web.revoke_sessions(target)
                self.store.audit(uid, 'foydalanuvchi_' + action, {}, 'tayyor', 'himoya')
                return self.redirect('/admin')
        return self.page('Topilmadi', note('Bunday amal yo‘q.'), p, code=404)

    async def delete_user(self, uid):
        self.store.set_blocked(uid, True)
        if self.oauth:
            self.oauth.revoke_all(uid)
        if self.instagram:
            self.instagram.forget(uid)
        self.web.revoke_sessions(uid)
        await self.core.actions.cancel_user(uid)
        async with self.core.locks.setdefault(uid, asyncio.Lock()):
            await self.core.pool.drop(uid)
            for folder in ('users', 'downloads', 'outbox'):
                root = self.core.data_dir / folder
                target = root / uid
                if root.is_symlink() or target.is_symlink():
                    raise SafeError('Foydalanuvchi papkasi xavfsiz emas; akkaunt bloklangan holda qoldi.')
                if target.exists():
                    shutil.rmtree(target)
            with self.store.db:
                self.store.db.execute('DELETE FROM users WHERE user_id=?', (uid,))

"""Shared account entrance and Instagram UI around the existing Telegram panel."""
import asyncio
import os
import re
import secrets
import time
from urllib.parse import parse_qs

from starlette.responses import HTMLResponse, JSONResponse
from web import Panel, SESSION, GUEST, HEADERS
from web_ui import e, field, form, card, note, dump, when, layout
from security import SafeError
from site_accounts import SiteAccounts
from telegram_link import TelegramLink
from instagram_service import InstagramService

OAUTH = '__Host-ig_oauth'
LINK = '__Host-tg_link'


class SocialPanel(Panel):
    def __init__(self, core, public_url, vault, client_factory=None):
        super().__init__(core, public_url, vault, client_factory)
        self.accounts = SiteAccounts(self.web)
        self.instagram = InstagramService(self.web, vault, public_url)
        self.telegram_link = TelegramLink(self.web, vault, core.pool, **({'factory':client_factory} if client_factory else {}))

    def page(self, title, content, p=None, path='', csrf='', code=200):
        html = layout(title, content, p, path, csrf)
        html = html.replace('<span>Telegram<small>', '<span>Social MCP<small>').replace(' · Telegram nazorati</title>', ' · Social MCP</title>')
        if p:
            nav = '<div class="platform-tabs"><a href="/"'+ (' aria-current="page"' if path=='/' else '') +'>Hisoblar</a><a href="/telegram"'+ (' aria-current="page"' if path=='/telegram' else '') +'>Telegram</a><a href="/instagram"'+ (' aria-current="page"' if path.startswith('/instagram') else '') +'>Instagram</a><a href="/account"'+ (' aria-current="page"' if path=='/account' else '') +'>Hisob</a></div>'
            html = html.replace('<main id="main"', nav + '<main id="main"')
        html = html.replace('<footer>', '<footer><div><a href="/privacy">Maxfiylik</a> · <a href="/data-deletion">Ma’lumotlarni o‘chirish</a></div>')
        return HTMLResponse(html, status_code=code, headers=HEADERS)

    async def handle(self, request):
        path = request.url.path
        if path in ('/privacy','/data-deletion') and request.method == 'GET':
            return self.privacy(path)
        if path.startswith('/instagram/deletion-status/') and request.method == 'GET':
            receipt = path.rsplit('/',1)[1]
            found = self.web.db.execute('SELECT 1 FROM instagram_deletions WHERE receipt_hash=?', (self.web.key('deletion:' + receipt),)).fetchone()
            return self.page('Ma’lumotlarni o‘chirish', note('Instagram ulanishi va unga tegishli ma’lumotlar o‘chirildi.' if found else 'Tasdiq topilmadi.'), code=200 if found else 404)
        if path in ('/instagram/deauthorize','/instagram/data-deletion'):
            return await self.meta_callback(request)
        if path == '/instagram/callback':
            return await self.oauth_callback(request)
        if path.startswith('/telegram/connect'):
            return await self.link_handle(request)
        return await super().handle(request)

    async def public(self, path, post, values, guest, csrf, ip, setup_cookie=''):
        if path == '/login':
            if post:
                username = values.get('username','').strip()
                if username.casefold() == os.getenv('ADMIN_LOGIN_USER','').casefold() and username:
                    return await super().public(path,post,values,guest,csrf,ip,setup_cookie)
                session = await self.accounts.login(username,values.get('password',''),ip)
                response = self.cookie(self.redirect('/'),SESSION,session,43200)
                self.cookie(response,GUEST,'',0)
                return response
            body = '<p class="muted">O‘z hisobingizga kiring. Telegram va Instagram bir joyda.</p>'
            body += field('username','Login',attrs='autocomplete="username" maxlength="32" autocapitalize="none" spellcheck="false"')
            body += field('password','Parol','password',attrs='autocomplete="current-password" maxlength="128"')
            return self.page('Hisobga kirish',card(form('/login',csrf,body,'Kirish →')) +
                '<p class="center">Hisobingiz yo‘qmi? <a href="/register">Yangi hisob yaratish</a></p><details><summary>Oldingi Telegram hisobiga kirish</summary><p><a href="/login/telegram">API ID va PIN bilan kirish</a></p></details>')
        if path == '/register':
            # Keep the existing owner's first-time setup path available if not yet bootstrapped.
            if self.first_setup_valid(guest,setup_cookie) and not self.web.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone():
                return await super().public(path,post,values,guest,csrf,ip,setup_cookie)
            if post:
                await self.accounts.register(values.get('username',''),values.get('password',''),values.get('confirm',''),ip)
                return self.page('Hisob yaratildi',note('Hisobingiz tayyor. Endi yaratgan login va parolingiz bilan kiring.') + '<a class="button" href="/login">Hisobga kirish →</a>')
            body = '<p class="muted">Login va parol tanlang. Keyin kerakli akkauntlaringizni ulaysiz.</p>'
            body += field('username','Yangi login',hint='3–32 belgi. Lotin harflari, raqam, nuqta, _ yoki -.',attrs='autocomplete="username" minlength="3" maxlength="32" autocapitalize="none" spellcheck="false"')
            body += field('password','Yangi parol','password',hint='Kamida 8 belgi.',attrs='autocomplete="new-password" minlength="8" maxlength="128"')
            body += field('confirm','Parolni takrorlang','password',attrs='autocomplete="new-password" minlength="8" maxlength="128"')
            body += '<p class="muted"><a href="/privacy">Ma’lumotlar qanday saqlanadi</a></p>'
            return self.page('Yangi hisob yaratish',card(form('/register',csrf,body,'Hisob yaratish')) + '<p class="center"><a href="/login">Hisobim bor — kirish</a></p>')
        return await super().public(path,post,values,guest,csrf,ip,setup_cookie)

    def view(self, path, request, p, csrf):
        uid = p['user_id']
        if path == '/':
            ig = self.instagram.account(uid)
            body = '<p class="intro">Akkauntingizni ulang va shaxsiy MCP havolangizni oling.</p>'
            body += '<div class="platform-grid">' + card('<span class="pill '+('live' if p['telegram_id'] else '')+'">'+('Ulangan' if p['telegram_id'] else 'Ulanmagan')+'</span><h2>Telegram</h2><p class="muted">Chatlar, xabarlar va avvalgi boshqaruv vositalari.</p><a class="button" href="/telegram">Telegram →</a>')
            body += card('<span class="pill '+('live' if ig else '')+'">'+('Ulangan' if ig else 'Ulanmagan')+'</span><h2>Instagram</h2><p class="muted">'+('@'+e(ig['username']) if ig else 'Akkauntingizni ulang. ChatGPT yoki Claude uchun MCP.')+'</p><a class="button secondary" href="/instagram">Instagram →</a>')+'</div>'
            return self.page('Hisoblaringiz',body,p,'/',csrf)
        if path == '/telegram':
            if p['telegram_id']:
                response = super().view('/',request,p,csrf)
                # Existing Telegram dashboard contents and actions are retained.
                return response
            body = card('<h2>Telegram akkauntini ulash</h2><p class="muted">API ID, API hash va telefon raqamingiz bilan Telegram’ni ulang. Keyin Telegram kodi bilan tasdiqlaysiz.</p><a class="button" href="/telegram/connect">Telegram’ni ulash →</a>')
            return self.page('Telegram',body,p,path,csrf)
        if path == '/instagram':
            ig = self.instagram.account(uid)
            if ig:
                body = card('<span class="pill live">Ulangan</span><h2>@'+e(ig['username'])+'</h2><p class="muted">Instagram ID: '+e(ig['instagram_id'])+'</p><p class="muted">Ruxsat muddati: '+e(when(ig['expires']) if ig['expires'] else 'Muddatsiz; Meta ruxsati bekor qilinishi mumkin')+'</p>')
                body += card('<h2>ChatGPT / Claude bilan ulash</h2><p class="muted">Shaxsiy MCP havolasini yarating va AI ilovangizning MCP server qo‘shish bo‘limiga kiriting.</p>'+form('/instagram/mcp',csrf,'','MCP havolasini yaratish')+'<p class="muted">Yangi havola avvalgisini bekor qiladi. Havola faqat sizga tegishli.</p>')
                rows = self.web.db.execute("SELECT id,status,created,expires FROM instagram_actions WHERE user_id=? ORDER BY created DESC LIMIT 30",(uid,)).fetchall()
                body += card('<h2>Javoblarni tasdiqlash</h2>'+(''.join('<p><a href="/instagram/actions/'+e(r['id'])+'">'+e(when(r['created']))+' · '+e(self.action_status(r))+'</a></p>' for r in rows) or '<p class="muted">AI tayyorlagan javoblar shu yerda tasdiqlanadi.</p>'))
                body += card('<h2>Ulanish</h2>'+form('/instagram/connect',csrf,'','Ruxsatni yangilash','secondary')+form('/instagram/disconnect',csrf,'','Instagram’ni uzish','danger')+'<small>Ulanish, MCP kaliti va saqlangan Instagram amallari o‘chiriladi.</small>')
            elif not self.instagram.configured:
                body = card('<h2>Instagram’ni ulash</h2>'+note('Instagram ulanishi tayyorlanmoqda. Sayt egasi Meta ulanishini sozlagach, shu yerda akkauntingizni ulaysiz.')+'<p class="muted">Business yoki Creator akkaunt qo‘llanadi. Instagram paroli Instagram’ning o‘z oynasida kiritiladi.</p>')
            else:
                body = card('<h2>Instagram’ni ulash</h2><p class="muted">Instagram oynasida Business yoki Creator akkauntingizga kiring va ruxsat bering. Parolingiz bu saytga berilmaydi.</p>'+form('/instagram/connect',csrf,'','Instagram orqali kirish →'))
            if p['is_admin']:
                body += self.setup_info()
            return self.page('Instagram',body,p,path,csrf)
        if re.fullmatch(r'/instagram/actions/[a-f0-9]{32}',path):
            row = self.instagram.action(uid,path.rsplit('/',1)[1])
            body = card('<p class="pill">'+e(self.action_status(row))+'</p><h2>'+('Direct javobi' if row['kind']=='message' else 'Kommentga javob')+'</h2><p>Nishon: <code>'+e(row['target'])+'</code></p><pre>'+e(row['text'])+'</pre>')
            if row['status']=='pending' and row['expires']>time.time():
                body += '<div class="decision">'+form(path+'/approve',csrf,'','Tasdiqlash va yuborish')+form(path+'/reject',csrf,'','Rad etish','danger')+'</div>'
            return self.page('Instagram amali',body+'<p><a href="/instagram">Instagram’ga qaytish</a></p>',p,'/instagram',csrf)
        if path == '/account':
            row = self.web.db.execute('SELECT username FROM site_logins WHERE user_id=?',(uid,)).fetchone()
            body = card('<h2>'+e(row['username'] if row else p['display_name'])+'</h2><p class="muted">Sayt hisobi</p>')
            if row:
                fields = field('current','Hozirgi parol','password',attrs='autocomplete="current-password" maxlength="128"')+field('password','Yangi parol','password',attrs='autocomplete="new-password" minlength="8" maxlength="128"')+field('confirm','Yangi parolni takrorlang','password',attrs='autocomplete="new-password" minlength="8" maxlength="128"')
                body += card('<h2>Login parolini o‘zgartirish</h2>'+form('/account/password',csrf,fields,'Parolni yangilash'))
            if p['telegram_id']:
                body += card('<h2>Telegram sozlamalari</h2><p class="muted">Telegram PINi va MCP manzili avvalgi sozlamalar bo‘limida.</p><a class="button secondary" href="/settings">Telegram sozlamalari</a>')
            body += card(form('/logout',csrf,'','Hisobdan chiqish','secondary'))
            if row and not p['is_admin']:
                body += card('<h2>Hisobni o‘chirish</h2><p class="muted">Sayt hisobingiz, Telegram sessiyasi, Instagram ulanishi va barcha MCP kalitlari o‘chadi. Telegram va Instagram akkauntlaringizning o‘zi o‘chirilmaydi.</p>'+form('/account/delete',csrf,field('password','Sayt paroli','password',attrs='autocomplete="current-password" maxlength="128"')+'<label class="check"><input type="checkbox" name="confirm" value="delete" required>Hisobimni o‘chirishni tasdiqlayman</label>','Hisobni butunlay o‘chirish','danger'))
            return self.page('Mening hisobim',body,p,path,csrf)
        # New users should see linking instructions, never an unconnected Telegram dashboard.
        if not p['telegram_id'] and (path in ('/settings','/pending','/logs') or path.startswith('/actions/')):
            return self.redirect('/telegram')
        return super().view(path,request,p,csrf)

    @staticmethod
    def action_status(row):
        if row['status']=='pending' and row['expires']<=time.time():
            return 'Muddati tugagan'
        return {'pending':'Tasdiq kutilmoqda','done':'Yuborildi','rejected':'Rad etildi','running':'Yuborilmoqda','uncertain':'Natijani Instagram’da tekshiring'}.get(row['status'],row['status'])

    async def mutate(self,path,values,p,token,csrf,ip):
        uid=p['user_id']
        if path=='/instagram/connect':
            # A cross-origin 303 after POST can be blocked by form-action 'self'
            # in Chrome. Finish the same-origin POST, then navigate from a new
            # document. Keep a normal link available when automatic navigation fails.
            destination=self.instagram.begin(uid,token)
            body=card('<h2>Instagram’da davom etish</h2><p>Kirish oynasi ochilmoqda. Avtomatik ochilmasa, quyidagi tugmani bosing.</p><a id="instagram-oauth-continue" class="button" rel="noreferrer" href="'+e(destination)+'">Instagram’da davom etish →</a><p class="muted">Agar oyna ochilmasa, brauzer menyusidan Chrome’da ochishni tanlang va shu tugmani bosing.</p>')
            response=self.page('Instagram’ga o‘tish',body,p,'/instagram',csrf)
            response.set_cookie(OAUTH,token,max_age=600,httponly=True,secure=True,samesite='lax',path='/')
            return response
        if path=='/instagram/mcp':
            secret=self.instagram.rotate(uid)
            body=note('Bu manzil faqat hozir ko‘rsatiladi. Uni boshqalarga bermang.')+card('<h2>Instagram MCP havolangiz</h2><pre id="mcp-secret">'+e(self.public_url+'/mcp/instagram/'+secret)+'</pre><button type="button" data-copy="mcp-secret">Havolani nusxalash</button><p class="muted">ChatGPT yoki Claude’da MCP server qo‘shishda shu URLni kiriting. Ulanish imkoniyati AI ilovangiz va tarifingizga bog‘liq.</p>')+'<a href="/instagram">Instagram’ga qaytish</a>'
            return self.page('MCP havola tayyor',body,p,'/instagram',csrf)
        if path=='/instagram/disconnect':
            async with self.instagram.locks.setdefault(uid,asyncio.Lock()):
                self.instagram.disconnect(uid)
            return self.redirect('/instagram')
        match=re.fullmatch(r'/instagram/actions/([a-f0-9]{32})/(approve|reject)',path)
        if match:
            await self.instagram.decide(uid,match[1],match[2]=='approve')
            return self.redirect('/instagram/actions/'+match[1])
        if path=='/account/password':
            session=await self.accounts.change(uid,values.get('current',''),values.get('password',''),values.get('confirm',''),ip)
            return self.cookie(self.redirect('/account'),SESSION,session,43200)
        if path=='/account/delete':
            if p['is_admin'] or values.get('confirm')!='delete':
                raise SafeError('Hisobni o‘chirish tasdig‘i yo‘q.')
            row=self.web.db.execute('SELECT username FROM site_logins WHERE user_id=?',(uid,)).fetchone()
            if not row:
                raise SafeError('Bu hisob administrator orqali boshqariladi.')
            session=await self.accounts.login(row['username'],values.get('password',''),ip)
            self.web.logout(uid,session)
            await self.delete_user(uid)
            return self.cookie(self.redirect('/login'),SESSION,'',0)
        return await super().mutate(path,values,p,token,csrf,ip)

    async def delete_user(self,uid):
        async with self.instagram.locks.setdefault(uid,asyncio.Lock()):
            for identity,flow in list(self.telegram_link.flows.items()):
                if flow.get('target_uid')==uid:
                    await self.telegram_link.discard(identity)
            await super().delete_user(uid)

    async def oauth_callback(self,request):
        if request.method!='GET':
            return self.page('Topilmadi',note('Bunday amal yo‘q.'),code=405)
        session=request.cookies.get(OAUTH,'')
        try:
            uid=await self.instagram.complete(request.query_params.get('state',''),request.query_params.get('code',''),session)
            if not self.web.db.execute('SELECT 1 FROM instagram_mcp WHERE user_id=?',(uid,)).fetchone():
                p=self.web.profile(uid)
                response=await self.mutate('/instagram/mcp',{},p,session,self.web.csrf(session),'oauth-callback')
            else:
                response=self.redirect('/instagram')
            self.cookie(response,SESSION,session,43200)
        except SafeError as error:
            response=self.page('Instagram ulanmagan',note(str(error),True)+'<a class="button" href="/instagram">Qayta urinish</a>',code=400)
        except Exception:
            response=self.page('Instagram ulanmagan',note('Ulanish tugamadi. Qayta urinib ko‘ring.',True)+'<a href="/instagram">Qaytish</a>',code=400)
        self.cookie(response,OAUTH,'',0)
        return response

    async def link_handle(self,request):
        session=request.cookies.get(SESSION,'')
        p=self.web.resolve_session(session)
        if not p:
            return self.redirect('/login')
        uid,path,post=p['user_id'],request.url.path,request.method=='POST'
        csrf=self.web.csrf(session)
        guest=request.cookies.get(LINK,'')
        fresh=not self.web.guest_valid(guest)
        if fresh:
            if post:
                return self.page('Oyna eskirgan',note('Telegram ulashni qayta boshlang.')+'<a href="/telegram/connect">Qayta boshlash</a>',p,code=403)
            guest=self.web.guest_token()
        ip=request.client.host if request.client else 'noma_lum'
        try:
            if p['telegram_id']:
                return self.redirect('/telegram')
            values=await self.fields(request,session) if post else {}
            if post and path=='/telegram/connect':
                await self.telegram_link.start_link(uid,guest,values,ip)
                response=self.redirect('/telegram/connect/verify')
            elif path in ('/telegram/connect/code','/telegram/connect/password','/telegram/connect/cancel') and post:
                flow=self.telegram_link.state(guest)
                if flow['target_uid']!=uid:
                    raise SafeError('Ulanish boshqa hisobga tegishli.')
                step=path.rsplit('/',1)[1]
                if step=='cancel':
                    await self.telegram_link.cancel(guest)
                    response=self.redirect('/telegram')
                else:
                    result=await self.telegram_link.verify(guest,values.get('value',''),step,ip)
                    if result:
                        _,new_session,secret=result
                        response=self.secret_page(self.web.profile(uid),self.web.csrf(new_session),secret,'Telegram ulandi')
                        self.cookie(response,SESSION,new_session,43200)
                        self.cookie(response,LINK,'',0)
                    else:
                        response=self.redirect('/telegram/connect/verify')
            elif path=='/telegram/connect/verify' and not post:
                flow=self.telegram_link.state(guest)
                if flow['target_uid']!=uid:
                    raise SafeError('Ulanish boshqa hisobga tegishli.')
                password=flow['step']=='password'
                body=field('value','Telegram 2FA paroli' if password else 'Telegram kodi','password' if password else 'text',attrs='autocomplete="off" maxlength="256"' if password else 'inputmode="numeric" autocomplete="one-time-code" maxlength="8"')
                response=self.page('Telegram tasdig‘i',card(form('/telegram/connect/'+flow['step'],csrf,body,'Tasdiqlash'))+form('/telegram/connect/cancel',csrf,'','Bekor qilish','secondary'),p,'/telegram',csrf)
            elif path=='/telegram/connect' and not post:
                body=field('api_id','API ID',attrs='inputmode="numeric" maxlength="10"')+field('api_hash','API hash','password',attrs='maxlength="32" autocomplete="off"')
                body+='<p class="muted">API ma’lumotlarini <a href="https://my.telegram.org" target="_blank" rel="noreferrer">my.telegram.org</a> orqali oling.</p>'
                body+=field('phone','Telefon raqami','tel',attrs='placeholder="+998" autocomplete="tel" maxlength="20"')+field('pin','Telegram boshqaruvi uchun PIN','password',hint='Saytga kirish parolidan alohida. Kamida 6 belgi.',attrs='minlength="6" maxlength="128" autocomplete="new-password"')+field('confirm','PINni takrorlang','password',attrs='minlength="6" maxlength="128" autocomplete="new-password"')
                response=self.page('Telegram’ni ulash',card(form(path,csrf,body,'Telegram kodini olish')),p,'/telegram',csrf)
            else:
                response=self.page('Topilmadi',note('Bunday sahifa yo‘q.'),p,code=404)
        except SafeError as error:
            response=self.page('Telegram ulanmagan',note(str(error),True)+'<a href="/telegram/connect/verify">Tasdiqqa qaytish</a> · <a href="/telegram/connect">Qayta boshlash</a>',p,code=400)
        except Exception:
            response=self.page('Telegram ulanmagan',note('Ulanish tugamadi. Qayta urinib ko‘ring.',True),p,code=400)
        if fresh:
            self.cookie(response,LINK,guest,1200)
        return response

    def setup_info(self):
        return card('<h2>Administrator: Instagram sozlamalari</h2><p class="muted">Meta ilovasida API setup with Unified login’ni sozlang. Railway Variables’da INSTAGRAM_APP_ID (Meta App ID), INSTAGRAM_CONFIG_ID va INSTAGRAM_APP_SECRET (Meta App Secret) ni kiriting. INSTAGRAM_LOGIN_MODE=unified. Konfiguratsiyada token muddati Never bo‘lsa INSTAGRAM_TOKEN_LIFETIME=never qo‘ying. Barcha foydalanuvchilar uchun Meta App Review, kerakli ruxsatlarga Advanced Access va Live rejim talab etiladi.</p><h3>Redirect URI</h3><pre>'+e(self.instagram.callback)+'</pre><h3>Maxfiylik manzili</h3><pre>'+e(self.public_url+'/privacy')+'</pre><h3>Ma’lumotlarni o‘chirish callback</h3><pre>'+e(self.public_url+'/instagram/data-deletion')+'</pre><h3>Deauthorize callback</h3><pre>'+e(self.public_url+'/instagram/deauthorize')+'</pre><p class="muted">Konfiguratsiya ruxsatlari: instagram_basic, instagram_manage_messages, instagram_manage_comments.</p>')

    def privacy(self,path):
        if path=='/data-deletion':
            body=card('<h2>Instagram ma’lumotlari</h2><p>Hisobga kiring → Instagram → Instagram’ni uzish. Saqlangan Instagram tokeni, MCP kaliti, resurs identifikatorlari va javob takliflari o‘chiriladi. Instagram orqali ulanish ruxsatini bekor qilganingizda ham tegishli ma’lumotlar callback orqali o‘chiriladi.</p><h2>Butun sayt hisobi</h2><p>Hisob → Hisobni o‘chirish. Yangi login-parol hisoblari shu yerdan o‘chiriladi. Eski hisoblarni sayt administratori boshqaradi.</p><a class="button" href="/account">Hisobimga o‘tish</a>')
        else:
            body=card('<h2>Qanday ma’lumot saqlanadi?</h2><p>Sayt logini, parolning scrypt xeshi, kirish sessiyalari va ulagan hisoblaringiz identifikatorlari saqlanadi. Telegram sessiyasi va Instagram kirish tokeni shifrlanadi. Instagram parolini bu sayt olmaydi.</p><h2>AI ulanishi</h2><p>Shaxsiy MCP havolasini ulagan AI xizmatiga akkauntingiz ma’lumotlarini o‘qish imkonini berasiz. Instagram xabarlari va kommentlari so‘rov vaqtida olinadi. Javob takliflari shifrlanib, tasdiqlash uchun qisqa muddat saqlanadi. Xabar matni audit jurnaliga yozilmaydi. Kirish IP manzili cheklovlar uchun xesh shaklida ishlatiladi.</p><h2>Boshqarish va o‘chirish</h2><p>MCP havolasini yangilash eski havolani bekor qiladi. Instagram bo‘limida ulanishni uzishingiz mumkin. Hisob o‘chirilganda uning sessiyalari va tegishli ma’lumotlari o‘chiriladi. Xizmat Railway’da ishlaydi; Meta, Telegram va siz tanlagan AI xizmatlari o‘z maxfiylik qoidalariga ega.</p><a href="/data-deletion">O‘chirish ko‘rsatmasi</a>')
        return self.page('Maxfiylik va ma’lumotlar' if path=='/privacy' else 'Ma’lumotlarni o‘chirish',body)

    async def meta_callback(self,request):
        if request.method!='POST':
            return JSONResponse({'ok':False},status_code=405,headers=HEADERS)
        try:
            body=bytearray()
            async with asyncio.timeout(15):
                async for part in request.stream():
                    body.extend(part)
                    if len(body)>16384:
                        raise SafeError('So‘rov katta.')
            values=parse_qs(body.decode(),max_num_fields=4)
            signed=values.get('signed_request',[])
            if len(signed)!=1:
                raise SafeError('Tasdiq kerak.')
            igid=self.instagram.signed_user(signed[0])
            rows=self.web.db.execute("""SELECT a.user_id, a.instagram_id FROM instagram_accounts a
                LEFT JOIN instagram_auth m ON m.user_id=a.user_id
                WHERE a.instagram_id=? OR m.subject_id=?""",(igid,igid)).fetchall()
            for row in rows:
                async with self.instagram.locks.setdefault(row['user_id'],asyncio.Lock()):
                    current=self.instagram.account(row['user_id'])
                    if current and current['instagram_id']==row['instagram_id']:
                        self.instagram.disconnect(row['user_id'])
            if request.url.path.endswith('/data-deletion'):
                receipt=secrets.token_urlsafe(24)
                with self.web.db:
                    self.web.db.execute('DELETE FROM instagram_deletions WHERE created<?',(time.time()-30*86400,))
                    self.web.db.execute('INSERT INTO instagram_deletions VALUES(?,?)',(self.web.key('deletion:'+receipt),time.time()))
                return JSONResponse({'url':self.public_url+'/instagram/deletion-status/'+receipt,'confirmation_code':receipt},headers=HEADERS)
            return JSONResponse({'ok':True},headers=HEADERS)
        except Exception:
            return JSONResponse({'ok':False},status_code=400,headers=HEADERS)

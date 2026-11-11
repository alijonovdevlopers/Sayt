import asyncio
import base64
import hashlib
import hmac
from html import unescape
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.fernet import Fernet
from core import Core
from security import SafeError, Vault
from storage import Store
from telegram_adapter import ClientPool
from server import build_app
from social_panel import OAUTH, BLOCKED
from web import SESSION
from test_web import FakeLogin, value


class SocialTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.store=Store(self.root/'state.sqlite3','p'*43)
        self.vault=Vault(self.root,Fernet.generate_key().decode())
        self.pool=ClientPool(self.vault,self.store)
        self.core=Core(self.store,self.pool,self.root)
        self.fake=FakeLogin()
        self.app=build_app(self.core,'https://example.test',enable_writes=True,vault=self.vault,client_factory=lambda *_:self.fake,enable_portal=True)
        self.panel=self.app.panel
        self.web=self.panel.web
        self.ig=self.panel.instagram
        self.client=httpx.AsyncClient(transport=httpx.ASGITransport(self.app),base_url='https://example.test')
        self.env=patch.dict(os.environ,{'INSTAGRAM_LOGIN_MODE':'instagram','INSTAGRAM_APP_ID':'111','INSTAGRAM_APP_SECRET':'test-app-secret','ADMIN_LOGIN_USER':'ExistingOwner'})
        self.env.start()
        self.calls=[]
        self.ig.transport=httpx.MockTransport(self.meta)

    async def asyncTearDown(self):
        await self.panel.telegram_link.close()
        await self.panel.registration.close()
        await self.client.aclose()
        self.env.stop()
        self.store.close()
        self.tmp.cleanup()

    def meta(self,request):
        self.calls.append(request)
        path=request.url.path
        if path=='/oauth/access_token':
            return httpx.Response(200,json={'access_token':'SHORT-SECRET','user_id':'777'})
        if path=='/access_token':
            return httpx.Response(200,json={'access_token':'LONG-SECRET','expires_in':5184000})
        if path.endswith('/me'):
            return httpx.Response(200,json={'user_id':'777','username':'instagram_test'})
        if path.endswith('/me/media'):
            return httpx.Response(200,json={'data':[{'id':'123','caption':'hello'}], 'paging':{'next':'https://graph.instagram.com?access_token=LONG-SECRET','cursors':{'after':'PAGE2'}}})
        if path.endswith('/me/conversations'):
            return httpx.Response(200,json={'data':[{'id':'thread:123'}]})
        if path.endswith('/thread:123'):
            if 'messages' in request.url.params.get('fields',''):
                return httpx.Response(200,json={'messages':{'data':[{'id':'msg1','message':'hello'}]}})
            return httpx.Response(200,json={'participants':{'data':[{'id':'777'},{'id':'888'}]}})
        if path.endswith('/123/comments'):
            return httpx.Response(200,json={'data':[{'id':'456','text':'price?'}]})
        if path.endswith('/777/messages') or path.endswith('/456/replies'):
            return httpx.Response(200,json={'id':'sent1'})
        if path=='/refresh_access_token':
            return httpx.Response(200,json={'access_token':'REFRESHED-SECRET','expires_in':5184000})
        return httpx.Response(400,json={'error':{'message':'RAW SECRET ERROR','code':100}})

    async def signup(self,name='alice',ip='test-ip'):
        return await self.panel.accounts.register(name,'Password123!','Password123!',ip)

    def signin(self,uid):
        token=self.web.create_session(uid)
        self.client.cookies.clear()
        self.client.cookies.set(SESSION,token,domain='example.test',path='/')
        return token

    async def post(self,path,token,**data):
        return await self.client.post(path,data={'csrf':self.web.csrf(token),**data},headers={'Origin':'https://example.test'})

    def connect_fake(self,uid,igid='777'):
        with self.store.db:
            self.store.db.execute('INSERT INTO instagram_accounts VALUES(?,?,?,?,?,?)',
                (uid,igid,'test_'+igid,self.vault.fernet.encrypt(('TOKEN-'+igid).encode()),time.time()+5184000,time.time()))

    async def test_public_register_then_separate_login_and_duplicate(self):
        r=await self.client.get('/register')
        self.assertEqual(r.status_code,200)
        self.assertNotIn('Taklif kodi',r.text)
        data={'csrf':value(r.text,'csrf'),'username':'alice','password':'Password123!','confirm':'Password123!'}
        r=await self.client.post('/register',data=data,headers={'Origin':'https://example.test'})
        self.assertIn('Hisob yaratildi',r.text)
        self.assertNotIn(SESSION,self.client.cookies)
        self.assertEqual((await self.client.get('/')).status_code,303)
        r=await self.client.get('/login')
        r=await self.client.post('/login',data={'csrf':value(r.text,'csrf'),'username':'ALICE','password':'Password123!'},headers={'Origin':'https://example.test'})
        self.assertEqual(r.status_code,303)
        r=await self.client.get('/')
        self.assertIn('Instagram',r.text)
        self.assertIn('Telegram',r.text)
        self.assertNotIn('API hash',r.text)
        with self.assertRaises(SafeError):
            await self.signup('aLiCe')
        with self.assertRaises(SafeError):
            await self.signup('existingowner')
        row=self.store.db.execute('SELECT password_hash FROM site_logins').fetchone()
        self.assertNotIn('Password123',row[0])

    async def test_csrf_bad_password_rate_block_and_nonadmin(self):
        uid=await self.signup()
        token=self.signin(uid)
        self.assertEqual((await self.client.post('/instagram/connect',data={'csrf':'bad'},headers={'Origin':'https://example.test'})).status_code,400)
        self.assertEqual((await self.client.post('/instagram/connect',data={'csrf':self.web.csrf(token)},headers={'Origin':'https://evil.test'})).status_code,403)
        self.assertEqual((await self.client.get('/admin')).status_code,400)
        for _ in range(5):
            with self.assertRaises(SafeError):
                await self.panel.accounts.login('alice','bad','bad-ip')
        with self.assertRaises(SafeError):
            await self.panel.accounts.login('alice','Password123!','bad-ip')

    async def test_telegram_links_same_user_and_legacy_mcp_remains(self):
        uid=await self.signup()
        token=self.signin(uid)
        r=await self.client.get('/telegram/connect')
        self.assertEqual(r.status_code,200)
        r=await self.post('/telegram/connect',token,api_id='123',api_hash='a'*32,phone='+998901234567',pin='PIN123',confirm='PIN123')
        self.assertEqual(r.status_code,303)
        r=await self.post('/telegram/connect/code',token,value='12345')
        self.assertEqual(r.status_code,200)
        self.assertIn('/mcp/',r.text)
        self.assertEqual(self.store.user(uid)['telegram_id'],303)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM users WHERE user_id!='__system__'").fetchone()[0],1)
        self.assertEqual(self.vault.load(uid)['api_id'],123)
        await self.panel.accounts.login('alice','Password123!','test')
        self.assertIn('Telegram', (await self.client.get('/telegram')).text)

    async def test_oauth_bound_to_session_one_use_and_encrypted(self):
        uid=await self.signup()
        token=self.signin(uid)
        r=await self.post('/instagram/connect',token)
        self.assertEqual(r.status_code,200)
        self.assertNotIn('location',r.headers)
        self.assertIn("form-action 'self'",r.headers['content-security-policy'])
        self.assertIn('SameSite=lax',r.headers['set-cookie'])
        destination=unescape(re.search(r'id="instagram-oauth-continue"[^>]*href="([^"]+)"',r.text).group(1))
        self.assertTrue(destination.startswith('https://www.instagram.com/oauth/authorize?'))
        self.assertNotIn('test-app-secret',r.text)
        state=parse_qs(urlsplit(destination).query)['state'][0]
        bad=await self.signup('bob')
        wrong=self.web.create_session(bad)
        with self.assertRaises(SafeError):
            await self.ig.complete(state,'code',wrong)
        # Simulate a cross-site redirect: Strict main session isn't sent, Lax OAuth cookie is.
        self.client.cookies.clear()
        self.client.cookies.set(OAUTH,token,domain='example.test',path='/')
        r=await self.client.get('/instagram/callback',params={'code':'test-code','state':state})
        self.assertEqual(r.status_code,200)
        self.assertIn('/mcp/instagram/',r.text)
        self.assertEqual(self.ig.account(uid)['instagram_id'],'777')
        raw=self.store.db.execute('SELECT token_enc FROM instagram_accounts WHERE user_id=?',(uid,)).fetchone()[0]
        self.assertNotIn(b'LONG-SECRET',raw)
        with self.assertRaises(SafeError):
            await self.ig.complete(state,'test-code',token)
        self.assertEqual(len([r for r in self.calls if r.url.path=='/oauth/access_token']),1)

    async def test_logout_invalidates_pending_oauth_and_missing_config(self):
        uid=await self.signup()
        token=self.signin(uid)
        url=self.ig.begin(uid,token)
        state=parse_qs(urlsplit(url).query)['state'][0]
        self.web.logout(uid,token)
        with self.assertRaises(SafeError):
            await self.ig.complete(state,'code',token)
        with patch.dict(os.environ,{'INSTAGRAM_APP_SECRET':''}):
            with self.assertRaises(SafeError):
                self.ig.begin(uid,token)

    async def test_tenant_isolation_approval_and_rotation(self):
        a,b=await self.signup('alice'),await self.signup('bob')
        self.connect_fake(a)
        self.connect_fake(b,'999')
        secret=self.ig.rotate(a)
        self.assertEqual(self.ig.authenticate(secret),a)
        data=await self.ig.call(a,'instagram_posts',{})
        self.assertNotIn('SECRET',json.dumps(data))
        self.assertEqual(data['after'],'PAGE2')
        with self.assertRaises(SafeError):
            await self.ig.call(b,'instagram_comments',{'media_id':'123'})
        await self.ig.call(a,'instagram_comments',{'media_id':'123'})
        result=await self.ig.call(a,'instagram_prepare_comment_reply',{'comment_id':'456','text':'Salom'})
        aid=result['action_id']
        self.assertFalse(any(r.method=='POST' for r in self.calls))
        with self.assertRaises(SafeError):
            await self.ig.decide(b,aid,True)
        await self.ig.decide(a,aid,True)
        self.assertEqual(self.ig.action(a,aid)['status'],'done')
        with self.assertRaises(SafeError):
            await self.ig.decide(a,aid,True)
        self.assertEqual(len([r for r in self.calls if r.method=='POST']),1)
        next_secret=self.ig.rotate(a)
        self.assertIsNone(self.ig.authenticate(secret))
        self.assertEqual(self.ig.authenticate(next_secret),a)
        self.ig.disconnect(a)
        self.assertIsNone(self.ig.authenticate(next_secret))
        self.assertIsNotNone(self.ig.account(b))

    async def test_direct_prepare_and_confirm(self):
        uid=await self.signup()
        self.connect_fake(uid)
        await self.ig.call(uid,'instagram_conversations',{})
        messages=await self.ig.call(uid,'instagram_messages',{'conversation_id':'thread:123'})
        self.assertEqual(messages['data'][0]['message'],'hello')
        result=await self.ig.call(uid,'instagram_prepare_reply',{'conversation_id':'thread:123','text':'Javob'})
        token=self.signin(uid)
        r=await self.client.get('/instagram/actions/'+result['action_id'])
        self.assertIn('Javob',r.text)
        r=await self.post('/instagram/actions/'+result['action_id']+'/approve',token)
        self.assertEqual(r.status_code,303)
        post=[r for r in self.calls if r.method=='POST'][0]
        self.assertEqual(json.loads(post.content),{'recipient':{'id':'888'},'message':{'text':'Javob'}})

    async def test_mcp_transport_tool_list_and_tenant_bound_keys(self):
        uid=await self.signup()
        self.connect_fake(uid)
        secret=self.ig.rotate(uid)
        async with self.app.downstream.router.lifespan_context(self.app.downstream):
            headers={'Accept':'application/json, text/event-stream'}
            r=await self.client.post('/mcp/instagram/'+secret,json={'jsonrpc':'2.0','id':1,'method':'tools/list'},headers=headers)
            self.assertEqual(r.status_code,200,r.text)
            names=[t['name'] for t in r.json()['result']['tools']]
            self.assertIn('instagram_profile',names)
            self.assertNotIn('send_message',names)
            r=await self.client.post('/mcp/instagram/'+secret,json={'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'instagram_profile','arguments':{}}},headers=headers)
            self.assertEqual(r.status_code,200,r.text)
            self.assertIn('instagram_test',r.text)
            r=await self.client.post('/mcp/'+secret,json={'jsonrpc':'2.0','id':3,'method':'tools/list'},headers=headers)
            self.assertEqual(r.status_code,404)
            self.store.set_blocked(uid,True)
            r=await self.client.post('/mcp/instagram/'+secret,json={'jsonrpc':'2.0','id':4,'method':'tools/list'},headers=headers)
            self.assertEqual(r.status_code,404)

    async def test_signed_deletion_and_cross_user_preservation(self):
        a,b=await self.signup('alice'),await self.signup('bob')
        self.connect_fake(a)
        self.connect_fake(b,'999')
        enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        body=enc(json.dumps({'algorithm':'HMAC-SHA256','user_id':'777'}).encode())
        sig=enc(hmac.new(b'test-app-secret',body.encode(),hashlib.sha256).digest())
        r=await self.client.post('/instagram/data-deletion',data={'signed_request':'bad.'+body})
        self.assertEqual(r.status_code,400)
        self.assertIsNotNone(self.ig.account(a))
        r=await self.client.post('/instagram/data-deletion',data={'signed_request':sig+'.'+body})
        self.assertEqual(r.status_code,200)
        self.assertIsNone(self.ig.account(a))
        self.assertIsNotNone(self.ig.account(b))
        status=await self.client.get(r.json()['url'])
        self.assertEqual(status.status_code,200)

    async def test_existing_owner_login_and_telegram_mcp_in_portal(self):
        from security import pin_hash
        from test_core import FakeAdapter
        uid, tg_token=self.store.create_user('OwnerPIN',101)
        self.vault.save(uid,api_id=11,api_hash='a'*32,session='OLD-TG-SESSION')
        self.web.add_profile(uid,11,'a'*32,'Existing owner')
        self.web.bootstrap_admin(uid)
        self.pool.clients[uid]=FakeAdapter(101)
        with patch.dict(os.environ,{'ADMIN_LOGIN_USER':'ExistingOwner','ADMIN_PASSWORD_HASH':pin_hash('OwnerPassword!'),'ADMIN_TELEGRAM_ID':'101','ADMIN_API_ID':'11'}):
            r=await self.client.get('/login')
            r=await self.client.post('/login',data={'csrf':value(r.text,'csrf'),'username':'ExistingOwner','password':'OwnerPassword!'},headers={'Origin':'https://example.test'})
            self.assertEqual(r.status_code,303)
            self.assertEqual((await self.client.get('/admin')).status_code,200)
            self.assertIn('101',(await self.client.get('/telegram')).text)
            self.assertIn('INSTAGRAM_APP_ID',(await self.client.get('/instagram')).text)
        self.assertEqual(self.store.authenticate(tg_token),uid)
        self.assertEqual(self.vault.load(uid)['session'],'OLD-TG-SESSION')
        async with self.app.downstream.router.lifespan_context(self.app.downstream):
            r=await self.client.post('/mcp/'+tg_token,json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'whoami','arguments':{}}},headers={'Accept':'application/json, text/event-stream'})
            self.assertEqual(r.status_code,200,r.text)
            self.assertIn('101',r.text)

    async def test_admin_stats_blocking_with_telegram_contact_and_messaging(self):
        from test_core import FakeAdapter
        admin_uid, _ = self.store.create_user('OwnerPIN', 101)
        self.web.add_profile(admin_uid, 11, 'a'*32, 'Existing owner')
        self.web.bootstrap_admin(admin_uid)
        self.pool.clients[admin_uid] = FakeAdapter(101)
        alice = await self.signup('alice', 'ip-1')
        bob = await self.signup('bob', 'ip-2')
        self.connect_fake(alice, '777')

        admin_token = self.signin(admin_uid)
        r = await self.client.get('/admin')
        self.assertEqual(r.status_code, 200)
        self.assertIn('Jami foydalanuvchilar', r.text)
        self.assertIn('Foydalanuvchilarga xabar yuborish', r.text)
        self.assertIn('@alice', r.text)
        self.assertIn('@bob', r.text)

        # Send broadcast message and personal message to Alice
        r = await self.post('/admin/message/send', admin_token, target='all', title='Umumiy yangilik', message='Barchaga e’lon matni')
        self.assertEqual(r.status_code, 303)
        r = await self.post('/admin/message/send', admin_token, target=alice, title='Shaxsiy xabar', message='Faqat Alice uchun')
        self.assertEqual(r.status_code, 303)

        # Verify Alice sees both messages on / and /messages
        alice_token = self.signin(alice)
        r = await self.client.get('/')
        self.assertIn('Xabarlar (2)', r.text)
        self.assertIn('Umumiy yangilik', r.text)
        self.assertIn('Shaxsiy xabar', r.text)
        r = await self.client.get('/messages')
        self.assertEqual(r.status_code, 200)
        self.assertIn('Faqat Alice uchun', r.text)
        r = await self.post('/messages/read-all', alice_token)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.panel.admin_service.unread_count(alice), 0)

        # Verify Bob only sees the broadcast message, never Alice's personal message
        bob_token = self.signin(bob)
        r = await self.client.get('/')
        self.assertIn('Xabarlar (1)', r.text)
        self.assertIn('Umumiy yangilik', r.text)
        self.assertNotIn('Faqat Alice uchun', r.text)

        # Admin blocks Bob while Bob has an active session
        admin_token = self.signin(admin_uid)
        r = await self.post('/admin/user/' + bob + '/block', admin_token)
        self.assertEqual(r.status_code, 303)
        self.assertIsNone(self.web.resolve_session(bob_token))

        # Bob visits site with his old session cookie -> sees blocked screen with @alijonov_aex under Admin
        self.client.cookies.clear()
        self.client.cookies.set(SESSION, bob_token, domain='example.test', path='/')
        r = await self.client.get('/')
        self.assertEqual(r.status_code, 403)
        self.assertIn('Siz saytga kira olmaysiz, iltimos adminga murojaat qiling', r.text)
        self.assertIn('<h3>Admin</h3>', r.text)
        self.assertIn('https://t.me/alijonov_aex', r.text)
        self.assertIn('@alijonov_aex', r.text)

        # Bob tries to log in on a fresh browser at /login -> also sees blocked screen and cannot enter
        self.client.cookies.clear()
        login_page = await self.client.get('/login')
        r = await self.client.post('/login', data={'csrf': value(login_page.text, 'csrf'), 'username': 'bob', 'password': 'Password123!'}, headers={'Origin': 'https://example.test'})
        self.assertEqual(r.status_code, 403)
        self.assertIn('Siz saytga kira olmaysiz, iltimos adminga murojaat qiling', r.text)
        self.assertIn('@alijonov_aex', r.text)
        self.assertTrue(self.client.cookies.get(BLOCKED))
        # Subsequent GET / on Bob's browser still shows blocked screen
        r = await self.client.get('/')
        self.assertEqual(r.status_code, 403)
        self.assertIn('@alijonov_aex', r.text)
        # Switching account link clears BLOCKED cookie
        r = await self.client.get('/login?switch=1')
        self.assertEqual(r.status_code, 200)

        # Admin unblocks Bob -> Bob can log in again
        admin_token = self.signin(admin_uid)
        r = await self.post('/admin/user/' + bob + '/unblock', admin_token)
        self.assertEqual(r.status_code, 303)
        self.client.cookies.clear()
        login_page = await self.client.get('/login')
        r = await self.client.post('/login', data={'csrf': value(login_page.text, 'csrf'), 'username': 'bob', 'password': 'Password123!'}, headers={'Origin': 'https://example.test'})
        self.assertEqual(r.status_code, 303)
        self.assertEqual((await self.client.get('/')).status_code, 200)

    async def test_duplicate_instagram_link_cannot_move_other_tenant(self):
        a,b=await self.signup('alice'),await self.signup('bob')
        self.connect_fake(a)
        token=self.web.create_session(b)
        state=parse_qs(urlsplit(self.ig.begin(b,token)).query)['state'][0]
        with self.assertRaises(SafeError):
            await self.ig.complete(state,'code',token)
        self.assertIsNone(self.ig.account(b))
        self.assertEqual(self.ig.account(a)['instagram_id'],'777')

    async def test_telegram_two_factor_and_wrong_account_flow(self):
        a,b=await self.signup('alice'),await self.signup('bob')
        guest=self.web.guest_token()
        self.fake.need_password=True
        await self.panel.telegram_link.start_link(a,guest,dict(api_id='123',api_hash='a'*32,phone='+998901234567',pin='PIN123',confirm='PIN123'),'ip')
        result=await self.panel.telegram_link.verify(guest,'12345','code','ip')
        self.assertIsNone(result)
        self.assertEqual(self.panel.telegram_link.state(guest)['step'],'password')
        self.assertIsNone(self.store.user(a)['telegram_id'])
        from social_panel import LINK
        token=self.signin(b)
        self.client.cookies.set(LINK,guest,domain='example.test',path='/')
        r=await self.post('/telegram/connect/password',token,value='MY-2FA-SECRET')
        self.assertEqual(r.status_code,400)
        self.assertIsNone(self.store.user(b)['telegram_id'])
        result=await self.panel.telegram_link.verify(guest,'MY-2FA-SECRET','password','ip')
        self.assertEqual(result[0],a)

    async def test_uncertain_write_not_retried_and_stopped_account(self):
        uid=await self.signup()
        self.connect_fake(uid)
        self.ig.remember(uid,'comment',['456'])
        action=await self.ig.call(uid,'instagram_prepare_comment_reply',{'comment_id':'456','text':'Javob'})
        def failure(request):
            self.calls.append(request)
            raise httpx.ReadTimeout('secret=NEVER_SHOW_THIS')
        self.ig.transport=httpx.MockTransport(failure)
        with self.assertRaises(SafeError) as raised:
            await self.ig.decide(uid,action['action_id'],True)
        self.assertNotIn('NEVER_SHOW',str(raised.exception))
        self.assertEqual(self.ig.action(uid,action['action_id'])['status'],'uncertain')
        with self.assertRaises(SafeError):
            await self.ig.decide(uid,action['action_id'],True)
        self.assertEqual(len(self.calls),1)
        self.store.stop(uid)
        with self.assertRaises(SafeError):
            await self.ig.call(uid,'instagram_profile',{})

    async def test_password_change_and_account_delete(self):
        a,b=await self.signup('alice'),await self.signup('bob')
        token=self.signin(a)
        r=await self.post('/account/password',token,current='Password123!',password='NewPassword123!',confirm='NewPassword123!')
        self.assertEqual(r.status_code,303)
        self.assertIsNone(self.web.resolve_session(token))
        token=self.client.cookies.get(SESSION)
        self.connect_fake(a)
        r=await self.post('/account/delete',token,password='NewPassword123!',confirm='delete')
        self.assertEqual(r.status_code,303)
        with self.assertRaises(SafeError):
            self.store.user(a)
        self.assertIsNotNone(self.store.user(b))
        self.assertIsNone(self.ig.account(a))

    def unified_transport(self, pages=None, lifetime=None):
        self.unified_pages = pages if pages is not None else {'': [{'id':'777','username':'unified_test'}]}
        def handler(request):
            self.calls.append(request)
            self.assertEqual(request.url.host, 'graph.facebook.com')
            path=request.url.path
            if path.endswith('/oauth/access_token'):
                self.assertEqual(request.url.params['client_id'],'111')
                self.assertEqual(request.url.params['client_secret'],'test-app-secret')
                self.assertEqual(request.url.params['redirect_uri'],'https://example.test/instagram/callback')
                return httpx.Response(200,json={'access_token':'UNIFIED-SECRET',**({'expires_in':lifetime} if lifetime is not None else {})})
            self.assertEqual(request.headers['authorization'],'Bearer UNIFIED-SECRET')
            if path.endswith('/me'):
                return httpx.Response(200,json={'id':'999'})
            if path.endswith('/me/assigned_instagram_accounts'):
                after=request.url.params.get('after','')
                rows=self.unified_pages.get(after,[])
                paging={'cursors':{'after':'NEXT'}} if after=='' and 'NEXT' in self.unified_pages else {}
                return httpx.Response(200,json={'data':rows,'paging':paging})
            if path.endswith('/777'):
                self.assertNotIn('user_id',request.url.params.get('fields',''))
                self.assertNotIn('account_type',request.url.params.get('fields',''))
                return httpx.Response(200,json={'id':'777','username':'unified_test'})
            if path.endswith('/777/media'):
                return httpx.Response(200,json={'data':[{'id':'123'}]})
            if path.endswith('/777/conversations'):
                return httpx.Response(200,json={'data':[{'id':'thread:123'}]})
            return self.meta(request)
        self.ig.transport=httpx.MockTransport(handler)

    async def finish_unified(self, uid, session):
        response=await self.post('/instagram/connect',session)
        self.assertEqual(response.status_code,200)
        self.assertNotIn('location',response.headers)
        self.assertIn("form-action 'self'",response.headers['content-security-policy'])
        url=unescape(re.search(r'id="instagram-oauth-continue"[^>]*href="([^"]+)"',response.text).group(1))
        query=parse_qs(urlsplit(url).query)
        self.assertEqual(urlsplit(url).netloc,'www.facebook.com')
        self.assertEqual(query['config_id'],['222'])
        self.assertEqual(query['override_default_response_type'],['true'])
        self.assertNotIn('scope',query)
        self.assertNotEqual(query['state'],['<STATE>'])
        return await self.ig.complete(query['state'][0],'meta-code',session)

    async def test_unified_exchange_account_routes_and_approved_reply(self):
        uid=await self.signup(); session=self.signin(uid)
        self.unified_transport()
        with patch.dict(os.environ,{'INSTAGRAM_LOGIN_MODE':'unified','INSTAGRAM_CONFIG_ID':'222','INSTAGRAM_TOKEN_LIFETIME':'never'}):
            await self.finish_unified(uid,session)
            self.assertEqual(self.ig.account(uid)['expires'],0)
            self.assertEqual(self.ig.account(uid)['instagram_id'],'777')
            self.assertEqual(await self.ig.token(uid),'UNIFIED-SECRET')
            raw=self.store.db.execute('SELECT token_enc FROM instagram_accounts WHERE user_id=?',(uid,)).fetchone()[0]
            self.assertNotIn(b'UNIFIED-SECRET',raw)
            await self.ig.call(uid,'instagram_profile',{})
            await self.ig.call(uid,'instagram_posts',{})
            await self.ig.call(uid,'instagram_conversations',{})
            action=await self.ig.call(uid,'instagram_prepare_reply',{'conversation_id':'thread:123','text':'Salom'})
            aid=self.store.db.execute('SELECT id FROM instagram_actions WHERE user_id=?',(uid,)).fetchone()[0]
            await self.ig.decide(uid,aid,True)
            self.assertEqual(self.ig.action(uid,aid)['status'],'done')
            self.assertFalse(any('refresh_access_token' in r.url.path for r in self.calls))
            self.assertEqual(sum(r.url.path.endswith('/oauth/access_token') for r in self.calls),1)
        self.assertEqual(self.ig.account_mode(uid),'unified')
        await self.ig.call(uid,'instagram_profile',{})

    async def test_unified_multiple_accounts_paginated_and_reconnect(self):
        uid=await self.signup(); session=self.signin(uid)
        self.unified_transport({'':[{'id':'888','username':'other'}], 'NEXT':[{'id':'777','username':'wanted'}]})
        with patch.dict(os.environ,{'INSTAGRAM_LOGIN_MODE':'unified','INSTAGRAM_CONFIG_ID':'222','INSTAGRAM_TOKEN_LIFETIME':'never'}):
            with self.assertRaisesRegex(SafeError,'Bir nechta'):
                await self.finish_unified(uid,session)
            self.assertIsNone(self.ig.account(uid))
            self.connect_fake(uid,'777')
            await self.finish_unified(uid,session)
            self.assertEqual(self.ig.account(uid)['instagram_id'],'777')
            self.assertTrue(any(r.url.params.get('after')=='NEXT' for r in self.calls))

    async def test_unified_expiry_and_missing_asset_fail_closed(self):
        uid=await self.signup(); session=self.signin(uid)
        with patch.dict(os.environ,{'INSTAGRAM_LOGIN_MODE':'unified','INSTAGRAM_CONFIG_ID':'222','INSTAGRAM_TOKEN_LIFETIME':''}):
            self.unified_transport()
            with self.assertRaisesRegex(SafeError,'muddati'):
                await self.finish_unified(uid,session)
            self.unified_transport({'':[]}, lifetime=3600)
            with self.assertRaisesRegex(SafeError,'ulashilmadi'):
                await self.finish_unified(uid,session)
            self.assertIsNone(self.ig.account(uid))
            self.unified_transport(lifetime=3600)
            await self.finish_unified(uid,session)
            self.assertAlmostEqual(self.ig.account(uid)['expires'],time.time()+3600,delta=10)
            with self.store.db:
                self.store.db.execute('UPDATE instagram_accounts SET expires=? WHERE user_id=?',(time.time()-1,uid))
            with self.assertRaises(SafeError):
                await self.ig.token(uid)
            self.assertFalse(any('refresh_access_token' in r.url.path for r in self.calls))

    async def test_unified_system_subject_deletion_and_missing_config(self):
        uid=await self.signup(); session=self.signin(uid)
        other=await self.signup('bob'); self.connect_fake(other,'888')
        self.unified_transport()
        with patch.dict(os.environ,{'INSTAGRAM_LOGIN_MODE':'unified','INSTAGRAM_CONFIG_ID':'222','INSTAGRAM_TOKEN_LIFETIME':'never'}):
            await self.finish_unified(uid,session)
            enc=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
            body=enc(json.dumps({'algorithm':'HMAC-SHA256','user_id':'999'}).encode())
            sig=enc(hmac.new(b'test-app-secret',body.encode(),hashlib.sha256).digest())
            r=await self.client.post('/instagram/data-deletion',data={'signed_request':sig+'.'+body})
            self.assertEqual(r.status_code,200)
            self.assertIsNone(self.ig.account(uid))
            self.assertIsNotNone(self.ig.account(other))
            self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM instagram_auth WHERE user_id=?',(uid,)).fetchone()[0],0)
            with patch.dict(os.environ,{'INSTAGRAM_CONFIG_ID':''}):
                self.assertFalse(self.ig.configured)
                with self.assertRaises(SafeError): self.ig.begin(uid,session)

if __name__=='__main__':
    unittest.main()

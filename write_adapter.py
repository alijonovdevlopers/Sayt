"""Tasdiqlangan B amallari uchun haqiqiy Telethon 1.45.0 chaqiruvlari."""
from datetime import datetime, timedelta, timezone
import io

from actions import digest
from security import SafeError
from telegram_adapter import WaitRequired


class OutcomeUnknown(Exception):
    def __init__(self, seconds=None):
        self.seconds = seconds


class WriteAdapter:
    def __init__(self, adapter):
        self.adapter, self.client = adapter, adapter.client

    async def freeze(self, value):
        from telethon import types, utils
        from v1_compat import to_chat
        entity = await self.adapter.guarded(self.client.get_entity(to_chat(value)))
        marked_id = utils.get_peer_id(entity)
        if marked_id == 777000:
            raise SafeError('Telegram xizmat chatiga ruxsat yo‘q.')
        peer = utils.get_input_peer(entity)
        kind = 'user' if isinstance(peer, (types.InputPeerUser, types.InputPeerSelf)) else 'chat' if isinstance(peer, types.InputPeerChat) else 'channel' if isinstance(peer, types.InputPeerChannel) else None
        if kind is None:
            raise SafeError('Bu turdagi nishon qo‘llanmaydi.')
        return {'id': marked_id, 'raw_id': entity.id, 'kind': kind,
                'access_hash': getattr(peer, 'access_hash', None),
                'self': isinstance(peer, types.InputPeerSelf),
                'label': getattr(entity, 'title', None) or getattr(entity, 'first_name', '')}

    @staticmethod
    def peer(ref):
        from telethon import types
        if ref['id'] == 777000:
            raise SafeError('Telegram xizmat chatiga ruxsat yo‘q.')
        if ref['kind'] == 'user':
            if ref.get('self'):
                return types.InputPeerSelf()
            return types.InputPeerUser(ref['raw_id'], ref['access_hash'])
        if ref['kind'] == 'chat':
            return types.InputPeerChat(ref['raw_id'])
        if ref['kind'] == 'channel':
            return types.InputPeerChannel(ref['raw_id'], ref['access_hash'])
        raise SafeError('Nishon noto‘g‘ri.')

    async def snapshots(self, ref, ids):
        from core import allowed_message
        rows = await self.adapter.guarded(self.client.get_messages(self.peer(ref), ids=ids))
        results = []
        for mid, m in zip(ids, rows):
            if not m or m.id != mid or m.chat_id != ref['id']:
                raise SafeError('Xabar ko‘rsatilgan chatga tegishli emas yoki topilmadi.')
            item = self.adapter.public_message(m)
            if not allowed_message(item):
                raise SafeError('Xizmat xabari bilan amal taqiqlangan.')
            data = {'id': m.id, 'chat': m.chat_id, 'text': m.raw_text or '',
                    'media': getattr(m.photo or m.document, 'id', None),
                    'edited': str(getattr(m, 'edit_date', None))}
            results.append({'id': m.id, 'digest': digest(data), 'preview': (m.raw_text or '')[:500]})
        if len(results) != len(ids):
            raise SafeError('Xabarlar to‘liq topilmadi.')
        return results

    async def invite_preview(self, invite_hash):
        from telethon import functions
        info = await self.adapter.guarded(self.client(functions.messages.CheckChatInviteRequest(invite_hash)))
        chat = getattr(info, 'chat', None)
        return getattr(info, 'title', None) or getattr(chat, 'title', 'Taklifdagi chat')

    async def member_present(self, chat, user):
        if chat['kind'] == 'channel':
            from telethon import functions, types, utils
            result = await self.adapter.guarded(self.client(functions.channels.GetParticipantRequest(
                utils.get_input_channel(self.peer(chat)), self.peer(user))))
            if isinstance(result.participant, (types.ChannelParticipantBanned, types.ChannelParticipantLeft)):
                raise SafeError('Foydalanuvchi faol a’zo emas; cheklovlarini o‘zgartirmaymiz.')

    async def perform(self, tool, bundle, step=0, file_bytes=None):
        from telethon.errors import FloodWaitError
        try:
            return await self._perform(tool, bundle, step, file_bytes)
        except FloodWaitError as error:
            raise WaitRequired(error.seconds) from None

    async def _perform(self, tool, bundle, step=0, file_bytes=None):
        from telethon import functions as f, types as t, utils
        p, refs = bundle['params'], bundle['peers']
        peer = self.peer(refs['chat']) if 'chat' in refs else None
        user = self.peer(refs['user']) if 'user' in refs else None
        channel = lambda: utils.get_input_channel(peer)
        mid = p.get('message_id')
        c = self.client
        # Markdown talqini o‘chiq: ko‘rsatilgan matn aynan o‘sha holda yuboriladi.
        if tool in ('send_message', 'reply', 'schedule_message'):
            result = await c.send_message(peer, p['text'], reply_to=mid if tool == 'reply' else None,
                parse_mode=None, link_preview=False,
                schedule=datetime.fromisoformat(p['when']) if tool == 'schedule_message' else None)
        elif tool == 'edit_message':
            result = await c.edit_message(peer, mid, p['text'], parse_mode=None, link_preview=False)
        elif tool == 'delete_messages':
            result = await c.delete_messages(peer, p['message_ids'], revoke=p['revoke'])
        elif tool == 'forward_messages':
            result = await c.forward_messages(peer, [p['message_ids'][step]], from_peer=self.peer(refs['from_chat']))
        elif tool == 'send_file':
            data = io.BytesIO(file_bytes)
            data.name = p['filename']
            result = await c.send_file(peer, data, caption=p['caption'], parse_mode=None, force_document=True)
        elif tool == 'react':
            result = await c(f.messages.SendReactionRequest(peer, mid,
                reaction=[t.ReactionEmoji(p['emoji'])] if p['emoji'] else []))
        elif tool == 'pin':
            result = await c.pin_message(peer, mid, notify=p['notify'])
        elif tool == 'unpin':
            result = await c.unpin_message(peer, mid)
        elif tool == 'mark_read':
            result = await c.send_read_acknowledge(peer, max_id=p['max_id'])
        elif tool == 'join_chat':
            result = await c(f.messages.ImportChatInviteRequest(bundle['invite_hash'])) if 'invite_hash' in bundle else await c(f.channels.JoinChannelRequest(channel()))
        elif tool == 'leave_chat':
            result = await c(f.channels.LeaveChannelRequest(channel())) if refs['chat']['kind'] == 'channel' else await c(f.messages.DeleteChatUserRequest(refs['chat']['raw_id'], t.InputUserSelf()))
        elif tool == 'create_group':
            result = await c(f.messages.CreateChatRequest([utils.get_input_user(self.peer(u)) for u in refs['users']], p['title']))
        elif tool == 'create_channel':
            result = await c(f.channels.CreateChannelRequest(p['title'], p['about'], broadcast=not p['megagroup'], megagroup=p['megagroup']))
        elif tool == 'add_member':
            result = await c(f.channels.InviteToChannelRequest(channel(), [utils.get_input_user(user)])) if refs['chat']['kind'] == 'channel' else await c(f.messages.AddChatUserRequest(refs['chat']['raw_id'], utils.get_input_user(user), 0))
        elif tool == 'remove_member':
            # Telethon kanal a’zosini ban+unban bilan chiqaradi. Ikkinchi qism
            # xatosidan keyin butun amalni takrorlash mumkin emas.
            try:
                result = await c.kick_participant(peer, user)
            except Exception as error:
                from telethon.errors import FloodWaitError
                raise OutcomeUnknown(error.seconds if isinstance(error, FloodWaitError) else None) from None
        elif tool == 'set_title':
            result = await c(f.channels.EditTitleRequest(channel(), p['title'])) if refs['chat']['kind'] == 'channel' else await c(f.messages.EditChatTitleRequest(refs['chat']['raw_id'], p['title']))
        elif tool == 'set_about':
            result = await c(f.messages.EditChatAboutRequest(peer, p['about']))
        elif tool in ('block', 'unblock'):
            result = await c(f.contacts.BlockRequest(user) if tool == 'block' else f.contacts.UnblockRequest(user))
        elif tool == 'archive':
            result = await c.edit_folder(peer, folder=1 if p['archived'] else 0)
        elif tool == 'mute':
            until = datetime.now(timezone.utc) + timedelta(hours=p['hours']) if p['muted'] else datetime.fromtimestamp(0, timezone.utc)
            result = await c(f.account.UpdateNotifySettingsRequest(t.InputNotifyPeer(peer), t.InputPeerNotifySettings(mute_until=until)))
        elif tool == 'send_poll':
            poll = t.Poll(id=0, question=t.TextWithEntities(p['question'], []),
                answers=[t.PollAnswer(t.TextWithEntities(text, []), bytes([i])) for i, text in enumerate(p['options'])],
                hash=0, public_voters=not p['anonymous'], multiple_choice=p['multiple'])
            result = await c(f.messages.SendMediaRequest(peer, t.InputMediaPoll(poll), '', random_id=bundle['random_id']))
        else:
            raise SafeError('Amal bajaruvchisi yo‘q.')
        ids = [x.id for x in (result if isinstance(result, list) else [result]) if isinstance(x, t.Message)]
        updates = getattr(result, 'updates', None)
        chats = getattr(result, 'chats', None) or getattr(updates, 'chats', [])
        return {'xabar': 'Telegram javobi olindi.', 'message_ids': ids,
                'chat_ids': [utils.get_peer_id(chat) for chat in chats]}

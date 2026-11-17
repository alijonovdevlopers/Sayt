"""Kutubxonasiz HTML. Tashqi qiymatlarning hammasi escape qilinadi."""
from datetime import datetime
from html import escape
import json
from zoneinfo import ZoneInfo


def e(value):
    text = str(value)
    for c in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069':
        text = text.replace(c, '[U+' + format(ord(c), '04X') + ']')
    return escape(text, quote=True)


def when(stamp):
    return datetime.fromtimestamp(stamp, ZoneInfo('Asia/Tashkent')).strftime('%d.%m · %H:%M')


def field(name, label, kind='text', *, required=True, hint='', attrs=''):
    return f'<label>{e(label)}<input name="{e(name)}" type="{e(kind)}" {"required" if required else ""} {attrs}></label>' + (f'<small>{e(hint)}</small>' if hint else '')


def hidden(name, value):
    return f'<input type="hidden" name="{e(name)}" value="{e(value)}">'


def form(path, csrf, body, label, tone='', extra=''):
    return f'<form method="post" action="{e(path)}">{hidden("csrf", csrf)}{body}<button class="{e(tone)}" {extra}>{e(label)}</button></form>'


def card(body, cls=''):
    return f'<section class="card {e(cls)}">{body}</section>'


def note(text, bad=False):
    return f'<div class="notice {"bad" if bad else ""}" role="status">{e(text)}</div>'


def dump(value):
    return '<pre dir="ltr">' + e(json.dumps(value, ensure_ascii=False, indent=2)) + '</pre>'


LABELS = {'send_message': 'Xabar yuborish', 'reply': 'Javob yozish', 'edit_message': 'Xabarni tahrirlash',
          'delete_messages': 'Xabarlarni o‘chirish', 'forward_messages': 'Xabarlarni uzatish', 'send_file': 'Fayl yuborish',
          'react': 'Reaksiya', 'pin': 'Mahkamlash', 'unpin': 'Mahkamdan olish', 'mark_read': 'O‘qilgan deb belgilash',
          'join_chat': 'Chatga qo‘shilish', 'leave_chat': 'Chatdan chiqish', 'create_group': 'Guruh yaratish',
          'create_channel': 'Kanal yaratish', 'add_member': 'A’zo qo‘shish', 'remove_member': 'A’zoni chiqarish',
          'set_title': 'Nomni o‘zgartirish', 'set_about': 'Tavsifni o‘zgartirish', 'block': 'Bloklash', 'unblock': 'Blokdan olish',
          'archive': 'Arxiv', 'mute': 'Bildirishnomalar', 'schedule_message': 'Xabarni rejalash', 'send_poll': 'So‘rovnoma yuborish'}
STATUS = {'pending': 'Tasdiq kutilmoqda', 'approved': 'Bajarish kutilmoqda', 'running': 'Bajarilmoqda',
          'done': 'Bajarildi', 'rejected': 'Rad etildi', 'expired': 'Muddati tugadi', 'cancelled': 'Bekor qilindi',
          'partial': 'Qisman bajarildi', 'uncertain': 'Natija noaniq', 'invalid': 'Tasdiq yaroqsiz', 'failed': 'Xato'}


def action_row(row):
    return f'<a class="action-row" href="/actions/{e(row["id"])}"><span class="action-icon">↗</span><span class="row-main"><strong>{e(LABELS.get(row["tool"], row["tool"]))}</strong><small>{e(when(row["created"]))} · {e(STATUS.get(row["status"], row["status"]))}</small></span><span aria-hidden="true">›</span></a>'


def layout(title, content, profile=None, active='', csrf=''):
    nav = ''
    if profile:
        links = [('/', 'Bosh', '◈'), ('/pending', 'Amallar', '≡'), ('/logs', 'Jurnal', '◷'), ('/settings', 'Sozlamalar', '⚙')]
        nav = '<nav aria-label="Asosiy menyu">' + ''.join(f'<a href="{path}" {"aria-current=page" if path == active else ""}><span aria-hidden="true">{icon}</span>{name}</a>' for path, name, icon in links) + '</nav>'
        top = f'<span class="account">{e(profile["display_name"])}</span>'
        if profile['is_admin']:
            top += '<a class="owner-link" href="/admin">Boshqaruv</a>'
    else:
        top = '<span class="pill">SHAXSIY NAZORAT</span>'
    return f'''<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#0b101b"><title>{e(title)} · Telegram nazorati</title><link rel="stylesheet" href="/assets/panel.css"><script src="/assets/panel.js" defer></script></head>
    <body><a class="skip" href="#main">Mazmunga o‘tish</a><div class="shell"><header><a class="brand" href="/"><span class="brand-mark">↗</span><span>Telegram<small>NAZORAT MARKAZI</small></span></a><div class="top-meta">{top}</div></header>{nav}<main id="main" class="{'' if profile else 'auth'}"><div class="page-heading"><p class="eyebrow">{'SIZNING BOSHQARUVINGIZ' if profile else 'XUSH KELIBSIZ'}</p><h1>{e(title)}</h1></div>{content}</main><footer>Qaror sizda. Har bir o‘zgarish tasdiq bilan.<span>Toshkent vaqti · UTC+5</span></footer></div></body></html>'''

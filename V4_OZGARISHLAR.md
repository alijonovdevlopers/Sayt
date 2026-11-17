# v4: Google bilan kirish (1-bosqich, veb qismi)

## Yangi
- `google_auth.py`: PKCE, imzolangan oqim cookiesi, email ruxsat ro‘yxati, admin emaili, sub bog‘lash.
- Panelda: "Google bilan kirish" tugmasi, `/auth/google`, `/auth/google/callback`.
- Admin paneli: "Google emaillar" (qo‘shish / olib tashlash, jami 50 tagacha).
- `ADMIN_EMAIL` bilan kirgan odam egasi hisobiga avtomatik bog‘lanadi.
- Ruxsat ro‘yxatidagi yangi email taklif kodisiz Telegram ulaydi; oldingi hisobni PIN bilan kirib bog‘lash ham mumkin.

## O‘zgarmagan
- API ID + API hash + PIN bilan kirish, taklif kodlari, MCP maxfiy manzillari, tasdiq navbati.
- GOOGLE_* o‘zgaruvchilari berilmasa, sayt avvalgidek ishlaydi (Google tugmasi chiqmaydi).

## Hali yo‘q
- MCP uchun bitta URL + OAuth (4-bosqich), Instagram.

## Railway Variables
PUBLIC_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, ADMIN_EMAIL
Google redirect URI: PUBLIC_URL + /auth/google/callback

# v2 → v3 o‘zgarishlari

Bu yangilanish faqat quyidagi o‘zgargan/yangi fayllarni to‘liq beradi.
`tg_userbot_mcp_v2.zip` ustiga chiqaring; avvalgi qolgan fayllar kerak.
`.env`, `data/`, sessiya va yangi paket kiritilmagan.

## O‘zgargan fayllar

- `OZGARISHLAR.md`
- `README.md`
- `SINOV_JURNALI.txt`
- `TEST_NATIJALARI.txt`
- `action_service.py`
- `core.py`
- `server.py`
- `storage.py`
- `telegram_adapter.py`

## Yangi fayllar

- `assets/panel.css`
- `assets/panel.js`
- `registration.py`
- `test_web.py`
- `web.py`
- `web_admin.py`
- `web_store.py`
- `web_ui.py`

## Natijadagi xatti-harakat

- Telefon uchun o‘zbekcha qorong‘i panel: kirish, taklifli ro‘yxat, bosh, amallar, jurnal, sozlamalar va egaga boshqaruv.
- Tasdiqlash haqiqiy parametr nusxasiga bog‘langan; ommaviy amalda alohida imzoli ikkinchi tasdiq.
- Taklif bilan kod/2FA oqimi; sirlar RAMda, yakuniy sessiya/hash shifrlanadi; shu mijoz poolga beriladi.
- Scrypt PIN, HMAC sessiya, CSRF, HTTPS/Host/Origin, CSP, 12 soatlik sessiya va 5 urinishli IP/akkaunt cheklovi.
- PINli resume, PINni almashtirish, MCP manzilini yangilash; foydalanuvchilar ajratilgan.
- Egaga taklif/bloklash/mahalliy o‘chirish. O‘chirishdan avval ishchi bekor, faol core amali tugashi kutiladi, keyin fayl/baza o‘chadi.
- `storage.py` yangi web jadvallarini avtomatik qo‘shadi; `web_store.py` eski shifrlangan profillarni indekslaydi.
- `core.py` o‘chirilgan foydalanuvchidan kechikkan chaqiruvga nazoratli xato qaytaradi.
- `server.py` panel va MCP yo‘llarini ajratadi; bitta jarayon, umumiy pool va lifecycle saqlanadi.
- Avvalgi 126 sinov + 44 yangi panel sinovi = 170 muvaffaqiyatli. 33 Python fayli compile qilindi.
- Brauzer muhiti cheklangani uchun vizual/telefon sinovi hali tasdiqlanmagan. Jonli Telegram ishlatilmadi.
- Docker/Cloudflare (4), ilovalarga ulash (5), Instagram (6) qo‘shilmadi.

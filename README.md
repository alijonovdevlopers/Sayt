# Telegram akkaunt MCP — v3, 3-bosqich: sayt paneli

Asos: yuborilgan `tg_userbot_mcp_v1.zip`. Kod o‘qildi va asl 9 ta test alohida
ishga tushirildi. Himoyalangan HTTP yadro va 2-bosqich navbati saqlandi. Endi taklifli ro‘yxatdan
o‘tish, API hash + PIN bilan kirish va telefon uchun qorong‘i sayt paneli qo‘shildi.

**Bu ZIP — v2 ustiga qo‘yiladigan yangilanish.** Faqat v2dan o‘zgargan/yangi
fayllar kiritilgan; v2dagi boshqa fayllar kerak. Avval v2, so‘ng v3 ZIPni bir
katalogga chiqaring. `.env` va `data/` arxivga kiritilmagan.

3-bosqich kodi tayyor. Jonli Telegram va vizual brauzer sinovi hali bajarilmagan;
aniq sinov chegaralari `TEST_NATIJALARI.txt`da. 4-bosqich joylash hali boshlanmadi.

## Nima tayyor

8 ta o‘qish vositasi, 24 ta B taklif vositasi va `action_status` mavjud.
B chaqiruvi Telegramni o‘zgartirmaydi: bazaga `pending` yozadi va ID qaytaradi.
Egasi aniq nishon, matn, fayl va xabarlar sonini ko‘rib tasdiqlaydi. Tasdiq
berilmagan amal 10 daqiqada eskiradi. 10 tadan ko‘p xabar/a’zoda ikkinchi
alohida tasdiq kerak. Yangi yuborishlar orasida kamida 2 soniya, har foydalanuvchiga
oxirgi 3600 soniyada 30 yuborish. Limitlar bazada qoladi.

Har akkauntga bitta Telethon mijozi; HTTP MCP va ishchi ayni jarayonda.
`approve.py` Telegramga ulanmaydi. Sayt, MCP va ishchi ayni yadro va mijozdan foydalanadi.
Foydalanuvchi maxfiy MCP manzilidan aniqlanadi; vositalar `user_id` olmaydi.
Sessiya va API hash Fernet bilan `data/users/<user_id>/credentials.enc`ga
shifrlanadi. Papka 700, fayl 600. PIN scrypt bilan heshlanadi.

## v1 bilan moslash

`whoami`, `list_chats`, `read_messages` nomlari va eski o‘zbekcha maydonlar
saqlandi: `ism`, `chatlar`, `xabarlar`, `nom`, `tur`, `oqilmagan`, `matn`,
`sana`, `kim`, `media_bor`. Qo‘shimcha `ok`, `data`, `eslatma` bor.
`MAX_LIMIT`, `MAX_TEXT`, chat IDni songa aylantirish va eski `xabarlar`da matnni
`…` bilan qisqartirish saqlandi. `data` yangi batafsil natijani beradi.

`ReadOnly` yangi A/B ruxsat qatlami bilan almashtirildi. Eski stdio sozlamasi
HTTP manziliga avtomatik mos emas. Noto‘g‘ri limitlar endi rad etiladi.
`check.py` endi tarmoqqa chiqmaydigan sinovlarni bajaradi; akkauntni jonli
tekshirish uchun MCPdagi `whoami` va `list_chats` ishlatiladi.

## Vositalar

| A vosita | Parametrlar |
|---|---|
| `whoami` | yo‘q |
| `list_chats` | `limit=30` |
| `read_messages` | `chat`, `limit=30`, `offset_id=0` |
| `search_messages` | `query`, `chat=null`, `limit=30` |
| `get_chat_info` | `chat` |
| `list_members` | `chat`, `limit=30` |
| `get_unread` | `limit=30` |
| `download_media` | `chat`, `message_id` |

`chat` — ID yoki username. Limit 1–100 va `.env`dagi `MAX_LIMIT`dan oshmaydi.
`get_unread` faqat ko‘rilgan dastlabki chatlarni tekshiradi, global jami emas.
Telefon, sessiya va API hash chiqarilmaydi. 777000 xizmat chati ID, username,
jo‘natuvchi va forward manbasi bo‘yicha yopiq. O‘qilgan matn buyruq deb olinmaydi.
Media faqat `data/downloads/<user_id>/<id>.bin`ga: bitta fayl 20 MiB, jami
foydalanuvchiga 100 MiB. Haqiqiy hajm tekshiriladi, yarim fayl o‘chiriladi.

| B vosita | Majburiy parametrlar | Ixtiyoriy parametrlar |
|---|---|---|
| `send_message` | `chat`, `text` | — |
| `reply` / `edit_message` | `chat`, `message_id`, `text` | — |
| `delete_messages` | `chat`, `message_ids` | `revoke=true` |
| `forward_messages` | `from_chat`, `chat`, `message_ids` | — |
| `send_file` | `chat`, `filename` | `caption=""` |
| `react` | `chat`, `message_id`, `emoji` | Bo‘sh emoji reaksiyani olib tashlaydi |
| `pin` | `chat`, `message_id` | `notify=false` |
| `unpin` | `chat`, `message_id` | — |
| `mark_read` | `chat`, `max_id` | Faqat shu IDgacha |
| `join_chat` / `leave_chat` | `chat` | Join uchun taklif havolasi ham mumkin |
| `create_group` | `title`, `users` | 1–20 a’zo |
| `create_channel` | `title` | `about=""`, `megagroup=false` |
| `add_member` / `remove_member` | `chat`, `user` | — |
| `set_title` | `chat`, `title` | — |
| `set_about` | `chat`, `about` | — |
| `block` / `unblock` | `user` | — |
| `archive` | `chat` | `archived=true`; false arxivdan chiqaradi |
| `mute` | `chat` | `muted=true`, `hours=24`; false ovozni yoqadi |
| `schedule_message` | `chat`, `text`, `when` | — |
| `send_poll` | `chat`, `question`, `options` | `anonymous=true`, `multiple=false` |

Matn 4096 UTF-16 birlik, izoh 1024. Markdown va link preview o‘chirilgan:
ko‘rsatilgan matn aynan yuboriladi. O‘chirish 1–100 ID, forward 1–30 ID.
Forwardlar bitta-bitta, har biri limitga hisoblanadi. Xabar IDlari aynan
ko‘rsatilgan chatga tegishliligi tekshiriladi; boshqa chatdagi ID o‘tmaydi.

`when` zona bilan ISO vaqt, masalan `2026-11-10T18:00:00+05:00`; navbatda UTCga
aylanadi. Bajarishda kamida 1 daqiqa qolishi kerak. Poll oddiy so‘rovnoma:
2–10 noyob javob; quiz va maxsus pullik reaksiya qo‘shilmagan.
`remove_member` superguruh/kanalda Telethonning ban+unban usulidan foydalanadi;
ikki qism orasida xato bo‘lsa avtomatik takrorlanmaydi. Avval bloklangan a’zoning
cheklovini tasodifan olib tashlash ham bloklangan.

## Tasdiqlash

AI taklifdan `pending` va ID oladi. Egasi boshqa terminalda:

```bash
python approve.py AMAL_ID
```

Foydalanuvchi ID va PIN so‘raladi. Yoki IDni buyruqda bering:

```bash
python approve.py AMAL_ID --user FOYDALANUVCHI_ID
```

Tafsilot AI tavsifidan emas, bazadagi parametrdan olinadi: to‘liq yuboriladigan
matn, kimga, xabar ID/soni, fayl nomi/hajmi/SHA-256. Nishondagi xabarning dastlabki
500 belgisi namuna, to‘liq mazmun izi o‘zgarishni aniqlash uchun saqlanadi.
Yashirin yo‘nalish belgilari terminalda ko‘rinadigan qilib chiqariladi.

Aynan `RUXSAT` yoki `RAD` yoziladi. Ommaviy amalda yana `OMMAVIY AMAL_ID`
yozilishi shart. Tasdiq ko‘rsatilgan nusxaga bog‘langan. 10 daqiqadan keyingi
tasdiq qabul qilinmaydi. Server o‘chiq yoki limit band bo‘lsa tasdiqlangan
amal kutadi; buyruq darhol yuborildi deb aytmaydi.

```bash
python approve.py list --user FOYDALANUVCHI_ID
```

Tugagan amalni o‘sha ID bilan qayta ko‘rish mumkin. AI `action_status(action_id)`
orqali holat, bajarilgan qismlar va xabar/chat IDlarini oladi. MCPda tasdiqlash
vositasi yo‘q. 5 xato PINdan keyin mahalliy tasdiq 15 daqiqaga bloklanadi.

| Holat | Ma’nosi |
|---|---|
| `pending` / `approved` | Tasdiqni / ishchini kutmoqda |
| `running` / `done` | Bajarilmoqda yoki limitni kutmoqda / tugagan |
| `rejected` / `expired` | Rad etilgan / tasdiq muddati tugagan |
| `cancelled` / `partial` | To‘xtagan / ayrim qismlari bajarilgan |
| `uncertain` | Natija noaniq; Telegramda tekshiring, avtomatik qaytarilmaydi |
| `invalid` / `failed` | Tasdiq yaxlitligi buzilgan / boshlashda xato |

Server uzilganda `running` amallar qayta ishga tushishda `uncertain` bo‘ladi.
Bitta amalni ikki ishchi yoki takroriy tasdiq ikki marta bajarmaydi.
Noaniq amalni qayta taklif qilishdan oldin Telegramda natijani tekshiring.

## Fayl, to‘xtatish va jurnal

Yuboriladigan fayl `data/outbox/<user_id>/` ichiga qo‘yiladi. `filename` faqat
nom, masalan `audio.mp3`; URL/to‘liq yo‘l yo‘q. Symlink, ko‘p bog‘lamli fayl va
20 MiB dan kattasi rad etiladi. Tasdiqdan keyin fayl o‘zgarsa yuborilmaydi.
Tekshirilgan baytlar xotiradan hujjat sifatida yuboriladi.

```bash
python admin.py toxtatish FOYDALANUVCHI_ID
```

O‘sha egasining `pending`/`approved` amallari bekor, A/B vositalari yopiq bo‘ladi.
Ishchi keyingi yuborishdan oldin yana holatni tekshiradi. Allaqachon ketgan
amal yoki Telegramga oldin topshirilgan rejalashtirilgan xabar avtomatik
qaytarilmaydi. Qayta yoqish faqat saytdagi Sozlamalar sahifasida PIN bilan bajariladi.

```bash
python admin.py holat FOYDALANUVCHI_ID
python admin.py jurnal FOYDALANUVCHI_ID
```

Jurnalda matn, maxfiy manzil, API hash, sessiya, PIN va xom xatolar yashiriladi.
Navbat esa tasdiq uchun to‘liq parametrni saqlaydi; u jurnal emas, baza 600 ruxsatda.
MCP access-log o‘chirilgan. Tunnel/proxy logida ham to‘liq maxfiy yo‘lni yozmang.

## Cloud Shell: v2 → v3 yangilash

Avval ishlayotgan `python server.py` jarayonini to‘xtating. `tg_userbot_mcp/`
katalogi turgan joyga v3 ZIPni yuklang. Buyruqlarni birin-ketin bajaring:

```bash
cp -a tg_userbot_mcp tg_userbot_mcp_v2_backup
chmod 700 tg_userbot_mcp_v2_backup
unzip -o tg_userbot_mcp_v3.zip
cd tg_userbot_mcp
source .venv/bin/activate
python check.py
python web_admin.py FOYDALANUVCHI_ID
python server.py
```

`FOYDALANUVCHI_ID` o‘rniga `login.py` yoki migratsiya bergan 32 belgili IDni
qo‘ying. IDni topa olmasangiz, `data/users/`dagi o‘z akkaunt papkangiz nomini
oling. `web_admin.py` o‘sha akkauntning PINini so‘raydi va birinchi sayt egasini
faqat bir marta belgilaydi. Bu buyruqdan keyingi foydalanuvchilar sayt taklifi
orqali kiradi. Boshqa foydalanuvchilarni egaga aylantiradigan ochiq yo‘l yo‘q.

Mavjud `.env`, `ENC_KEY`, `MCP_SECRET` va `data/`ni saqlang; qayta login qilmang.
SQLite yangi jadvallarni o‘zi qo‘shadi. v2 akkauntlariga shifrlangan fayldan
sayt kirishi uchun profil yaratiladi; API hash ochiq bazaga yozilmaydi.
Yangi paket yo‘q; v2 virtual muhiti yetadi. Kalit yoki API hashni chatga yubormang.

## Cloud Shell: birinchi o‘rnatish

Python 3.12 va avvalgi `tg_userbot_mcp_v2.zip` ham kerak. Ikkala ZIP bir joyda:

```bash
mkdir tg_mcp_v3_work
unzip tg_userbot_mcp_v2.zip -d tg_mcp_v3_work
unzip -o tg_userbot_mcp_v3.zip -d tg_mcp_v3_work
cd tg_mcp_v3_work/tg_userbot_mcp
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock.txt
python check.py
python setup.py
python login.py
python web_admin.py FOYDALANUVCHI_ID
python server.py
```

`login.py` faqat birinchi sayt egasi uchun: API ID/hash, yangi sayt PINi, telefon,
kod va zarur bo‘lsa Telegram 2FA parolini yashirin so‘raydi. Foydalanuvchi ID va
MCP manzilini o‘zingiz saqlang. API ma’lumotlari [my.telegram.org](https://my.telegram.org)
 orqali olinadi. PIN Telegram 2FA parolidan alohida.

Server `127.0.0.1:8000`da ishlaydi; tashqi kirish faqat **HTTPS** orqali.
`.env`dagi `PUBLIC_URL` haqiqiy HTTPS domen bo‘lsin. Cookie `__Host-` prefiksi,
Secure, HttpOnly, SameSite=Strict, Path=/ bilan beriladi. HTTP orqali panelga
kirish ataylab bloklangan; sinash uchun bu himoyani o‘chirmang.
Tunnel haqiqiy Host va HTTPS protokolini yetkazishi kerak. Forwarded sarlavhalar
faqat mahalliy 127.0.0.1dan ishoniladi; foydalanuvchi IPsi to‘g‘ri uzatilishi
bloklash uchun muhim. Docker, Oracle ARM va Cloudflare bilan joylash — 4-bosqich.
Bu arxiv avtomatik ravishda internetga sayt chiqarmaydi.

## Saytdan foydalanish

1. `PUBLIC_URL`ni brauzerda oching. O‘z API ID + API hash + sayt PINi bilan kiring.
2. Sayt egasi **Boshqaruv → Bir martalik kod yaratish** orqali taklif oladi.
   Kod 24 soat amal qiladi, bir marta ko‘rsatiladi. Uni taklif qilinayotgan odamga
   alohida bering. Kod URLga joylanmaydi.
3. Yangi odam **Taklif bilan qo‘shilish** sahifasida o‘z API ma’lumotlari, telefon
   va PINini kiritadi. Telegram kodi, kerak bo‘lsa 2FA so‘raladi. Oyna 10 daqiqalik.
   Telegram xato qaytarsa kodi/paroli javob va jurnalga chiqarilmaydi.
4. Yakunda maxfiy MCP manzili bir marta ko‘rsatiladi. **Sozlamalar → Yangi manzil
   yaratish** PIN talab qiladi va eski manzilni darhol bekor qiladi.
5. **Bosh** holat va kutayotgan amallar sonini ko‘rsatadi. “Sessiya saqlangan”
   jonli ulanish isboti emas; **Ulanishni tekshirish** Telegramdan `whoami` oladi.
6. **Amallar** ichidagi qatorni oching. Aniq nishon, to‘liq parametr/matn, fayl
   ma’lumoti va xabarlar soni bazadan chiqadi. Ko‘k **Ruxsat**, qizil **Rad** bor.
   Ommaviy amalda yana alohida sahifa va belgilash katagi talab qilinadi.
7. **Jurnal**: Bugun, Xatolar, B daraja, Barchasi. Vaqtlar Toshkent, UTC+5.
8. **HAMMASINI TO‘XTATISH** o‘z A/B vositalaringizni yopadi va kutayotgan
   amallarni bekor qiladi. PIN bilan qayta yoqish bekor amallarni tiriltirmaydi.
9. **Sozlamalar**da PINni almashtirish boshqa sayt seanslarini bekor qiladi.
   Sayt seansi yaratilganidan 12 soat o‘tgach tugaydi; foydalanish uni uzaytirmaydi.
10. Egasi **Boshqaruv** orqali foydalanuvchini bloklaydi yoki saytdan o‘chiradi.
    O‘chirish alohida sahifada egasining PINini talab qiladi. Shifrlangan sessiya,
    outbox/downloads va bazadagi tegishli yozuvlar o‘chadi. Telegram akkauntining
    o‘zi o‘chirilmaydi, Telegramdagi boshqa qurilma sessiyalari tugatilmaydi.
    Fayl o‘chirish tugamasa akkaunt bloklangan qoladi; xatoni tuzatib qayta urining.

Sayt egasi boshqalarning jurnalini, navbat matnlarini yoki MCP manzilini ko‘rmaydi;
unga faqat foydalanuvchi profili va bloklash/o‘chirish boshqaruvi beriladi.
5 xato urinishdan keyin IP hamda akkaunt 15 daqiqaga cheklanadi. Har bir POST
forma CSRF va aynan sayt Originini talab qiladi. Tashqi matnlar HTML sifatida
bajarilmaydi; CSP ham ichki skriptlarni cheklaydi. JavaScript o‘chiq bo‘lsa ham
formalar ishlaydi; faqat nusxalash va takror bosishni kamaytirish yordamchisi yo‘q.

Yangi ro‘yxatda bir API to‘plamiga bitta sayt akkaunti olinadi. Eski v2 bazada
bir API bilan bir nechta akkaunt bo‘lsa, kirishda qo‘shimcha foydalanuvchi IDni
kiriting. Telefon/kod/2FA Telegramga egalikni tekshiradi; API hashning o‘zi
shaxsni tasdiqlovchi parol sifatida olinmaydi.

Ro‘yxat davomida telefon, kod hash va API hash faqat RAMda turadi; PIN scrypt
heshi ko‘rinishida. Yakunda sessiya va API hash Fernet bilan diskka yoziladi.
Telegram kodi va 2FA paroli diskka yozilmaydi. Server qayta ishga tushsa tugamagan
kirishni qayta boshlash kerak; taklif bandligi 10 daqiqada tugaydi.

## Ishlayotgan v1 ni yangilash

Avval eski stdio serverni to‘xtating. Bir akkauntni ikki serverda parallel
ishlatmang. Eski loyiha katalogi turgan joyda:

```bash
cp -a tg_userbot_mcp tg_userbot_mcp_v1_backup
chmod 700 tg_userbot_mcp_v1_backup
unzip -o tg_userbot_mcp_v2.zip
unzip -o tg_userbot_mcp_v3.zip
cd tg_userbot_mcp
```

Python 3.12 muhitini yuqoridagidek tayyorlab, paketlarni o‘rnating. Keyin:

```bash
python setup.py
python migrate_v1.py
python check.py
python web_admin.py FOYDALANUVCHI_ID
python server.py
```

`setup.py` eski `.env` qiymatlarini saqlab, yetishmagan kalitlarni qo‘shadi.
`migrate_v1.py` eski `SESSION_PATH`dagi 600 ruxsatli SQLite sessiyani faqat
o‘qiydi, akkauntni tekshiradi va shifrlangan nusxa yaratadi. Sessiya satri
chiqarilmaydi. Eski fayl o‘chirilmaydi: yangi ulanishni tekshirgach eski
ochiq nusxa va zaxiralarini o‘zingiz tartibga keltiring.

1-bosqichdagi shifrlangan baza ishlayotgan bo‘lsa, eski serverni to‘xtatib
`.env` va `data/`ni birga yangi loyiha katalogiga o‘tkazing. `ENC_KEY` va
`MCP_SECRET`ni o‘zgartirmang, qayta login/migratsiya qilmang. Yangi jadvallar
avtomatik qo‘shiladi; eski akkauntlar va jurnal saqlanadi.

## Sinov va qo‘lda tekshirish

```bash
python check.py
```

Bu barcha Python fayllariga `py_compile` va avtomatik testlar bajaradi.
Telethon/MCPsiz yadro va navbat sinovi:

```bash
python3.12 -S -m unittest -v test_core test_actions
```

Natijalar `TEST_NATIJALARI.txt`, xom chiqish `SINOV_JURNALI.txt`da.
Haqiqiy HTTPS va o‘zingizning sinov akkauntingizda quyidagilarni tekshiring:

1. `whoami` to‘g‘ri akkaunt va eski maydonlarni qaytarsin; 777000 ko‘rinmasin.
2. O‘zingizga `send_message` taklif qiling: tasdiqqacha xabar ketmasin.
3. Aniq matnni ko‘rib tasdiqlang: bir marta yuborilsin, status `done` bo‘lsin.
4. Boshqa taklifni rad eting, yana birini 10 daqiqa qoldiring: ikkalasi ham ketmasin.
5. Faqat test chatidagi 11 xabarda qo‘shimcha ommaviy tasdiqni tekshiring.
6. Ikki forward orasida kamida 2 soniya bo‘lsin. Soatlik limit uchun haqiqiy
   spam yuborish shart emas — avtomatik test bor.
7. Tasdiqdan keyin outbox faylini almashtiring: amal rad etilsin.
8. Ikkinchi foydalanuvchi birinchining amal IDsi bilan holat/tasdiq ololmasin.
9. Saytda ikki alohida brauzer bilan ikki foydalanuvchiga kiring. Begona amal
   IDni manzilga qo‘ysangiz uning matni ham, tasdig‘i ham ochilmasin.
10. Telefon ekranida Kirish, Bosh, Amallar, Jurnal, Sozlamalarni tekshiring:
    gorizontal siljish bo‘lmasin; pastki menyu forma tugmalarini yopmasin.
11. Taklif kodi bilan sinov akkaunti qo‘shing; 2FA bo‘lsa uni ham sinang.
    Bekor qilingan/ishlatilgan taklif bilan yangi kirish boshlanmasin.
12. PINni almashtiring; ikkinchi brauzerdagi eski sayt seansi qayta login so‘rasin.
13. MCP manzilini PIN bilan yangilang; eski maxfiy yo‘l 404 qaytarsin.
14. Faqat sinov foydalanuvchisini bloklang/oching; eski cookie ishlamasin.
    O‘chirishni faqat kerak bo‘lmagan sinov foydalanuvchisida tekshiring.
15. Eng oxirida sinov akkauntini to‘xtating: o‘z navbati bekor, boshqasiniki faol
    qolsin. Noto‘g‘ri PIN yoqmasin, to‘g‘ri PIN bilan faqat o‘z akkauntingiz yoqilsin.

## Chegaralar va keyingi bosqichlar

Telegram huquqlari va maxfiylik sozlamalari amallarni rad etishi mumkin.
Xabar yozishdan oldin qayta tekshiriladi, lekin alohida o‘qish/yozish orasidagi
juda qisqa o‘zgarishni Telegram API bilan atomar bloklash mumkin emas.
Limitlar shu serverning yuborish chaqiruvlariga tegishli; boshqa ilovalaringiz
va oldindan rejalashtirilgan xabarlarning haqiqiy yetkazilishini boshqarmaydi.
Oddiy odam nusxalagan kod matni/suratining kelib chiqishini ID bilan aniqlab bo‘lmaydi.

Taklifli sayt, cookie/CSRF, 12 soat sessiya, foydalanuvchi boshqaruvi va PIN
bilan qayta yoqish 3-bosqichda qo‘shildi. Docker/Cloudflare 4-bosqich,
Claude/ChatGPT amaliy ulash 5-bosqichda.
C amallari va Instagram qo‘shilmadi.

Jonli Telegram, tashqi HTTPS, ARM/Oracle va Claude/ChatGPT ilovasida ulanish
hali sinovdan o‘tmadi. Brauzer muhiti jarayon ochish va mahalliy faylni ochishni
chekladi; haqiqiy telefon/brauzer ko‘rinishi va tugma bosish sinovi tasdiqlanmagan.
HTTP formalar, HTML tuzilmasi va ishchi oqimi avtomatik ASGI testlarda tekshirildi. Sessiya migratsiyasi soxta mijoz bilan tekshirildi;
yuborilgan asosiy ZIP’da haqiqiy sessiya yo‘q edi.

Python 3.12, Telethon 1.45.0, MCP 1.29.0 (`mcp<2`), Starlette, uvicorn ishlatiladi.
SQLite/scrypt standart kutubxonadan; Fernet uchun ruxsat etilgan `cryptography`
saqlandi. Yangi paket qo‘shilmadi. Jinja2 ishlatilmaydi; HTML stdlib bilan, forma urllib.parse bilan; `httpx` va
`python-multipart` MCPning bog‘liqliklaridir. Aniq versiyalar lock-faylda.

- [Telethon 1.x mijoz usullari](https://docs.telethon.dev/en/stable/modules/client.html)
- [Telegram poll](https://core.telegram.org/api/poll)
- [Rejalashtirilgan xabarlar](https://core.telegram.org/api/scheduled-messages)
- [Reaksiyalar](https://core.telegram.org/method/messages.sendReaction)

Avvalgi 24 B yo‘li haqiqiy SDK turlari va TL serializatsiyasi bilan, tarmoqqa chiqmay
tekshirildi. v2dan o‘zgargan/yangi fayllar `OZGARISHLAR.md`da. ZIPda `.env`, shaxsiy
sessiya va baza yo‘q; eski `data/` ustidan yozilmaydi.

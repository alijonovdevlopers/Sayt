# v6: Instagram (Instagram API with Instagram Login)

Yoqish: Railway Variables ga `INSTAGRAM=1` (token Variables'ga yozilmaydi, saytda kiritiladi).

## Vositalar (MCP)
- `ig_conversations(limit)` — suhbatlar ro‘yxati (o‘qish).
- `ig_messages(conversation_id, limit)` — suhbatdagi so‘nggi xabarlar, 20 tagacha (o‘qish).
- `ig_send_message(recipient_id, text)` — YUBORMAYDI: qoralama saytdagi Instagram bo‘limida tasdiqni kutadi.

## Sayt
- Instagram bo‘limi (Sozlamalar → Instagram): token ulash (PIN bilan), ulanishni uzish, tasdiq kutayotgan xabarlar
  (aniq matn + qabul qiluvchi), "Yuborishga ruxsat" / "Rad etish", so‘nggi holatlar.

## Xavfsizlik
- Token bazada Fernet bilan shifrlangan va egasiga bog‘langan; sahifalarda/jurnalda ko‘rinmaydi.
- Qoralama matni va qabul qiluvchi o‘zgartirilsa (digest) yuborilmaydi; bir marta yuboriladi (parallel bosishda ham).
- Qoralama 1 soat yashaydi; to‘xtatish tugmasi va bloklash Instagram vositalariga ham amal qiladi.
- Matn jurnalga yozilmaydi; Instagram xatolari tokensiz, tushunarli xabar bilan qaytariladi.

## Cheklovlar (Meta qoidalari)
- Akkaunt Professional (Business/Creator) va ochiq bo‘lishi kerak. Guruh suhbatlari yo‘q.
- Faqat odam avval yozgan bo‘lsa va odatda 24 soat ichida javob berish mumkin.
- Instagram faqat oxirgi 20 xabarning matnini beradi.
- Webhook YO‘Q: u Live ilova, Advanced Access va Business verification talab qiladi. Xabarlar so‘rov paytida o‘qiladi.
- Token Dashboard'dan olinganda 60 kun yaroqli; tugashiga 20 kundan kam qolsa kuniga bir marta yangilashga urinadi
  (yangilash endpoint'i hujjatdan tekshirilmagan; bo‘lmasa panel tokenni qayta ulashni so‘raydi).

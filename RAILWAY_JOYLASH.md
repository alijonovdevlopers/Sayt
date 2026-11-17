# Railway'ga joylash

## 1. Loyiha va Volume
1. railway.com → New Project → Empty Project → **Empty Service** (yoki GitHub repo).
2. Servisga **Volume** qo'shing, Mount Path: `/data`  (sessiya va baza shu yerda saqlanadi).
3. Settings → **Replicas = 1** (bir akkauntni ikki joyda ishlatmang).

## 2. Variables
| Nom | Qiymat |
|---|---|
| `API_ID`, `API_HASH` | my.telegram.org dan |
| `ENC_KEY` | Fernet kalit (pastda) |
| `MCP_SECRET` | tasodifiy 43+ belgi (pastda) |
| `DATA_DIR` | `/data` |
| `PUBLIC_URL` | `https://<servis>.up.railway.app` (3-qadamdan keyin) |
| `HOST` / `TRUSTED_PROXY` | `0.0.0.0` / `*` (Dockerfile da bor) |

Kalitlarni kompyuteringizda yarating:
```bash
python3 -c "import secrets;print(secrets.token_urlsafe(32))"                      # MCP_SECRET
python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"  # ENC_KEY
```
ENC_KEY ni yo'qotsangiz, saqlangan sessiyalarni ochib bo'lmaydi. Uni xavfsiz joyda saqlang.

## 3. Domen
Settings → Networking → **Generate Domain**. Chiqqan `https://....up.railway.app`
ni `PUBLIC_URL` ga yozing va qayta deploy qiling.

## 4. Birinchi ega (bir marta, terminalda)
Railway CLI o'rnating (`npm i -g @railway/cli`), `railway login`, `railway link`, so'ng:
```bash
railway ssh
python login.py
python web_admin.py FOYDALANUVCHI_ID
exit
```
Keyin `PUBLIC_URL` ni brauzerda oching.

## Eslatma
- Volume'siz hamma ma'lumot har deployda o'chadi.
- Foydalanuvchi IP si `X-Forwarded-For` dan olinadi; Railway uni o'zi qo'yadi.

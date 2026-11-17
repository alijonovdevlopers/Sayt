# Oracle Cloud'ga joylash (Ubuntu, systemd + Caddy HTTPS)

Server `127.0.0.1:8000` da ishlaydi, tashqariga HTTPS ni Caddy chiqaradi.
Kerak: Oracle VM (Ubuntu 24.04 tavsiya — Python 3.12 bor) va domen/subdomen.
Domen yo'q bo'lsa — bepul `xxx.duckdns.org` oling va VM ning public IP siga yo'naltiring.

## 1. Oracle konsolida portlarni oching
Networking → VCN → Security List → Ingress Rules: `0.0.0.0/0` TCP **80** va **443**.
(8000 ni OCHMANG.)

## 2. VM ichida (ssh ubuntu@IP)
```bash
sudo iptables -I INPUT 6 -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save
sudo apt update && sudo apt install -y python3 python3-venv unzip caddy
python3 --version    # 3.12 bo'lishi kerak
```
Boshqa bot 80/443 ni band qilgan bo'lsa, avval tekshiring: `sudo ss -tlnp | grep -E ':80|:443'`

## 3. Kodni yuklash
Kompyuteringizdan: `scp tg_userbot_mcp_to_liq.zip ubuntu@IP:~`
```bash
unzip tg_userbot_mcp_to_liq.zip
cd tg_userbot_mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
python check.py
python setup.py
```

## 4. .env ni to'ldiring
```bash
nano .env      # API_ID, API_HASH (my.telegram.org) va PUBLIC_URL=https://SIZNING.DOMEN.UZ
chmod 600 .env
```
`ENC_KEY` va `MCP_SECRET` ni yo'qotmang va hech kimga yubormang.

## 5. Birinchi egani yaratish
```bash
python login.py          # API ma'lumot, PIN, telefon, kod, 2FA
python web_admin.py FOYDALANUVCHI_ID
```

## 6. HTTPS (Caddy)
```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile     # domenni yozing
sudo systemctl restart caddy
```

## 7. Doimiy ishga tushirish
```bash
sudo cp deploy/tg-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tg-mcp
sudo systemctl status tg-mcp
journalctl -u tg-mcp -f
```
Endi `https://SIZNING.DOMEN.UZ` ni telefonda oching.

## Yangilash
`sudo systemctl stop tg-mcp` → eski papkani zaxiralang → yangi fayllarni ustiga
yozing (`.env` va `data/` ga tegmang) → `python check.py` → `sudo systemctl start tg-mcp`.

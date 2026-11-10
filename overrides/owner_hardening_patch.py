"""admin_login_patch.py'dan KEYIN ishlaydi: scrypt parol tekshiruvi va REGISTRATION_ENABLED."""
from pathlib import Path


def ch(path, old, new):
    p = Path(path)
    s = p.read_text(encoding='utf-8')
    n = s.count(old)
    if n != 1:
        raise RuntimeError(f'{path}: expected 1 match, got {n}: {old[:80]}')
    p.write_text(s.replace(old, new), encoding='utf-8')


# 1) Parol: scrypt (eski pin_hash formati ham tekshiriladi).
ch('web.py',
   "        from security import pin_verify\n        ok_pwd = pin_verify(password, pwd)\n",
   "        from owner_password import verify_password\n        ok_pwd = verify_password(password, pwd)\n")

# 2) Boshqa foydalanuvchilar uchun ro'yxatdan o'tish: standart O'CHIQ.
#    Egasining birinchi Telegram ulashi (first_setup) bundan mustasno.
ch('web.py',
   "            first_setup = self.first_setup_valid(guest, setup_cookie) and not self.web.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone()\n",
   "            first_setup = self.first_setup_valid(guest, setup_cookie) and not self.web.db.execute('SELECT 1 FROM web_accounts WHERE is_admin=1').fetchone()\n"
   "            if not first_setup and os.environ.get('REGISTRATION_ENABLED', '0') != '1':\n"
   "                raise SafeError('Ro‘yxatdan o‘tish o‘chirilgan.')\n")
print('owner hardening patch applied')

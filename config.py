"""Shell kodini bajarmasdan, oddiy KEY=value sozlamalarini o‘qish."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from security import SafeError


@dataclass
class Config:
    data_dir: Path
    enc_key: str
    mcp_secret: str
    public_url: str
    google_client_id: str = ''
    google_client_secret: str = ''
    admin_email: str = ''
    mcp_oauth: bool = False
    oauth_redirects: tuple = ()
    instagram: bool = False
    instagram_version: str = 'v26.0'

    @property
    def host(self):
        return urlsplit(self.public_url).netloc


def load_env(path='.env'):
    path = Path(path)
    if path.exists():
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise SafeError('.env ruxsati 600 bo‘lishi kerak: chmod 600 .env')
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            key, sep, value = line.partition('=')
            if not sep or not re.fullmatch(r'[A-Z_]+', key):
                raise SafeError('.env formati noto‘g‘ri.')
            os.environ.setdefault(key, value.strip().strip('\"\''))


def config():
    load_env()
    key, secret = os.getenv('ENC_KEY', ''), os.getenv('MCP_SECRET', '')
    if len(secret) < 43:
        raise SafeError('MCP_SECRET yetarli emas; avval python setup.py bajaring.')
    try:
        from cryptography.fernet import Fernet
        Fernet(key.encode())
    except (ValueError, TypeError):
        raise SafeError('ENC_KEY noto‘g‘ri; avval python setup.py bajaring.') from None
    url = os.getenv('PUBLIC_URL', 'https://localhost').rstrip('/')
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.path or parts.query or parts.fragment:
        raise SafeError('PUBLIC_URL faqat HTTPS domen bo‘lsin, yo‘lsiz.')
    gid, gsecret, admin = (os.getenv(name, '').strip() for name in ('GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'ADMIN_EMAIL'))
    if (gid or gsecret) and not (gid and gsecret and admin):
        raise SafeError('Google kirishi uchun GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET va ADMIN_EMAIL uchalasi kerak.')
    if len(gid) > 256 or len(gsecret) > 256:
        raise SafeError('Google kalitlari noto‘g‘ri uzunlikda.')
    extra = tuple(item.strip() for item in os.getenv('OAUTH_REDIRECTS', '').split(',') if item.strip())
    for item in extra:
        parts = urlsplit(item)
        if (parts.scheme != 'https' or not parts.hostname or parts.fragment or parts.username or len(item) > 512
                or any(c.isspace() for c in item)):
            raise SafeError('OAUTH_REDIRECTS faqat vergul bilan ajratilgan HTTPS manzillar bo‘lsin.')
    oauth = os.getenv('MCP_OAUTH', '').strip().lower() in ('1', 'true', 'yes')
    return Config(Path(os.getenv('DATA_DIR', 'data')).absolute(), key, secret, url, gid, gsecret, admin, oauth, extra,
                  os.getenv('INSTAGRAM', '').strip().lower() in ('1', 'true', 'yes'),
                  os.getenv('INSTAGRAM_API_VERSION', 'v26.0').strip() or 'v26.0')

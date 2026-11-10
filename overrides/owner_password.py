"""Administrator paroli uchun scrypt hash va tekshiruv (faqat standart kutubxona).

Format: scrypt$N$r$p$tuz_b64url$hash_b64url
Eski (security.pin_hash) formatidagi qiymatlar ham tekshiriladi, shuning uchun
mavjud sozlamalar buzilmaydi.
"""
import base64
import hashlib
import hmac
import secrets

MIN_LENGTH = 12
MAX_LENGTH = 256
_N, _R, _P, _DKLEN = 2 ** 15, 8, 1, 32
_MAXMEM = 128 * 1024 * 1024


def _b64(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _unb64(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def hash_password(password):
    if not isinstance(password, str) or not (MIN_LENGTH <= len(password) <= MAX_LENGTH):
        raise ValueError(f'Parol {MIN_LENGTH}–{MAX_LENGTH} belgi bo‘lishi kerak.')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=_N, r=_R, p=_P,
                            maxmem=_MAXMEM, dklen=_DKLEN)
    return f'scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}'


def verify_password(password, stored):
    if not isinstance(password, str) or not isinstance(stored, str) or len(password) > MAX_LENGTH:
        return False
    if not stored.startswith('scrypt$'):
        try:  # eski format
            from security import pin_verify
            return bool(pin_verify(password, stored))
        except Exception:
            return False
    try:
        _, n, r, p, salt, digest = stored.split('$')
        n, r, p = int(n), int(r), int(p)
        if not (2 ** 14 <= n <= 2 ** 20 and 1 <= r <= 16 and 1 <= p <= 4):
            return False
        expected = _unb64(digest)
        actual = hashlib.scrypt(password.encode('utf-8'), salt=_unb64(salt), n=n, r=r, p=p,
                                maxmem=_MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)

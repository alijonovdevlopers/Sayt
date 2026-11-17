"""v1 core.py dagi sinalgan matn va limit yordamchilari."""
import os


def clamp(n, default, hi):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, hi))


def short(text, limit=None):
    limit = limit or int(os.getenv('MAX_TEXT', '500'))
    text = (text or '').replace('\r', '')
    return text if len(text) <= limit else text[:limit] + '…'


def to_chat(chat):
    s = str(chat).strip()
    return int(s) if s.lstrip('-').isdigit() else s

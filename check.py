"""Yadro sinovlari va py_compile; hech qanday Telegram kodi so‘ralmaydi."""
from pathlib import Path
import py_compile
import sys
import unittest


def main():
    root = Path(__file__).parent
    for path in root.glob('*.py'):
        py_compile.compile(str(path), doraise=True)
    print('py_compile: barcha Python fayllari o‘tdi.', flush=True)
    suite = unittest.defaultTestLoader.discover(str(root), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f'Natija: {result.testsRun} ta sinov, {len(result.failures)} ta muvaffaqiyatsiz, '
          f'{len(result.errors)} ta xato.')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())

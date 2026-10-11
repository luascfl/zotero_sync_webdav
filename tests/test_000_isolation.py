"""Isola a suíte do ambiente real do usuário.

O unittest carrega os módulos em ordem alfabética, então este roda antes de qualquer teste que
importe `zotero_sync_webdav`. O módulo calcula caminhos a partir de $HOME no import (log
diário, cache de hash, snapshot, auditoria, ~/Zotero/storage, env de configuração) e regrava o
cache de hash ao sair, e a conclusão de um sync dispara notificação de verdade. Sem isto, rodar
os testes apagava o cache real, escrevia no log do dia e abria popups na área de trabalho.

Com um HOME descartável e notificadores falsos, a suíte roda como no GitHub Actions. Rode sempre a
suíte inteira com `python3 -m unittest discover -s tests`. Rodar um arquivo isolado, por exemplo
`python3 -m unittest tests.test_x`, não carrega este módulo e volta a usar o ambiente real.
"""

import atexit
import os
import shutil
import stat
import tempfile
import unittest

_REAL_HOME = os.path.expanduser("~")
_FAKE_HOME = tempfile.mkdtemp(prefix="zsw-test-home-")
_STUBS = os.path.join(_FAKE_HOME, "stub-bin")
os.makedirs(_STUBS)
for _name in ("notify-send", "dunstify", "xdg-open"):
    _path = os.path.join(_STUBS, _name)
    with open(_path, "w", encoding="utf-8") as _fh:
        _fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(_path, os.stat(_path).st_mode | stat.S_IXUSR)

os.environ["HOME"] = _FAKE_HOME
os.environ["PATH"] = _STUBS + os.pathsep + os.environ.get("PATH", "")
for _key in [key for key in os.environ if key.startswith(("ZOTERO_", "ZSW_"))]:
    os.environ.pop(_key)
atexit.register(shutil.rmtree, _FAKE_HOME, ignore_errors=True)


class IsolationTests(unittest.TestCase):
    def test_module_paths_live_under_the_throwaway_home(self):
        import zotero_sync_webdav as zsync

        self.assertNotEqual(_REAL_HOME, _FAKE_HOME)
        for name in ("CACHE_DIR", "LOG_DIR", "LOCAL_COPY_DIR", "DUPLICATE_ACTIONS_LOG", "CACHE_FILE"):
            value = getattr(zsync, name)
            self.assertTrue(
                str(value).startswith(_FAKE_HOME),
                f"{name}={value} fora do HOME descartável: o módulo foi importado antes do isolamento",
            )

    def test_notifiers_are_stubs(self):
        import shutil as _shutil

        for name in ("notify-send", "dunstify", "xdg-open"):
            self.assertEqual(_shutil.which(name), os.path.join(_STUBS, name))


if __name__ == "__main__":
    unittest.main()

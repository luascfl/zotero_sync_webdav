#!/usr/bin/env python3
"""
zotero_remove_duplicatas.py

Remove anexos duplicados da biblioteca Zotero, mantendo sempre o mais antigo.
Detecta duplicatas por nome normalizado (básico e agressivo).

Uso:
    python3 zotero_remove_duplicatas.py           # modo dry-run (só mostra)
    python3 zotero_remove_duplicatas.py --executar  # apaga de verdade

Variáveis de ambiente necessárias (ou via .env):
    ZOTERO_LIBRARY_ID
    ZOTERO_LIBRARY_TYPE   (padrão: user)
    ZOTERO_API_KEY
"""

import os
import re
import sys
import time
import unicodedata
from collections import defaultdict
from pathlib import Path

# ── Carregar .env ─────────────────────────────────────────────────────────────

def load_env(path: str) -> None:
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val

for _env in [".env", os.path.expanduser("~/.config/zotero_sync_webdav/zotero_sync.env")]:
    load_env(_env)

LIBRARY_ID   = os.environ.get("ZOTERO_LIBRARY_ID", "")
LIBRARY_TYPE = os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
API_KEY      = os.environ.get("ZOTERO_API_KEY", "")

missing = [k for k, v in {
    "ZOTERO_LIBRARY_ID": LIBRARY_ID,
    "ZOTERO_API_KEY": API_KEY,
}.items() if not v]
if missing:
    raise SystemExit(f"❌ Variáveis ausentes: {', '.join(missing)}")

DRY_RUN = "--executar" not in sys.argv

# ── Normalização ──────────────────────────────────────────────────────────────

def norm_basic(s: str) -> str:
    return unicodedata.normalize("NFC", s).lower().strip() if s else ""

def norm_aggressive(s: str) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.lower()
    s = re.sub(r"[^a-z0-9\s._-]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def get_filename(item: dict) -> str:
    data = item.get("data", {})
    name = data.get("filename", "")
    if name:
        return name
    path = str(data.get("path", ""))
    for prefix in ("file:///", "file://", "file:", "storage:"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    return os.path.basename(path.replace("\\", "/"))

# ── Busca paginada ────────────────────────────────────────────────────────────

def fetch_all_attachments(zot) -> list[dict]:
    all_items = []
    start = 0
    page = 100
    print("  Baixando anexos", end="", flush=True)
    while True:
        items = zot.items(itemType="attachment", limit=page, start=start)
        if not items:
            break
        all_items.extend(items)
        print(".", end="", flush=True)
        if len(items) < page:
            break
        start += page
    print(f" {len(all_items)} anexos encontrados.")
    return all_items

# ── Detecção de duplicatas ────────────────────────────────────────────────────

def find_duplicate_groups(attachments: list[dict]) -> list[dict]:
    """
    Retorna grupos de duplicatas. Cada grupo tem:
      - norm: string normalizada usada para agrupar
      - method: 'nome normalizado' ou 'nome agressivo'
      - items: lista ordenada por dateAdded ASC (o primeiro é o mais antigo = keeper)
      - to_delete: todos exceto o primeiro
    """
    by_basic:      dict[str, list] = defaultdict(list)
    by_aggressive: dict[str, list] = defaultdict(list)

    for item in attachments:
        fname = get_filename(item)
        if not fname:
            continue
        # Ignora arquivos genéricos que não são PDFs (image.png, article.html, etc.)
        # para não apagar capturas de tela ou snapshots web que podem ter nomes repetidos
        # propositalmente. Ajuste esta lista conforme necessário.
        if not fname.lower().endswith(".pdf"):
            continue

        key  = item.get("key", "?")
        date = item.get("data", {}).get("dateAdded", "1970-01-01T00:00:00Z")
        parent = item.get("data", {}).get("parentItem", "")
        info = {"key": key, "filename": fname, "dateAdded": date, "parentItem": parent}

        nb = norm_basic(fname)
        na = norm_aggressive(fname)
        if nb:
            by_basic[nb].append(info)
        if na and na != nb:
            by_aggressive[na].append(info)

    seen_key_pairs: set[frozenset] = set()
    groups: list[dict] = []

    def add_group(norm_str: str, group: list, method: str):
        keys = frozenset(i["key"] for i in group)
        if keys in seen_key_pairs:
            return
        seen_key_pairs.add(keys)
        sorted_group = sorted(group, key=lambda x: x["dateAdded"])
        groups.append({
            "norm": norm_str,
            "method": method,
            "items": sorted_group,
            "keeper": sorted_group[0],
            "to_delete": sorted_group[1:],
        })

    for k, v in by_basic.items():
        if len(v) > 1:
            add_group(k, v, "nome normalizado")
    for k, v in by_aggressive.items():
        if len(v) > 1:
            add_group(k, v, "nome agressivo")

    return groups

# ── Remoção ───────────────────────────────────────────────────────────────────

def delete_attachments(zot, keys: list[str], dry_run: bool) -> tuple[int, int]:
    """Deleta os anexos pela chave. Retorna (ok, erros)."""
    ok = 0
    errors = 0
    for key in keys:
        if dry_run:
            print(f"    [DRY-RUN] Deletaria key={key}")
            ok += 1
            continue
        try:
            item = zot.item(key)
            zot.delete_item(item)
            print(f"    ✅ Deletado: key={key}")
            ok += 1
            # Pequena pausa para não sobrecarregar a API
            time.sleep(0.3)
        except Exception as exc:
            print(f"    ❌ Falha ao deletar key={key}: {exc}")
            errors += 1
    return ok, errors

# ── Relatório / main ──────────────────────────────────────────────────────────

def main():
    try:
        from pyzotero import zotero as pyzotero
    except ImportError:
        raise SystemExit("❌ pyzotero não instalado. Execute: pip install pyzotero")

    mode_label = "🔍 DRY-RUN (simulação)" if DRY_RUN else "⚠️  MODO REAL (vai deletar)"
    print(f"\n{'═'*60}")
    print(f"  REMOÇÃO DE DUPLICATAS ZOTERO  —  {mode_label}")
    print(f"  library_id={LIBRARY_ID}, type={LIBRARY_TYPE}")
    print(f"{'═'*60}\n")

    if not DRY_RUN:
        print("⚠️  ATENÇÃO: você está prestes a deletar anexos da sua biblioteca Zotero.")
        print("   Esta operação é IRREVERSÍVEL pela API.")
        confirm = input("   Digite 'sim' para continuar: ").strip().lower()
        if confirm not in ("sim", "s", "yes", "y"):
            print("Operação cancelada.")
            return
        print()

    print(f"🔗 Conectando ao Zotero...")
    zot = pyzotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
    try:
        zot.key_info()
        print("✅ Conexão OK.\n")
    except Exception as e:
        raise SystemExit(f"❌ Falha na conexão: {e}")

    print("📥 Buscando todos os anexos...")
    attachments = fetch_all_attachments(zot)

    print("\n🔍 Detectando duplicatas de PDFs...")
    groups = find_duplicate_groups(attachments)

    if not groups:
        print("\n✅ Nenhuma duplicata de PDF encontrada. Nada a fazer.")
        return

    total_to_delete = sum(len(g["to_delete"]) for g in groups)
    print(f"\nEncontrados {len(groups)} grupo(s) de duplicatas → {total_to_delete} anexo(s) a remover.\n")

    deleted_ok = 0
    deleted_err = 0

    for i, group in enumerate(groups, 1):
        keeper = group["keeper"]
        print(f"  Grupo #{i}  [{group['method']}]")
        print(f"  Arquivo: '{keeper['filename']}'")
        print(f"  ✔ Mantendo: key={keeper['key']}  dateAdded={keeper['dateAdded']}"
              f"  parent={keeper['parentItem'] or '(sem pai)'}")

        for item in group["to_delete"]:
            print(f"  ✗ Removendo: key={item['key']}  dateAdded={item['dateAdded']}"
                  f"  parent={item['parentItem'] or '(sem pai)'}")

        keys_to_delete = [item["key"] for item in group["to_delete"]]
        ok, err = delete_attachments(zot, keys_to_delete, DRY_RUN)
        deleted_ok += ok
        deleted_err += err
        print()

    print(f"{'═'*60}")
    if DRY_RUN:
        print(f"  DRY-RUN concluído.")
        print(f"  {deleted_ok} anexo(s) seriam deletados.")
        print(f"\n  Para executar de verdade, rode:")
        print(f"    python3 {Path(__file__).name} --executar")
    else:
        print(f"  Concluído: {deleted_ok} deletado(s) | {deleted_err} erro(s).")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()

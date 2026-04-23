#!/usr/bin/env python3
"""
zotero_diagnostico.py
Diagnóstico da biblioteca Zotero:
  1. Anexos duplicados (mesmo nome normalizado ou mesmo hash MD5)
  2. PDFs presentes na pasta WebDAV mas ausentes no Zotero

Uso:
    python3 zotero_diagnostico.py

Variáveis de ambiente necessárias (ou via .env):
    ZOTERO_LIBRARY_ID
    ZOTERO_LIBRARY_TYPE   (padrão: user)
    ZOTERO_API_KEY
    ZOTERO_SYNC_TARGET_FOLDER   (pasta WebDAV montada)
"""

import hashlib
import os
import re
import unicodedata
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote

# ── Carregar .env ────────────────────────────────────────────────────────────

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

# Tenta .env local e depois o arquivo do serviço
for _env in [".env", os.path.expanduser("~/.config/zotero_sync_webdav/zotero_sync.env")]:
    load_env(_env)

LIBRARY_ID   = os.environ.get("ZOTERO_LIBRARY_ID", "")
LIBRARY_TYPE = os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
API_KEY      = os.environ.get("ZOTERO_API_KEY", "")
TARGET_RAW   = os.environ.get("ZOTERO_SYNC_TARGET_FOLDER", "")

missing = [k for k, v in {
    "ZOTERO_LIBRARY_ID": LIBRARY_ID,
    "ZOTERO_API_KEY": API_KEY,
    "ZOTERO_SYNC_TARGET_FOLDER": TARGET_RAW,
}.items() if not v]
if missing:
    raise SystemExit(f"❌ Variáveis ausentes: {', '.join(missing)}")

def resolve_folder(raw: str) -> str:
    exp = os.path.expanduser(raw)
    for c in [exp, unquote(exp), exp.replace("%20", " ")]:
        if os.path.isdir(c):
            return c
    return exp

TARGET_FOLDER = resolve_folder(TARGET_RAW)

# ── Normalização ─────────────────────────────────────────────────────────────

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

# ── Hash ─────────────────────────────────────────────────────────────────────

def sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

def md5(path: str) -> str | None:
    """MD5 — Zotero usa MD5 internamente para comparar arquivos."""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None

# ── Busca paginada ────────────────────────────────────────────────────────────

def fetch_all_attachments(zot) -> list[dict]:
    """Baixa TODOS os anexos da biblioteca (sem limite)."""
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

# ── Diagnóstico 1: Duplicatas ─────────────────────────────────────────────────

def check_duplicates(attachments: list[dict]) -> dict:
    by_name_basic:      dict[str, list] = defaultdict(list)
    by_name_aggressive: dict[str, list] = defaultdict(list)

    for item in attachments:
        fname = get_filename(item)
        if not fname:
            continue
        key  = item.get("key", "?")
        date = item.get("data", {}).get("dateAdded", "?")
        info = {"key": key, "filename": fname, "dateAdded": date,
                "parentItem": item.get("data", {}).get("parentItem", "")}

        nb = norm_basic(fname)
        na = norm_aggressive(fname)
        if nb:
            by_name_basic[nb].append(info)
        if na and na != nb:
            by_name_aggressive[na].append(info)

    dupes_basic = {k: v for k, v in by_name_basic.items() if len(v) > 1}
    dupes_agg   = {k: v for k, v in by_name_aggressive.items() if len(v) > 1}

    # Juntar tudo sem dupla contagem
    seen_key_pairs: set[frozenset] = set()
    all_dupes: list[dict] = []

    def add_group(fname_norm: str, group: list, method: str):
        keys = frozenset(i["key"] for i in group)
        if keys in seen_key_pairs:
            return
        seen_key_pairs.add(keys)
        all_dupes.append({"norm": fname_norm, "method": method, "items": group})

    for k, v in dupes_basic.items():
        add_group(k, v, "nome normalizado")
    for k, v in dupes_agg.items():
        add_group(k, v, "nome agressivo")

    return {"groups": all_dupes, "total_groups": len(all_dupes)}

# ── Diagnóstico 2: PDFs ausentes no Zotero ───────────────────────────────────

def check_missing_in_zotero(attachments: list[dict], folder: str) -> dict:
    # Indexar nomes que já existem no Zotero
    zotero_names_basic:      set[str] = set()
    zotero_names_aggressive: set[str] = set()

    for item in attachments:
        fname = get_filename(item)
        if not fname:
            continue
        zotero_names_basic.add(norm_basic(fname))
        zotero_names_aggressive.add(norm_aggressive(fname))

    missing: list[dict] = []
    errors:  list[str]  = []

    if not os.path.isdir(folder):
        return {"missing": [], "errors": [f"Pasta não encontrada: {folder}"], "folder": folder}

    pdf_files = [e for e in os.scandir(folder) if e.is_file() and e.name.lower().endswith(".pdf")]
    print(f"  {len(pdf_files)} PDFs encontrados em {folder}")

    for entry in pdf_files:
        nb = norm_basic(entry.name)
        na = norm_aggressive(entry.name)
        in_zotero = nb in zotero_names_basic or na in zotero_names_aggressive
        if not in_zotero:
            try:
                size_kb = entry.stat().st_size // 1024
            except OSError:
                size_kb = -1
            missing.append({"filename": entry.name, "path": entry.path, "size_kb": size_kb})

    return {"missing": missing, "total_pdfs": len(pdf_files),
            "total_missing": len(missing), "errors": errors, "folder": folder}

# ── Relatório ─────────────────────────────────────────────────────────────────

def print_report(dupes: dict, missing_result: dict) -> None:
    SEP = "─" * 60

    print(f"\n{'═'*60}")
    print("  RELATÓRIO DE DIAGNÓSTICO ZOTERO")
    print(f"{'═'*60}")

    # ── Duplicatas ──
    print(f"\n{'━'*60}")
    print(f"  1. ANEXOS DUPLICADOS  ({dupes['total_groups']} grupo(s))")
    print(f"{'━'*60}")

    if not dupes["groups"]:
        print("  ✅ Nenhuma duplicata encontrada.")
    else:
        for i, group in enumerate(dupes["groups"], 1):
            print(f"\n  Grupo #{i}  [{group['method']}]  norm='{group['norm']}'")
            for item in group["items"]:
                parent = f"  parent={item['parentItem']}" if item['parentItem'] else "  (sem pai)"
                print(f"    • key={item['key']}  dateAdded={item['dateAdded']}")
                print(f"      filename='{item['filename']}'{parent}")

    # ── Ausentes ──
    print(f"\n{'━'*60}")
    mr = missing_result
    print(f"  2. PDFs SEM CORRESPONDÊNCIA NO ZOTERO")
    print(f"     Pasta: {mr['folder']}")
    print(f"     Total PDFs: {mr.get('total_pdfs', '?')}  |  Ausentes: {mr.get('total_missing', '?')}")
    print(f"{'━'*60}")

    if mr.get("errors"):
        for e in mr["errors"]:
            print(f"  ⚠️  {e}")

    if not mr.get("missing"):
        print("  ✅ Todos os PDFs da pasta já estão no Zotero.")
    else:
        for f in mr["missing"]:
            print(f"  • {f['filename']}  ({f['size_kb']} KB)")
            print(f"    {f['path']}")

    print(f"\n{'═'*60}\n")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    try:
        from pyzotero import zotero as pyzotero
    except ImportError:
        raise SystemExit("❌ pyzotero não instalado. Execute: pip install pyzotero")

    print(f"🔗 Conectando ao Zotero (library_id={LIBRARY_ID}, type={LIBRARY_TYPE})...")
    zot = pyzotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
    try:
        zot.key_info()
        print("✅ Conexão OK.")
    except Exception as e:
        raise SystemExit(f"❌ Falha na conexão: {e}")

    print("\n📥 Buscando TODOS os anexos da biblioteca...")
    attachments = fetch_all_attachments(zot)

    print("\n🔍 Verificando duplicatas...")
    dupes = check_duplicates(attachments)

    print(f"\n📂 Verificando PDFs ausentes no Zotero (pasta: {TARGET_FOLDER})...")
    missing_result = check_missing_in_zotero(attachments, TARGET_FOLDER)

    print_report(dupes, missing_result)

if __name__ == "__main__":
    main()

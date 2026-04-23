#!/usr/bin/env python3
"""
Espelha a hierarquia de coleções do Zotero em pastas dentro de um vault do Obsidian.

Escopo desta versão:
- Cria apenas diretórios (não move anexos, não apaga nada).
- Sanitiza nomes para serem válidos também no Windows.
- Mantém a árvore de coleções (pai -> filhos).

Uso:
  python3 zotero_mirror_collections_to_obsidian.py --dry-run
  python3 zotero_mirror_collections_to_obsidian.py --apply
  python3 zotero_mirror_collections_to_obsidian.py --apply --target-root "/caminho/do/ObsidianLocal"

Variáveis de ambiente lidas (via .env local ou ~/.config/zotero_sync_webdav/zotero_sync.env):
  ZOTERO_LIBRARY_ID
  ZOTERO_LIBRARY_TYPE (opcional, padrão: user)
  ZOTERO_API_KEY
  OBSIDIAN_ZOTERO_MIRROR_ROOT (opcional)
"""

from __future__ import annotations

import argparse
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List


DEFAULT_TARGET_ROOT = Path.home() / "Documentos/ObsidianLocal"
INVALID_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1F]')


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def sanitize_folder_name(name: str, fallback: str) -> str:
    clean = INVALID_FS_CHARS.sub("_", name or "")
    clean = re.sub(r"\s+", " ", clean).strip().rstrip(".")
    if clean in {"", ".", ".."}:
        clean = fallback
    return clean


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Espelha coleções do Zotero como pastas no Obsidian")
    parser.add_argument(
        "--target-root",
        help="Diretório raiz de destino no Obsidian. Padrão: OBSIDIAN_ZOTERO_MIRROR_ROOT ou ~/Documentos/ObsidianLocal",
    )
    parser.add_argument("--dry-run", action="store_true", help="Só mostra o que faria, sem criar pastas")
    parser.add_argument("--apply", action="store_true", help="Aplica de fato a criação das pastas")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Padrão seguro: dry-run, a menos que --apply seja informado
    apply_changes = args.apply and not args.dry_run

    script_dir = Path(__file__).resolve().parent
    load_env(script_dir / ".env")
    load_env(Path.home() / ".config/zotero_sync_webdav/zotero_sync.env")

    library_id = os.environ.get("ZOTERO_LIBRARY_ID", "").strip()
    library_type = os.environ.get("ZOTERO_LIBRARY_TYPE", "user").strip() or "user"
    api_key = os.environ.get("ZOTERO_API_KEY", "").strip()

    missing = [
        key
        for key, value in {
            "ZOTERO_LIBRARY_ID": library_id,
            "ZOTERO_API_KEY": api_key,
        }.items()
        if not value
    ]
    if missing:
        raise SystemExit(f"❌ Variáveis ausentes: {', '.join(missing)}")

    target_root_raw = (
        args.target_root
        or os.environ.get("OBSIDIAN_ZOTERO_MIRROR_ROOT", "").strip()
        or str(DEFAULT_TARGET_ROOT)
    )
    target_root = Path(os.path.expanduser(target_root_raw)).resolve()

    from pyzotero import zotero  # import tardio para erro claro só quando necessário

    print(f"🔗 Conectando ao Zotero (library_id={library_id}, type={library_type})...")
    zot = zotero.Zotero(library_id, library_type, api_key)
    zot.key_info()

    collections = zot.everything(zot.collections())
    print(f"📚 Coleções encontradas: {len(collections)}")
    print(f"📁 Destino Obsidian: {target_root}")
    print(f"🧪 Modo: {'APPLY' if apply_changes else 'DRY-RUN'}")

    by_key: Dict[str, dict] = {}
    children: Dict[str | None, List[str]] = defaultdict(list)

    for col in collections:
        key = col.get("key")
        data = col.get("data", {})
        if not key:
            continue
        by_key[key] = {
            "key": key,
            "name": data.get("name", ""),
            "parent": data.get("parentCollection") or None,
        }

    for key, payload in by_key.items():
        parent = payload["parent"]
        if parent and parent not in by_key:
            parent = None
        children[parent].append(key)

    created = 0
    existed = 0
    collisions = 0

    def mirror_subtree(parent_key: str | None, base_path: Path) -> None:
        nonlocal created, existed, collisions

        sibling_keys = children.get(parent_key, [])
        sibling_keys.sort(key=lambda k: (by_key[k]["name"] or "").casefold())

        used_names: Dict[str, int] = {}

        for key in sibling_keys:
            original_name = by_key[key]["name"]
            fallback = f"collection-{key.lower()}"
            safe_name = sanitize_folder_name(original_name, fallback)

            if safe_name in used_names:
                used_names[safe_name] += 1
                safe_name = f"{safe_name} ({used_names[safe_name]})"
                collisions += 1
            else:
                used_names[safe_name] = 1

            next_path = base_path / safe_name

            if next_path.exists():
                existed += 1
                print(f"= {next_path}")
            else:
                created += 1
                if apply_changes:
                    next_path.mkdir(parents=True, exist_ok=True)
                    print(f"+ {next_path}")
                else:
                    print(f"~ {next_path}")

            mirror_subtree(key, next_path)

    if apply_changes:
        target_root.mkdir(parents=True, exist_ok=True)

    mirror_subtree(None, target_root)

    print("\nResumo")
    print(f"- pastas já existentes: {existed}")
    print(f"- pastas criadas{' (simuladas)' if not apply_changes else ''}: {created}")
    print(f"- colisões de nome resolvidas: {collisions}")


if __name__ == "__main__":
    main()

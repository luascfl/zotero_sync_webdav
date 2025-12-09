import atexit
import hashlib
import heapq
import json
import os
import re
import shlex
import shutil
import subprocess
import unicodedata
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import unquote
from pyzotero import zotero
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent

env_file_from_env = os.environ.get("ZOTERO_ENV_FILE")
DEFAULT_ENV_FILE = Path(env_file_from_env) if env_file_from_env else SCRIPT_DIR / ".env"


def load_env_file(env_path: os.PathLike[str] | str) -> None:
    """Carrega variáveis de ambiente a partir de um arquivo .env simples."""
    if not env_path:
        return
    env_file = Path(env_path)
    if not env_file.is_file():
        return
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError as exc:
        logging.warning("Falha ao carregar variáveis do arquivo %s: %s", env_file, exc)


load_env_file(DEFAULT_ENV_FILE)

# --- Configuração Final (via .env / variáveis de ambiente) ---
LIBRARY_ID = os.environ.get("ZOTERO_LIBRARY_ID")
LIBRARY_TYPE = os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
API_KEY = os.environ.get("ZOTERO_API_KEY")

# Caminho padrão para a pasta que contém os arquivos PDF.
# Pode ser sobrescrito via variável de ambiente ZOTERO_SYNC_TARGET_FOLDER.
TARGET_FOLDER_RAW = os.environ.get("ZOTERO_SYNC_TARGET_FOLDER")

missing_env = [name for name, value in {
    "ZOTERO_LIBRARY_ID": LIBRARY_ID,
    "ZOTERO_API_KEY": API_KEY,
    "ZOTERO_SYNC_TARGET_FOLDER": TARGET_FOLDER_RAW,
}.items() if not value]

if missing_env:
    raise RuntimeError(
        f"Defina as variáveis de ambiente obrigatórias ({', '.join(missing_env)}). "
        "Use um arquivo .env na raiz do projeto ou exporte-as antes de executar."
    )


def resolve_target_folder(raw_path: str) -> str:
    """Resolve o caminho da pasta alvo, tentando decodificar espaços/percent-encoding."""
    expanded = os.path.expanduser(raw_path)
    candidates = [expanded]

    if "%" in expanded:
        decoded_uri = unquote(expanded)
        if decoded_uri not in candidates:
            candidates.append(decoded_uri)
        decoded_spaces = expanded.replace("%20", " ")
        if decoded_spaces not in candidates:
            candidates.append(decoded_spaces)

    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return expanded


TARGET_FOLDER = resolve_target_folder(TARGET_FOLDER_RAW)

# Pasta onde será criada a cópia local quando um novo anexo for enviado ao Zotero.
# Por padrão utiliza ~/Zotero/storage para acompanhar a estrutura padrão do Zotero.
LOCAL_COPY_DIR = os.path.join(os.path.expanduser("~"), "Zotero", "storage")

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "zotero_sync_webdav")
CACHE_FILE = os.path.join(CACHE_DIR, "hash_cache.json")
CACHE_VERSION = 1

LOG_DIR = os.path.join(CACHE_DIR, "logs")
LOG_FILE_NAME = "zotero_sync_today.log"
LOG_DATE_FILE = os.path.join(LOG_DIR, ".last_log_date")
LOG_DESKTOP_ID = "zotero-sync-log"
LOG_DESKTOP_FILE = os.path.join(
    os.path.expanduser("~"),
    ".local",
    "share",
    "applications",
    f"{LOG_DESKTOP_ID}.desktop",
)

CACHE_VERSION = 1

HASH_CACHE: Dict[str, dict] = {}

# Limite de arquivos mais recentes a serem verificados na pasta
MAX_FILES_TO_CHECK = 50
MAX_ATTACHMENTS_TO_CHECK = 50
# Ativar logs detalhados no console
DEBUG_DETAILED = True

def prepare_daily_log_file() -> str | None:
    """Garante um log diário único e retorna o caminho."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as exc:
        print(f"[LOG] Não foi possível preparar pasta de logs: {exc}")
        return None

    today_str = datetime.now().strftime("%Y-%m-%d")
    needs_reset = True
    try:
        last_date = Path(LOG_DATE_FILE).read_text(encoding="utf-8").strip()
        if last_date == today_str and os.path.exists(os.path.join(LOG_DIR, LOG_FILE_NAME)):
            needs_reset = False
    except FileNotFoundError:
        pass
    except OSError:
        pass

    log_path = os.path.join(LOG_DIR, LOG_FILE_NAME)
    mode = "w" if needs_reset else "a"
    try:
        with open(log_path, mode, encoding="utf-8") as fh:
            if needs_reset:
                fh.write(f"# Log diário do Zotero Sync - {today_str}\n\n")
            fh.write(f"--- Execução iniciada: {datetime.now().isoformat()} ---\n")
        Path(LOG_DATE_FILE).write_text(today_str, encoding="utf-8")
    except OSError as exc:
        print(f"[LOG] Não foi possível inicializar o log diário: {exc}")
        return None

    return log_path


LOG_FILE_PATH = prepare_daily_log_file()

handlers: List[logging.Handler] = [logging.StreamHandler()]
if LOG_FILE_PATH:
    try:
        file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
        handlers.append(file_handler)
    except OSError as exc:
        print(f"[LOG] Não foi possível anexar handler de arquivo: {exc}")

# Configuração do logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG_DETAILED else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers,
)

if LOG_FILE_PATH:
    logging.info("Log diário: %s", LOG_FILE_PATH)
else:
    logging.info("Log diário indisponível (falha ao criar arquivo).")


def ensure_log_desktop_entry(log_path: str) -> str | None:
    """Garante um .desktop que abre o log diário em um clique."""
    if not log_path:
        return None

    desktop_dir = os.path.dirname(LOG_DESKTOP_FILE)
    try:
        os.makedirs(desktop_dir, exist_ok=True)
    except OSError as exc:
        logging.warning("[LOG] Não foi possível preparar pasta de desktop entries: %s", exc)
        return None

    exec_cmd = f"xdg-open {shlex.quote(os.path.abspath(log_path))}"
    desktop_content = "\n".join(
        [
            "[Desktop Entry]",
            "Type=Application",
            "Terminal=false",
            "Name=Zotero Sync - Log de hoje",
            "Comment=Abre o log diário do sincronizador Zotero/WebDAV",
            f"Exec={exec_cmd}",
            "Icon=text-x-log",
            "Categories=Utility;",
        ]
    ) + "\n"

    try:
        if os.path.exists(LOG_DESKTOP_FILE):
            existing = Path(LOG_DESKTOP_FILE).read_text(encoding="utf-8")
            if existing == desktop_content:
                return LOG_DESKTOP_ID
        Path(LOG_DESKTOP_FILE).write_text(desktop_content, encoding="utf-8")
    except OSError as exc:
        logging.warning("[LOG] Não foi possível atualizar desktop entry: %s", exc)
        return None

    return LOG_DESKTOP_ID


def send_completion_notification(stats: dict, log_path: str | None) -> None:
    """Envia notificação sobre a execução e oferece abertura rápida do log."""
    if shutil.which("notify-send") is None:
        logging.debug("[NOTIFY] notify-send não encontrado; pulando notificação.")
        return

    body_parts = [
        f"Adicionados: {stats.get('added', 0)}",
        f"Existentes: {stats.get('skipped', 0)}",
        f"Erros: {stats.get('errors', 0)}",
    ]
    body = " • ".join(body_parts)
    if log_path:
        body += "\nClique para abrir o log de hoje."

    cmd = [
        "notify-send",
        "-a",
        "Zotero Sync",
        "-i",
        "text-x-log",
    ]

    desktop_hint = ensure_log_desktop_entry(log_path) if log_path else None
    if desktop_hint:
        cmd.extend(["-h", f"string:desktop-entry:{desktop_hint}"])
    else:
        logging.debug("[NOTIFY] Desktop entry indisponível; o clique pode não abrir o log.")

    cmd.extend(
        [
            "Sincronização Zotero/WebDAV concluída",
            body,
        ]
    )

    try:
        subprocess.run(cmd, check=False)
    except Exception as exc:
        logging.warning("[NOTIFY] Falha ao enviar notificação: %s", exc)


def finalize_execution(stats: dict, summary_text: str | None = None) -> None:
    """Atualiza o log diário e dispara a notificação."""
    if LOG_FILE_PATH:
        try:
            with open(LOG_FILE_PATH, "a", encoding="utf-8") as fh:
                if summary_text:
                    fh.write("\n")
                    fh.write(summary_text)
                    fh.write("\n")
                fh.write(f"--- Execução finalizada: {datetime.now().isoformat()} ---\n")
        except OSError as exc:
            logging.warning("[LOG] Não foi possível gravar o resumo no log diário: %s", exc)

    send_completion_notification(stats, LOG_FILE_PATH)

if TARGET_FOLDER_RAW != TARGET_FOLDER:
    logging.info("Pasta alvo configurada: %s (valor original: %s)", TARGET_FOLDER, TARGET_FOLDER_RAW)
else:
    logging.info("Pasta alvo configurada: %s", TARGET_FOLDER)
logging.info("Biblioteca Zotero configurada: %s (%s)", LIBRARY_ID, LIBRARY_TYPE)

# --- Funções de Normalização ---

def normalize_filename(fname: str) -> str:
    """Normalização básica: NFC, minúsculas, sem espaços nas bordas."""
    if not fname:
        return ""
    try:
        return unicodedata.normalize('NFC', fname).lower().strip()
    except Exception as e:
        logging.warning(f"Erro ao normalizar '{fname}': {e}")
        return ""

def normalize_aggressive(fname: str) -> str:
    """Normalização agressiva: remove acentos, caracteres especiais e espaços extras."""
    if not fname:
        return ""
    try:
        nfkd_form = unicodedata.normalize('NFD', fname)
        normalized = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
        normalized = normalized.lower()
        normalized = re.sub(r'[^a-z0-9\s._-]', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized
    except Exception as e:
        logging.warning(f"Erro na normalização agressiva de '{fname}': {e}")
        return ""

def get_filename_from_item(item: dict) -> str:
    """Extrai o nome do arquivo de um item de anexo da Pyzotero."""
    data = item.get('data', {})
    filename = data.get('filename', '')
    if filename:
        return filename
    path = data.get('path')
    if path:
        try:
            path_str = str(path)
            # Remover prefixos comuns de URI ou placeholders
            if path_str.startswith("file:///"):
                path_str = path_str[8:]
            elif path_str.startswith("file://"):
                path_str = path_str[7:]
            elif path_str.startswith("file:"):
                path_str = path_str[5:]
            elif path_str.startswith("storage:"):
                # Em linked files, "storage:" indica pastas dentro do storage local
                path_str = path_str.split(":", 1)[-1]

            path_str = path_str.replace("\\", "/")
            return os.path.basename(path_str)
        except Exception:
            pass
    return ""


def parse_zotero_date(date_str: str) -> datetime | None:
    """Converte a string de data do Zotero em datetime."""
    if not date_str:
        return None
    try:
        normalized = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        logging.warning("[ZOT] Data inválida recebida: %s", date_str)
        return None

def collect_recent_pdfs(directory: str, limit: int, stats: dict) -> List[str]:
    """Retorna os PDFs mais recentes, limitando o processamento aos "top N" por data."""
    logging.info("[SCAN] Iniciando varredura de PDFs em %s", directory)
    if limit <= 0:
        logging.warning("[SCAN] Limite de arquivos a verificar é %d. Nada será processado.", limit)
        return []

    recent_heap: List[Tuple[float, str]] = []
    total_pdfs = 0

    try:
        with os.scandir(directory) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                if not entry.name.lower().endswith('.pdf'):
                    continue

                try:
                    mtime = entry.stat().st_mtime
                except OSError as exc:
                    logging.warning("[SCAN] Não foi possível ler mtime de '%s': %s", entry.path, exc)
                    continue

                total_pdfs += 1
                heapq.heappush(recent_heap, (mtime, entry.path))
                if len(recent_heap) > limit:
                    heapq.heappop(recent_heap)

    except FileNotFoundError:
        logging.error("A pasta alvo não foi encontrada: %s", directory)
        return []
    except PermissionError:
        logging.error("Sem permissão para acessar a pasta: %s", directory)
        return []
    except Exception as exc:
        logging.error("Erro ao varrer a pasta '%s': %s", directory, exc)
        return []

    if not recent_heap:
        logging.info("[SCAN] Nenhum PDF encontrado em %s.", directory)
        return []

    recent_heap.sort(key=lambda item: item[0], reverse=True)

    stats['folder_total_pdfs'] = total_pdfs
    stats['folder_checked_pdfs'] = len(recent_heap)

    if total_pdfs > limit:
        logging.info(
            "[SCAN] PDFs contabilizados: %d | Selecionados (top %d): %d",
            total_pdfs,
            limit,
            stats['folder_checked_pdfs'],
        )
    else:
        logging.info(
            "[SCAN] PDFs contabilizados: %d | Selecionados: %d",
            total_pdfs,
            stats['folder_checked_pdfs'],
        )

    if DEBUG_DETAILED and recent_heap:
        logging.debug("[SCAN] Primeiro selecionado: %s", recent_heap[0][1])
        if len(recent_heap) > 1:
            logging.debug("[SCAN] Último selecionado: %s", recent_heap[-1][1])

    return [path for _, path in recent_heap]

def collect_recent_attachments(
    zot: zotero.Zotero,
    limit: int,
    stats: dict,
) -> Tuple[List[dict], dict, dict]:
    """Busca todos os anexos, indexa nomes normalizados e retorna os mais recentes por dateAdded."""
    page_size = 100
    start = 0
    total = 0
    recent_heap: List[Tuple[float, dict]] = []
    existing_filenames: dict = {}
    existing_filenames_aggressive: dict = {}

    logging.info("[ZOT] Iniciando varredura de anexos com janela top %d.", limit)

    while True:
        try:
            items = zot.items(
                itemType='attachment',
                limit=page_size,
                start=start,
                sort='dateAdded',
                direction='desc',
            )
        except Exception as exc:
            logging.error("[ZOT] Falha ao obter anexos (start=%d): %s", start, exc)
            break

        if not items:
            break

        total += len(items)
        logging.debug("[ZOT] Página de anexos recebida. start=%d | itens=%d", start, len(items))

        for item in items:
            data = item.get('data', {})
            date_added = parse_zotero_date(data.get('dateAdded'))
            if not date_added:
                continue
            timestamp = date_added.timestamp()
            item['_parsed_date_added'] = date_added
            item['_timestamp'] = timestamp
            heapq.heappush(recent_heap, (timestamp, item))
            if len(recent_heap) > limit:
                heapq.heappop(recent_heap)

            filename = get_filename_from_item(item)
            if filename:
                info = {'original': filename, 'key': item['key']}
                norm_file = normalize_filename(filename)
                norm_agg_file = normalize_aggressive(filename)
                if norm_file and norm_file not in existing_filenames:
                    existing_filenames[norm_file] = info
                if norm_agg_file and norm_agg_file not in existing_filenames_aggressive:
                    existing_filenames_aggressive[norm_agg_file] = info

        if len(items) < page_size:
            break
        start += page_size

    stats['zotero_attachments_scanned'] = total

    if not recent_heap:
        logging.warning("[ZOT] Nenhum anexo válido encontrado.")
        return []

    recent_heap.sort(key=lambda entry: entry[0], reverse=True)
    selected_items = [item for _, item in recent_heap]

    logging.info(
        "[ZOT] Varredura concluída. Total escaneado: %d | Selecionados (top %d): %d",
        total,
        limit,
            len(selected_items),
    )

    if DEBUG_DETAILED and selected_items:
        first = selected_items[0]
        last = selected_items[-1]
        logging.debug(
            "[ZOT] Top mais recente: dateAdded=%s | título=%s | filename=%s | key=%s",
            first.get('_parsed_date_added') or first.get('data', {}).get('dateAdded'),
            first.get('data', {}).get('title'),
            first.get('data', {}).get('filename') or first.get('data', {}).get('path'),
            first.get('key'),
        )
        logging.debug(
            "[ZOT] Top limite: dateAdded=%s | título=%s | filename=%s | key=%s",
            last.get('_parsed_date_added') or last.get('data', {}).get('dateAdded'),
            last.get('data', {}).get('title'),
            last.get('data', {}).get('filename') or last.get('data', {}).get('path'),
            last.get('key'),
        )

    return selected_items, existing_filenames, existing_filenames_aggressive

def _coerce_response_items(items):
    """Normaliza estruturas retornadas pela Pyzotero em listas de anexos."""
    if not items:
        return []
    if isinstance(items, dict):
        return list(items.values())
    if isinstance(items, list):
        return items
    return [items]

def _normalize_cache_path(path: str) -> str:
    return os.path.abspath(path)

def load_hash_cache() -> Dict[str, dict]:
    """Carrega o cache de hashes persistido em disco."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logging.warning("[CACHE] Falha ao carregar cache: %s", exc)
        return {}

    if not isinstance(payload, dict):
        return {}

    version = payload.get("version")
    entries = payload.get("entries")
    if version != CACHE_VERSION or not isinstance(entries, dict):
        return {}
    return entries

def save_hash_cache(cache: Dict[str, dict]) -> None:
    """Persiste o cache de hashes em disco."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        payload = {
            "version": CACHE_VERSION,
            "updated": datetime.now(timezone.utc).isoformat(),
            "entries": cache,
        }
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, indent=2)
    except Exception as exc:
        logging.warning("[CACHE] Falha ao salvar cache: %s", exc)

def get_cached_hash(path: str, cache: Dict[str, dict], stat_result: os.stat_result | None = None) -> str | None:
    """Recupera um hash do cache se mtime e tamanho coincidirem."""
    abspath = _normalize_cache_path(path)
    entry = cache.get(abspath)
    if not entry:
        return None

    try:
        stat = stat_result or os.stat(abspath)
    except OSError:
        return None

    size = entry.get("size")
    cached_mtime_ns = entry.get("mtime_ns")
    cached_mtime = entry.get("mtime")

    if size is None:
        return None

    if cached_mtime_ns is not None:
        if getattr(stat, "st_mtime_ns", None) != cached_mtime_ns or stat.st_size != size:
            return None
    elif cached_mtime is not None:
        if abs(stat.st_mtime - cached_mtime) > 1e-6 or stat.st_size != size:
            return None
    else:
        return None

    return entry.get("hash")

def set_cached_hash(path: str, file_hash: str, cache: Dict[str, dict], stat_result: os.stat_result | None = None) -> None:
    """Armazena no cache o hash calculado para um arquivo."""
    abspath = _normalize_cache_path(path)
    try:
        stat = stat_result or os.stat(abspath)
    except OSError:
        return

    entry = {
        "hash": file_hash,
        "size": stat.st_size,
    }
    if hasattr(stat, "st_mtime_ns"):
        entry["mtime_ns"] = stat.st_mtime_ns  # type: ignore[attr-defined]
    else:
        entry["mtime"] = stat.st_mtime
    cache[abspath] = entry

def rename_cache_entry(cache: Dict[str, dict], old_path: str, new_path: str) -> None:
    """Atualiza o cache quando um arquivo é renomeado."""
    old_abs = _normalize_cache_path(old_path)
    new_abs = _normalize_cache_path(new_path)
    if old_abs == new_abs:
        return
    entry = cache.pop(old_abs, None)
    if entry:
        cache[new_abs] = entry

def compute_sha256(path: str, cache: Dict[str, dict] | None = None) -> str | None:
    """Calcula o hash SHA-256 do arquivo fornecido com suporte a cache."""
    cache_ref = cache if cache is not None else HASH_CACHE
    abspath = _normalize_cache_path(path)
    try:
        stat = os.stat(abspath)
    except OSError as exc:
        logging.warning("[HASH] Não foi possível acessar '%s': %s", path, exc)
        return None

    if cache_ref is not None:
        cached = get_cached_hash(abspath, cache_ref, stat)
        if cached:
            return cached

    try:
        hasher = hashlib.sha256()
        with open(abspath, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
    except OSError as exc:
        logging.warning("[HASH] Não foi possível calcular hash de '%s': %s", path, exc)
        return None

    if cache_ref is not None:
        set_cached_hash(abspath, file_hash, cache_ref, stat)
    return file_hash

HASH_CACHE.update(load_hash_cache())
atexit.register(save_hash_cache, HASH_CACHE)

def get_latest_pdf_path(directory: str) -> str | None:
    """Retorna o PDF mais recente dentro de um diretório."""
    if not os.path.isdir(directory):
        return None
    try:
        candidates = [
            os.path.join(directory, name)
            for name in os.listdir(directory)
            if name.lower().endswith('.pdf')
        ]
    except OSError as exc:
        logging.warning("[HASH] Falha ao listar '%s': %s", directory, exc)
        return None

    if not candidates:
        return None

    candidates.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    return candidates[0]

def build_local_storage_index(existing_filenames: Dict[str, dict]) -> Tuple[Dict[str, List[dict]], Dict[str, str]]:
    """Indexa os anexos locais já sincronizados por SHA-256."""
    hash_index: Dict[str, List[dict]] = {}
    key_to_path: Dict[str, str] = {}
    seen_keys: set[str] = set()

    for info in existing_filenames.values():
        key = info.get('key')
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)

        local_dir = os.path.join(LOCAL_COPY_DIR, key)
        if not os.path.isdir(local_dir):
            continue
        local_file = get_latest_pdf_path(local_dir)
        if not local_file:
            continue
        file_hash = compute_sha256(local_file)
        if not file_hash:
            continue

        entry = {
            'key': key,
            'path': local_file,
            'filename': os.path.basename(local_file),
            'info': info,
        }
        hash_index.setdefault(file_hash, []).append(entry)
        key_to_path[key] = local_file

    return hash_index, key_to_path

def rename_webdav_file(src_path: str, desired_name: str) -> str:
    """Renomeia o arquivo no WebDAV para alinhar com o Zotero."""
    current_name = os.path.basename(src_path)
    if current_name == desired_name or not desired_name:
        return src_path

    dest_path = os.path.join(os.path.dirname(src_path), desired_name)
    if os.path.exists(dest_path):
        logging.warning(
            "[RENOMEIO] Destino '%s' já existe ao tentar renomear '%s'. Mantido nome original.",
            dest_path,
            src_path,
        )
        return src_path

    try:
        os.rename(src_path, dest_path)
        logging.info("[RENOMEIO] '%s' renomeado para '%s'.", current_name, desired_name)
        rename_cache_entry(HASH_CACHE, src_path, dest_path)
        return dest_path
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Falha ao renomear '%s' para '%s': %s",
            current_name,
            desired_name,
            exc,
        )
        return src_path

def register_local_hash(
    hash_index: Dict[str, List[dict]],
    key_to_path: Dict[str, str],
    key: str,
    file_path: str,
    info: dict,
) -> None:
    """Atualiza o índice de hashes com uma nova cópia local."""
    if not key or not file_path or not os.path.exists(file_path):
        return
    file_hash = compute_sha256(file_path)
    if not file_hash:
        return
    entry = {
        'key': key,
        'path': file_path,
        'filename': os.path.basename(file_path),
        'info': info,
    }
    bucket = hash_index.setdefault(file_hash, [])
    if not any(existing['key'] == key for existing in bucket):
        bucket.append(entry)
    key_to_path[key] = file_path

def rename_local_attachment(
    zot: zotero.Zotero,
    key: str,
    current_path: str,
    new_filename: str,
) -> str:
    """Renomeia o anexo local do Zotero e atualiza metadados via API."""
    if not key or not current_path or not os.path.exists(current_path) or not new_filename:
        return current_path

    current_name = os.path.basename(current_path)
    if current_name == new_filename:
        return current_path

    dest_path = os.path.join(os.path.dirname(current_path), new_filename)
    if os.path.exists(dest_path):
        logging.warning(
            "[RENOMEIO] Já existe '%s' ao renomear anexo %s. Mantido nome '%s'.",
            dest_path,
            key,
            current_name,
        )
        return current_path

    try:
        item = zot.item(key)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao obter anexo %s: %s", key, exc)
        return current_path

    try:
        os.rename(current_path, dest_path)
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Não foi possível renomear arquivo local '%s' para '%s': %s",
            current_name,
            new_filename,
            exc,
        )
        return current_path

    rename_cache_entry(HASH_CACHE, current_path, dest_path)

    try:
        item_data = item.get('data', {})
        item_data['filename'] = new_filename
        # Atualizar título apenas se estiver vazio ou igual ao nome anterior
        if not item_data.get('title') or item_data['title'] == current_name:
            item_data['title'] = new_filename
        item['data'] = item_data
        zot.update_item(item)
        logging.info("[RENOMEIO] Anexo %s atualizado para '%s'.", key, new_filename)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao atualizar metadados do anexo %s: %s", key, exc)

    return dest_path

def copy_to_local_storage(src_path: str, attachment_key: str, known_hash: str | None = None) -> str | None:
    """Garantir uma cópia local para o anexo recém-processado.

    Retorna:
        'copied'  -> nova cópia criada.
        'exists'  -> cópia já estava presente.
        None      -> falha.
    """
    if not LOCAL_COPY_DIR:
        return None

    try:
        os.makedirs(LOCAL_COPY_DIR, exist_ok=True)
    except Exception as exc:
        logging.error(
            "[COPIA-LOCAL] Falha ao preparar diretório local '%s': %s",
            LOCAL_COPY_DIR,
            exc,
        )
        return None

    dest_dir = os.path.join(LOCAL_COPY_DIR, attachment_key)
    dest_file = os.path.join(dest_dir, os.path.basename(src_path))

    if os.path.exists(dest_file):
        logging.info(
            "[COPIA-LOCAL] '%s' já existe. Nenhuma nova cópia criada.",
            dest_file,
        )
        if known_hash:
            set_cached_hash(dest_file, known_hash, HASH_CACHE)
        return "exists"

    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src_path, dest_file)
        logging.info("[COPIA-LOCAL] Arquivo copiado para %s", dest_file)
        if known_hash:
            set_cached_hash(dest_file, known_hash, HASH_CACHE)
        else:
            compute_sha256(dest_file)
        return "copied"
    except Exception as exc:
        logging.error(
            "[COPIA-LOCAL] Falha ao copiar '%s' para '%s': %s",
            src_path,
            dest_file,
            exc,
        )
        return None

def main():
    """Função principal do script."""
    print("Iniciando o comparador de PDFs (v1.0 Pyzotero)")
    
    stats = {
        'added': 0,
        'skipped': 0,
        'errors': 0,
        'zotero_attachments_scanned': 0,
        'zotero_recent_checked': 0,
        'zotero_unique_filenames': 0,
        'folder_total_pdfs': 0,
        'folder_checked_pdfs': 0,
        'local_copies': 0,
        'processed': 0,
        'hash_matches': 0,
        'renamed_webdav': 0,
        'renamed_local': 0,
    }
    
    # 1. Conectar ao Zotero
    try:
        zot = zotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
        zot.key_info() 
        print("✓ Conexão com a Zotero API bem-sucedida.")
    except Exception as e:
        logging.error(f"Falha ao conectar à Zotero API. Verifique suas credenciais. Erro: {e}")
        finalize_execution(stats)
        return

    # 2. Coletar todos os anexos existentes no Zotero
    print("\nColetando anexos da biblioteca Zotero... (Isso pode levar um tempo)")
    try:
        (
            recent_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_recent_attachments(
            zot,
            MAX_ATTACHMENTS_TO_CHECK,
            stats,
        )
        stats['zotero_recent_checked'] = len(recent_attachments)
        stats['zotero_unique_filenames'] = len(existing_filenames)

        if not recent_attachments:
            logging.error("Nenhum anexo recente pôde ser obtido da biblioteca Zotero.")
            finalize_execution(stats)
            return

        print(f"✓ {stats['zotero_recent_checked']} anexos mais recentes coletados (limite {MAX_ATTACHMENTS_TO_CHECK}).")
        
        for item in tqdm(recent_attachments, desc="Processando anexos recentes do Zotero"):
            filename = get_filename_from_item(item)
            if filename and DEBUG_DETAILED:
                data = item.get('data', {})
                date_added = item.get('_parsed_date_added') or data.get('dateAdded')
                logging.debug(
                    "[ZOT] dateAdded=%s | original='%s' | norm='%s' | norm_agg='%s'",
                    date_added,
                    filename,
                    normalize_filename(filename),
                    normalize_aggressive(filename),
                )
        
        print(f"✓ {stats['zotero_unique_filenames']} nomes de arquivos únicos coletados do Zotero.")

    except Exception as e:
        logging.error(f"Erro ao coletar anexos do Zotero: {e}")
        finalize_execution(stats)
        return

    hash_index, key_to_path = build_local_storage_index(existing_filenames)

    # 3. Processar arquivos da pasta local
    print(f"\nVerificando a pasta: {TARGET_FOLDER}")
    if not os.path.isdir(TARGET_FOLDER):
        logging.error(f"A pasta alvo não foi encontrada ou não é um diretório: {TARGET_FOLDER}")
        finalize_execution(stats)
        return

    try:
        files_to_process = collect_recent_pdfs(TARGET_FOLDER, MAX_FILES_TO_CHECK, stats)
        
        if not files_to_process:
            print("Nenhum arquivo PDF encontrado na pasta.")
            finalize_execution(stats)
            return

        stats['folder_checked_pdfs'] = len(files_to_process)
        
        print(f"Encontrados {stats['folder_total_pdfs']} PDFs. Verificando os {stats['folder_checked_pdfs']} mais recentes.")

        # 4. Comparar e adicionar arquivos faltantes
        for file_path in tqdm(files_to_process, desc="Verificando arquivos locais"):
            stats['processed'] += 1
            file_name = os.path.basename(file_path)
            file_hash = compute_sha256(file_path)
            if not file_hash:
                stats['errors'] += 1
                logging.error("[HASH] Não foi possível obter hash de '%s'. Arquivo ignorado.", file_name)
                continue

            norm_local = normalize_filename(file_name)
            norm_local_aggressive = normalize_aggressive(file_name)
            if DEBUG_DETAILED:
                logging.debug(
                    "[LOCAL] arquivo='%s' | norm='%s' | norm_agg='%s' | hash=%s",
                    file_name,
                    norm_local,
                    norm_local_aggressive,
                    file_hash,
                )

            hash_matches = hash_index.get(file_hash, [])
            if hash_matches:
                # Já sincronizado, alinhar nomes conforme mtime
                entry = hash_matches[0]
                canonical_key = entry['key']
                canonical_name = entry.get('info', {}).get('original') or entry['filename']
                canonical_path = entry.get('path')
                if canonical_path and os.path.exists(canonical_path):
                    canonical_actual_name = os.path.basename(canonical_path)
                    canonical_mtime = os.path.getmtime(canonical_path)
                    if canonical_actual_name:
                        canonical_name = canonical_actual_name
                else:
                    canonical_mtime = 0

                webdav_mtime = os.path.getmtime(file_path)
                webdav_name = os.path.basename(file_path)

                if canonical_path and os.path.exists(canonical_path) and webdav_name != canonical_name:
                    if webdav_mtime > (canonical_mtime + 1):
                        # WebDAV mais recente -> usar nome do WebDAV
                        updated_path = rename_local_attachment(zot, canonical_key, canonical_path, webdav_name)
                        if updated_path != canonical_path:
                            entry['path'] = updated_path
                            entry['filename'] = os.path.basename(updated_path)
                            key_to_path[canonical_key] = updated_path
                            canonical_name = entry['filename']
                            stats['renamed_local'] += 1
                    else:
                        # Storage local mais recente -> alinhar nome do WebDAV
                        new_path = rename_webdav_file(file_path, canonical_name)
                        if new_path != file_path:
                            file_path = new_path
                            webdav_name = canonical_name
                            stats['renamed_webdav'] += 1
                elif canonical_path and os.path.exists(canonical_path):
                    canonical_name = os.path.basename(canonical_path)
                else:
                    canonical_name = webdav_name

                file_name = os.path.basename(file_path)
                norm_local = normalize_filename(file_name)
                norm_local_aggressive = normalize_aggressive(file_name)
                info = {'original': canonical_name, 'key': canonical_key}
                existing_filenames[norm_local] = info
                existing_filenames_aggressive[norm_local_aggressive] = info
                stats['skipped'] += 1
                stats['hash_matches'] += 1
                logging.info("[HASH] '%s' já sincronizado (key=%s).", file_name, canonical_key)
                continue

            encontrado = (norm_local in existing_filenames or norm_local_aggressive in existing_filenames_aggressive)

            if encontrado:
                if DEBUG_DETAILED:
                    logging.info(f"[IGNORADO] '{file_name}' já existe na biblioteca.")
                stats['skipped'] += 1
                continue

            try:
                logging.info(f"[ADICIONANDO] '{file_name}'...")
                response = zot.attachment_simple([file_path])
                if not response:
                    stats['errors'] += 1
                    logging.error("[ERRO] Resposta vazia ao adicionar '%s'.", file_name)
                    continue

                success_items = _coerce_response_items(response.get("success"))
                unchanged_items = _coerce_response_items(response.get("unchanged"))
                failure_items = _coerce_response_items(response.get("failure"))

                handled = False

                if success_items:
                    attachment_info = success_items[0]
                    new_key = attachment_info.get("key")
                    if not new_key:
                        stats['errors'] += 1
                        logging.error("[ERRO] Chave não retornada para '%s'. Resposta: %s", file_name, response)
                        continue

                    stats['added'] += 1
                    info = {'original': file_name, 'key': new_key}
                    existing_filenames[norm_local] = info
                    existing_filenames_aggressive[norm_local_aggressive] = info
                    copy_outcome = copy_to_local_storage(file_path, new_key, file_hash)
                    if copy_outcome == "copied":
                        stats['local_copies'] += 1
                    elif copy_outcome is None:
                        logging.warning("[COPIA-LOCAL] Não foi possível copiar '%s' para o storage local.", file_name)
                    local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, new_key))
                    if local_path and os.path.exists(local_path):
                        register_local_hash(hash_index, key_to_path, new_key, local_path, info)
                    handled = True

                if unchanged_items:
                    attachment_info = unchanged_items[0]
                    existing_key = attachment_info.get("key")
                    if not existing_key:
                        stats['errors'] += 1
                        logging.error("[ERRO] Chave ausente para '%s' (unchanged). Resposta: %s", file_name, response)
                    else:
                        stats['skipped'] += 1
                        info = {'original': file_name, 'key': existing_key}
                        existing_filenames[norm_local] = info
                        existing_filenames_aggressive[norm_local_aggressive] = info
                        copy_outcome = copy_to_local_storage(file_path, existing_key, file_hash)
                        if copy_outcome == "copied":
                            stats['local_copies'] += 1
                        elif copy_outcome is None:
                            logging.warning("[COPIA-LOCAL] Não foi possível garantir cópia local de '%s'.", file_name)
                        local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, existing_key))
                        if local_path and os.path.exists(local_path):
                            register_local_hash(hash_index, key_to_path, existing_key, local_path, info)
                        logging.info("[IGNORADO] '%s' já existia no Zotero (unchanged).", file_name)
                    handled = True

                if not handled:
                    stats['errors'] += 1
                    logging.error(
                        "[ERRO] Falha ao adicionar '%s'. Falhas: %s",
                        file_name,
                        failure_items or response,
                    )

            except Exception as e:
                stats['errors'] += 1
                logging.error(f"[ERRO] Exceção ao adicionar '{file_name}': {e}")
                    
    except Exception as e:
        logging.error(f"Erro ao processar arquivos da pasta: {e}")
        finalize_execution(stats)
        return

    # 5. Gerar relatório final
    total_verificados = stats['processed'] or stats['folder_checked_pdfs']
    pct_adicionados = ((stats['added'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_ignorados = ((stats['skipped'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_erros = ((stats['errors'] / total_verificados) * 100) if total_verificados > 0 else 0

    summary = f"""
╔════════════════════════════════════════════════════════╗
║                   RELATÓRIO FINAL                      ║
╚════════════════════════════════════════════════════════╝

📂 Pasta: {TARGET_FOLDER}
🏠 Cópia local: {LOCAL_COPY_DIR}

┌─── 📊 COLETA DE ANEXOS ──────────────────────────────┐
│ Anexos varridos (total): {stats['zotero_attachments_scanned']:<25} │
│ Anexos recentes analisados: {stats['zotero_recent_checked']:<21} │
│ Nomes únicos recentes: {stats['zotero_unique_filenames']:<28} │
└──────────────────────────────────────────────────────┘

┌─── 📈 RESULTADOS DA VERIFICAÇÃO ───────────────────────┐
│ PDFs totais na pasta: {stats['folder_total_pdfs']:<30} │
│ 🔍 Processados (loop): {total_verificados:<30} │
│ ──────────────────────────────────────────────────── │
│ ✅ Adicionados: {stats['added']} ({pct_adicionados:.1f}%) {' ' * (33 - len(str(stats['added']) + str(pct_adicionados)))}│
│ ⏭️  Existentes: {stats['skipped']} ({pct_ignorados:.1f}%) {' ' * (33 - len(str(stats['skipped']) + str(pct_ignorados)))}│
│ 💾 Cópias locais: {stats['local_copies']:<34} │
│ ❌ Erros: {stats['errors']} ({pct_erros:.1f}%) {' ' * (38 - len(str(stats['errors']) + str(pct_erros)))}│
│ 🔁 Hash reaproveitados: {stats['hash_matches']:<23} │
│ ✏️  Renomes WebDAV: {stats['renamed_webdav']:<27} │
│ 📝 Renomes storage: {stats['renamed_local']:<27} │
└──────────────────────────────────────────────────────┘

✨ Processamento concluído!
"""
    print(summary)
    finalize_execution(stats, summary)

if __name__ == "__main__":
    main()

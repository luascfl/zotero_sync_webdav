"""Sincronizador bidirecional assistido entre uma pasta de PDFs no drive montado,
a biblioteca Zotero via API e o storage local em ~/Zotero/storage.

Workflow real deste script:
1. Lê configuração e resolve a pasta alvo montada no sistema de arquivos.
2. Consulta a API do Zotero para descobrir quais anexos já existem e qual chave cada
   nome conhecido aponta no servidor.
3. Indexa o storage local do Zotero em ~/Zotero/storage por hash SHA-256.
   Essa cópia local não é só cache. Ela é a âncora operacional do fluxo:
   - permite comparar conteúdo sem depender apenas do nome,
   - permite detectar renomeações entre drive e Zotero,
   - permite reconstruir a cópia local quando o Zotero conhece o anexo mas o storage
     local ainda não tem o PDF correspondente.
4. Varre os PDFs da pasta montada no drive.
5. Para cada PDF do drive, decide entre cinco caminhos:
   - caso 1: mesmo nome e mesmo conteúdo, então já está sincronizado;
   - caso 2: mesmo nome e conteúdo diferente, então o drive passou a ser a versão
     mais recente e a cópia local do Zotero é atualizada;
   - caso 3: mesmo conteúdo e nomes diferentes, então há conflito de nome e o lado
     mais recente por mtime define o título canônico temporário;
   - caso 4: o arquivo existe no drive, mas não existe no Zotero, então ele é enviado
     ao Zotero e também copiado para ~/Zotero/storage;
   - caso 5: o Zotero conhece o anexo, mas a cópia local em ~/Zotero/storage está
     ausente, então a cópia local é recriada a partir do drive.

Regras operacionais definidas pelo usuário para conflitos:
- presença é bidirecional: drive sem Zotero deve ir para o Zotero; Zotero sem drive
  deve ser materializado no drive em uma futura etapa de reconciliação completa;
- em hash_match com nomes diferentes, o lado com mtime mais recente vira a fonte de
  verdade temporária para o título;
- se o Zotero estiver mais recente, renomeia-se o drive;
- se o drive estiver mais recente, modifica-se o Zotero para refletir o nome do drive,
  porque esse foi o ajuste manual mais recente do usuário.

Limites atuais importantes:
- a implementação já cobre bem a direção drive -> Zotero e a reconstrução da cópia
  local do Zotero;
- a presença Zotero -> drive ainda não é uma reconciliação global completa, apesar de
  a política do projeto já exigir isso;
- mounts FUSE/rclone podem listar arquivos mas travar na leitura do conteúdo, então o
  script faz probes e usa timeouts para distinguir lentidão de mount quebrado.
"""

import atexit
import hashlib
import heapq
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
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

# Pasta onde o Zotero Desktop espera encontrar os anexos importados.
# Esta cópia local em ~/Zotero/storage é necessária para o workflow prático do projeto:
# sem ela, o script perde a referência de conteúdo usada para comparar hashes,
# reconstruir anexos locais ausentes e decidir renomeações entre drive e Zotero.
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

HASH_CACHE: Dict[str, dict] = {}

# FIX: Limites aumentados para cobrir bibliotecas grandes.
# 0 = sem limite (processa tudo).
MAX_FILES_TO_CHECK = 0        # 0 = todos os PDFs da pasta
MAX_ATTACHMENTS_TO_CHECK = 0  # 0 = todos os anexos do Zotero

# Ativar logs detalhados no console
DEBUG_DETAILED = True
HASH_READ_TIMEOUT_SECONDS_DEFAULT = 180
CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT = 60


def get_env_int(name: str, default: int) -> int:
    """Lê inteiro de ambiente com fallback seguro."""
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        logging.warning("Valor inválido para %s=%r. Usando %d.", name, raw_value, default)
        return default
    return max(0, value)


HASH_READ_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_HASH_TIMEOUT_SECONDS",
    HASH_READ_TIMEOUT_SECONDS_DEFAULT,
)
CONTENT_PROBE_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_CONTENT_PROBE_TIMEOUT_SECONDS",
    CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT,
)


def probe_pdf_content_read(
    path: str,
    timeout_seconds: int = CONTENT_PROBE_TIMEOUT_SECONDS,
    bytes_to_read: int = 65536,
) -> bool:
    """Testa leitura curta de conteúdo em subprocesso para detectar mount travado."""
    if not path:
        return False
    if timeout_seconds <= 0:
        logging.info("[PROBE] Probe de conteúdo desativado para '%s'.", path)
        return True

    logging.info(
        "[PROBE] Testando leitura inicial de %d bytes de '%s' (timeout=%ss).",
        bytes_to_read,
        path,
        timeout_seconds,
    )
    probe_code = (
        "import sys\n"
        "path = sys.argv[1]\n"
        "size = int(sys.argv[2])\n"
        "with open(path, 'rb') as handle:\n"
        "    handle.read(size)\n"
    )
    started_at = time.monotonic()
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", probe_code, path, str(bytes_to_read)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        while True:
            return_code = process.poll()
            if return_code is not None:
                break

            elapsed = time.monotonic() - started_at
            if elapsed >= timeout_seconds:
                process.kill()
                logging.error(
                    "[PROBE] Timeout após %.1fs lendo '%s'. Processo filho pid=%s pode ficar preso em I/O do mount; abortando o sync.",
                    elapsed,
                    path,
                    process.pid,
                )
                return False

            time.sleep(0.2)

        _, stderr = process.communicate()
        if return_code != 0:
            logging.error(
                "[PROBE] Falha ao ler conteúdo de '%s' (rc=%s): %s",
                path,
                return_code,
                (stderr or "").strip(),
            )
            return False
    except OSError as exc:
        logging.error("[PROBE] Erro ao executar probe de conteúdo para '%s': %s", path, exc)
        return False

    elapsed = time.monotonic() - started_at
    logging.info("[PROBE] Leitura inicial OK para '%s' em %.1fs.", path, elapsed)
    return True


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

    cmd = ["notify-send", "-a", "Zotero Sync", "-i", "text-x-log"]

    desktop_hint = ensure_log_desktop_entry(log_path) if log_path else None
    if desktop_hint:
        cmd.extend(["-h", f"string:desktop-entry:{desktop_hint}"])

    cmd.extend(["Sincronização Zotero/WebDAV concluída", body])

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
            if path_str.startswith("file:///"):
                path_str = path_str[8:]
            elif path_str.startswith("file://"):
                path_str = path_str[7:]
            elif path_str.startswith("file:"):
                path_str = path_str[5:]
            elif path_str.startswith("storage:"):
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


def collect_all_pdfs(directory: str, stats: dict) -> List[str]:
    """Retorna todos os PDFs da pasta, ordenados do mais recente ao mais antigo."""
    logging.info("[SCAN] Iniciando varredura de PDFs em %s", directory)

    entries: List[Tuple[float, str]] = []

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
                entries.append((mtime, entry.path))

    except FileNotFoundError:
        logging.error("A pasta alvo não foi encontrada: %s", directory)
        return []
    except PermissionError:
        logging.error("Sem permissão para acessar a pasta: %s", directory)
        return []
    except Exception as exc:
        logging.error("Erro ao varrer a pasta '%s': %s", directory, exc)
        return []

    if not entries:
        logging.info("[SCAN] Nenhum PDF encontrado em %s.", directory)
        return []

    entries.sort(key=lambda x: x[0], reverse=True)

    stats['folder_total_pdfs'] = len(entries)
    stats['folder_checked_pdfs'] = len(entries)

    logging.info("[SCAN] PDFs encontrados: %d", len(entries))

    return [path for _, path in entries]


def collect_all_attachments(
    zot: zotero.Zotero,
    stats: dict,
) -> Tuple[List[dict], dict, dict]:
    """
    Busca TODOS os anexos da biblioteca sem limite de janela.

    FIX: A versão anterior limitava a janela de "recentes" a MAX_ATTACHMENTS_TO_CHECK,
    o que fazia o índice de nomes ficar incompleto — anexos antigos eram ignorados
    na comparação, causando duplicatas ao re-adicionar o mesmo arquivo.

    Agora:
    - existing_filenames / existing_filenames_aggressive indexam TODOS os anexos.
    - A lista retornada também é a lista completa (usada apenas para logging/debug).
    """
    page_size = 100
    start = 0
    total = 0
    all_items: List[dict] = []
    existing_filenames: dict = {}
    existing_filenames_aggressive: dict = {}

    logging.info("[ZOT] Iniciando varredura completa de anexos (sem limite).")

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
        logging.debug("[ZOT] Página recebida. start=%d | itens=%d | total=%d", start, len(items), total)

        for item in items:
            data = item.get('data', {})
            date_added = parse_zotero_date(data.get('dateAdded'))
            if date_added:
                item['_parsed_date_added'] = date_added
                item['_timestamp'] = date_added.timestamp()

            filename = get_filename_from_item(item)
            if filename:
                info = {'original': filename, 'key': item['key']}
                norm_file = normalize_filename(filename)
                norm_agg_file = normalize_aggressive(filename)
                # Guarda o primeiro encontrado (mais recente, pois ordenamos desc)
                if norm_file and norm_file not in existing_filenames:
                    existing_filenames[norm_file] = info
                if norm_agg_file and norm_agg_file not in existing_filenames_aggressive:
                    existing_filenames_aggressive[norm_agg_file] = info

            all_items.append(item)

        if len(items) < page_size:
            break
        start += page_size

    stats['zotero_attachments_scanned'] = total

    logging.info(
        "[ZOT] Varredura concluída. Total: %d anexos | Nomes únicos (basic): %d | (aggressive): %d",
        total,
        len(existing_filenames),
        len(existing_filenames_aggressive),
    )

    # FIX: retorna tupla consistente mesmo quando vazio (bug anterior retornava [] sozinho)
    return all_items, existing_filenames, existing_filenames_aggressive


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


def compute_sha256(
    path: str,
    cache: Dict[str, dict] | None = None,
    timeout_seconds: int | None = None,
) -> str | None:
    """Calcula o hash SHA-256 do arquivo fornecido com suporte a cache e timeout."""
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
            logging.debug("[HASH] Cache hit para '%s'.", path)
            return cached

    effective_timeout = HASH_READ_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    size_mb = stat.st_size / (1024 * 1024)
    logging.info(
        "[HASH] Calculando SHA-256 de '%s' (%.1f MiB, timeout=%ss).",
        path,
        size_mb,
        effective_timeout if effective_timeout else "sem",
    )

    alarm_enabled = False
    previous_handler = None

    def raise_hash_timeout(signum, frame):
        raise TimeoutError(f"timeout ao calcular hash de {path}")

    try:
        if effective_timeout and effective_timeout > 0:
            try:
                previous_handler = signal.getsignal(signal.SIGALRM)
                signal.signal(signal.SIGALRM, raise_hash_timeout)
                signal.alarm(effective_timeout)
                alarm_enabled = True
            except ValueError:
                logging.debug("[HASH] Timeout por SIGALRM indisponível neste contexto.")

        started_at = time.monotonic()
        hasher = hashlib.sha256()
        with open(abspath, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        elapsed = time.monotonic() - started_at
        logging.info("[HASH] SHA-256 concluído para '%s' em %.1fs.", path, elapsed)
    except TimeoutError:
        logging.error(
            "[HASH] Timeout após %ss ao calcular SHA-256 de '%s'. Arquivo ignorado nesta execução.",
            effective_timeout,
            path,
        )
        return None
    except OSError as exc:
        logging.warning("[HASH] Não foi possível calcular hash de '%s': %s", path, exc)
        return None
    finally:
        if alarm_enabled:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

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
    """Indexa por hash a cópia local do Zotero em ~/Zotero/storage.

    O storage local funciona como espelho operacional dos anexos já conhecidos pelo
    Zotero. Quando a API conhece um item, mas o PDF local sumiu, o script tenta
    reconstruir essa cópia. Quando drive e Zotero têm o mesmo conteúdo com nomes
    diferentes, o storage local permite comparar mtime e decidir qual lado deve ceder.
    """
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
        if not item_data.get('title') or item_data['title'] == current_name:
            item_data['title'] = new_filename
        item['data'] = item_data
        zot.update_item(item)
        logging.info("[RENOMEIO] Anexo %s atualizado para '%s'.", key, new_filename)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao atualizar metadados do anexo %s: %s", key, exc)

    return dest_path


def copy_to_local_storage(src_path: str, attachment_key: str, known_hash: str | None = None) -> str | None:
    """Garante uma cópia local para o anexo recém-processado."""
    if not LOCAL_COPY_DIR:
        return None

    try:
        os.makedirs(LOCAL_COPY_DIR, exist_ok=True)
    except Exception as exc:
        logging.error("[COPIA-LOCAL] Falha ao preparar diretório local '%s': %s", LOCAL_COPY_DIR, exc)
        return None

    dest_dir = os.path.join(LOCAL_COPY_DIR, attachment_key)
    dest_file = os.path.join(dest_dir, os.path.basename(src_path))

    if os.path.exists(dest_file):
        logging.info("[COPIA-LOCAL] '%s' já existe. Nenhuma nova cópia criada.", dest_file)
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
        logging.error("[COPIA-LOCAL] Falha ao copiar '%s' para '%s': %s", src_path, dest_file, exc)
        return None


def main():
    """Executa a sincronização observando API do Zotero, drive montado e storage local.
"""
    print("Iniciando o sincronizador Zotero/WebDAV (v2.0)")

    stats = {
        'added': 0,
        'skipped': 0,
        'errors': 0,
        'zotero_attachments_scanned': 0,
        'zotero_unique_filenames': 0,
        'folder_total_pdfs': 0,
        'folder_checked_pdfs': 0,
        'local_copies': 0,
        'processed': 0,
        'hash_matches': 0,
        'renamed_webdav': 0,
        'renamed_local': 0,
        'updated_content': 0,
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

    # 2. Coletar TODOS os anexos existentes no Zotero
    print("\nColetando anexos da biblioteca Zotero... (pode levar alguns instantes)")
    try:
        (
            all_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_all_attachments(zot, stats)

        stats['zotero_unique_filenames'] = len(existing_filenames)

        if not existing_filenames:
            logging.warning("[ZOT] Nenhum nome de arquivo indexado. A biblioteca pode estar vazia.")

        print(f"✓ {stats['zotero_attachments_scanned']} anexos escaneados | "
              f"{stats['zotero_unique_filenames']} nomes únicos indexados.")

    except Exception as e:
        logging.error(f"Erro ao coletar anexos do Zotero: {e}")
        finalize_execution(stats)
        return

    hash_index, key_to_path = build_local_storage_index(existing_filenames)

    # 3. Processar arquivos da pasta montada no drive.
    #
    print(f"\nVerificando a pasta: {TARGET_FOLDER}")
    if not os.path.isdir(TARGET_FOLDER):
        logging.error(f"A pasta alvo não foi encontrada ou não é um diretório: {TARGET_FOLDER}")
        finalize_execution(stats)
        return

    try:
        files_to_process = collect_all_pdfs(TARGET_FOLDER, stats)

        if not files_to_process:
            print("Nenhum arquivo PDF encontrado na pasta.")
            finalize_execution(stats)
            return

        print(f"Encontrados {stats['folder_total_pdfs']} PDFs. Processando todos.")

        if not probe_pdf_content_read(files_to_process[0]):
            stats['errors'] += 1
            logging.error(
                "[PROBE] Sincronização abortada: o mount não conseguiu ler conteúdo do primeiro PDF. "
                "Verifique o rclone/Koofr antes de tentar adicionar ou comparar anexos.",
            )
            finalize_execution(stats)
            return

        # 4. Processar cada PDF da pasta WebDAV
        #
        # Ordem de verificação para cada arquivo:
        #
        # CASO 1 — Nome encontrado no Zotero, hash igual ao storage local
        #          → Já sincronizado. Ignora.
        #
        # CASO 2 — Nome encontrado no Zotero, hash diferente do storage local
        #          → Conteúdo foi atualizado no WebDAV. Atualiza o arquivo no Zotero.
        #
        # CASO 3 — Nome NÃO encontrado, hash encontrado no storage local
        #          → Arquivo foi renomeado no WebDAV. Atualiza o nome no Zotero e no storage.
        #
        # CASO 4 — Nome NÃO encontrado, hash NÃO encontrado
        #          → Arquivo novo. Adiciona ao Zotero e copia para storage local.
        #
        # CASO 5 — Nome encontrado mas não há cópia local (storage vazio para essa key)
        #          → Garante a cópia local sem re-adicionar ao Zotero.
        #
        # Nota de performance: hashes podem ser calculados em qualquer caso que precise
        # confirmar conteúdo, detectar atualização, reconciliar rename ou criar cópia local.
        # Em mounts FUSE/rclone isso pode ler o PDF inteiro pela rede; logs e timeout ajudam a diferenciar lentidão de travamento.

        total_files_to_process = len(files_to_process)

        for index, file_path in enumerate(tqdm(files_to_process, desc="Verificando arquivos locais"), start=1):
            stats['processed'] += 1
            file_name = os.path.basename(file_path)
            logging.info("[LOOP] Processando %d/%d: '%s'.", index, total_files_to_process, file_name)
            norm_local = normalize_filename(file_name)
            norm_local_aggressive = normalize_aggressive(file_name)

            nome_info = (
                existing_filenames.get(norm_local)
                or existing_filenames_aggressive.get(norm_local_aggressive)
            )
            nome_encontrado = nome_info is not None and nome_info.get('key') != '__pending__'

            if nome_encontrado:
                zotero_key = nome_info['key']
                local_dir = os.path.join(LOCAL_COPY_DIR, zotero_key)
                local_file = get_latest_pdf_path(local_dir)

                if local_file and os.path.exists(local_file):
                    # Temos cópia local — compara hash para detectar atualização de conteúdo
                    local_hash = compute_sha256(local_file)
                    webdav_hash = compute_sha256(file_path)

                    if not local_hash or not webdav_hash:
                        stats['errors'] += 1
                        logging.error(
                            "[HASH] Falha ao comparar hashes de '%s' (local_hash=%s, webdav_hash=%s). Arquivo ignorado.",
                            file_name,
                            "ok" if local_hash else "falhou",
                            "ok" if webdav_hash else "falhou",
                        )
                        continue

                    if local_hash and webdav_hash and local_hash == webdav_hash:
                        # CASO 1: nome ok, conteúdo igual → já sincronizado
                        logging.info("[CASO 1] '%s' já sincronizado (key=%s).", file_name, zotero_key)
                        stats['skipped'] += 1
                        stats['hash_matches'] += 1
                        continue

                    elif local_hash and webdav_hash and local_hash != webdav_hash:
                        # CASO 2: nome ok, conteúdo diferente → WebDAV tem versão mais nova
                        logging.info("[CASO 2] '%s' atualizado no WebDAV. Atualizando storage local (key=%s).", file_name, zotero_key)
                        try:
                            shutil.copy2(file_path, local_file)
                            set_cached_hash(local_file, webdav_hash, HASH_CACHE)
                            register_local_hash(hash_index, key_to_path, zotero_key, local_file, nome_info)
                            stats['local_copies'] += 1
                            stats['updated_content'] += 1
                            logging.info("[CASO 2] Storage local atualizado: '%s'.", local_file)
                        except Exception as exc:
                            logging.warning("[CASO 2] Falha ao atualizar storage local de '%s': %s", file_name, exc)
                            stats['errors'] += 1
                        stats['skipped'] += 1
                        continue

                else:
                    # CASO 5: nome encontrado no Zotero mas sem cópia local
                    logging.info("[CASO 5] '%s' existe no Zotero mas sem cópia local. Copiando (key=%s).", file_name, zotero_key)
                    webdav_hash = compute_sha256(file_path)
                    if not webdav_hash:
                        stats['errors'] += 1
                        logging.error(
                            "[HASH] Não foi possível obter hash de '%s' para recriar cópia local. Arquivo ignorado.",
                            file_name,
                        )
                        continue
                    copy_outcome = copy_to_local_storage(file_path, zotero_key, webdav_hash)
                    if copy_outcome == "copied":
                        stats['local_copies'] += 1
                        new_local = get_latest_pdf_path(local_dir)
                        if new_local:
                            register_local_hash(hash_index, key_to_path, zotero_key, new_local, nome_info)
                    stats['skipped'] += 1
                    continue

            # Nome não encontrado — calcula hash para casos 3 e 4
            file_hash = compute_sha256(file_path)
            if not file_hash:
                stats['errors'] += 1
                logging.error("[HASH] Não foi possível obter hash de '%s'. Arquivo ignorado.", file_name)
                continue

            if DEBUG_DETAILED:
                logging.debug(
                    "[LOCAL] arquivo='%s' | norm='%s' | norm_agg='%s' | hash=%s",
                    file_name, norm_local, norm_local_aggressive, file_hash,
                )

            hash_matches = hash_index.get(file_hash, [])
            if hash_matches:
                # CASO 3: hash encontrado, nome diferente → arquivo foi renomeado no WebDAV
                entry = hash_matches[0]
                canonical_key = entry['key']
                canonical_path = entry.get('path')
                webdav_name = file_name
                webdav_mtime = os.path.getmtime(file_path)

                if canonical_path and os.path.exists(canonical_path):
                    canonical_name = os.path.basename(canonical_path)
                    canonical_mtime = os.path.getmtime(canonical_path)

                    logging.info(
                        "[CASO 3] Mesmo conteúdo, nomes diferentes: WebDAV='%s' | storage='%s' (key=%s).",
                        webdav_name, canonical_name, canonical_key,
                    )

                    if webdav_mtime > (canonical_mtime + 1):
                        # WebDAV mais recente → atualiza nome no storage e no Zotero
                        updated_path = rename_local_attachment(zot, canonical_key, canonical_path, webdav_name)
                        if updated_path != canonical_path:
                            entry['path'] = updated_path
                            entry['filename'] = webdav_name
                            key_to_path[canonical_key] = updated_path
                            stats['renamed_local'] += 1
                            logging.info("[CASO 3] Nome atualizado no storage: '%s'.", webdav_name)
                    else:
                        # Storage mais recente → renomeia o arquivo no WebDAV
                        new_path = rename_webdav_file(file_path, canonical_name)
                        if new_path != file_path:
                            file_path = new_path
                            file_name = canonical_name
                            stats['renamed_webdav'] += 1
                            logging.info("[CASO 3] Nome atualizado no WebDAV: '%s'.", canonical_name)
                else:
                    canonical_name = webdav_name

                norm_local = normalize_filename(file_name)
                norm_local_aggressive = normalize_aggressive(file_name)
                info = {'original': canonical_name, 'key': canonical_key}
                existing_filenames[norm_local] = info
                existing_filenames_aggressive[norm_local_aggressive] = info
                stats['skipped'] += 1
                stats['hash_matches'] += 1
                continue

            # CASO 4: nome e hash não encontrados → arquivo novo
            # Registra como pendente antes de chamar a API para evitar duplicatas
            # caso o mesmo arquivo apareça duas vezes no loop.
            existing_filenames[norm_local] = {'original': file_name, 'key': '__pending__'}
            existing_filenames_aggressive[norm_local_aggressive] = {'original': file_name, 'key': '__pending__'}

            try:
                logging.info("[CASO 4] Adicionando '%s' ao Zotero...", file_name)
                response = zot.attachment_simple([file_path])
                if not response:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Resposta vazia ao adicionar '%s'.", file_name)
                    continue

                success_items = _coerce_response_items(response.get("success"))
                unchanged_items = _coerce_response_items(response.get("unchanged"))
                failure_items = _coerce_response_items(response.get("failure"))
                handled = False

                if success_items:
                    new_key = success_items[0].get("key")
                    if not new_key:
                        existing_filenames.pop(norm_local, None)
                        existing_filenames_aggressive.pop(norm_local_aggressive, None)
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
                        logging.warning("[COPIA-LOCAL] Não foi possível copiar '%s'.", file_name)
                    local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, new_key))
                    if local_path and os.path.exists(local_path):
                        register_local_hash(hash_index, key_to_path, new_key, local_path, info)
                    logging.info("[CASO 4] '%s' adicionado com sucesso (key=%s).", file_name, new_key)
                    handled = True

                if unchanged_items:
                    existing_key = unchanged_items[0].get("key")
                    if not existing_key:
                        existing_filenames.pop(norm_local, None)
                        existing_filenames_aggressive.pop(norm_local_aggressive, None)
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
                        local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, existing_key))
                        if local_path and os.path.exists(local_path):
                            register_local_hash(hash_index, key_to_path, existing_key, local_path, info)
                        logging.info("[CASO 4] '%s' já existia no Zotero (unchanged, key=%s).", file_name, existing_key)
                    handled = True

                if not handled:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Falha ao adicionar '%s'. Falhas: %s", file_name, failure_items or response)

            except Exception as e:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['errors'] += 1
                logging.error("[ERRO] Exceção ao adicionar '%s': %s", file_name, e)

    except Exception as e:
        logging.error(f"Erro ao processar arquivos da pasta: {e}")
        finalize_execution(stats)
        return

    # 5. Relatório final
    total_verificados = stats['processed'] or stats['folder_checked_pdfs']
    pct_adicionados = ((stats['added'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_ignorados = ((stats['skipped'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_erros = ((stats['errors'] / total_verificados) * 100) if total_verificados > 0 else 0

    summary = f"""
╔════════════════════════════════════════════════════════╗
║           RELATÓRIO FINAL  (v2.0)                      ║
╚════════════════════════════════════════════════════════╝

📂 Pasta: {TARGET_FOLDER}
🏠 Cópia local: {LOCAL_COPY_DIR}

┌─── 📊 COLETA DE ANEXOS ──────────────────────────────┐
│ Anexos varridos (total): {stats['zotero_attachments_scanned']:<25} │
│ Nomes únicos indexados:  {stats['zotero_unique_filenames']:<25} │
└──────────────────────────────────────────────────────┘

┌─── 📈 RESULTADOS DA VERIFICAÇÃO ───────────────────────┐
│ PDFs totais na pasta: {stats['folder_total_pdfs']:<30} │
│ 🔍 Processados: {total_verificados:<36} │
│ ──────────────────────────────────────────────────── │
│ ✅ Adicionados: {stats['added']} ({pct_adicionados:.1f}%) {' ' * (33 - len(str(stats['added']) + str(round(pct_adicionados,1))))}│
│ ⏭️  Existentes: {stats['skipped']} ({pct_ignorados:.1f}%) {' ' * (33 - len(str(stats['skipped']) + str(round(pct_ignorados,1))))}│
│ 💾 Cópias locais: {stats['local_copies']:<34} │
│ ❌ Erros: {stats['errors']} ({pct_erros:.1f}%) {' ' * (38 - len(str(stats['errors']) + str(round(pct_erros,1))))}│
│ 🔁 Hash reaproveitados: {stats['hash_matches']:<23} │
│ 🔄 Conteúdo atualizado: {stats['updated_content']:<23} │
│ ✏️  Renomes WebDAV: {stats['renamed_webdav']:<27} │
│ 📝 Renomes storage: {stats['renamed_local']:<27} │
└──────────────────────────────────────────────────────┘

✨ Processamento concluído!
"""
    print(summary)
    finalize_execution(stats, summary)


if __name__ == "__main__":
    main()

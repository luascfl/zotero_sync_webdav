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
   - caso 3: mesmo conteúdo e nomes diferentes, então o nome canônico por metadados
     do item pai vence. Quando não há metadados suficientes, usa-se mtime como
     fallback conservador;
   - caso 4: o arquivo existe no drive, mas não existe no Zotero, então ele é enviado
     ao Zotero, anexado a um pai bibliográfico único quando possível, renomeado pelo
     padrão canônico e também copiado para ~/Zotero/storage;
   - caso 5: o Zotero conhece o anexo, mas a cópia local em ~/Zotero/storage está
     ausente, então a cópia local é recriada a partir do drive.
6. Após a varredura do drive, reconcilia Zotero -> drive: anexos PDF que existem
   no Zotero e não têm correspondente no drive são materializados no drive a partir
   da cópia local ou, se ela faltar, baixados da API do Zotero primeiro.

Regras operacionais definidas pelo usuário para conflitos:
- presença é bidirecional: drive sem Zotero deve ir para o Zotero; Zotero sem drive
  deve ser materializado no drive automaticamente;
- anexos PDF com item bibliográfico pai devem usar o padrão
  "título - sobrenome ano.pdf" no Zotero, no drive e no storage local;
- marcadores de cópia como "Cópia de", "Copy of" e "(1)" não podem vencer como nome
  canônico;
- em hash_match sem metadados bibliográficos suficientes, o lado com mtime mais
  recente vira a fonte de verdade temporária para o título.

Limites atuais importantes:
- a reconciliação bidirecional cobre nomes, hashes, cópia local e materialização de
  PDFs do Zotero para o drive;
- mounts FUSE/rclone podem listar arquivos mas travar na leitura do conteúdo, então o
  script faz probes e usa timeouts para distinguir lentidão de mount quebrado.
"""

import argparse
import atexit
import configparser
import hashlib
import heapq
from difflib import SequenceMatcher
import io
import json
import logging
import os
import re
import shlex
import shutil
import signal
import tempfile
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import unquote
from pyzotero import zotero
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent

CONFIG_ENV_FILE = Path.home() / ".config" / "zotero_sync_webdav" / "zotero_sync.env"
PROJECT_ENV_FILE = SCRIPT_DIR / ".env"
env_file_from_env = os.environ.get("ZOTERO_ENV_FILE")


def load_env_file(env_path: os.PathLike[str] | str, override: bool = False) -> None:
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
            if key and (override or key not in os.environ):
                os.environ[key] = value
    except OSError as exc:
        logging.warning("Falha ao carregar variáveis do arquivo %s: %s", env_file, exc)
LIBRARY_ID = ""
LIBRARY_TYPE = "user"
API_KEY = ""
TARGET_FOLDER_RAW = ""
TARGET_FOLDER = ""

_config_loaded = False

def load_config() -> None:
    global LIBRARY_ID, LIBRARY_TYPE, API_KEY, TARGET_FOLDER_RAW, TARGET_FOLDER, _config_loaded
    if _config_loaded:
        return
    
    env_file_from_env = os.environ.get("ZOTERO_ENV_FILE")
    if env_file_from_env:
        load_env_file(env_file_from_env, override=True)
    else:
        load_env_file(CONFIG_ENV_FILE, override=True)
        load_env_file(PROJECT_ENV_FILE, override=False)

    LIBRARY_ID = os.environ.get("ZOTERO_LIBRARY_ID", "")
    LIBRARY_TYPE = os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
    API_KEY = os.environ.get("ZOTERO_API_KEY", "")
    TARGET_FOLDER_RAW = os.environ.get("ZOTERO_SYNC_TARGET_FOLDER", "")
    TARGET_FOLDER = resolve_target_folder(TARGET_FOLDER_RAW)

    if TARGET_FOLDER_RAW != TARGET_FOLDER:
        logging.info("Pasta alvo configurada: %s (valor original: %s)", TARGET_FOLDER, TARGET_FOLDER_RAW)
    else:
        logging.info("Pasta alvo configurada: %s", TARGET_FOLDER)
    logging.info("Biblioteca Zotero configurada: %s (%s)", LIBRARY_ID, LIBRARY_TYPE)

    _config_loaded = True

def check_environment_requirements() -> None:
    """Valida a presença das variáveis de ambiente obrigatórias."""
    load_config()
    missing_env = [name for name, value in {
        "ZOTERO_LIBRARY_ID": LIBRARY_ID,
        "ZOTERO_API_KEY": API_KEY,
        "ZOTERO_SYNC_TARGET_FOLDER": TARGET_FOLDER_RAW,
    }.items() if not value]

    if missing_env:
        raise RuntimeError(
            f"Defina as variáveis de ambiente obrigatórias ({', '.join(missing_env)}). "
            "Use ~/.config/zotero_sync_webdav/zotero_sync.env, um .env na raiz do projeto, "
            "ZOTERO_ENV_FILE ou exporte-as antes de executar."
        )

def resolve_target_folder(raw_path: str | None) -> str:
    """Resolve o caminho da pasta alvo, tentando decodificar espaços/percent-encoding."""
    if not raw_path:
        return ""
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

def get_target_folder() -> str:
    check_environment_requirements()
    return TARGET_FOLDER


# Pasta onde o Zotero Desktop espera encontrar os anexos importados.
# Esta cópia local em ~/Zotero/storage é necessária para o workflow prático do projeto:
# sem ela, o script perde a referência de conteúdo usada para comparar hashes,
# reconstruir anexos locais ausentes e decidir renomeações entre drive e Zotero.
LOCAL_COPY_DIR = os.path.join(os.path.expanduser("~"), "Zotero", "storage")

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "zotero_sync_webdav")
CACHE_FILE = os.path.join(CACHE_DIR, "hash_cache.json")
CACHE_VERSION = 1

REVIEW_DUPLICATE_TAG = "zotero-sync: revisar duplicata"
ZOTERO_READONLY_UPDATE_FIELDS = {"lastRead", "dateAdded", "dateModified", "library"}
PENDING_QUEUE_NOTIFICATION_SUMMARY = "Zotero fechado"
COMPLETION_NOTIFICATION_SUMMARY = "Sync concluído"

LOG_DIR = os.path.join(CACHE_DIR, "logs")
LOG_FILE_NAME = "zotero_sync_today.log"
SYNC_PROGRESS_NOTIFICATION_SUMMARY = "Sync em andamento"
PENDING_IMPORTS_LOG_FILE_NAME = "zotero_pending_imports_today.log"
PENDING_IMPORTS_LOG_DATE_FILE = os.path.join(LOG_DIR, ".last_pending_imports_log_date")
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
HASH_READ_TIMEOUT_SECONDS_DEFAULT = 30
CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT = 60
PYZOTERO_UPLOAD_TIMEOUT_SECONDS_DEFAULT = 900


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

def get_env_bool(name: str, default: bool) -> bool:
    """Lê booleano de ambiente com fallback seguro."""
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on", "sim"}:
        return True
    if normalized in {"0", "false", "no", "off", "nao", "não"}:
        return False
    logging.warning("Valor inválido para %s=%r. Usando %s.", name, raw_value, default)
    return default


def resolve_desktop_recognizer_plugin_dir(
    script_dir: Path,
    shared_data_dir: Path | None = None,
    configured_dir: str | None = None,
) -> Path:
    """Resolve os assets do plugin tanto no checkout quanto na instalação do usuário."""
    shared_data_dir = shared_data_dir or Path.home() / ".local" / "share" / "zotero_sync_webdav"
    candidates = [
        Path(configured_dir).expanduser() if configured_dir else None,
        script_dir / "zotero_sync_recognizer",
        shared_data_dir / "zotero_sync_recognizer",
    ]
    for candidate in candidates:
        if candidate and candidate.is_dir():
            return candidate
    return script_dir / "zotero_sync_recognizer"


def stage_desktop_recognizer_assets() -> Path | None:
    """Instala os assets do plugin em local estável para o script copiado em ~/.local/bin."""
    source = SCRIPT_DIR / "zotero_sync_recognizer"
    destination = Path.home() / ".local" / "share" / "zotero_sync_webdav" / "zotero_sync_recognizer"
    if not source.is_dir():
        return None
    if source.resolve() != destination.resolve():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    return destination


def resolve_zotero_desktop_binary(
    configured_binary: str | None = None,
    path_binary: str | None = None,
    home_dir: Path | None = None,
) -> str:
    """Resolve o binário do Zotero também no PATH reduzido de serviços systemd."""
    if configured_binary:
        return configured_binary
    if path_binary:
        return path_binary
    local_binary = (home_dir or Path.home()) / ".local" / "bin" / "zotero"
    return str(local_binary) if local_binary.is_file() else ""




HASH_READ_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_HASH_TIMEOUT_SECONDS",
    HASH_READ_TIMEOUT_SECONDS_DEFAULT,
)
CONTENT_PROBE_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_CONTENT_PROBE_TIMEOUT_SECONDS",
    CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT,
)
PYZOTERO_UPLOAD_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_UPLOAD_TIMEOUT_SECONDS",
    PYZOTERO_UPLOAD_TIMEOUT_SECONDS_DEFAULT,
)

ZOTERO_PROFILE_ROOT = Path.home() / ".zotero" / "zotero"
ZOTERO_DESKTOP_BINARY = resolve_zotero_desktop_binary(
    os.environ.get("ZOTERO_DESKTOP_BINARY"),
    shutil.which("zotero"),
)
ZOTERO_DESKTOP_CONNECTOR_URL = os.environ.get(
    "ZOTERO_DESKTOP_CONNECTOR_URL",
    "http://127.0.0.1:23119",
).rstrip("/")
ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_ID = "zotero-sync-recognizer@example.com"
ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_DIR = resolve_desktop_recognizer_plugin_dir(
    SCRIPT_DIR,
    configured_dir=os.environ.get("ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_DIR"),
)
ZOTERO_DESKTOP_RECOGNIZER_PING_URL = (
    f"{ZOTERO_DESKTOP_CONNECTOR_URL}/zoteroSyncRecognize/ping"
)
ZOTERO_DESKTOP_RECOGNIZER_RECOGNIZE_URL = (
    f"{ZOTERO_DESKTOP_CONNECTOR_URL}/zoteroSyncRecognize/recognize"
)
ZOTERO_DESKTOP_RECOGNIZER_IMPORT_URL = (
    f"{ZOTERO_DESKTOP_CONNECTOR_URL}/zoteroSyncRecognize/import"
)
ZOTERO_DESKTOP_RECOGNITION_ENABLED = get_env_bool(
    "ZOTERO_DESKTOP_RECOGNITION_ENABLED",
    True,
)
ZOTERO_DESKTOP_START_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_DESKTOP_START_TIMEOUT_SECONDS",
    45,
)
ZOTERO_DESKTOP_RECOGNIZE_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_DESKTOP_RECOGNIZE_TIMEOUT_SECONDS",
    900,
)


def configure_pyzotero_upload_transport(
    timeout_seconds: int = PYZOTERO_UPLOAD_TIMEOUT_SECONDS,
) -> None:
    """Ajusta timeouts e exceções do upload Pyzotero/httpx para arquivos grandes.

    Pyzotero 1.7.3 chama `httpx.post(...)` diretamente no upload S3 usando o
    timeout padrão do httpx. Esse padrão é curto para PDFs grandes e pode gerar
    `WriteTimeout`. Além disso, essa versão tenta capturar `httpx.ConnectionError`,
    atributo que não existe em httpx 0.28.1, mascarando o erro real com
    `module 'httpx' has no attribute 'ConnectionError'`.
    """
    httpx_module = zotero.httpx

    if not hasattr(httpx_module, "ConnectionError"):
        httpx_module.ConnectionError = httpx_module.TransportError
        logging.info(
            "[ZOT-UPLOAD] Compatibilidade aplicada: httpx.ConnectionError -> httpx.TransportError."
        )

    if getattr(httpx_module, "_zotero_sync_webdav_post_patched", False):
        return

    original_post = httpx_module.post

    def post_with_upload_timeout(*args, **kwargs):
        if "timeout" not in kwargs:
            if timeout_seconds > 0:
                kwargs["timeout"] = httpx_module.Timeout(
                    timeout_seconds,
                    connect=min(timeout_seconds, 30),
                    read=timeout_seconds,
                    write=timeout_seconds,
                    pool=timeout_seconds,
                )
            else:
                kwargs["timeout"] = None
        return original_post(*args, **kwargs)

    httpx_module.post = post_with_upload_timeout
    httpx_module._zotero_sync_webdav_post_patched = True
    logging.info(
        "[ZOT-UPLOAD] Timeout padrão para upload Pyzotero configurado em %ss.",
        timeout_seconds if timeout_seconds > 0 else "sem limite",
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


def send_desktop_notification(
    summary: str,
    body: str,
    icon: str = "zotero",
    desktop_hint: str | None = None,
) -> bool:
    """Envia notificação por notify-send, com fallback para gdbus."""
    if shutil.which("notify-send"):
        cmd = ["notify-send", "-a", "Zotero Sync", "-i", icon]
        if desktop_hint:
            cmd.extend(["-h", f"string:desktop-entry:{desktop_hint}"])
        cmd.extend([summary, body])
        try:
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                return True
        except Exception as exc:
            logging.warning("[NOTIFY] Falha ao enviar via notify-send: %s", exc)

    if shutil.which("gdbus"):
        cmd = [
            "gdbus",
            "call",
            "--session",
            "--dest",
            "org.freedesktop.Notifications",
            "--object-path",
            "/org/freedesktop/Notifications",
            "--method",
            "org.freedesktop.Notifications.Notify",
            "Zotero Sync",
            "0",
            icon,
            summary,
            body,
            "[]",
            "{}",
            "5000",
        ]
        try:
            result = subprocess.run(cmd, check=False)
            if result.returncode == 0:
                return True
        except Exception as exc:
            logging.warning("[NOTIFY] Falha ao enviar via gdbus: %s", exc)

    logging.debug("[NOTIFY] Nenhum backend de notificação disponível.")
    return False


def build_pending_queue_notification_body(pending_count: int) -> str:
    """Monta texto da notificação quando Zotero Desktop está fechado."""
    if pending_count == 1:
        return "1 PDF novo está na fila. Abra o Zotero para sincronizá-lo."
    return f"{pending_count} PDFs novos estão na fila. Abra o Zotero para sincronizá-los."


def build_first_open_sync_notification_body() -> str:
    """Monta texto da primeira sync disparada ao abrir o Zotero."""
    return "Zotero aberto detectado. Primeira sync iniciada."


def build_sync_stage_notification_body(stage_name: str) -> str:
    """Monta texto de progresso de etapa da sync."""
    return f"Etapa: {stage_name}."


def send_sync_progress_notification(body: str) -> None:
    """Envia notificação de progresso de sync."""
    send_desktop_notification(SYNC_PROGRESS_NOTIFICATION_SUMMARY, body, icon="zotero")


def update_pending_import_queue_files(pending: list[str]) -> None:
    """Mantém fila pendente em log diário, sem sidecar txt."""
    pending_log = os.path.join(LOG_DIR, PENDING_IMPORTS_LOG_FILE_NAME)
    legacy_pending_file = os.path.join(LOG_DIR, "zotero_pending_imports.txt")
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        if os.path.exists(legacy_pending_file):
            os.remove(legacy_pending_file)
        if not pending:
            for path in (pending_log, PENDING_IMPORTS_LOG_DATE_FILE):
                if os.path.exists(path):
                    os.remove(path)
            return

        today = datetime.now().strftime("%Y-%m-%d")
        now = datetime.now()
        header_needed = True
        if os.path.exists(PENDING_IMPORTS_LOG_DATE_FILE):
            try:
                header_needed = Path(PENDING_IMPORTS_LOG_DATE_FILE).read_text(encoding="utf-8") != today
            except OSError:
                header_needed = True
        mode = "w" if header_needed else "a"
        with open(pending_log, mode, encoding="utf-8") as fh:
            if header_needed:
                fh.write(f"# Log diário da fila do Zotero fechado - {today}\n")
            fh.write(f"--- Fila atualizada: {now.isoformat()} ---\n")
            fh.write(f"Pendentes: {len(pending)}\n")
            for item in pending:
                fh.write(f"- {item}\n")
        Path(PENDING_IMPORTS_LOG_DATE_FILE).write_text(today, encoding="utf-8")
        send_desktop_notification(
            PENDING_QUEUE_NOTIFICATION_SUMMARY,
            build_pending_queue_notification_body(len(pending)),
            icon="zotero",
        )
    except Exception as exc:
        logging.warning("[FILA] Erro ao atualizar lista de pendentes: %s", exc)


def build_completion_notification_body(stats: dict, log_path: str | None) -> str:
    """Monta o corpo da notificação de conclusão."""
    body_parts = [
        f"Adicionados: {stats.get('added', 0)}",
        f"Existentes: {stats.get('skipped', 0)}",
    ]
    if stats.get('errors', 0) > 0:
        body_parts.append(f"Erros: {stats.get('errors', 0)}")
    pending_count = len(stats.get('pending_desktop_imports', []))
    if pending_count > 0:
        body_parts.append(f"Fila: {pending_count}")
    review_count = max(
        int(stats.get('review_tags_applied', 0) or 0),
        int(stats.get('blocked_duplicate_risk', 0) or 0),
        int(stats.get('auto_duplicate_cleanup_skipped', 0) or 0),
    )
    body = " • ".join(body_parts)
    if review_count > 0:
        body += (
            f"\nRevisar duplicatas: {review_count}. "
            f"Abra o Zotero e pesquise a tag '{REVIEW_DUPLICATE_TAG}'."
        )
    if log_path:
        body += "\nClique para abrir o log de hoje."
    return body


def send_completion_notification(stats: dict, log_path: str | None) -> None:
    """Envia notificação sobre a execução e oferece abertura rápida do log."""
    desktop_hint = ensure_log_desktop_entry(log_path) if log_path else None
    send_desktop_notification(
        COMPLETION_NOTIFICATION_SUMMARY,
        build_completion_notification_body(stats, log_path),
        icon="text-x-log",
        desktop_hint=desktop_hint,
    )


def finalize_execution(
    stats: dict,
    summary_text: str | None = None,
    notify_completion: bool = True,
) -> None:
    """Atualiza o log diário e dispara a notificação."""
    global _HEADLESS_ZOTERO_PROC
    if '_HEADLESS_ZOTERO_PROC' in globals() and _HEADLESS_ZOTERO_PROC is not None:
        logging.info("[DESKTOP] Sincronização concluída. Encerrando Zotero invisível...")
        try:
            _HEADLESS_ZOTERO_PROC.terminate()
            _HEADLESS_ZOTERO_PROC.wait(timeout=5)
        except Exception:
            _HEADLESS_ZOTERO_PROC.kill()
        _HEADLESS_ZOTERO_PROC = None

    update_pending_import_queue_files(stats.get('pending_desktop_imports', []))

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

    if notify_completion:
        send_completion_notification(stats, LOG_FILE_PATH)


# Logging de configuração movido para load_config() para import-safety.


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


def get_attachment_file_path(item: dict) -> str | None:
    """Resolve o caminho local de um anexo a partir do campo path."""
    data = item.get('data', {})
    path = data.get('path')
    if not path:
        return None
    path_str = str(path).strip()
    if not path_str:
        return None
    if path_str.startswith("storage:"):
        filename = path_str.split(":", 1)[-1]
        key = item.get('key') or data.get('key')
        if not key or not filename:
            return None
        return os.path.join(LOCAL_COPY_DIR, key, filename)
    if path_str.startswith("file:///"):
        path_str = path_str[8:]
    elif path_str.startswith("file://"):
        path_str = path_str[7:]
    elif path_str.startswith("file:"):
        path_str = path_str[5:]
    return os.path.abspath(unquote(path_str))


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

def normalize_bibliographic_text(value: str) -> str:
    """Normaliza texto bibliográfico para comparação conservadora de títulos."""
    if not value:
        return ""
    try:
        decomposed = unicodedata.normalize('NFD', str(value))
        without_accents = "".join(
            char for char in decomposed if not unicodedata.combining(char)
        )
        lowered = without_accents.lower()
        alnum_only = re.sub(r'[^a-z0-9]+', ' ', lowered)
        return re.sub(r'\s+', ' ', alnum_only).strip()
    except Exception as exc:
        logging.warning("[BIB] Erro ao normalizar texto bibliográfico %r: %s", value, exc)
        return ""


def normalize_doi(value: str | None) -> str:
    """Normaliza DOI para chave estável de comparação bibliográfica."""
    if not value:
        return ""
    doi = str(value).strip().lower()
    for prefix in ("https://doi.org/", "http://doi.org/", "doi:"):
        if doi.startswith(prefix):
            doi = doi[len(prefix):]
    return doi.strip()

INVALID_FILENAME_CHARS_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
CANONICAL_FILENAME_MAX_BYTES = 240
CANONICAL_TITLE_MAX_BYTES = 180
AUTHOR_CREATOR_TYPES = {
    'author',
    'bookAuthor',
    'podcaster',
    'programmer',
    'cartographer',
    'presenter',
    'interviewee',
}



COPY_PREFIX_RE = re.compile(r'^\s*(?:c[oó]pia\s+de|copy\s+of)\s+', re.IGNORECASE)
COPY_NUMBER_SUFFIX_RE = re.compile(r'(?:\s*\(\d+\))\s*$')


def canonical_duplicate_stem(stem: str) -> str:
    """Remove marcadores comuns de cópia sem tratar o resultado como metadado final."""
    cleaned = (stem or "").strip()
    previous = None
    while cleaned and previous != cleaned:
        previous = cleaned
        cleaned = COPY_PREFIX_RE.sub('', cleaned).strip()
    cleaned = COPY_NUMBER_SUFFIX_RE.sub('', cleaned).strip()
    return re.sub(r'\s+', ' ', cleaned).strip(" -_.")


def canonical_duplicate_filename(filename: str) -> str:
    """Retorna o nome sem marcadores como 'Cópia de' ou '(1)'."""
    basename = os.path.basename(filename or "")
    if not basename:
        return ""
    suffix = ''.join(Path(basename).suffixes)
    if suffix:
        stem = basename[:-len(suffix)]
    else:
        stem = basename
    canonical_stem = canonical_duplicate_stem(stem)
    return f"{canonical_stem}{suffix}" if canonical_stem else basename


def duplicate_name_key(filename: str) -> str:
    """Chave agressiva para comparar nomes após remoção de marcadores de cópia."""
    return normalize_aggressive(canonical_duplicate_filename(filename))


def is_copy_variant_filename(filename: str) -> bool:
    """Identifica nomes gerados por cópia do gerenciador de arquivos ou do drive."""
    if not filename:
        return False
    return duplicate_name_key(filename) != normalize_aggressive(os.path.basename(filename))


def choose_non_copy_canonical_name(left_name: str, right_name: str) -> str | None:
    """Escolhe o nome sem marcador de cópia quando dois nomes representam o mesmo conteúdo."""
    left_is_copy = is_copy_variant_filename(left_name)
    right_is_copy = is_copy_variant_filename(right_name)
    if left_is_copy == right_is_copy:
        return None
    return right_name if left_is_copy else left_name

def truncate_utf8(value: str, max_bytes: int) -> str:
    """Trunca texto sem cortar sequência UTF-8 no meio."""
    if len(value.encode('utf-8')) <= max_bytes:
        return value
    encoded = value.encode('utf-8')[:max_bytes]
    return encoded.decode('utf-8', errors='ignore').rstrip()


def sanitize_filename_component(value: str, max_bytes: int) -> str:
    """Normaliza um componente de nome de arquivo preservando texto legível."""
    if not value:
        return ""
    normalized = unicodedata.normalize('NFC', str(value))
    normalized = INVALID_FILENAME_CHARS_RE.sub(' ', normalized)
    normalized = normalized.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    normalized = re.sub(r'\s+', ' ', normalized).strip(" .-_")
    normalized = canonical_duplicate_stem(normalized)
    return truncate_utf8(normalized, max_bytes).strip(" .-_")


def creator_surname(creator: dict) -> str:
    """Extrai sobrenome de um creator Zotero."""
    last_name = sanitize_filename_component(creator.get('lastName') or '', 48)
    if last_name:
        return last_name
    full_name = sanitize_filename_component(creator.get('name') or '', 80)
    if not full_name:
        return ""
    if ',' in full_name:
        return sanitize_filename_component(full_name.split(',', 1)[0], 48)
    parts = [part for part in full_name.split() if part]
    return sanitize_filename_component(parts[-1], 48) if parts else ""


def primary_creator_surname(item_data: dict) -> str:
    """Escolhe o sobrenome principal para o padrão 'título - sobrenome ano'."""
    creators = item_data.get('creators') or []
    preferred = [
        creator for creator in creators
        if creator.get('creatorType') in AUTHOR_CREATOR_TYPES
    ]
    for creator in preferred or creators:
        surname = creator_surname(creator)
        if surname:
            return surname
    return ""


def extract_bibliographic_year(item_data: dict) -> str:
    """Extrai o primeiro ano bibliográfico plausível dos campos do item."""
    for field in ('date', 'dateEnacted', 'issueDate', 'filingDate'):
        value = item_data.get(field)
        if not value:
            continue
        match = re.search(r'\b((?:18|19|20)\d{2})\b', str(value))
        if match:
            return match.group(1)
    return ""


def canonical_parent_pdf_filename(parent_item: dict | None) -> str | None:
    """Gera 'título - sobrenome ano.pdf' a partir do item bibliográfico pai."""
    if not parent_item:
        return None
    data = parent_item.get('data', parent_item)
    title = sanitize_filename_component(data.get('title') or '', CANONICAL_TITLE_MAX_BYTES)
    if not title:
        return None
    surname = primary_creator_surname(data)
    year = extract_bibliographic_year(data)
    suffix = " ".join(part for part in (surname, year) if part)
    if not suffix:
        return None
    stem = sanitize_filename_component(f"{title} - {suffix}", CANONICAL_FILENAME_MAX_BYTES - len('.pdf'))
    if not stem:
        return None
    return f"{stem}.pdf"


def canonical_standalone_attachment_filename(item: dict) -> str | None:
    """Remove marcadores de cópia de anexos PDF standalone sem inventar metadados."""
    data = item.get('data', {})
    if data.get('parentItem') or not attachment_is_pdf(item):
        return None
    current_name = os.path.basename(get_filename_from_item(item) or data.get('title') or '')
    if not current_name:
        return None
    if not current_name.lower().endswith('.pdf'):
        current_name = f"{current_name}.pdf"
    desired = canonical_duplicate_filename(current_name)
    return desired if desired and desired != current_name else None



def filename_title_candidates(filename: str) -> List[str]:
    """Gera candidatos de título a partir de um nome de PDF no padrão Zotero."""
    stem = Path(os.path.basename(filename)).stem
    duplicate_stem = Path(canonical_duplicate_filename(filename)).stem
    raw_variants: list[str] = [stem, duplicate_stem]

    def clean(value: str) -> str:
        value = value.replace("_", " ")
        value = re.sub(r'\s*\(\d+\)\s*$', '', value)
        value = re.sub(r'(\b(?:18|19|20)\d{2})\s+\d+\s*$', r'\1', value)
        value = re.sub(r'\s+', ' ', value)
        return value.strip(" -_.")

    cleaned = clean(stem)
    raw_variants.append(cleaned)

    if " - " in cleaned:
        left, right = cleaned.rsplit(" - ", 1)
        if re.search(r'\b(?:18|19|20)\d{2}\b', right) or len(right.split()) <= 4:
            raw_variants.append(left)

    without_leading_citation = re.sub(
        r'^[A-Za-zÀ-ÿ0-9 ,._&+-]+?\(\s*(?:18|19|20)\d{2}\s*\)\s+',
        '',
        cleaned,
    )
    if without_leading_citation != cleaned:
        raw_variants.append(without_leading_citation)
        if " - " in without_leading_citation:
            raw_variants.append(without_leading_citation.rsplit(" - ", 1)[0])

    candidates: list[str] = []
    seen: set[str] = set()
    for variant in raw_variants:
        normalized = normalize_bibliographic_text(clean(variant))
        if len(normalized) < 20 or normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)
    return candidates


SEQUENCE_MARKER_RE = re.compile(
    r'^(?P<base>.+?)\s+(?:(?:parte|part|volume|vol|tomo|livro|capitulo|cap|chapter)\s+)?'
    r'(?P<marker>i|ii|iii|iv|v|vi|vii|viii|ix|x|[1-9][0-9]*)$'
)


def split_terminal_sequence_marker(value: str) -> tuple[str, str] | None:
    """Separa marcador terminal de série, como I, II, III ou parte 1."""
    normalized = normalize_bibliographic_text(value)
    match = SEQUENCE_MARKER_RE.match(normalized)
    if not match:
        return None
    base = match.group('base').strip()
    marker = match.group('marker').strip()
    if len(base) < 20:
        return None
    return base, marker


def terminal_sequence_markers_conflict(left: str, right: str) -> bool:
    """Detecta títulos de uma série que diferem apenas pelo marcador final."""
    left_marker = split_terminal_sequence_marker(left)
    right_marker = split_terminal_sequence_marker(right)
    if not left_marker or not right_marker:
        return False
    return left_marker[0] == right_marker[0] and left_marker[1] != right_marker[1]


def title_match_score(candidate_title: str, item_title: str) -> float:
    """Pontua uma possível correspondência de título sem aceitar palpites fracos."""
    candidate = normalize_bibliographic_text(candidate_title)
    title = normalize_bibliographic_text(item_title)
    if len(candidate) < 20 or len(title) < 20:
        return 0.0
    if terminal_sequence_markers_conflict(candidate, title):
        return 0.0


    if candidate == title:
        return 1.0

    if title.startswith(candidate):
        coverage = len(candidate) / len(title)
        if len(candidate) >= 35 or coverage >= 0.55:
            return min(0.95, 0.78 + (coverage * 0.17))

    if candidate.startswith(title):
        coverage = len(title) / len(candidate)
        if len(title) >= 35 or coverage >= 0.55:
            return min(0.94, 0.78 + (coverage * 0.16))

    if (candidate in title or title in candidate) and min(len(candidate), len(title)) >= 30:
        return 0.85

    ratio = SequenceMatcher(None, candidate, title).ratio()
    if ratio >= 0.92:
        return ratio
    return 0.0


def bibliographic_item_entry(item: dict) -> dict | None:
    """Converte um item bibliográfico Zotero em entrada pesquisável para parent matching."""
    data = item.get('data', {})
    if data.get('itemType') == 'attachment':
        return None
    title = data.get('title') or ''
    normalized_title = normalize_bibliographic_text(title)
    if len(normalized_title) < 20:
        return None
    return {
        'key': item.get('key') or data.get('key'),
        'title': title,
        'normalized_title': normalized_title,
        'doi': normalize_doi(data.get('DOI')),
        'itemType': data.get('itemType'),
        'dateAdded': data.get('dateAdded'),
        'dateModified': data.get('dateModified'),
        'collections': list(data.get('collections') or []),
        'tags': list(data.get('tags') or []),
        'relations': dict(data.get('relations') or {}),
        'item': item,
    }


def build_bibliographic_parent_index(items: List[dict]) -> List[dict]:
    """Cria índice de itens bibliográficos que podem receber anexos novos."""
    entries: list[dict] = []
    seen_keys: set[str] = set()
    for item in items:
        entry = bibliographic_item_entry(item)
        key = entry.get('key') if entry else None
        if not entry or not key or key in seen_keys:
            continue
        seen_keys.add(key)
        entries.append(entry)
    return entries


def find_parent_candidates_for_pdf(
    filename: str,
    parent_index: List[dict],
    min_score: float = 0.82,
) -> List[dict]:
    """Encontra itens bibliográficos candidatos a pai de um PDF novo."""
    title_candidates = filename_title_candidates(filename)
    if not title_candidates:
        return []

    matches: list[dict] = []
    for entry in parent_index:
        best_score = 0.0
        best_candidate = ""
        for candidate in title_candidates:
            score = title_match_score(candidate, entry.get('normalized_title', ''))
            if score > best_score:
                best_score = score
                best_candidate = candidate
        if best_score >= min_score:
            match = dict(entry)
            match['score'] = round(best_score, 4)
            match['matched_candidate'] = best_candidate
            matches.append(match)

    matches.sort(key=lambda match: (-match['score'], match.get('dateAdded') or '', match['key']))
    return matches


def top_parent_candidates_are_different_item_types(candidates: List[dict]) -> bool:
    """Detecta empate de título explicado por tipos bibliográficos diferentes."""
    item_types = {
        (candidate.get('itemType') or '').strip()
        for candidate in candidates
        if candidate.get('itemType')
    }
    return len(item_types) > 1


def select_parent_for_new_attachment(
    filename: str,
    parent_index: List[dict],
    tie_margin: float = 0.03,
) -> tuple[dict | None, List[dict]]:
    """Seleciona pai único e seguro para anexar PDF novo, ou bloqueia ambiguidade."""
    candidates = find_parent_candidates_for_pdf(filename, parent_index)
    if not candidates:
        return None, []

    best_score = candidates[0]['score']
    top_candidates = [
        candidate for candidate in candidates
        if best_score - candidate['score'] <= tie_margin
    ]
    if len(top_candidates) == 1:
        return top_candidates[0], candidates
    if top_parent_candidates_are_different_item_types(top_candidates):
        return None, []
    return None, candidates


def bibliographic_duplicate_identity(entry: dict) -> tuple[str, str] | None:
    """Retorna identidade conservadora para agrupar duplicatas bibliográficas."""
    doi = entry.get('doi') or ''
    if doi:
        return ('doi', doi)
    title = entry.get('normalized_title') or ''
    item_type = (entry.get('itemType') or '').strip()
    if len(title) >= 20 and item_type:
        return ('title+type', f"{item_type}:{title}")
    if len(title) >= 20:
        return ('title', title)
    return None


def build_bibliographic_duplicate_groups(parent_index: List[dict]) -> List[dict]:
    """Agrupa itens bibliográficos duplicados por DOI ou título normalizado exato."""
    grouped: dict[tuple[str, str], list[dict]] = {}
    for entry in parent_index:
        identity = bibliographic_duplicate_identity(entry)
        if not identity:
            continue
        grouped.setdefault(identity, []).append(entry)

    duplicate_groups: list[dict] = []
    for identity, entries in grouped.items():
        if len(entries) < 2:
            continue
        sorted_entries = sorted(entries, key=lambda entry: (entry.get('dateAdded') or '', entry.get('key') or ''))
        duplicate_groups.append({
            'identity': identity,
            'items': sorted_entries,
        })
    return duplicate_groups


def attachment_is_pdf(item: dict) -> bool:
    """Confirma se um child item é anexo PDF."""
    data = item.get('data', {})
    if data.get('itemType') != 'attachment':
        return False
    if data.get('linkMode') == 'imported_url':
        return False
    filename = get_filename_from_item(item)
    content_type = (data.get('contentType') or '').lower()
    return filename.lower().endswith('.pdf') or content_type == 'application/pdf'


def classify_unsafe_duplicate_child(child: dict) -> dict:
    """Classifica children que impedem limpeza automática de duplicata."""
    data = child.get('data', {})
    child_key = child.get('key') or data.get('key') or '?'
    item_type = (data.get('itemType') or '').lower()
    annotation_type = (data.get('annotationType') or '').lower()
    content_type = (data.get('contentType') or '').lower()
    link_mode = (data.get('linkMode') or '').lower()

    if item_type == 'note':
        return {'key': child_key, 'reason': 'note', 'label': 'nota'}
    if item_type == 'annotation':
        if annotation_type == 'highlight':
            return {'key': child_key, 'reason': 'highlight', 'label': 'highlight'}
        if annotation_type:
            return {
                'key': child_key,
                'reason': f'annotation:{annotation_type}',
                'label': f'anotação {annotation_type}',
            }
        return {'key': child_key, 'reason': 'annotation', 'label': 'anotação'}
    if item_type == 'attachment' and (link_mode == 'imported_url' or content_type == 'text/html'):
        return {'key': child_key, 'reason': 'snapshot', 'label': 'snapshot HTML'}
    if item_type == 'attachment':
        return {'key': child_key, 'reason': 'non_pdf_attachment', 'label': 'anexo não-PDF'}
    if item_type:
        return {'key': child_key, 'reason': f'child:{item_type}', 'label': f'child {item_type}'}
    return {'key': child_key, 'reason': 'unknown_child', 'label': 'child desconhecido'}


def describe_unsafe_duplicate_children(summary: dict) -> str:
    """Explica por que children do item duplicado bloqueiam a deleção."""
    details = summary.get('unsafe_child_details') or []
    if not details:
        return ""
    labels: list[str] = []
    seen: set[str] = set()
    for detail in details:
        label = detail.get('label') or 'child preservado'
        if label in seen:
            continue
        seen.add(label)
        labels.append(label)
    if len(labels) == 1:
        return f"item duplicado tem {labels[0]} filho"
    return f"item duplicado tem filhos preservados: {', '.join(labels)}"


def summarize_duplicate_children(
    children: List[dict],
    key_to_path: Dict[str, str] | None = None,
) -> dict:
    """Resume children de item duplicado sem permitir deleção quando há dados únicos."""
    key_to_path = key_to_path or {}
    summary = {
        'pdf_hashes': set(),
        'pdf_filenames': [],
        'unsafe_children': [],
        'unsafe_child_details': [],
        'missing_hash_attachments': [],
    }

    for child in children:
        data = child.get('data', {})
        child_key = child.get('key') or data.get('key')
        if not attachment_is_pdf(child):
            unsafe_detail = classify_unsafe_duplicate_child(child)
            summary['unsafe_children'].append(unsafe_detail['key'])
            summary['unsafe_child_details'].append(unsafe_detail)
            continue

        filename = get_filename_from_item(child)
        summary['pdf_filenames'].append(filename)
        local_path = key_to_path.get(child_key) if child_key else None
        if not local_path:
            local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, child_key)) if child_key else None
        if not local_path or not os.path.exists(local_path):
            summary['missing_hash_attachments'].append(child_key or filename or '?')
            continue
        file_hash = compute_sha256(local_path)
        if file_hash:
            summary['pdf_hashes'].add(file_hash)
        else:
            summary['missing_hash_attachments'].append(child_key or filename or '?')

    return summary


def _entry_timestamp(entry: dict) -> float:
    parsed = parse_zotero_date(entry.get('dateAdded') or '')
    return parsed.timestamp() if parsed else float('inf')


def choose_bibliographic_duplicate_keeper(
    entries: List[dict],
    child_summaries: Dict[str, dict],
) -> dict:
    """Escolhe item mestre preservando PDFs antes de preferir antiguidade."""
    def score(entry: dict) -> tuple[int, int, float, str]:
        summary = child_summaries.get(entry.get('key'), {})
        has_pdf = 1 if summary.get('pdf_hashes') else 0
        has_non_copy_pdf = 1 if any(
            not is_copy_variant_filename(filename)
            for filename in summary.get('pdf_filenames', [])
        ) else 0
        return (has_pdf, has_non_copy_pdf, -_entry_timestamp(entry), entry.get('key') or '')

    return max(entries, key=score)

def duplicate_summary_has_child_content(summary: dict) -> bool:
    """Indica se o item duplicado tem algum child que precisa ser preservado."""
    return bool(
        summary.get('pdf_hashes')
        or summary.get('pdf_filenames')
        or summary.get('unsafe_child_details')
        or summary.get('unsafe_children')
        or summary.get('missing_hash_attachments')
    )


def duplicate_item_can_be_deleted(
    duplicate_entry: dict,
    keeper_entry: dict,
    duplicate_summary: dict,
    keeper_summary: dict,
) -> tuple[bool, str]:
    """Decide se uma duplicata bibliográfica pode ser apagada sem perder conteúdo."""
    duplicate_has_child_content = duplicate_summary_has_child_content(duplicate_summary)
    keeper_has_child_content = duplicate_summary_has_child_content(keeper_summary)
    if not duplicate_has_child_content and (
        keeper_has_child_content
        or (
            duplicate_entry.get('doi')
            and duplicate_entry.get('doi') == keeper_entry.get('doi')
        )
    ):
        return True, "item duplicado sem anexos"

    if duplicate_entry.get('relations'):
        return False, "item duplicado tem relações Zotero"
    unsafe_reason = describe_unsafe_duplicate_children(duplicate_summary)
    if unsafe_reason:
        return False, unsafe_reason
    if duplicate_summary.get('missing_hash_attachments'):
        return False, "não foi possível validar hash de todos os anexos PDF"

    duplicate_hashes = set(duplicate_summary.get('pdf_hashes') or set())
    keeper_hashes = set(keeper_summary.get('pdf_hashes') or set())
    if not duplicate_entry.get('doi') and not duplicate_hashes and not keeper_hashes:
        return False, "duplicata por título sem DOI nem PDF redundante validado"
    if duplicate_hashes and not duplicate_hashes.issubset(keeper_hashes):
        return False, "item duplicado tem PDF não redundante no mestre"
    return True, "seguro"

def merge_duplicate_metadata_into_keeper(
    zot: zotero.Zotero,
    keeper_entry: dict,
    duplicate_entry: dict,
) -> bool:
    """Preserva coleções, tags e relações da duplicata antes de apagá-la."""
    keeper_item = keeper_entry.get('item')
    if not keeper_item:
        return True

    data = dict(keeper_item.get('data') or keeper_item)
    changed = False

    current_collections = list(data.get('collections') or [])
    merged_collections = sorted(set(current_collections) | set(duplicate_entry.get('collections') or []))
    if merged_collections != current_collections:
        data['collections'] = merged_collections
        changed = True

    current_tags = list(data.get('tags') or [])
    by_tag = {tag.get('tag'): tag for tag in current_tags if tag.get('tag')}
    for tag in duplicate_entry.get('tags') or []:
        tag_name = tag.get('tag')
        if tag_name and tag_name not in by_tag:
            by_tag[tag_name] = tag
            changed = True
    if changed:
        data['tags'] = list(by_tag.values())

    current_relations = dict(data.get('relations') or {})
    merged_relations = {key: value for key, value in current_relations.items()}
    for predicate, duplicate_value in (duplicate_entry.get('relations') or {}).items():
        if not predicate or not duplicate_value:
            continue
        current_value = merged_relations.get(predicate)
        if not current_value:
            merged_relations[predicate] = duplicate_value
            changed = True
            continue
        current_values = current_value if isinstance(current_value, list) else [current_value]
        duplicate_values = duplicate_value if isinstance(duplicate_value, list) else [duplicate_value]
        combined = list(current_values)
        for value in duplicate_values:
            if value not in combined:
                combined.append(value)
                changed = True
        merged_relations[predicate] = combined if len(combined) > 1 else combined[0]
    if changed:
        data['relations'] = merged_relations
        if keeper_item.get('data') is not None:
            keeper_item['data'] = data
        zot.update_item(data)
    return True


def sanitize_zotero_update_payload(item_data: dict) -> dict:
    """Remove campos somente leitura antes de chamar zot.update_item()."""
    return {
        key: value
        for key, value in item_data.items()
        if key not in ZOTERO_READONLY_UPDATE_FIELDS
    }

def record_current_review_duplicate(stats: dict, item_key: str) -> None:
    """Registra item que ainda precisa manter tag de revisão nesta execução."""
    if item_key:
        stats.setdefault('current_review_duplicate_keys', set()).add(item_key)


def remove_review_tag_from_item(
    zot: zotero.Zotero,
    item_key: str,
    item: dict | None = None,
    tag_name: str = REVIEW_DUPLICATE_TAG,
) -> bool:
    """Remove a tag de revisão quando o item deixou de bater como duplicado."""
    if not item_key:
        return False
    try:
        current_item = item if item and item.get("data") else zot.item(item_key)
        item_data = dict(current_item.get("data") or current_item)
        tags = list(item_data.get("tags") or [])
        kept_tags = [
            tag for tag in tags
            if not (isinstance(tag, dict) and tag.get("tag") == tag_name)
        ]
        if len(kept_tags) == len(tags):
            return False
        item_data["tags"] = kept_tags
        zot.update_item(sanitize_zotero_update_payload(item_data))
        if item is not None:
            item.setdefault("data", {})["tags"] = kept_tags
        logging.info("[TAG] Item %s deixou de bater como duplicado; tag '%s' removida.", item_key, tag_name)
        return True
    except Exception as exc:
        logging.warning("[TAG] Falha ao remover tag de revisão do item %s: %s", item_key, exc)
        return False


def clear_stale_review_duplicate_tags(
    zot: zotero.Zotero,
    parent_index: List[dict],
    stats: dict,
    tag_name: str = REVIEW_DUPLICATE_TAG,
) -> None:
    """Remove tags antigas dos itens que não foram marcados como risco nesta execução."""
    current_keys = stats.setdefault('current_review_duplicate_keys', set())
    stats.setdefault('review_tags_removed', 0)
    for entry in parent_index:
        item_key = entry.get('key')
        if not item_key or item_key in current_keys:
            continue
        tags = ((entry.get('item') or {}).get('data') or {}).get('tags') or []
        if not any(isinstance(tag, dict) and tag.get("tag") == tag_name for tag in tags):
            continue
        if remove_review_tag_from_item(zot, item_key, item=entry.get('item'), tag_name=tag_name):
            stats['review_tags_removed'] += 1



def add_review_tag_to_item(
    zot: zotero.Zotero,
    item_key: str,
    reason: str,
    item: dict | None = None,
    tag_name: str = REVIEW_DUPLICATE_TAG,
) -> bool:
    """Marca um item Zotero para revisão manual de duplicidade."""
    if not item_key:
        return False
    try:
        current_item = item if item and item.get("data") else zot.item(item_key)
        item_data = dict(current_item.get("data") or current_item)
        tags = list(item_data.get("tags") or [])
        if any(tag.get("tag") == tag_name for tag in tags if isinstance(tag, dict)):
            return False
        tags.append({"tag": tag_name})
        item_data["tags"] = tags
        zot.update_item(sanitize_zotero_update_payload(item_data))
        if item is not None:
            item.setdefault("data", {})["tags"] = tags
        logging.info("[TAG] Item %s marcado com '%s' para revisão manual: %s", item_key, tag_name, reason)
        return True
    except Exception as exc:
        logging.warning("[TAG] Falha ao marcar item %s para revisão manual: %s", item_key, exc)
        return False


def collect_all_pdfs(directory: str, stats: dict) -> List[str]:
    """Retorna todos os PDFs da pasta, incluindo subpastas, ordenados do mais recente ao mais antigo."""
    logging.info("[SCAN] Iniciando varredura recursiva de PDFs em %s", directory)

    entries: List[Tuple[float, str]] = []

    try:
        for root, dirnames, filenames in os.walk(directory):
            dirnames[:] = [name for name in dirnames if name not in {'.git', '.obsidian', '__pycache__'}]
            for name in filenames:
                if not name.lower().endswith('.pdf'):
                    continue
                file_path = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(file_path)
                except OSError as exc:
                    logging.warning("[SCAN] Não foi possível ler mtime de '%s': %s", file_path, exc)
                    continue
                entries.append((mtime, file_path))
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


def preprocess_drive_copy_variants(file_paths: List[str], stats: dict) -> List[str]:
    """Normaliza nomes com marcador de cópia antes do loop principal do sync."""
    stats.setdefault('preprocessed_drive_copy_variants', 0)
    stats.setdefault('blocked_drive_copy_variants', 0)
    seen_paths: set[str] = set()
    normalized_paths: list[str] = []
    for file_path in file_paths:
        if not file_path or not os.path.exists(file_path):
            continue
        current_path = file_path
        file_name = os.path.basename(file_path)
        if is_copy_variant_filename(file_name):
            desired_name = canonical_duplicate_filename(file_name)
            desired_path = os.path.join(os.path.dirname(file_path), desired_name)
            new_path = relocate_drive_file(file_path, desired_path, None, stats)
            if new_path != file_path:
                stats['preprocessed_drive_copy_variants'] += 1
                current_path = new_path
                logging.info(
                    "[PRE-COPY] Marcador de cópia consolidado antes do sync: '%s' -> '%s'.",
                    file_path,
                    new_path,
                )
            elif is_copy_variant_filename(os.path.basename(new_path)):
                stats['blocked_drive_copy_variants'] += 1
                logging.warning(
                    "[PRE-COPY] Não foi possível consolidar o marcador de cópia de '%s'.",
                    file_path,
                )
        if not os.path.exists(current_path):
            continue
        abs_path = os.path.abspath(current_path)
        if abs_path in seen_paths:
            continue
        seen_paths.add(abs_path)
        normalized_paths.append(current_path)
    return normalized_paths


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
                info = {
                    'original': filename,
                    'key': item['key'],
                    'dateModified': data.get('dateModified'),
                }
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

def collect_all_bibliographic_items(zot: zotero.Zotero, stats: dict) -> List[dict]:
    """Busca itens bibliográficos top-level para evitar anexos soltos duplicadores."""
    page_size = 100
    start = 0
    all_items: list[dict] = []

    logging.info("[BIB] Iniciando varredura completa de itens bibliográficos top-level.")

    while True:
        try:
            items = zot.top(
                limit=page_size,
                start=start,
                sort='dateAdded',
                direction='desc',
            )
        except Exception as exc:
            logging.error("[BIB] Falha ao obter itens bibliográficos (start=%d): %s", start, exc)
            raise

        if not items:
            break

        logging.debug("[BIB] Página recebida. start=%d | itens=%d.", start, len(items))
        for item in items:
            data = item.get('data', {})
            if data.get('itemType') == 'attachment':
                continue
            if data.get('title'):
                all_items.append(item)

        if len(items) < page_size:
            break
        start += page_size

    stats['zotero_bibliographic_scanned'] = len(all_items)
    logging.info("[BIB] Varredura concluída. Itens bibliográficos: %d.", len(all_items))
    return all_items


def extract_pdf_content_preview(key: str, filename: str, max_lines: int = 5) -> str:
    """Extrai as primeiras linhas de texto de um PDF no storage local para preview."""
    pdf_path = os.path.join(LOCAL_COPY_DIR, key, filename)
    if not os.path.isfile(pdf_path):
        return "(arquivo não encontrado no storage local)"
    try:
        result = subprocess.run(
            ["pdftotext", pdf_path, "-", "-l", "1"],
            capture_output=True, text=True, timeout=10,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if not lines:
            return "(sem texto extraível)"
        return " | ".join(lines[:max_lines])
    except FileNotFoundError:
        return "(pdftotext não instalado)"
    except Exception:
        return "(erro ao extrair texto)"


def build_duplicate_groups(attachments: List[dict]) -> List[dict]:
    """Agrupa anexos PDF duplicados por nome normalizado."""
    by_basic: Dict[str, List[dict]] = {}
    by_aggressive: Dict[str, List[dict]] = {}

    def push(bucket: Dict[str, List[dict]], norm_name: str, info: dict) -> None:
        bucket.setdefault(norm_name, []).append(info)

    for item in attachments:
        filename = get_filename_from_item(item)
        if not filename or not filename.lower().endswith('.pdf'):
            continue
        data = item.get('data', {})
        info = {
            'key': item.get('key', '?'),
            'filename': filename,
            'dateAdded': data.get('dateAdded', '?'),
            'parentItem': data.get('parentItem', ''),
        }
        norm_basic = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        if norm_basic:
            push(by_basic, norm_basic, info)
        if norm_aggressive and norm_aggressive != norm_basic:
            push(by_aggressive, norm_aggressive, info)

    groups: List[dict] = []
    seen_key_pairs: set[frozenset[str]] = set()

    def add_group(norm_name: str, items: List[dict], method: str) -> None:
        keys = frozenset(entry['key'] for entry in items)
        if len(keys) < 2 or keys in seen_key_pairs:
            return
        seen_key_pairs.add(keys)
        sorted_items = sorted(items, key=lambda entry: entry['dateAdded'])
        groups.append({
            'norm': norm_name,
            'method': method,
            'items': sorted_items,
            'keeper': sorted_items[0],
            'to_delete': sorted_items[1:],
        })

    for norm_name, items in by_basic.items():
        add_group(norm_name, items, 'nome normalizado')
    for norm_name, items in by_aggressive.items():
        add_group(norm_name, items, 'nome agressivo')

    return groups


def find_missing_drive_pdfs_in_zotero(
    attachments: List[dict],
    folder: str,
    ) -> dict:
    """Lista PDFs do drive que ainda não têm correspondência nominal no Zotero."""
    zotero_names_basic: set[str] = set()
    zotero_names_aggressive: set[str] = set()

    for item in attachments:
        filename = get_filename_from_item(item)
        if not filename:
            continue
        zotero_names_basic.add(normalize_filename(filename))
        zotero_names_aggressive.add(normalize_aggressive(filename))

    missing: List[dict] = []
    errors: List[str] = []
    if not os.path.isdir(folder):
        return {'missing': [], 'errors': [f'Pasta não encontrada: {folder}'], 'folder': folder}

    try:
        pdf_entries = [
            entry for entry in os.scandir(folder)
            if entry.is_file() and entry.name.lower().endswith('.pdf')
        ]
    except OSError as exc:
        return {'missing': [], 'errors': [f'Falha ao ler pasta {folder}: {exc}'], 'folder': folder}

    for entry in pdf_entries:
        norm_basic = normalize_filename(entry.name)
        norm_aggressive = normalize_aggressive(entry.name)
        if norm_basic in zotero_names_basic or norm_aggressive in zotero_names_aggressive:
            continue
        try:
            size_kb = entry.stat().st_size // 1024
        except OSError:
            size_kb = -1
        missing.append({'filename': entry.name, 'path': entry.path, 'size_kb': size_kb})

    return {
        'missing': missing,
        'errors': errors,
        'folder': folder,
        'total_pdfs': len(pdf_entries),
        'total_missing': len(missing),
    }


def print_diagnostic_report(duplicate_groups: List[dict], missing_result: dict) -> None:
    print(f"\n{'═'*60}")
    print('  RELATÓRIO DE DIAGNÓSTICO ZOTERO')
    print(f"{'═'*60}")

    print(f"\n{'━'*60}")
    print(f"  1. ANEXOS DUPLICADOS  ({len(duplicate_groups)} grupo(s))")
    print(f"{'━'*60}")
    if not duplicate_groups:
        print('  ✅ Nenhuma duplicata encontrada.')
    else:
        for index, group in enumerate(duplicate_groups, start=1):
            print(f"\n  Grupo #{index}  [{group['method']}]  norm='{group['norm']}'")
            for item in group['items']:
                parent = f"  parent={item['parentItem']}" if item['parentItem'] else '  (sem pai)'
                print(f"    • key={item['key']}  dateAdded={item['dateAdded']}")
                print(f"      filename='{item['filename']}'{parent}")

    print(f"\n{'━'*60}")
    print('  2. PDFs SEM CORRESPONDÊNCIA NO ZOTERO')
    print(f"     Pasta: {missing_result['folder']}")
    print(f"     Total PDFs: {missing_result.get('total_pdfs', '?')}  |  Ausentes: {missing_result.get('total_missing', '?')}")
    print(f"{'━'*60}")
    for error in missing_result.get('errors', []):
        print(f'  ⚠️  {error}')
    if not missing_result.get('missing'):
        print('  ✅ Todos os PDFs da pasta já estão no Zotero.')
    else:
        for item in missing_result['missing']:
            print(f"  • {item['filename']}  ({item['size_kb']} KB)")
            print(f"    {item['path']}")
    print(f"\n{'═'*60}\n")


def delete_attachment_keys(zot: zotero.Zotero, keys: List[str], dry_run: bool) -> tuple[int, int]:
    """Remove anexos pela chave, com dry-run opcional."""
    deleted_ok = 0
    deleted_err = 0
    for key in keys:
        if dry_run:
            print(f'    [DRY-RUN] Deletaria key={key}')
            deleted_ok += 1
            continue
        try:
            item = zot.item(key)
            zot.delete_item(item)
            print(f'    ✅ Deletado: key={key}')
            deleted_ok += 1
            time.sleep(0.3)
        except Exception as exc:
            print(f'    ❌ Falha ao deletar key={key}: {exc}')
            deleted_err += 1
    return deleted_ok, deleted_err


def run_safe_bibliographic_duplicate_cleanup(
    zot: zotero.Zotero,
    stats: dict,
    key_to_path: Dict[str, str],
) -> bool:
    """Remove automaticamente duplicatas bibliográficas comprovadamente redundantes."""
    stats.setdefault('bibliographic_duplicate_groups', 0)
    stats.setdefault('auto_removed_bibliographic_duplicates', 0)
    stats.setdefault('auto_duplicate_cleanup_skipped', 0)
    stats.setdefault('merged_duplicate_metadata', 0)
    stats.setdefault('review_tags_applied', 0)

    try:
        bibliographic_items = collect_all_bibliographic_items(zot, stats)
        parent_index = build_bibliographic_parent_index(bibliographic_items)
    except Exception as exc:
        stats['errors'] += 1
        logging.error("[DUP-BIB] Falha ao coletar itens bibliográficos para limpeza automática: %s", exc)
        return False

    groups = build_bibliographic_duplicate_groups(parent_index)
    stats['bibliographic_duplicate_groups'] = len(groups)
    if not groups:
        logging.info("[DUP-BIB] Nenhuma duplicata bibliográfica detectada para limpeza automática.")
        return False

    logging.info("[DUP-BIB] %d grupo(s) de duplicatas bibliográficas detectado(s).", len(groups))
    changed = False

    for group in groups:
        child_summaries: dict[str, dict] = {}
        failed_children = False
        for entry in group['items']:
            key = entry['key']
            try:
                children = zot.children(key)
            except Exception as exc:
                stats['errors'] += 1
                stats['auto_duplicate_cleanup_skipped'] += 1
                failed_children = True
                logging.warning("[DUP-BIB] Falha ao buscar filhos de %s: %s", key, exc)
                break
            child_summaries[key] = summarize_duplicate_children(children, key_to_path)

        if failed_children:
            continue

        keeper = choose_bibliographic_duplicate_keeper(group['items'], child_summaries)
        keeper_key = keeper['key']
        keeper_summary = child_summaries.get(keeper_key, {})
        logging.info(
            "[DUP-BIB] Grupo %s: mestre escolhido key=%s title='%s'.",
            group['identity'],
            keeper_key,
            keeper.get('title', '')[:120],
        )

        for duplicate in group['items']:
            duplicate_key = duplicate['key']
            if duplicate_key == keeper_key:
                continue

            duplicate_summary = child_summaries.get(duplicate_key, {})
            can_delete, reason = duplicate_item_can_be_deleted(
                duplicate,
                keeper,
                duplicate_summary,
                keeper_summary,
            )
            if not can_delete:
                stats['auto_duplicate_cleanup_skipped'] += 1
                record_current_review_duplicate(stats, duplicate_key)
                if add_review_tag_to_item(
                    zot,
                    duplicate_key,
                    f"duplicata bibliográfica preservada: {reason}",
                    item=duplicate.get('item'),
                ):
                    stats['review_tags_applied'] += 1
                logging.warning(
                    "[DUP-BIB] Duplicata key=%s não removida: %s.",
                    duplicate_key,
                    reason,
                )
                continue

            try:
                before_collections = set((keeper.get('item') or {}).get('data', {}).get('collections') or [])
                before_tags = {
                    tag.get('tag')
                    for tag in (keeper.get('item') or {}).get('data', {}).get('tags', [])
                    if tag.get('tag')
                }
                merge_duplicate_metadata_into_keeper(zot, keeper, duplicate)
                after_collections = set((keeper.get('item') or {}).get('data', {}).get('collections') or [])
                after_tags = {
                    tag.get('tag')
                    for tag in (keeper.get('item') or {}).get('data', {}).get('tags', [])
                    if tag.get('tag')
                }
                if before_collections != after_collections or before_tags != after_tags:
                    stats['merged_duplicate_metadata'] += 1

                zot.delete_item(duplicate['item'])
                stats['auto_removed_bibliographic_duplicates'] += 1
                changed = True
                logging.info(
                    "[DUP-BIB] Duplicata bibliográfica removida automaticamente: key=%s title='%s' | mestre=%s.",
                    duplicate_key,
                    duplicate.get('title', '')[:120],
                    keeper_key,
                )
                time.sleep(0.3)
            except Exception as exc:
                stats['errors'] += 1
                stats['auto_duplicate_cleanup_skipped'] += 1
                logging.error("[DUP-BIB] Falha ao remover duplicata key=%s: %s", duplicate_key, exc)

    return changed


def connect_zotero_client() -> zotero.Zotero:
    """Conecta na API do Zotero usando a configuração ativa."""
    check_environment_requirements()
    client = zotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
    client.key_info()
    return client

def run_diagnostic_mode() -> None:
    check_environment_requirements()
    print(f'🔗 Conectando ao Zotero (library_id={LIBRARY_ID}, type={LIBRARY_TYPE})...')
    try:
        client = connect_zotero_client()
        print('✅ Conexão OK.')
    except Exception as exc:
        raise SystemExit(f'❌ Falha na conexão: {exc}')

    print('\n📥 Buscando TODOS os anexos da biblioteca...')
    attachments, _, _ = collect_all_attachments(client, {'zotero_attachments_scanned': 0})
    print('\n🔍 Verificando duplicatas...')
    duplicate_groups = build_duplicate_groups(attachments)
    print(f"\n📂 Verificando PDFs ausentes no Zotero (pasta: {TARGET_FOLDER})...")
    missing_result = find_missing_drive_pdfs_in_zotero(attachments, TARGET_FOLDER)
    print_diagnostic_report(duplicate_groups, missing_result)



def _is_dir_empty(path: str) -> bool:
    """Verifica se um diretório está vazio (sem arquivos nem subpastas com conteúdo)."""
    try:
        for current, dirnames, filenames in os.walk(path):
            if filenames:
                return False
            # Filter out hidden/protected dirs
            dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        return True
    except OSError:
        return False


def find_empty_and_duplicate_drive_folders(
    target_folder: str,
    collection_by_key: dict[str, dict],
    path_to_key: dict[str, str],
) -> tuple[list[dict], list[dict]]:
    """Detecta pastas vazias e duplicadas no drive.

    Retorna:
        duplicate_groups: pastas com mesmo nome normalizado (pelo menos uma vazia)
        orphan_empties: pastas vazias sem coleção Zotero correspondente ou com coleção vazia
    """
    if not os.path.isdir(target_folder):
        return [], []

    protected_names = {'.obsidian', '.trash', '.git', '__pycache__'}
    entries: list[dict] = []
    for entry_name in os.listdir(target_folder):
        full_path = os.path.join(target_folder, entry_name)
        if not os.path.isdir(full_path):
            continue
        if entry_name in protected_names:
            continue
        is_empty = _is_dir_empty(full_path)
        norm_key = normalize_aggressive(entry_name)
        entries.append({
            'name': entry_name,
            'path': full_path,
            'empty': is_empty,
            'norm_key': norm_key,
        })

    # Group by normalized name to find duplicates
    from collections import defaultdict
    norm_groups: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        if entry['norm_key']:
            norm_groups[entry['norm_key']].append(entry)

    duplicate_groups: list[dict] = []
    seen_paths: set[str] = set()
    for norm_key, members in norm_groups.items():
        if len(members) < 2:
            continue
        # Check: at least one non-empty and at least one empty
        empties = [m for m in members if m['empty']]
        non_empties = [m for m in members if not m['empty']]
        if empties and non_empties:
            for e in empties:
                seen_paths.add(e['path'])
            duplicate_groups.append({
                'norm_key': norm_key,
                'keeper': non_empties[0],
                'to_delete': empties,
            })
        elif len(members) > 1 and all(m['empty'] for m in members):
            # All empty: keep the one with shorter/simpler name, delete the rest
            sorted_members = sorted(members, key=lambda m: (len(m['name']), m['name']))
            keeper = sorted_members[0]
            to_del = sorted_members[1:]
            for e in to_del:
                seen_paths.add(e['path'])
            duplicate_groups.append({
                'norm_key': norm_key,
                'keeper': keeper,
                'to_delete': to_del,
            })

    # Orphan empties: empty folders not already covered by duplicate groups
    # that have no Zotero collection OR whose Zotero collection is also empty
    orphan_empties: list[dict] = []
    for entry in entries:
        if entry['path'] in seen_paths:
            continue
        if not entry['empty']:
            continue
        # Check if this folder matches a Zotero collection
        rel = entry['name']
        rel_norm = normalize_relative_path_key(rel)
        matched_key = path_to_key.get(rel_norm)
        if matched_key:
            # Collection exists in Zotero — only delete if the collection has no items
            # We can't check item count here without an API call, so we leave it to caller
            entry['collection_key'] = matched_key
            entry['reason'] = 'empty_folder_with_collection'
        else:
            entry['reason'] = 'empty_folder_no_collection'
        orphan_empties.append(entry)

    return duplicate_groups, orphan_empties


def cleanup_empty_drive_folders(
    zot: zotero.Zotero,
    target_folder: str,
    dry_run: bool,
) -> tuple[int, int]:
    """Remove pastas duplicadas vazias e pastas órfãs vazias do drive.

    Retorna (removed_ok, skipped).
    """
    collections = fetch_zotero_collections(zot)
    collection_by_key, _children, path_to_key = build_collection_path_model(collections)

    duplicate_groups, orphan_empties = find_empty_and_duplicate_drive_folders(
        target_folder, collection_by_key, path_to_key,
    )

    removed = 0
    skipped = 0

    if duplicate_groups:
        print(f"\n{'─'*60}")
        print(f"  PASTAS DUPLICADAS NO DRIVE  ({len(duplicate_groups)} grupo(s))")
        print(f"{'─'*60}\n")
        for group in duplicate_groups:
            keeper = group['keeper']
            print(f"  Nome normalizado: '{group['norm_key']}'")
            print(f"  ✔ Mantendo: '{keeper['name']}/' ({'vazia' if keeper['empty'] else 'com conteúdo'})")
            for folder in group['to_delete']:
                print(f"  ✗ Removendo: '{folder['name']}/' (vazia)")
                if not dry_run:
                    try:
                        shutil.rmtree(folder['path'])
                        removed += 1
                        logging.info("[PASTA-DUP] Removida pasta duplicada vazia: '%s'", folder['path'])
                    except OSError as exc:
                        logging.error("[PASTA-DUP] Falha ao remover '%s': %s", folder['path'], exc)
                        skipped += 1
                else:
                    removed += 1
            print()

    # For orphan empties, check Zotero collection item count before deleting
    deletable_orphans: list[dict] = []
    for entry in orphan_empties:
        col_key = entry.get('collection_key')
        if col_key:
            # Check if the Zotero collection has items
            try:
                col_items = zot.collection_items(col_key, limit=1)
                if col_items:
                    # Collection has items — skip, the folder should exist
                    skipped += 1
                    continue
            except Exception:
                # Can't verify — skip to be safe
                skipped += 1
                continue
        deletable_orphans.append(entry)

    if deletable_orphans:
        print(f"\n{'─'*60}")
        print(f"  PASTAS VAZIAS SEM CONTEÚDO NO ZOTERO  ({len(deletable_orphans)})")
        print(f"{'─'*60}\n")
        for entry in deletable_orphans:
            reason_label = (
                'sem coleção no Zotero'
                if entry['reason'] == 'empty_folder_no_collection'
                else 'coleção Zotero também vazia'
            )
            print(f"  ✗ Removendo: '{entry['name']}/' ({reason_label})")
            if not dry_run:
                try:
                    shutil.rmtree(entry['path'])
                    removed += 1
                    logging.info("[PASTA-VAZIA] Removida pasta vazia: '%s' (%s)", entry['path'], reason_label)
                except OSError as exc:
                    logging.error("[PASTA-VAZIA] Falha ao remover '%s': %s", entry['path'], exc)
                    skipped += 1
            else:
                removed += 1

    return removed, skipped


def run_duplicate_cleanup_mode(execute: bool) -> None:
    dry_run = not execute
    mode_label = '🔍 DRY-RUN (simulação)' if dry_run else '⚠️  MODO REAL (vai deletar)'
    print(f"\n{'═'*60}")
    print(f'  REMOÇÃO DE DUPLICATAS ZOTERO  —  {mode_label}')
    print(f'  library_id={LIBRARY_ID}, type={LIBRARY_TYPE}')
    print(f"{'═'*60}\n")

    if not dry_run:
        print("⚠️  ATENÇÃO: você está prestes a deletar anexos da sua biblioteca Zotero.")
        print('   Esta operação é IRREVERSÍVEL pela API.')
        confirm = input("   Digite 'sim' para continuar: ").strip().lower()
        if confirm not in ('sim', 's', 'yes', 'y'):
            print('Operação cancelada.')
            return
        print()

    print('🔗 Conectando ao Zotero...')
    try:
        client = connect_zotero_client()
        print('✅ Conexão OK.\n')
    except Exception as exc:
        raise SystemExit(f'❌ Falha na conexão: {exc}')

    print('📥 Buscando todos os anexos...')
    attachments, _, _ = collect_all_attachments(client, {'zotero_attachments_scanned': 0})
    print('\n🔍 Detectando duplicatas de PDFs...')
    groups = build_duplicate_groups(attachments)

    total_to_delete = sum(len(group['to_delete']) for group in groups) if groups else 0

    if groups:
        print(f"\nEncontrados {len(groups)} grupo(s) de duplicatas → {total_to_delete} anexo(s) a remover.\n")
    else:
        print('\n✅ Nenhuma duplicata de PDF encontrada.')

    deleted_ok = 0
    deleted_err = 0
    for index, group in enumerate(groups, start=1):
        keeper = group['keeper']
        all_items = [keeper] + group['to_delete']
        print(f"  Grupo #{index}  [{group['method']}]")
        print(f"  Arquivo: '{keeper['filename']}'")
        # Build content preview for each item
        item_previews: dict[str, str] = {}
        for item in all_items:
            item_previews[item['key']] = extract_pdf_content_preview(item['key'], item['filename'])
        # Determine which to_delete items are true content duplicates of the keeper
        keeper_preview = item_previews[keeper['key']]
        true_duplicates = []
        different_content = []
        for item in group['to_delete']:
            if item_previews[item['key']] == keeper_preview:
                true_duplicates.append(item)
            else:
                different_content.append(item)
        has_different_content = len(different_content) > 0
        # Display all items
        for item in all_items:
            is_keeper = item['key'] == keeper['key']
            is_protected = item in different_content
            if is_keeper:
                marker = "✔ Mantendo"
            elif is_protected:
                marker = "⏭️  Protegido (conteúdo diferente)"
            else:
                marker = "✗ Removendo"
            print(
                f"  {marker}: key={item['key']}  dateAdded={item['dateAdded']}"
                f"  parent={item['parentItem'] or '(sem pai)'}"
            )
            print(f"    📄 {item_previews[item['key']]}")
        if has_different_content:
            print(
                f"  ⚠️  {len(different_content)} anexo(s) protegido(s): "
                f"mesmo nome mas conteúdo diferente do keeper."
            )
        # Only delete true duplicates
        keys_to_delete = [item['key'] for item in true_duplicates]
        if keys_to_delete:
            ok, err = delete_attachment_keys(client, keys_to_delete, dry_run=dry_run)
            deleted_ok += ok
            deleted_err += err
        elif not has_different_content:
            print("  (nada a remover)")
        print()

    print(f"\n{'═'*60}")
    if dry_run:
        print('  DRY-RUN — anexos:')
        print(f'  {deleted_ok} anexo(s) seriam deletados.')
    else:
        print(f'  Anexos: {deleted_ok} deletado(s) | {deleted_err} erro(s).')
    print(f"{'═'*60}")

    # --- Limpeza de pastas duplicadas/vazias no drive ---
    print(f"\n{'═'*60}")
    print(f'  LIMPEZA DE PASTAS DO DRIVE  —  {mode_label}')
    print(f"{'═'*60}")
    folders_removed, folders_skipped = cleanup_empty_drive_folders(client, TARGET_FOLDER, dry_run)
    if folders_removed == 0 and folders_skipped == 0:
        print('\n✅ Nenhuma pasta duplicada ou vazia encontrada no drive.')
    else:
        print(f"\n{'─'*60}")
        if dry_run:
            print(f'  Pastas: {folders_removed} seria(m) removida(s) | {folders_skipped} preservada(s).')
            print('\n  Para executar de verdade, rode:')
            print(f'    python3 {Path(__file__).name} remove-duplicatas --executar')
        else:
            print(f'  Pastas: {folders_removed} removida(s) | {folders_skipped} preservada(s).')
        print(f"{'─'*60}")
    print(f"\n{'═'*60}\n")


SETUP_AUTOSTART_SHELL = '#!/usr/bin/env bash\n#\n# Configura a montagem WebDAV e o serviço de sincronização Zotero em modo usuário.\n# - Copia o script Python para ~/.local/bin/\n# - Gera arquivo de configuração com variáveis compartilhadas\n# - Cria helper de montagem + unidades systemd de usuário\n# - Integra com secret-tool para guardar credenciais WebDAV\n\nset -euo pipefail\n\nreadonly CONFIG_DIR="$HOME/.config/zotero_sync_webdav"\nreadonly ENV_FILE="$CONFIG_DIR/zotero_sync.env"\nreadonly DEFAULT_REMOTE_SUBPATH="Google Drive/zoterodb"\n\ndie() {\n  echo "Erro: $*" >&2\n  exit 1\n}\n\nrequire_command() {\n  local cmd\n  for cmd in "$@"; do\n    if ! command -v "$cmd" >/dev/null 2>&1; then\n      die "Dependência ausente: $cmd"\n    fi\n  done\n}\n\nprompt_value() {\n  local prompt="$1"\n  local default="${2-}"\n  local allow_empty="${3:-0}"\n  local value\n  while true; do\n    if [[ -n "$default" ]]; then\n      read -r -p "$prompt [$default]: " value || exit 1\n      [[ -z "$value" ]] && value="$default"\n    else\n      read -r -p "$prompt: " value || exit 1\n    fi\n    if [[ -n "$value" || "$allow_empty" == "1" ]]; then\n      printf \'%s\' "$value"\n      return\n    fi\n    echo "Valor obrigatório." >&2\n  done\n}\n\nprompt_secret() {\n  local prompt="$1"\n  local secret confirm\n  while true; do\n    read -r -s -p "$prompt: " secret || exit 1\n    echo\n    if [[ -z "$secret" ]]; then\n      echo "A senha não pode ser vazia." >&2\n      continue\n    fi\n    read -r -s -p "Confirme a senha: " confirm || exit 1\n    echo\n    if [[ "$secret" != "$confirm" ]]; then\n      echo "As senhas não conferem. Tente novamente." >&2\n      continue\n    fi\n    printf \'%s\' "$secret"\n    return\n  done\n}\n\nprompt_yes_no() {\n  local prompt="$1"\n  local default="${2:-s}"\n  local answer default_hint\n  case "$default" in\n    [sS]|[yY]) default_hint=" [S/n]" ;;\n    [nN]) default_hint=" [s/N]" ;;\n    *) default_hint=" [s/n]"; default="" ;;\n  esac\n  while true; do\n    read -r -p "$prompt$default_hint " answer || exit 1\n    [[ -z "$answer" && -n "$default" ]] && answer="$default"\n    case "${answer,,}" in\n      s|sim|y|yes) return 0 ;;\n      n|nao|não|no) return 1 ;;\n      *) echo "Responda com \'s\' ou \'n\'." >&2 ;;\n    esac\n  done\n}\n\ndeclare -a SECRET_ENTRIES=()\ndeclare -a MOUNTED_WEBDAV=()\n\nload_env_file_simple() {\n  local env_path="$1"\n  [[ -f "$env_path" ]] || return\n  while IFS= read -r line || [[ -n "$line" ]]; do\n    line="${line%$\'\\r\'}"\n    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue\n    local key="${line%%=*}"\n    local value="${line#*=}"\n    key="${key#"${key%%[![:space:]]*}"}"\n    key="${key%"${key##*[![:space:]]}"}"\n    value="${value#"${value%%[![:space:]]*}"}"\n    value="${value%"${value##*[![:space:]]}"}"\n    # Remove aspas simples ou duplas ao redor do valor, se presentes.\n    if [[ "$value" == \\"*\\" && "$value" == *\\" ]]; then\n      value="${value:1:${#value}-2}"\n    elif [[ "$value" == \\\'*\\\' && "$value" == *\\\' ]]; then\n      value="${value:1:${#value}-2}"\n    fi\n    export "$key=$value"\n  done <"$env_path"\n}\n\ndecode_mount_entry() {\n  local entry="$1"\n  IFS=\'|\' read -r _ label user host scheme port remote_path mount_path <<<"$entry"\n  label="$(decode_field "$label")"\n  user="$(decode_field "$user")"\n  host="$(decode_field "$host")"\n  scheme="$(decode_field "$scheme")"\n  port="$(decode_field "$port")"\n  remote_path="$(decode_field "$remote_path")"\n  mount_path="$(decode_field "$mount_path")"\n  printf \'%s|%s|%s|%s|%s|%s|%s\\n\' "$label" "$user" "$host" "$scheme" "$port" "$remote_path" "$mount_path"\n}\n\nencode_field() {\n  local value="$1"\n  value="${value//\\\\/\\\\\\\\}"\n  value="${value//|/\\\\u007c}"\n  printf \'%s\' "$value"\n}\n\ndecode_field() {\n  local value="$1"\n  value="${value//\\\\u007c/|}"\n  value="${value//\\\\\\\\/\\\\}"\n  printf \'%s\' "$value"\n}\n\ncollect_secret_entries() {\n  SECRET_ENTRIES=()\n  local proto output line label user server url remote_path port attr_proto encoded\n\n  for proto in davs dav; do\n    output="$(secret-tool search --all protocol "$proto" 2>/dev/null)" || continue\n\n    label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"\n\n    while IFS= read -r line || [[ -n "$line" ]]; do\n      line="${line%$\'\\r\'}"\n\n      if [[ -z "$line" ]]; then\n        if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then\n          encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"\n          SECRET_ENTRIES+=("$encoded")\n        fi\n        label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"\n        continue\n      fi\n\n      case "$line" in\n        \\[*\\]) continue ;;\n        secret\\ =*) continue ;;\n        created\\ =*) continue ;;\n        modified\\ =*) continue ;;\n        schema\\ =*) continue ;;\n        label\\ =*)\n          label="${line#*= }"\n          ;;\n        attribute.user\\ =*)\n          user="${line#*= }"\n          ;;\n        attribute.server\\ =*)\n          server="${line#*= }"\n          ;;\n        attribute.url\\ =*)\n          url="${line#*= }"\n          ;;\n        attribute.remote_path\\ =*)\n          remote_path="${line#*= }"\n          ;;\n        attribute.port\\ =*)\n          port="${line#*= }"\n          ;;\n        attribute.protocol\\ =*)\n          attr_proto="${line#*= }"\n          ;;\n      esac\n    done <<<"$output"\n\n    if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then\n      encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"\n      SECRET_ENTRIES+=("$encoded")\n    fi\n  done\n}\n\ncollect_mounted_webdav() {\n  MOUNTED_WEBDAV=()\n  local gvfs_dir="/run/user/$(id -u)/gvfs"\n  [[ -d "$gvfs_dir" ]] || return\n\n  shopt -s nullglob\n  local mount_path name part host user port ssl prefix decoded dec_user dec_prefix scheme label\n  for mount_path in "$gvfs_dir"/dav:*; do\n    name="${mount_path##*/}"\n    host=""; user=""; port=""; ssl=""; prefix=""\n    IFS=\',\' read -ra parts <<<"${name#dav:}"\n    for part in "${parts[@]}"; do\n      case "$part" in\n        host=*) host="${part#host=}" ;;\n        user=*) user="${part#user=}" ;;\n        port=*) port="${part#port=}" ;;\n        ssl=*) ssl="${part#ssl=}" ;;\n        prefix=*) prefix="${part#prefix=}" ;;\n      esac\n    done\n\n    mapfile -t decoded < <(U="$user" P="$prefix" python3 - <<\'PY\'\nimport os, urllib.parse\nprint(urllib.parse.unquote(os.environ.get("U","")))\nprint(urllib.parse.unquote(os.environ.get("P","")))\nPY\n)\n    dec_user="${decoded[0]}"\n    dec_prefix="${decoded[1]}"\n    [[ -z "$dec_prefix" ]] && dec_prefix="/"\n    scheme="dav"\n    [[ "${ssl,,}" == "true" ]] && scheme="davs"\n    label="Mount ${name}"\n    MOUNTED_WEBDAV+=("$(encode_field "$label")|$(encode_field "$dec_user")|$(encode_field "$host")|$(encode_field "$scheme")|$(encode_field "$port")|$(encode_field "$dec_prefix")|$(encode_field "$mount_path")")\n  done\n  shopt -u nullglob\n}\n\nchoose_secret_entry() {\n  local count="${#SECRET_ENTRIES[@]}"\n  [[ "$count" -eq 0 ]] && return 1\n\n  local fallback_user="" fallback_host="" fallback_scheme="" fallback_port="" fallback_remote=""\n  if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then\n    IFS=\'|\' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"\n  fi\n\n  echo\n  echo "Credenciais WebDAV encontradas no keyring:"\n\n  local idx=1 entry label user server url remote_path port protocol\n  for entry in "${SECRET_ENTRIES[@]}"; do\n    IFS=\'|\' read -r label user server url remote_path port protocol <<<"$entry"\n    label="$(decode_field "$label")"\n    user="$(decode_field "$user")"\n    server="$(decode_field "$server")"\n    url="$(decode_field "$url")"\n    remote_path="$(decode_field "$remote_path")"\n    port="$(decode_field "$port")"\n    protocol="$(decode_field "$protocol")"\n\n    [[ -z "$user" && -n "$fallback_user" ]] && user="$fallback_user"\n    [[ -z "$server" && -n "$fallback_host" ]] && server="$fallback_host"\n    [[ -z "$protocol" && -n "$fallback_scheme" ]] && protocol="$fallback_scheme"\n    [[ -z "$remote_path" && -n "$fallback_remote" ]] && remote_path="$fallback_remote"\n\n    [[ -z "$label" ]] && label="(sem label)"\n    [[ -z "$user" ]] && user="(usuário desconhecido)"\n    [[ -z "$server" ]] && server="(servidor desconhecido)"\n    if [[ -z "$url" ]]; then\n      local inferred_url=""\n      if [[ -n "$server" ]]; then\n        local scheme="$protocol"\n        [[ -z "$scheme" ]] && scheme="davs"\n        if [[ "$scheme" != "dav" && "$scheme" != "davs" ]]; then\n          scheme="davs"\n        fi\n        local path="$remote_path"\n        [[ -z "$path" ]] && path="/"\n        [[ "$path" != /* ]] && path="/$path"\n        if [[ -n "$port" ]]; then\n          inferred_url="$scheme://$server:$port$path"\n        else\n          inferred_url="$scheme://$server$path"\n        fi\n      fi\n      [[ -n "$inferred_url" ]] && url="$inferred_url" || url="(URL não registrada)"\n    fi\n\n    printf "  [%d] %s -> %s@%s (%s)\\n" "$idx" "$label" "$user" "$server" "$url"\n    ((idx++))\n  done\n  echo "  [0] Registrar nova credencial"\n\n  local choice\n  while true; do\n    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1\n    if [[ -z "$choice" ]]; then\n      choice=0\n    fi\n    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then\n      break\n    fi\n    echo "Opção inválida." >&2\n  done\n\n  if [[ "$choice" -eq 0 ]]; then\n    SELECTED_SECRET_ENTRY=""\n    return 1\n  fi\n\n  SELECTED_SECRET_ENTRY="${SECRET_ENTRIES[$((choice-1))]}"\n  return 0\n}\n\nchoose_mounted_entry() {\n  local count="${#MOUNTED_WEBDAV[@]}"\n  [[ "$count" -eq 0 ]] && return 1\n\n  echo\n  echo "Perfis WebDAV já montados detectados:"\n\n  local idx=1 entry label user host scheme port remote_path mount_path\n  for entry in "${MOUNTED_WEBDAV[@]}"; do\n    IFS=\'|\' read -r label user host scheme port remote_path mount_path <<<"$entry"\n    label="$(decode_field "$label")"\n    user="$(decode_field "$user")"\n    host="$(decode_field "$host")"\n    scheme="$(decode_field "$scheme")"\n    port="$(decode_field "$port")"\n    remote_path="$(decode_field "$remote_path")"\n    mount_path="$(decode_field "$mount_path")"\n\n    [[ -z "$label" ]] && label="(sem label)"\n    [[ -z "$user" ]] && user="(usuário desconhecido)"\n    [[ -z "$host" ]] && host="(servidor desconhecido)"\n    [[ -z "$remote_path" ]] && remote_path="/"\n\n    local host_display="$host"\n    [[ -n "$port" ]] && host_display="$host_display:$port"\n    printf "  [%d] %s -> %s@%s (%s://%s%s | %s)\\n" "$idx" "$label" "$user" "$host_display" "$scheme" "$host_display" "$remote_path" "$mount_path"\n    ((idx++))\n  done\n  echo "  [0] Não usar montagens existentes"\n\n  local choice\n  while true; do\n    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1\n    if [[ -z "$choice" ]]; then\n      choice=0\n    fi\n    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then\n      break\n    fi\n    echo "Opção inválida." >&2\n  done\n\n  if [[ "$choice" -eq 0 ]]; then\n    SELECTED_MOUNT_ENTRY=""\n    return 1\n  fi\n\n  SELECTED_MOUNT_ENTRY="${MOUNTED_WEBDAV[$((choice-1))]}"\n  return 0\n}\n\nlookup_secret_exists() {\n  local scheme="$1" host="$2" port="$3" user="$4"\n  local -a args=(protocol "$scheme" server "$host" user "$user")\n  if [[ -n "$port" ]]; then\n    args+=(port "$port")\n  fi\n  if secret-tool lookup "${args[@]}" >/dev/null 2>&1; then\n    return 0\n  fi\n  return 1\n}\n\nstore_secret() {\n  local scheme="$1" host="$2" port="$3" user="$4" label="$5" url="$6" remote_path="$7"\n  local password\n  password="$(prompt_secret "Senha WebDAV")"\n  local -a attrs=(protocol "$scheme" server "$host" user "$user")\n  [[ -n "$port" ]] && attrs+=(port "$port")\n  attrs+=(url "$url" remote_path "$remote_path" display "$label")\n  printf "%s" "$password" | secret-tool store --label="$label" "${attrs[@]}"\n  echo "Senha armazenada no keyring com o label \'$label\'."\n}\n\ncompute_paths() {\n  local server_url="$1"\n  local username="$2"\n  local remote_subpath="$3"\n  local result\n\n  result="$(SERVER_URL="$server_url" WEBDAV_USER="$username" REMOTE_SUBPATH="$remote_subpath" python3 - <<\'PY\'\nimport os\nfrom pathlib import PurePosixPath\nfrom urllib.parse import urlparse, quote\n\nserver_url = os.environ["SERVER_URL"].strip()\nuser = os.environ["WEBDAV_USER"]\nremote_subpath = os.environ.get("REMOTE_SUBPATH", "")\n\nif not server_url:\n    raise SystemExit("A URL base do servidor não pode ser vazia.")\n\nparsed = urlparse(server_url)\nif not parsed.scheme:\n    raise SystemExit("Informe a URL com o esquema (ex: davs://servidor/dav/).")\n\nscheme = parsed.scheme.lower()\nif scheme in ("https", "davs"):\n    scheme = "davs"\n    ssl = "true"\nelif scheme in ("http", "dav"):\n    scheme = "dav"\n    ssl = "false"\nelse:\n    raise SystemExit(f"Esquema não suportado: {parsed.scheme}")\n\nhost = parsed.hostname\nif not host:\n    raise SystemExit("A URL precisa conter o host.")\n\nport = parsed.port\nbase_path = parsed.path or "/"\nif not base_path.startswith("/"):\n    base_path = "/" + base_path\n\nif not base_path.endswith("/"):\n    base_path = base_path + "/"\n\nremote_path = base_path.rstrip("/")\nif remote_subpath:\n    remote_path = str(PurePosixPath(remote_path or "/") / remote_subpath)\nelif not remote_path:\n    remote_path = "/"\n\nremote_path = remote_path or "/"\n\nuser_enc = quote(user, safe=\'\')\nhost_display = host if port is None else f"{host}:{port}"\nremote_path_enc = quote(remote_path, safe=\'/\')\nmount_uri = f"{scheme}://{user_enc}@{host_display}{remote_path_enc}"\n\nprefix = remote_path\nif prefix.startswith(\'/\'):\n    prefix = \'%2F\' + prefix[1:]\n\nuid = os.getuid()\nparts = [f"dav:host={host}"]\nif port is not None:\n    parts.append(f"port={port}")\nparts.append(f"ssl={\'true\' if scheme == \'davs\' else \'false\'}")\nparts.append(f"user={user_enc}")\nparts.append(f"prefix={prefix}")\ntarget_folder = f"/run/user/{uid}/gvfs/" + ",".join(parts)\n\nprint(f"SCHEME={scheme}")\nprint(f"SSL={\'true\' if scheme == \'davs\' else \'false\'}")\nprint(f"HOST={host}")\nprint(f"PORT={port or \'\'}")\nprint(f"BASE_PATH={base_path}")\nprint(f"REMOTE_PATH={remote_path}")\nprint(f"MOUNT_URI={mount_uri}")\nprint(f"TARGET_FOLDER={target_folder}")\nPY\n)" || {\n    die "Falha ao processar a URL WebDAV."\n  }\n\n  declare -gA COMPUTED=()\n  local line key value\n  while IFS=\'=\' read -r key value; do\n    [[ -z "$key" ]] && continue\n    COMPUTED["$key"]="$value"\n  done <<<"$result"\n}\n\nwrite_env_file() {\n  mkdir -p "$CONFIG_DIR"\n  : >"$ENV_FILE"\n  local key value\n  {\n    echo "# Arquivo gerado automaticamente por setup_autostart.sh"\n    echo "# Modifique com cuidado."\n    for key in "${!ENV_VARS[@]}"; do\n      value="${ENV_VARS[$key]}"\n      printf \'%s=%q\\n\' "$key" "$value"\n    done\n  } >>"$ENV_FILE"\n}\n\ninstall_helper_script() {\n  local helper_path="$1"\n  cat <<\'EOF\' >"$helper_path"\n#!/usr/bin/env bash\nset -euo pipefail\n\nENV_FILE="$HOME/.config/zotero_sync_webdav/zotero_sync.env"\n[[ -f "$ENV_FILE" ]] || { echo "Arquivo de configuração não encontrado: $ENV_FILE" >&2; exit 1; }\n\n# shellcheck disable=SC1090\nsource "$ENV_FILE"\n\nGIO_BIN="${ZSW_GIO_BIN:-gio}"\nMOUNT_URI="${ZSW_GIO_MOUNT_URI:?ZSW_GIO_MOUNT_URI não definido}"\n\ncleanup() {\n  [[ -z "${TMP_FILE:-}" ]] || rm -f "$TMP_FILE"\n}\n\nalready_mounted_msg() {\n  grep -qiE \'already mounted|já está montad\' "$TMP_FILE"\n}\n\nnot_mounted_msg() {\n  grep -qiE \'not mounted|não está montad\' "$TMP_FILE"\n}\n\ncase "${1:-start}" in\n  start)\n    TMP_FILE="$(mktemp)"\n    trap cleanup EXIT\n    if "$GIO_BIN" mount "$MOUNT_URI" 2>"$TMP_FILE"; then\n      exit 0\n    fi\n    if already_mounted_msg; then\n      exit 0\n    fi\n    cat "$TMP_FILE" >&2\n    exit 1\n    ;;\n  stop|unmount)\n    TMP_FILE="$(mktemp)"\n    trap cleanup EXIT\n    if "$GIO_BIN" mount -u "$MOUNT_URI" 2>"$TMP_FILE"; then\n      exit 0\n    fi\n    if not_mounted_msg; then\n      exit 0\n    fi\n    cat "$TMP_FILE" >&2\n    exit 1\n    ;;\n  status)\n    if "$GIO_BIN" mount -l | grep -F "$MOUNT_URI" >/dev/null 2>&1; then\n      exit 0\n    fi\n    exit 1\n    ;;\n  *)\n    echo "Uso: $0 [start|stop|status]" >&2\n    exit 2\n    ;;\nesac\nEOF\n  chmod 755 "$helper_path"\n}\n\ncreate_webdav_service() {\n  local service_path="$1"\n  local helper_path="$2"\n  local wait_net="$(dirname "$helper_path")/wait_network.sh"\n\n  cat >"$wait_net" <<\'WAITEOF\'\n#!/usr/bin/env bash\nsource "$HOME/.config/zotero_sync_webdav/zotero_sync.env"\ni=0\nwhile [ $i -lt 30 ]; do\n    ping -c1 -W2 "$ZSW_HOST" >/dev/null 2>&1 && exit 0\n    sleep 2\n    i=$((i+1))\ndone\necho "Timeout: host $ZSW_HOST nao respondeu." >&2\nexit 1\nWAITEOF\n  chmod 755 "$wait_net"\n\n  cat <<EOF >"$service_path"\n[Unit]\nDescription=Montar WebDAV (gio)\nAfter=graphical-session.target network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env\nExecStartPre=$wait_net\nExecStart=$helper_path start\nExecStop=$helper_path stop\n\n[Install]\nWantedBy=default.target\nEOF\n}\n\ncreate_sync_service() {\n  local service_path="$1"\n  local python_bin="$2"\n  local python_script="$3"\n  local wait_folder="$(dirname "$python_script")/wait_webdav.sh"\n\n  cat >"$wait_folder" <<\'WAITEOF\'\n#!/usr/bin/env bash\nsource "$HOME/.config/zotero_sync_webdav/zotero_sync.env"\ni=0\nwhile [ $i -lt 20 ]; do\n    test -d "$ZSW_TARGET_FOLDER" && exit 0\n    sleep 3\n    i=$((i+1))\ndone\necho "Timeout: pasta WebDAV nao ficou disponivel." >&2\nexit 1\nWAITEOF\n  chmod 755 "$wait_folder"\n\n  cat <<EOF >"$service_path"\n[Unit]\nDescription=Zotero WebDAV Sync (Python)\nAfter=webdav-koofr.service\nRequires=webdav-koofr.service\n\n[Service]\nType=oneshot\nEnvironment=PYTHONUNBUFFERED=1\nEnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env\nExecStartPre=$wait_folder\nExecStart=$python_bin $python_script\n\n[Install]\nWantedBy=default.target\nEOF\n}\n\nmain() {\n  if [[ $EUID -eq 0 ]]; then\n    die "Execute este script como usuário normal, não como root."\n  fi\n\n  require_command python3 gio systemctl install secret-tool\n\n  local script_dir python_name python_src python_bin gio_bin\n  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n  python_name="${1:-zotero_sync_webdav.py}"\n  python_src="$script_dir/$python_name"\n  [[ -f "$python_src" ]] || die "Arquivo Python não encontrado: $python_src"\n\n  python_bin="$(command -v python3)"\n  gio_bin="$(command -v gio)"\n\n  local bin_dir="$HOME/.local/bin"\n  local python_target="$bin_dir/$python_name"\n  mkdir -p "$bin_dir"\n  install -m 755 "$python_src" "$python_target"\n\n  [[ -d "$CONFIG_DIR" ]] || mkdir -p "$CONFIG_DIR"\n  if [[ -f "$ENV_FILE" ]]; then\n    # shellcheck disable=SC1091\n    source "$ENV_FILE"\n  fi\n  # Se existir um .env na pasta do script, use-o como base (ex.: já configurado manualmente).\n  local project_env="$script_dir/.env"\n  if [[ -f "$project_env" ]]; then\n    load_env_file_simple "$project_env"\n  fi\n\n  collect_secret_entries\n  collect_mounted_webdav\n  local secret_entries_count="${#SECRET_ENTRIES[@]}"\n  local default_user="${ZSW_USERNAME-}"\n  local default_label="${ZSW_SECRET_LABEL-}"\n  local default_server_url="${ZSW_SERVER_URL-}"\n  local default_remote_subpath="${ZSW_REMOTE_SUBPATH:-$DEFAULT_REMOTE_SUBPATH}"\n  local default_scheme="${ZSW_SCHEME-}"\n  local default_port="${ZSW_PORT-}"\n  local default_target_folder="${ZSW_TARGET_FOLDER-}"\n  local default_library_id="${ZOTERO_LIBRARY_ID:-10830189}"\n  local default_library_type="${ZOTERO_LIBRARY_TYPE:-user}"\n  local default_api_key="${ZOTERO_API_KEY-}"\n\n  [[ -n "$default_user" ]] || default_user="$USER"\n  [[ -n "$default_label" ]] || default_label="WebDAV Sync"\n  [[ -n "$default_server_url" ]] || default_server_url="davs://app.koofr.net/dav/"\n\n  local auto_defaults=0\n\n  if [[ "$secret_entries_count" -gt 0 ]]; then\n    if choose_secret_entry; then\n      local selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol\n      IFS=\'|\' read -r selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol <<<"$SELECTED_SECRET_ENTRY"\n      selected_label="$(decode_field "$selected_label")"\n      selected_user="$(decode_field "$selected_user")"\n      selected_server="$(decode_field "$selected_server")"\n      selected_url="$(decode_field "$selected_url")"\n      selected_remote="$(decode_field "$selected_remote")"\n      selected_port="$(decode_field "$selected_port")"\n      selected_protocol="$(decode_field "$selected_protocol")"\n\n      # Completar campos ausentes com o primeiro mount detectado (se existir).\n      if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then\n        IFS=\'|\' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"\n        [[ -z "$selected_user" && -n "$fallback_user" ]] && selected_user="$fallback_user"\n        [[ -z "$selected_server" && -n "$fallback_host" ]] && selected_server="$fallback_host"\n        [[ -z "$selected_protocol" && -n "$fallback_scheme" ]] && selected_protocol="$fallback_scheme"\n        [[ -z "$selected_port" && -n "$fallback_port" ]] && selected_port="$fallback_port"\n        [[ -z "$selected_remote" && -n "$fallback_remote" ]] && selected_remote="$fallback_remote"\n      fi\n\n      [[ -n "$selected_user" ]] && default_user="$selected_user"\n      [[ -z "$selected_label" ]] && selected_label="(sem label)"\n      if [[ "$selected_label" != "(sem label)" ]]; then\n        default_label="$selected_label"\n      fi\n      [[ -n "$selected_url" ]] && default_server_url="$selected_url"\n      if [[ -n "$selected_remote" ]]; then\n        default_remote_subpath="$selected_remote"\n      fi\n      if [[ -n "$selected_protocol" ]]; then\n        default_scheme="$selected_protocol"\n      fi\n      if [[ -n "$selected_port" ]]; then\n        default_port="$selected_port"\n      fi\n\n      local display_server="$selected_server"\n      [[ -z "$display_server" ]] && display_server="(servidor desconhecido)"\n\n      echo\n      echo "Usando a credencial selecionada (${selected_label} -> ${default_user}@${display_server}) para preencher os campos padrão."\n      auto_defaults=1\n    else\n      echo\n      echo "Nenhuma credencial existente selecionada. Informe novos dados."\n    fi\n  fi\n\n  if choose_mounted_entry; then\n    local selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path\n    IFS=\'|\' read -r selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path <<<"$SELECTED_MOUNT_ENTRY"\n    selected_label="$(decode_field "$selected_label")"\n    selected_user="$(decode_field "$selected_user")"\n    selected_host="$(decode_field "$selected_host")"\n    selected_scheme="$(decode_field "$selected_scheme")"\n    selected_port="$(decode_field "$selected_port")"\n    selected_remote_path="$(decode_field "$selected_remote_path")"\n    selected_mount_path="$(decode_field "$selected_mount_path")"\n\n    [[ -n "$selected_user" ]] && default_user="$selected_user"\n    [[ -n "$selected_host" ]] || selected_host="(servidor desconhecido)"\n    if [[ -n "$selected_scheme" ]]; then\n      default_scheme="$selected_scheme"\n    fi\n    if [[ -n "$selected_port" ]]; then\n      default_port="$selected_port"\n    fi\n    if [[ -n "$selected_remote_path" ]]; then\n      # Se a montagem já tem um prefixo, usamos ele como caminho base.\n      default_server_url="${selected_scheme}://${selected_host}"\n      [[ -n "$selected_port" ]] && default_server_url+=":${selected_port}"\n      default_server_url+="$selected_remote_path"\n      [[ "$default_server_url" != */ ]] && default_server_url+="/"\n      default_remote_subpath=""\n    fi\n    if [[ -n "$selected_mount_path" ]]; then\n      default_target_folder="$selected_mount_path"\n    fi\n\n    echo\n    echo "Usando dados da montagem existente (${selected_label}) como padrão:"\n    echo "  Usuário........: ${default_user}"\n    echo "  URL base.......: ${default_server_url}"\n    [[ -n "$default_target_folder" ]] && echo "  Pasta local....: ${default_target_folder}"\n    auto_defaults=1\n  fi\n\n  echo\n  echo "Informe os dados para montar o WebDAV:"\n  local webdav_user webdav_label server_url remote_subpath\n  local accepted_defaults=0\n  if [[ "$auto_defaults" -eq 1 ]]; then\n    echo "Detectei valores padrão: usuário=${default_user}, URL=${default_server_url}, subpasta=\'${default_remote_subpath}\', pasta local=\'${default_target_folder:-(não definida)}\'."\n    if prompt_yes_no "Usar esses valores sem alterar?" "s"; then\n      webdav_user="$default_user"\n      webdav_label="$default_label"\n      server_url="$default_server_url"\n      remote_subpath="$default_remote_subpath"\n      accepted_defaults=1\n    fi\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_user-}" ]]; then\n    webdav_user="$(prompt_value "Usuário WebDAV" "$default_user")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_label-}" ]]; then\n    webdav_label="$(prompt_value "Label para salvar no keyring" "$default_label")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${server_url-}" ]]; then\n    server_url="$(prompt_value "URL base do servidor WebDAV (ex: davs://servidor/dav/)" "$default_server_url")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${remote_subpath-}" ]]; then\n    remote_subpath="$(prompt_value "Subpasta remota (relativa ao caminho base ou caminho completo)" "${default_remote_subpath}" 1)"\n  fi\n\n  compute_paths "$server_url" "$webdav_user" "$remote_subpath"\n\n  echo\n  echo "Resumo da configuração sugerida:"\n  echo "  Servidor.......: ${COMPUTED[HOST]}"\n  [[ -n "${COMPUTED[PORT]}" ]] && echo "  Porta..........: ${COMPUTED[PORT]}"\n  echo "  Esquema........: ${COMPUTED[SCHEME]}"\n  echo "  Caminho base...: ${COMPUTED[BASE_PATH]}"\n  echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"\n  echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"\n  echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"\n\n  local target_confirmed=0\n  if ! prompt_yes_no "Essas informações estão corretas?" "s"; then\n    remote_subpath="$(prompt_value "Informe novamente a subpasta/remoto (relativa ao caminho base)" "$remote_subpath" 1)"\n    compute_paths "$server_url" "$webdav_user" "$remote_subpath"\n    echo\n    echo "Ajuste aplicado:"\n    echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"\n    echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"\n    echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"\n  else\n    target_confirmed=1\n  fi\n\n  local target_folder="${COMPUTED[TARGET_FOLDER]}"\n  if [[ -n "$default_target_folder" ]]; then\n    target_folder="$default_target_folder"\n  fi\n  if [[ "$target_confirmed" -ne 1 ]]; then\n    if ! prompt_yes_no "Pasta local inferida (${target_folder}) está correta?" "s"; then\n      target_folder="$(prompt_value "Informe o caminho local completo da pasta WebDAV" "$target_folder")"\n    fi\n  fi\n\n  echo\n  echo "Configuração Zotero:"\n  local library_id library_type api_key\n  library_id="$(prompt_value "Library ID" "$default_library_id")"\n  library_type="$(prompt_value "Library type (user/group)" "$default_library_type")"\n\n  if [[ -n "$default_api_key" ]]; then\n    local masked_api="****${default_api_key: -4}"\n    echo "API key atual (mascarada): $masked_api"\n    if prompt_yes_no "Manter API key existente?" "s"; then\n      api_key="$default_api_key"\n    else\n      api_key="$(prompt_secret "Nova API key do Zotero")"\n    fi\n  else\n    api_key="$(prompt_secret "API key do Zotero")"\n  fi\n\n  local scheme="${COMPUTED[SCHEME]}"\n  local host="${COMPUTED[HOST]}"\n  local port="${COMPUTED[PORT]}"\n  local remote_path="${COMPUTED[REMOTE_PATH]}"\n  local mount_uri="${COMPUTED[MOUNT_URI]}"\n\n  if lookup_secret_exists "$scheme" "$host" "$port" "$webdav_user"; then\n    echo "Credencial WebDAV já encontrada no keyring para $webdav_user@$host."\n  else\n    echo\n    echo "Nenhuma credencial encontrada para $webdav_user@$host. Será necessário informar a senha."\n    store_secret "$scheme" "$host" "$port" "$webdav_user" "$webdav_label" "$server_url" "$remote_path"\n  fi\n\n  declare -gA ENV_VARS=()\n  ENV_VARS[ZSW_CONFIG_VERSION]="2"\n  ENV_VARS[ZSW_GIO_BIN]="$gio_bin"\n  ENV_VARS[ZSW_USERNAME]="$webdav_user"\n  ENV_VARS[ZSW_SECRET_LABEL]="$webdav_label"\n  ENV_VARS[ZSW_SERVER_URL]="$server_url"\n  ENV_VARS[ZSW_REMOTE_SUBPATH]="$remote_subpath"\n  ENV_VARS[ZSW_REMOTE_PATH]="$remote_path"\n  ENV_VARS[ZSW_SCHEME]="$scheme"\n  ENV_VARS[ZSW_HOST]="$host"\n  ENV_VARS[ZSW_PORT]="$port"\n  ENV_VARS[ZSW_GIO_MOUNT_URI]="$mount_uri"\n  ENV_VARS[ZSW_TARGET_FOLDER]="$target_folder"\n  ENV_VARS[ZOTERO_SYNC_TARGET_FOLDER]="$target_folder"\n  ENV_VARS[ZOTERO_LIBRARY_ID]="$library_id"\n  ENV_VARS[ZOTERO_LIBRARY_TYPE]="$library_type"\n  ENV_VARS[ZOTERO_API_KEY]="$api_key"\n\n  write_env_file\n\n  local helper_path="$bin_dir/mount_webdav.sh"\n  install_helper_script "$helper_path"\n\n  local systemd_dir="$HOME/.config/systemd/user"\n  mkdir -p "$systemd_dir"\n\n  local webdav_service="$systemd_dir/webdav-koofr.service"\n  create_webdav_service "$webdav_service" "$helper_path"\n\n  local sync_service="$systemd_dir/zotero-sync.service"\n  create_sync_service "$sync_service" "$python_bin" "$python_target"\n\n  systemctl --user daemon-reload\n\n  systemctl --user enable webdav-koofr.service\n  systemctl --user enable zotero-sync.service\n\n  local webdav_failed=0\n  if ! systemctl --user start webdav-koofr.service; then\n    webdav_failed=1\n    echo\n    echo "Aviso: webdav-koofr.service não conseguiu montar automaticamente." >&2\n    echo "Execute manualmente para testar:" >&2\n    echo "  $gio_bin mount ${COMPUTED[MOUNT_URI]}" >&2\n    echo "Confirme que a senha está salva no keyring e tente novamente com:" >&2\n    echo "  systemctl --user restart webdav-koofr.service" >&2\n  fi\n\n  if [[ "$webdav_failed" -eq 0 ]]; then\n    systemctl --user start zotero-sync.service || true\n  else\n    echo\n    echo "O serviço de sincronização será iniciado após a montagem bem-sucedida." >&2\n    echo "Comandos sugeridos:" >&2\n    echo "  systemctl --user restart webdav-koofr.service" >&2\n    echo "  systemctl --user start zotero-sync.service" >&2\n  fi\n\n  cat <<MSG\n\nConfiguração concluída.\n  Script Python: $python_target\n  Arquivo de configuração: $ENV_FILE\n  Serviços habilitados: webdav-koofr.service e zotero-sync.service\n\nUse \'journalctl --user -u webdav-koofr -f\' para acompanhar a montagem.\nSe alterar a senha WebDAV, execute novamente este script para atualizar o keyring.\nMSG\n}\n\nmain "$@"\n'


def run_setup_autostart_mode(extra_args: List[str]) -> None:
    """Executa o configurador de autostart integrado sem depender de arquivo separado."""
    import tempfile
    stage_desktop_recognizer_assets()

    with tempfile.TemporaryDirectory(prefix="zsw-autostart-") as temp_dir:
        temp_script = Path(temp_dir) / 'setup_autostart.sh'
        temp_script.write_text(SETUP_AUTOSTART_SHELL, encoding='utf-8')
        temp_script.chmod(0o755)
        cmd = ['bash', str(temp_script), Path(__file__).name, *extra_args]
        raise SystemExit(subprocess.run(cmd, check=False).returncode)



def _coerce_response_items(items):
    """Normaliza estruturas retornadas pela Pyzotero em listas de anexos."""
    if not items:
        return []
    if isinstance(items, dict):
        return list(items.values())
    if isinstance(items, list):
        return items
    return [items]


def cleanup_failed_attachment_upload(zot: zotero.Zotero, source_path: str) -> int:
    """Remove anexos preliminares quebrados após falha de upload Pyzotero.

    Quando o Pyzotero cria o item preliminar no Zotero, mas o upload S3 falha,
    podem sobrar anexos sem conteúdo, com ou sem pai, e com `filename` derivado do
    caminho absoluto local. Esses itens não representam um anexo funcional e
    causam duplicatas em execuções futuras.
    """
    basename = os.path.basename(source_path)
    path_filename = os.path.abspath(source_path).replace(os.sep, "_")
    deleted = 0

    try:
        candidates = zot.items(
            itemType="attachment",
            limit=100,
            start=0,
            sort="dateAdded",
            direction="desc",
        )
    except Exception as exc:
        logging.warning(
            "[ZOT-UPLOAD] Não foi possível buscar anexos recentes para limpar falha de upload de '%s': %s",
            basename,
            exc,
        )
        return 0

    for item in candidates:
        data = item.get("data", {})
        if data.get("title") != basename:
            continue
        if data.get("filename") != path_filename:
            continue
        if data.get("contentType"):
            continue
        if data.get("linkMode") != "imported_file":
            continue

        key = item.get("key")
        try:
            zot.delete_item(item)
            deleted += 1
            logging.warning(
                "[ZOT-UPLOAD] Anexo preliminar quebrado removido após falha de upload: key=%s filename='%s'.",
                key,
                data.get("filename"),
            )
        except Exception as exc:
            logging.error(
                "[ZOT-UPLOAD] Falha ao remover anexo preliminar quebrado key=%s: %s",
                key,
                exc,
            )

    return deleted


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


def remove_cache_entry(cache: Dict[str, dict], path: str) -> None:
    """Remove uma entrada do cache quando um arquivo deixa de existir."""
    cache.pop(_normalize_cache_path(path), None)


def delete_redundant_webdav_duplicate(
    redundant_path: str,
    canonical_path: str,
    canonical_hash: str | None = None,
    ) -> bool:
    """Remove um duplicado redundante no drive quando o canônico já existe.

    Só remove automaticamente quando os dois arquivos têm o mesmo hash. Isso permite
    consolidar colisões de nome no caso 3 sem sobrescrever conteúdo diferente.
    """
    if not redundant_path or not canonical_path or redundant_path == canonical_path:
        return False
    if not os.path.exists(redundant_path) or not os.path.exists(canonical_path):
        return False

    keep_hash = canonical_hash or compute_sha256(canonical_path)
    redundant_hash = compute_sha256(redundant_path)
    if not keep_hash or not redundant_hash:
        logging.warning(
            "[RENOMEIO] Não foi possível validar hashes para consolidar '%s' e '%s'.",
            redundant_path,
            canonical_path,
        )
        return False
    if keep_hash != redundant_hash:
        logging.warning(
            "[RENOMEIO] Colisão de nome entre '%s' e '%s' com conteúdo diferente. Revisão manual necessária.",
            redundant_path,
            canonical_path,
        )
        return False

    try:
        os.remove(redundant_path)
        remove_cache_entry(HASH_CACHE, redundant_path)
        logging.info(
            "[RENOMEIO] Duplicado redundante removido do drive: '%s'. Canônico preservado: '%s'.",
            redundant_path,
            canonical_path,
        )
        return True
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Falha ao remover duplicado redundante '%s': %s",
            redundant_path,
            exc,
        )
        return False



def relocate_drive_file(
    current_path: str,
    desired_path: str,
    file_hash: str | None,
    stats: dict,
) -> str:
    """Move ou renomeia arquivo no drive criando subpastas quando necessário."""
    if not current_path or not desired_path:
        return current_path
    current_abs = os.path.abspath(current_path)
    desired_abs = os.path.abspath(desired_path)
    if current_abs == desired_abs:
        return current_path

    try:
        os.makedirs(os.path.dirname(desired_abs), exist_ok=True)
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Não foi possível criar pasta destino '%s': %s",
            os.path.dirname(desired_abs),
            exc,
        )
        return current_path

    if os.path.exists(desired_abs):
        if delete_redundant_webdav_duplicate(current_abs, desired_abs, canonical_hash=file_hash):
            stats['pruned_drive_duplicates'] += 1
            return desired_abs
        return current_path

    try:
        os.rename(current_abs, desired_abs)
        rename_cache_entry(HASH_CACHE, current_abs, desired_abs)
        stats['renamed_webdav'] += 1
        logging.info("[RENOMEIO] Drive realocado: '%s' -> '%s'.", current_abs, desired_abs)
        return desired_abs
    except OSError as exc:
        logging.warning("[RENOMEIO] Falha ao mover '%s' para '%s': %s", current_abs, desired_abs, exc)
        return current_path


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
        if cached == "QUARANTINE_TIMEOUT":
            logging.warning("[HASH] Arquivo ignorado (quarentena de timeout recente): '%s'.", path)
            return None
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
            "[HASH] Timeout após %ss ao calcular SHA-256 de '%s'. Adicionado à quarentena.",
            effective_timeout,
            path,
        )
        if cache_ref is not None:
            set_cached_hash(abspath, "QUARANTINE_TIMEOUT", cache_ref, stat)
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

def build_unindexed_local_storage_hashes(indexed_paths: dict[str, str]) -> set[str]:
    """Localiza anexos recém-importados que ainda não chegaram à API do Zotero."""
    indexed = {os.path.realpath(path) for path in indexed_paths.values()}
    hashes: set[str] = set()
    if not os.path.isdir(LOCAL_COPY_DIR):
        return hashes

    for entry in os.scandir(LOCAL_COPY_DIR):
        if not entry.is_dir():
            continue
        local_file = get_latest_pdf_path(entry.path)
        if not local_file or os.path.realpath(local_file) in indexed:
            continue
        file_hash = compute_sha256(local_file)
        if file_hash:
            hashes.add(file_hash)
    return hashes


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

def enforce_drive_canonical_name(
    file_path: str,
    desired_name: str,
    file_hash: str,
    stats: dict,
) -> str:
    """Renomeia ou remove uma cópia redundante no drive preservando o nome canônico."""
    if not file_path or not desired_name:
        return file_path
    dest_path = os.path.join(os.path.dirname(file_path), desired_name)
    return relocate_drive_file(file_path, dest_path, file_hash, stats)



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


def update_zotero_attachment_filename(
    zot: zotero.Zotero,
    key: str,
    new_filename: str,
    item: dict | None = None,
    linked_path: str | None = None,
) -> bool:
    """Atualiza title/filename do anexo no Zotero."""
    if not key or not new_filename:
        return False
    try:
        zotero_item = item if item and item.get('data') else zot.item(key)
        item_data = dict(zotero_item.get('data') or zotero_item)
        current_name = os.path.basename(get_filename_from_item({'data': item_data}))
        current_title = item_data.get('title')
        if item_data.get('linkMode') == 'linked_file':
            resolved_linked_path = linked_path
            if not resolved_linked_path:
                current_path = get_attachment_file_path({'data': item_data, 'key': key})
                if current_path:
                    resolved_linked_path = os.path.join(os.path.dirname(current_path), new_filename)
                else:
                    resolved_linked_path = os.path.join(TARGET_FOLDER, new_filename)
            if (
                current_name == new_filename
                and current_title == new_filename
                and os.path.abspath(item_data.get('path') or "") == os.path.abspath(resolved_linked_path)
            ):
                return False
            item_data.pop('filename', None)
            item_data['title'] = new_filename
            item_data['path'] = os.path.abspath(resolved_linked_path)
        else:
            if current_name == new_filename and current_title == new_filename:
                return False
            item_data['filename'] = new_filename
            item_data['title'] = new_filename
            if item_data.get('path', '').startswith('storage:'):
                item_data['path'] = f"storage:{new_filename}"
        zot.update_item(item_data)
        latest = zot.item(key)
        latest_name = os.path.basename(get_filename_from_item(latest))
        latest_title = latest.get('data', {}).get('title')
        if latest_name != new_filename and latest_title != new_filename:
            logging.warning(
                "[RENOMEIO] Zotero aceitou atualização do anexo %s, mas o nome retornado ainda é '%s'.",
                key,
                latest_name or latest_title,
            )
            return False
        if item is not None:
            target_data = item.setdefault('data', {})
            target_data['filename'] = latest.get('data', {}).get('filename')
            target_data['title'] = latest.get('data', {}).get('title')
            target_data['path'] = latest.get('data', {}).get('path')
            target_data['dateModified'] = latest.get('data', {}).get('dateModified')
        logging.info("[RENOMEIO] Anexo %s atualizado para '%s'.", key, new_filename)
        return True
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao atualizar metadados do anexo %s: %s", key, exc)
        return False


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
    try:
        item = zot.item(key)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao obter anexo %s: %s", key, exc)
        return current_path

    if current_name == new_filename:
        update_zotero_attachment_filename(zot, key, new_filename, item)
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
    if not update_zotero_attachment_filename(zot, key, new_filename, item):
        os.rename(dest_path, current_path)
        rename_cache_entry(HASH_CACHE, dest_path, current_path)
        logging.warning(
            "[RENOMEIO] Revertido rename local do anexo %s porque o Zotero não confirmou '%s'.",
            key,
            new_filename,
        )
        return current_path
    return dest_path


def rename_linked_attachment_file(
    zot: zotero.Zotero,
    key: str,
    current_path: str,
    new_filename: str,
) -> str:
    """Renomeia o arquivo real de um linked_file e atualiza o Zotero."""
    if not key or not current_path or not os.path.exists(current_path) or not new_filename:
        return current_path

    current_name = os.path.basename(current_path)
    try:
        item = zot.item(key)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao obter linked_file %s: %s", key, exc)
        return current_path

    if current_name == new_filename:
        update_zotero_attachment_filename(zot, key, new_filename, item, linked_path=current_path)
        return current_path

    dest_path = os.path.join(os.path.dirname(current_path), new_filename)
    if os.path.exists(dest_path):
        logging.warning(
            "[RENOMEIO] Já existe '%s' ao renomear linked_file %s. Mantido nome '%s'.",
            dest_path,
            key,
            current_name,
        )
        return current_path

    try:
        os.rename(current_path, dest_path)
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Não foi possível renomear linked_file '%s' para '%s': %s",
            current_name,
            new_filename,
            exc,
        )
        return current_path

    rename_cache_entry(HASH_CACHE, current_path, dest_path)
    if not update_zotero_attachment_filename(zot, key, new_filename, item, linked_path=dest_path):
        os.rename(dest_path, current_path)
        rename_cache_entry(HASH_CACHE, dest_path, current_path)
        logging.warning(
            "[RENOMEIO] Revertido rename do linked_file %s porque o Zotero não confirmou '%s'.",
            key,
            new_filename,
        )
        return current_path
    return dest_path


def resolve_zotero_profile_dir() -> Path | None:
    """Resolve o profile ativo do Zotero Desktop."""
    profiles_ini = ZOTERO_PROFILE_ROOT / "profiles.ini"
    if not profiles_ini.is_file():
        return None

    parser = configparser.RawConfigParser()
    try:
        parser.read(profiles_ini, encoding="utf-8")
    except OSError:
        return None

    fallback = None
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        raw_path = parser.get(section, "Path", fallback="").strip()
        if not raw_path:
            continue
        profile_path = Path(raw_path)
        if parser.get(section, "IsRelative", fallback="1") != "0":
            profile_path = ZOTERO_PROFILE_ROOT / profile_path
        if fallback is None:
            fallback = profile_path
        if parser.get(section, "Default", fallback="0") == "1":
            return profile_path
    return fallback



def build_desktop_recognizer_xpi() -> bytes:
    """Empacota o plugin local que expõe o reconhecimento do Zotero Desktop."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in ("manifest.json", "bootstrap.js"):
            source = ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_DIR / relative
            zinfo = zipfile.ZipInfo(relative, (2026, 1, 1, 0, 0, 0))
            archive.writestr(zinfo, source.read_text(encoding="utf-8"))
    return buffer.getvalue()


def install_desktop_recognizer_plugin(stats: dict) -> tuple[bool, bool]:
    """Garante que o plugin local de reconhecimento esteja instalado no profile do Zotero."""
    profile_dir = resolve_zotero_profile_dir()
    if not profile_dir:
        logging.warning("[DESKTOP] Profile do Zotero não encontrado. Reconhecimento automático indisponível.")
        return False, False

    if not ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_DIR.is_dir():
        logging.warning(
            "[DESKTOP] Fonte do plugin de reconhecimento não encontrada em '%s'.",
            ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_DIR,
        )
        return False, False

    extensions_dir = profile_dir / "extensions"
    extensions_dir.mkdir(parents=True, exist_ok=True)
    plugin_path = extensions_dir / f"{ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_ID}.xpi"
    payload = build_desktop_recognizer_xpi()
    changed = True
    if plugin_path.is_file():
        try:
            changed = plugin_path.read_bytes() != payload
        except OSError:
            changed = True

    if changed:
        with tempfile.NamedTemporaryFile(delete=False, dir=extensions_dir, suffix=".xpi") as handle:
            handle.write(payload)
            temp_path = Path(handle.name)
        os.replace(temp_path, plugin_path)
        stats['desktop_plugin_updates'] = stats.get('desktop_plugin_updates', 0) + 1
        logging.info("[DESKTOP] Plugin local de reconhecimento instalado/atualizado em '%s'.", plugin_path)

    proxy_path = extensions_dir / ZOTERO_DESKTOP_RECOGNIZER_PLUGIN_ID
    if proxy_path.exists():
        try:
            proxy_path.unlink()
            changed = True
        except OSError as exc:
            logging.warning("[DESKTOP] Não foi possível remover proxy legado '%s': %s", proxy_path, exc)

    prefs_path = profile_dir / "prefs.js"
    if prefs_path.is_file():
        try:
            lines = prefs_path.read_text(encoding="utf-8").splitlines()
            filtered = [
                line for line in lines
                if 'extensions.lastAppBuildId' not in line
                and 'extensions.lastAppVersion' not in line
            ]
            if filtered != lines:
                prefs_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")
                changed = True
        except OSError as exc:
            logging.warning("[DESKTOP] Não foi possível atualizar prefs.js do Zotero: %s", exc)

    return True, changed


def request_local_json(
    url: str,
    payload: dict | None = None,
    timeout_seconds: int = 5,
) -> tuple[int | None, dict | str]:
    """Executa requisição JSON contra o Zotero Desktop local."""
    body = None
    headers = {}
    method = "GET"
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = raw
            return response.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = raw
        return exc.code, parsed
    except OSError as exc:
        return None, {"error": str(exc)}


def ensure_zotero_desktop_connector_running() -> bool:
    """Garante que o Zotero Desktop esteja com o conector HTTP disponível."""
    global _HEADLESS_ZOTERO_PROC
    status, _ = request_local_json(
        f"{ZOTERO_DESKTOP_CONNECTOR_URL}/connector/ping",
        timeout_seconds=3,
    )
    if status == 200:
        return True
    if not ZOTERO_DESKTOP_BINARY:
        return False
    try:
        logging.info("[DESKTOP] Zotero fechado. Iniciando temporariamente no modo invisível (--headless)...")
        _HEADLESS_ZOTERO_PROC = subprocess.Popen(
            [ZOTERO_DESKTOP_BINARY, "--headless"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        logging.warning("[DESKTOP] Falha ao iniciar Zotero Desktop em background: %s", exc)
        return False
    
    deadline = time.monotonic() + ZOTERO_DESKTOP_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        time.sleep(1)
        status, _ = request_local_json(
            f"{ZOTERO_DESKTOP_CONNECTOR_URL}/connector/ping",
            timeout_seconds=3,
        )
        if status == 200:
            return True
    
    return False


def ensure_desktop_recognizer_available(stats: dict) -> bool:
    """Instala o plugin e garante que o endpoint local de reconhecimento esteja ativo."""
    if not ZOTERO_DESKTOP_RECOGNITION_ENABLED:
        logging.info("[DESKTOP] Reconhecimento via Zotero Desktop desabilitado por configuração.")
        return False

    installed, changed = install_desktop_recognizer_plugin(stats)
    if not installed:
        return False
    if not ensure_zotero_desktop_connector_running():
        return False

    deadline = time.monotonic() + (15 if changed else 10)
    while time.monotonic() < deadline:
        status, _ = request_local_json(ZOTERO_DESKTOP_RECOGNIZER_PING_URL, timeout_seconds=3)
        if status == 200:
            return True
        time.sleep(1)

    logging.warning(
        "[DESKTOP] Endpoint local de reconhecimento não está ativo. "
        "Se o plugin foi atualizado com o Zotero já aberto, reinicie o Zotero Desktop.",
    )
    return False


def stage_file_for_desktop_import(
    file_path: str,
    staging_dir: Path | None = None,
) -> Path:
    """Copia o PDF do mount para disco local antes de entregá-lo ao Zotero headless."""
    source = Path(file_path)
    if not source.is_file():
        raise FileNotFoundError(source)

    destination_dir = staging_dir or Path(LOG_DIR) / "desktop-import-staging"
    destination_dir.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix="zotero-import-", dir=destination_dir))
    destination = stage_dir / source.name
    try:
        shutil.copyfile(source, destination)
    except Exception:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise
    return destination


def import_attachment_via_desktop(
    file_path: str,
    collection_key: str | None,
    parent_key: str | None = None,
    auto_recognize: bool = True,
) -> dict | None:
    """Importa anexo pelo Zotero Desktop para respeitar o backend WebDAV configurado."""
    staged_path = stage_file_for_desktop_import(file_path)
    try:
        status, payload = request_local_json(
            ZOTERO_DESKTOP_RECOGNIZER_IMPORT_URL,
            payload={
                "filePath": str(staged_path),
                "parentKey": parent_key or "",
                "collectionKey": collection_key or "",
                "autoRecognize": auto_recognize,
            },
            timeout_seconds=180,
        )
    finally:
        shutil.rmtree(staged_path.parent, ignore_errors=True)

    if status != 200 or not isinstance(payload, dict):
        logging.warning("[DESKTOP] Falha ao importar '%s' via Zotero Desktop: %s", file_path, payload)
        return None
    return payload


def normalize_standalone_attachment_names(
    zot: zotero.Zotero,
    attachments: List[dict],
    stats: dict,
) -> bool:
    """Remove marcadores de cópia de anexos PDF standalone."""
    stats.setdefault('normalized_standalone_attachments', 0)
    changed = False

    for item in attachments:
        data = item.get('data', {})
        key = item.get('key') or data.get('key')
        if not key or data.get('parentItem') or not attachment_is_pdf(item):
            continue

        desired_name = canonical_standalone_attachment_filename(item)
        if not desired_name:
            continue

        current_name = os.path.basename(get_filename_from_item(item) or data.get('title') or '')
        changed_this_item = False
        if data.get('linkMode') == 'linked_file':
            linked_path = get_attachment_file_path(item)
            if linked_path and os.path.exists(linked_path):
                updated_path = rename_linked_attachment_file(zot, key, linked_path, desired_name)
                changed_this_item = updated_path != linked_path
            else:
                changed_this_item = update_zotero_attachment_filename(zot, key, desired_name, item)
        else:
            local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, key))
            if local_path and os.path.exists(local_path):
                updated_path = rename_local_attachment(zot, key, local_path, desired_name)
                changed_this_item = updated_path != local_path
            else:
                changed_this_item = update_zotero_attachment_filename(zot, key, desired_name, item)

        if changed_this_item:
            stats['normalized_standalone_attachments'] += 1
            changed = True
            logging.info(
                "[NOME-STANDALONE] Anexo standalone %s normalizado: '%s' -> '%s'.",
                key,
                current_name,
                desired_name,
            )
    return changed


def recognize_standalone_pdf_attachments(
    attachments: List[dict],
    stats: dict,
) -> bool:
    """Aciona o Zotero Desktop para reconhecer PDFs standalone."""
    stats.setdefault('desktop_recognition_requested', 0)
    stats.setdefault('desktop_recognition_processed', 0)
    stats.setdefault('desktop_recognition_skipped', 0)
    stats.setdefault('desktop_parent_fallbacks', 0)

    candidates: list[str] = []
    for item in attachments:
        data = item.get('data', {})
        key = item.get('key') or data.get('key')
        if not key or data.get('parentItem') or not attachment_is_pdf(item):
            continue
        candidates.append(key)

    if not candidates:
        return False

    stats['desktop_recognition_requested'] += len(candidates)
    if not ensure_desktop_recognizer_available(stats):
        stats['desktop_recognition_skipped'] += len(candidates)
        return False

    status, payload = request_local_json(
        ZOTERO_DESKTOP_RECOGNIZER_RECOGNIZE_URL,
        payload={"itemKeys": candidates},
        timeout_seconds=ZOTERO_DESKTOP_RECOGNIZE_TIMEOUT_SECONDS,
    )
    if status != 200 or not isinstance(payload, dict):
        stats['desktop_recognition_skipped'] += len(candidates)
        logging.warning("[DESKTOP] Falha ao acionar reconhecimento local: %s", payload)
        return False

    processed = int(payload.get("processed", 0) or 0)
    skipped = int(payload.get("skipped", 0) or 0)
    fallback_parents = int(payload.get("fallbackParents", 0) or 0)
    stats['desktop_recognition_processed'] += processed
    stats['desktop_recognition_skipped'] += skipped
    stats['desktop_parent_fallbacks'] += fallback_parents
    logging.info(
        "[DESKTOP] Reconhecimento de PDFs standalone concluído. solicitados=%d processados=%d ignorados=%d pais_fallback=%d.",
        len(candidates),
        processed,
        skipped,
        fallback_parents,
    )
    return processed > 0 or fallback_parents > 0


def build_item_by_key(items: List[dict]) -> dict[str, dict]:
    """Indexa itens Zotero por key."""
    indexed: dict[str, dict] = {}
    for item in items:
        data = item.get('data', {})
        key = item.get('key') or data.get('key')
        if key:
            indexed[key] = item
    return indexed


def attachment_metadata_filename(
    attachment_key: str,
    attachment_items_by_key: dict[str, dict],
    parent_items_by_key: dict[str, dict],
) -> str | None:
    """Retorna o nome canônico por metadados para um anexo, quando existir."""
    attachment = attachment_items_by_key.get(attachment_key)
    parent_key = (attachment or {}).get('data', {}).get('parentItem')
    return canonical_parent_pdf_filename(parent_items_by_key.get(parent_key))


def choose_hash_match_entry(
    hash_matches: list[dict],
    drive_name: str,
    attachment_items_by_key: dict[str, dict],
    parent_items_by_key: dict[str, dict],
) -> dict:
    """Prefere match cujo anexo tenha nome canônico derivado de metadados."""
    if not hash_matches:
        return {}

    drive_norm = normalize_filename(drive_name)
    scored: list[tuple[int, int, float, str, dict]] = []
    for entry in hash_matches:
        key = entry.get('key') or ''
        desired = attachment_metadata_filename(key, attachment_items_by_key, parent_items_by_key)
        desired_norm = normalize_filename(desired or '')
        if desired_norm and desired_norm == drive_norm:
            metadata_score = 2
        elif desired_norm:
            metadata_score = 1
        else:
            metadata_score = 0
        copy_score = 0 if is_copy_variant_filename(entry.get('filename') or '') else 1
        modified = 0.0
        parsed = parse_zotero_date(((entry.get('info') or {}).get('dateModified') or ''))
        if parsed:
            modified = parsed.timestamp()
        scored.append((metadata_score, copy_score, modified, key, entry))

    return max(scored, key=lambda row: row[:4])[-1]


def enforce_attachment_metadata_filenames(
    zot: zotero.Zotero,
    attachments: List[dict],
    parent_items_by_key: dict[str, dict],
    stats: dict,
) -> bool:
    """Força anexos PDF com pai a usarem 'título - sobrenome ano.pdf'."""
    stats.setdefault('canonical_attachment_names', 0)
    changed = False

    for item in attachments:
        data = item.get('data', {})
        key = item.get('key') or data.get('key')
        parent_key = data.get('parentItem')
        if not key or not parent_key or not attachment_is_pdf(item):
            continue

        desired_name = canonical_parent_pdf_filename(parent_items_by_key.get(parent_key))
        if not desired_name:
            continue

        current_name = os.path.basename(get_filename_from_item(item))
        if current_name == desired_name:
            continue

        changed_this_item = False
        if data.get('linkMode') == 'linked_file':
            linked_path = get_attachment_file_path(item)
            if linked_path and os.path.exists(linked_path):
                updated_path = rename_linked_attachment_file(zot, key, linked_path, desired_name)
                if updated_path != linked_path:
                    changed_this_item = True
            else:
                changed_this_item = update_zotero_attachment_filename(zot, key, desired_name, item)
        else:
            local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, key))
            if local_path and os.path.exists(local_path):
                local_name = os.path.basename(local_path)
                if local_name != desired_name:
                    updated_path = rename_local_attachment(zot, key, local_path, desired_name)
                    if updated_path != local_path:
                        stats['renamed_local'] += 1
                        changed_this_item = True
                else:
                    changed_this_item = update_zotero_attachment_filename(zot, key, desired_name)
            else:
                changed_this_item = update_zotero_attachment_filename(zot, key, desired_name, item)

        if changed_this_item:
            data['filename'] = desired_name
            data['title'] = desired_name
            item['data'] = data
            stats['canonical_attachment_names'] += 1
            changed = True
            logging.info(
                "[NOME-CANONICO] Anexo %s normalizado por metadados do pai %s: '%s' -> '%s'.",
                key,
                parent_key,
                current_name,
                desired_name,
            )

    return changed


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


def set_mtime_from_zotero_date(path: str, date_modified: str | None) -> None:
    """Alinha o mtime de uma cópia materializada com o dateModified do Zotero."""
    parsed = parse_zotero_date(date_modified or "")
    if not parsed:
        return
    timestamp = parsed.timestamp()
    try:
        os.utime(path, (timestamp, timestamp))
    except OSError as exc:
        logging.warning("[ZOT->DRIVE] Não foi possível ajustar mtime de '%s': %s", path, exc)


def download_zotero_attachment_to_local(
    zot: zotero.Zotero,
    item: dict,
    filename: str,
    ) -> str | None:
    """Baixa o arquivo do anexo Zotero para ~/Zotero/storage/<key>/ quando a cópia local falta."""
    key = item.get('key')
    if not key or not filename:
        return None

    dest_dir = os.path.join(LOCAL_COPY_DIR, key)
    dest_file = os.path.join(dest_dir, os.path.basename(filename))
    if os.path.exists(dest_file):
        return dest_file

    try:
        os.makedirs(dest_dir, exist_ok=True)
        zot.dump(key, filename=os.path.basename(filename), path=dest_dir)
    except Exception as exc:
        logging.warning("[ZOT->DRIVE] Falha ao baixar anexo %s do Zotero: %s", key, exc)
        return None

    if not os.path.exists(dest_file):
        logging.warning("[ZOT->DRIVE] Download do anexo %s não gerou o arquivo esperado: %s", key, dest_file)
        return None

    data = item.get('data', {})
    set_mtime_from_zotero_date(dest_file, data.get('dateModified'))
    compute_sha256(dest_file)
    logging.info("[ZOT->DRIVE] Anexo %s baixado para cópia local: %s", key, dest_file)
    return dest_file


def build_drive_pdf_index(directory: str, stats: dict | None = None) -> tuple[dict, dict, dict, dict, dict]:
    """Indexa PDFs atuais do drive por nome, caminho relativo e hash."""
    name_index: dict[str, str] = {}
    aggressive_index: dict[str, str] = {}
    path_index: dict[str, str] = {}
    path_aggressive_index: dict[str, str] = {}
    hash_index: dict[str, list[dict]] = {}

    temp_stats = {'folder_total_pdfs': 0, 'folder_checked_pdfs': 0}
    for path in collect_all_pdfs(directory, temp_stats):
        filename = os.path.basename(path)
        relative_path = relpath_from_root(directory, path)
        norm = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        rel_norm = normalize_relative_path_key(relative_path)
        rel_agg = normalize_relative_path_aggressive_key(relative_path)
        if norm and norm not in name_index:
            name_index[norm] = path
        if norm_aggressive and norm_aggressive not in aggressive_index:
            aggressive_index[norm_aggressive] = path
        if rel_norm and rel_norm not in path_index:
            path_index[rel_norm] = path
        if rel_agg and rel_agg not in path_aggressive_index:
            path_aggressive_index[rel_agg] = path

        file_hash = compute_sha256(path)
        if not file_hash:
            if stats is not None:
                stats['recoverable_hash_skips'] += 1
            logging.warning("[ZOT->DRIVE] Hash skip recuperável durante índice final: %s", path)
            continue

        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        hash_index.setdefault(file_hash, []).append({
            'path': path,
            'filename': filename,
            'relative_path': relative_path,
            'mtime': mtime,
        })

    logging.info(
        "[ZOT->DRIVE] Índice final do drive: %d nomes | %d caminhos | %d hashes únicos.",
        len(name_index),
        len(path_index),
        len(hash_index),
    )
    return name_index, aggressive_index, path_index, path_aggressive_index, hash_index


def build_drive_name_path_indexes(directory: str) -> tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]:
    """Indexa o drive por nome e caminho relativo sem calcular hash."""
    name_index: dict[str, str] = {}
    aggressive_index: dict[str, str] = {}
    path_index: dict[str, str] = {}
    path_aggressive_index: dict[str, str] = {}
    temp_stats = {'folder_total_pdfs': 0, 'folder_checked_pdfs': 0}
    for path in collect_all_pdfs(directory, temp_stats):
        filename = os.path.basename(path)
        relative_path = relpath_from_root(directory, path)
        norm = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        rel_norm = normalize_relative_path_key(relative_path)
        rel_agg = normalize_relative_path_aggressive_key(relative_path)
        if norm and norm not in name_index:
            name_index[norm] = path
        if norm_aggressive and norm_aggressive not in aggressive_index:
            aggressive_index[norm_aggressive] = path
        if rel_norm and rel_norm not in path_index:
            path_index[rel_norm] = path
        if rel_agg and rel_agg not in path_aggressive_index:
            path_aggressive_index[rel_agg] = path
    return name_index, aggressive_index, path_index, path_aggressive_index


def materialize_zotero_attachments_to_drive(
    zot: zotero.Zotero,
    attachments: List[dict],
    parent_items_by_key: dict[str, dict],
    collection_by_key: dict[str, dict],
    drive_name_index: dict,
    drive_aggressive_index: dict,
    drive_path_index: dict,
    drive_path_aggressive_index: dict,
    drive_hash_index: dict,
    key_to_path: Dict[str, str],
    stats: dict,
    tie_conflicts: list[dict[str, str]],
    ) -> None:
    """Materializa no drive PDFs conhecidos pelo Zotero respeitando caminhos de coleção."""
    seen_keys: set[str] = set()
    protected_canonical_names: set[str] = set()
    for attachment in attachments:
        attachment_data = attachment.get('data', {})
        desired = canonical_parent_pdf_filename(
            parent_items_by_key.get(attachment_data.get('parentItem'))
        )
        if desired:
            protected_canonical_names.add(normalize_filename(desired))


    for item in attachments:
        data = item.get('data', {})
        key = item.get('key')
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)

        filename = get_filename_from_item(item)
        if not filename or not filename.lower().endswith('.pdf'):
            continue
        filename = os.path.basename(filename)
        metadata_filename = canonical_parent_pdf_filename(
            parent_items_by_key.get(data.get('parentItem'))
        )
        if metadata_filename:
            filename = metadata_filename

        location = attachment_target_location(
            item,
            filename,
            parent_items_by_key,
            collection_by_key,
        )
        desired_relpath = location["relative_path"]
        desired_drive_path = os.path.join(TARGET_FOLDER, *desired_relpath.split("/"))
        rel_norm = normalize_relative_path_key(desired_relpath)
        rel_aggressive = normalize_relative_path_aggressive_key(desired_relpath)
        if (rel_norm and rel_norm in drive_path_index) or (rel_aggressive and rel_aggressive in drive_path_aggressive_index):
            continue

        norm = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        local_path = key_to_path.get(key) or get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, key))
        if not local_path or not os.path.exists(local_path):
            local_path = download_zotero_attachment_to_local(zot, item, filename)
            if local_path:
                stats['downloaded_zotero'] += 1
                stats['local_copies'] += 1

        if not local_path or not os.path.exists(local_path):
            stats['errors'] += 1
            logging.warning(
                "[ZOT->DRIVE] Anexo %s existe no Zotero, mas não há arquivo local nem download disponível. Não materializado.",
                key,
            )
            continue

        local_hash = compute_sha256(local_path)
        if not local_hash:
            stats['errors'] += 1
            logging.warning("[ZOT->DRIVE] Não foi possível calcular hash da origem local para anexo %s.", key)
            continue

        hash_matches = drive_hash_index.get(local_hash, [])
        if hash_matches:
            drive_entry = max(hash_matches, key=lambda entry: entry.get('mtime', 0.0))
            drive_path = drive_entry['path']
            drive_name = drive_entry['filename']
            drive_mtime = drive_entry.get('mtime', 0.0)
            drive_relative_path = drive_entry.get('relative_path') or relpath_from_root(TARGET_FOLDER, drive_path)
            zotero_date_modified = parse_zotero_date(data.get('dateModified', ''))
            zotero_mtime = zotero_date_modified.timestamp() if zotero_date_modified else os.path.getmtime(local_path)

            if drive_name == filename and drive_relative_path == desired_relpath:
                continue
            drive_norm = normalize_filename(drive_name)
            if (
                metadata_filename
                and drive_norm in protected_canonical_names
                and drive_norm != normalize_filename(metadata_filename)
            ):
                dest_path = desired_drive_path
                if os.path.exists(dest_path):
                    dest_hash = compute_sha256(dest_path)
                    if dest_hash and dest_hash == local_hash:
                        logging.info(
                            "[ZOT->DRIVE] Nome canônico distinto já existe no drive para hash compartilhado: '%s'.",
                            metadata_filename,
                        )
                        continue
                    stats['errors'] += 1
                    logging.warning(
                        "[ZOT->DRIVE] Nome canônico distinto colide com conteúdo diferente. Não sobrescrito: %s",
                        dest_path,
                    )
                    continue
                try:
                    shutil.copy2(local_path, dest_path)
                    set_mtime_from_zotero_date(dest_path, data.get('dateModified'))
                    set_cached_hash(dest_path, local_hash, HASH_CACHE)
                    metadata_norm = normalize_filename(metadata_filename)
                    metadata_norm_aggressive = normalize_aggressive(metadata_filename)
                    drive_name_index[metadata_norm] = dest_path
                    drive_aggressive_index[metadata_norm_aggressive] = dest_path
                    drive_hash_index.setdefault(local_hash, []).append({
                        'path': dest_path,
                        'filename': metadata_filename,
                        'mtime': os.path.getmtime(dest_path),
                    })
                    stats['materialized_drive'] += 1
                    logging.info(
                        "[ZOT->DRIVE] Hash compartilhado materializado também com nome canônico deste anexo: '%s'.",
                        metadata_filename,
                    )
                except Exception as exc:
                    stats['errors'] += 1
                    logging.error(
                        "[ZOT->DRIVE] Falha ao materializar nome canônico distinto '%s': %s",
                        metadata_filename,
                        exc,
                    )
                continue


            if metadata_filename:
                current_zotero_name = os.path.basename(get_filename_from_item(item))
                if current_zotero_name != metadata_filename:
                    if update_zotero_attachment_filename(zot, key, metadata_filename, item):
                        stats['canonical_attachment_names'] += 1
                    data['filename'] = metadata_filename
                    data['title'] = metadata_filename
                if os.path.basename(local_path) != metadata_filename:
                    updated_path = rename_local_attachment(zot, key, local_path, metadata_filename)
                    if updated_path != local_path:
                        key_to_path[key] = updated_path
                        local_path = updated_path
                        stats['renamed_local'] += 1
                new_path = enforce_drive_canonical_name(drive_path, metadata_filename, local_hash, stats)
                if new_path != drive_path:
                    drive_entry['path'] = new_path
                    drive_entry['filename'] = os.path.basename(new_path)
                    drive_entry['mtime'] = os.path.getmtime(new_path)
                    drive_name_index[norm] = new_path
                    drive_aggressive_index[norm_aggressive] = new_path
                    logging.info("[ZOT->DRIVE] Drive consolidado pelo nome canônico de metadados: '%s'.", metadata_filename)
                continue
            if not metadata_filename and normalize_filename(drive_name) in protected_canonical_names:
                current_zotero_name = os.path.basename(get_filename_from_item(item))
                if current_zotero_name != drive_name:
                    if update_zotero_attachment_filename(zot, key, drive_name, item):
                        stats['canonical_attachment_names'] += 1
                    data['filename'] = drive_name
                    data['title'] = drive_name
                if os.path.basename(local_path) != drive_name:
                    updated_path = rename_local_attachment(zot, key, local_path, drive_name)
                    if updated_path != local_path:
                        key_to_path[key] = updated_path
                        local_path = updated_path
                        stats['renamed_local'] += 1
                logging.info(
                    "[ZOT->DRIVE] Nome protegido por metadados de outro anexo preservado para hash compartilhado: '%s'.",
                    drive_name,
                )
                continue
            copy_preferred_name = choose_non_copy_canonical_name(drive_name, filename)
            if copy_preferred_name == filename:
                new_path = enforce_drive_canonical_name(drive_path, filename, local_hash, stats)
                if new_path != drive_path:
                    drive_entry['path'] = new_path
                    drive_entry['filename'] = os.path.basename(new_path)
                    drive_entry['mtime'] = os.path.getmtime(new_path)
                    drive_name_index[norm] = new_path
                    drive_aggressive_index[norm_aggressive] = new_path
                    logging.info("[ZOT->DRIVE] Nome de cópia no drive consolidado pelo canônico Zotero: '%s'.", filename)
            elif copy_preferred_name == drive_name:
                updated_path = rename_local_attachment(zot, key, local_path, drive_name)
                if updated_path != local_path:
                    key_to_path[key] = updated_path
                    stats['renamed_local'] += 1
                    logging.info("[ZOT->DRIVE] Zotero atualizado pelo nome não-cópia do drive: '%s'.", drive_name)
            elif zotero_mtime > drive_mtime:
                new_path = enforce_drive_canonical_name(drive_path, filename, local_hash, stats)
                if new_path != drive_path:
                    drive_entry['path'] = new_path
                    drive_entry['filename'] = os.path.basename(new_path)
                    drive_entry['mtime'] = os.path.getmtime(new_path)
                    drive_name_index[norm] = new_path
                    drive_aggressive_index[norm_aggressive] = new_path
                    logging.info("[ZOT->DRIVE] Drive renomeado pelo Zotero mais recente: '%s'.", filename)
            elif drive_mtime > zotero_mtime:
                updated_path = rename_local_attachment(zot, key, local_path, drive_name)
                if updated_path != local_path:
                    key_to_path[key] = updated_path
                    stats['renamed_local'] += 1
                    logging.info("[ZOT->DRIVE] Zotero atualizado pelo drive mais recente: '%s'.", drive_name)
            else:
                stats['mtime_ties'] += 1
                tie_conflicts.append({
                    'key': key,
                    'drive_name': drive_name,
                    'zotero_name': filename,
                })
                logging.warning("[ZOT->DRIVE] Empate de mtime entre drive e Zotero para key=%s.", key)
            continue

        dest_path = desired_drive_path
        if os.path.exists(dest_path):
            dest_hash = compute_sha256(dest_path)
            if dest_hash and dest_hash == local_hash:
                logging.info("[ZOT->DRIVE] '%s' já existe no drive com mesmo hash.", filename)
                continue
            stats['errors'] += 1
            logging.warning(
                "[ZOT->DRIVE] Destino já existe com conteúdo diferente. Não sobrescrito: %s",
                dest_path,
            )
            continue

        try:
            shutil.copy2(local_path, dest_path)
            set_mtime_from_zotero_date(dest_path, data.get('dateModified'))
            set_cached_hash(dest_path, local_hash, HASH_CACHE)
            drive_name_index[norm] = dest_path
            drive_aggressive_index[norm_aggressive] = dest_path
            if rel_norm:
                drive_path_index[rel_norm] = dest_path
            if rel_aggressive:
                drive_path_aggressive_index[rel_aggressive] = dest_path
            drive_hash_index.setdefault(local_hash, []).append({
                'path': dest_path,
                'filename': filename,
                'relative_path': desired_relpath,
                'mtime': os.path.getmtime(dest_path),
            })
            stats['materialized_drive'] += 1
            logging.info("[ZOT->DRIVE] Anexo %s materializado no drive: %s", key, dest_path)
        except Exception as exc:
            stats['errors'] += 1
            logging.error("[ZOT->DRIVE] Falha ao materializar anexo %s em '%s': %s", key, dest_path, exc)


def reconcile_drive_collection_paths(
    zot: zotero.Zotero,
    attachments: List[dict],
    parent_items_by_key: dict[str, dict],
    collection_by_key: dict[str, dict],
    collection_path_to_key: dict[str, str],
    drive_name_index: dict[str, str],
    drive_aggressive_index: dict[str, str],
    key_to_path: Dict[str, str],
    stats: dict,
) -> None:
    """Alinha a coleção do Zotero ao caminho real já existente no drive quando houver conteúdo."""
    stats.setdefault('drive_authoritative_collection_updates', 0)
    for item in attachments:
        data = item.get('data', {})
        key = item.get('key') or data.get('key')
        filename = get_filename_from_item(item)
        if not key or not filename or not attachment_is_pdf(item):
            continue
        filename = os.path.basename(filename)
        metadata_filename = canonical_parent_pdf_filename(parent_items_by_key.get(data.get('parentItem')))
        if metadata_filename:
            filename = metadata_filename
        current_location = attachment_target_location(item, filename, parent_items_by_key, collection_by_key)

        local_path = key_to_path.get(key) or get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, key))
        if not local_path or not os.path.exists(local_path):
            continue
        local_hash = compute_sha256(local_path)
        if not local_hash:
            continue

        norm_name = normalize_filename(filename)
        norm_name_aggressive = normalize_aggressive(filename)
        candidate_path = (
            drive_name_index.get(norm_name)
            or drive_aggressive_index.get(norm_name_aggressive)
        )
        if not candidate_path or not os.path.exists(candidate_path):
            continue
        candidate_hash = compute_sha256(candidate_path)
        if not candidate_hash or candidate_hash != local_hash:
            continue

        relative_drive_path = relpath_from_root(TARGET_FOLDER, candidate_path)
        drive_collection_key = infer_collection_key_from_relative_path(
            relative_drive_path,
            collection_path_to_key,
        )
        if not drive_collection_key or drive_collection_key == current_location['collection_key']:
            continue

        target_item_key = data.get('parentItem') or key
        target_item = parent_items_by_key.get(data.get('parentItem')) if data.get('parentItem') else item
        if sync_item_collections_to_drive_collection(
            zot,
            target_item_key,
            drive_collection_key,
            collection_by_key,
            item=target_item,
        ):
            stats['drive_authoritative_collection_updates'] += 1


DEFAULT_OBSIDIAN_SNAP_APP_DIR = Path.home() / "snap/obsidian/current/.config/obsidian"
DEFAULT_OBSIDIAN_DEB_APP_DIR = Path.home() / ".config/obsidian"
DEFAULT_OBSIDIAN_TARGET_ROOT = Path.home() / "Documentos/ObsidianLocal"
INVALID_OBSIDIAN_FS_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1F]')


def obsidian_log(msg: str) -> None:
    print(f"[obsidian] {msg}")


def obsidian_fail(msg: str, code: int = 1) -> None:
    print(f"[obsidian][erro] {msg}", file=sys.stderr)
    raise SystemExit(code)


def obsidian_is_windows_noop(kind: str) -> bool:
    return kind == "windows" and os.name != "nt"


def parse_path_map_entries(entries: List[str] | None) -> List[Tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for raw in entries or []:
        if "=" not in raw:
            obsidian_fail(f"Mapeamento inválido '{raw}'. Use FORMATO antigo=novo")
        old, new = raw.split("=", 1)
        old = old.strip()
        new = new.strip()
        if not old or not new:
            obsidian_fail(f"Mapeamento inválido '{raw}'. Lados antigo e novo são obrigatórios")
        pairs.append((old, new))
    return pairs


def replace_path_prefix(text: str, pairs: List[Tuple[str, str]]) -> str:
    for old, new in pairs:
        if text == old or text.startswith(old.rstrip("/") + "/"):
            suffix = text[len(old.rstrip("/")):]
            return new.rstrip("/") + suffix
    return text


def default_windows_obsidian_app_dir() -> Path:
    if os.name != "nt":
        obsidian_fail("Diretório padrão do Windows só é resolvido no próprio Windows")
    appdata = os.environ.get("APPDATA")
    if not appdata:
        obsidian_fail("APPDATA não definido no Windows")
    return Path(appdata) / "Obsidian"


def windows_style_path(path: str) -> str:
    return path.replace("/", "\\\\")


def resolve_obsidian_app_dir(kind: str, explicit_app_dir: str | None) -> Tuple[str, Path]:
    if explicit_app_dir:
        return kind, Path(explicit_app_dir).expanduser()

    if kind == "snap":
        return kind, DEFAULT_OBSIDIAN_SNAP_APP_DIR
    if kind == "deb":
        return kind, DEFAULT_OBSIDIAN_DEB_APP_DIR
    if kind == "windows":
        return kind, default_windows_obsidian_app_dir()

    if os.name == "nt":
        windows_dir = default_windows_obsidian_app_dir()
        if windows_dir.exists():
            return "windows", windows_dir

    for candidate_kind, candidate_path in [
        ("snap", DEFAULT_OBSIDIAN_SNAP_APP_DIR),
        ("deb", DEFAULT_OBSIDIAN_DEB_APP_DIR),
    ]:
        if candidate_path.exists():
            return candidate_kind, candidate_path

    obsidian_fail(
        "Não foi possível detectar instalação do Obsidian. Use --source/--target explícito e --app-dir"
    )
    raise AssertionError("unreachable")


def read_json_file(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        obsidian_fail(f"Arquivo não encontrado: {path}")
    except json.JSONDecodeError as exc:
        obsidian_fail(f"JSON inválido em {path}: {exc}")
    raise AssertionError("unreachable")


def write_json_file(path: Path, payload: dict, dry_run: bool) -> None:
    if dry_run:
        obsidian_log(f"[dry-run] escrever JSON em {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def backup_existing_path(path: Path, dry_run: bool) -> Path | None:
    if not path.exists():
        return None
    backup = path.parent / f"{path.name}.backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    if dry_run:
        obsidian_log(f"[dry-run] backup {path} -> {backup}")
        return backup
    shutil.move(str(path), str(backup))
    return backup


def copy_tree_checked(src: Path, dst: Path, dry_run: bool) -> None:
    if not src.exists():
        obsidian_fail(f"Origem não encontrada: {src}")
    if dry_run:
        obsidian_log(f"[dry-run] copiar árvore {src} -> {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True)


def copy_file_checked(src: Path, dst: Path, dry_run: bool) -> None:
    if not src.exists():
        obsidian_fail(f"Arquivo origem não encontrado: {src}")
    if dry_run:
        obsidian_log(f"[dry-run] copiar arquivo {src} -> {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def inspect_obsidian_config(kind: str, app_dir: Path) -> dict:
    report = {
        "kind": kind,
        "app_dir": str(app_dir),
        "skipped": False,
        "errors": [],
        "app_dir_exists": app_dir.exists(),
        "obsidian_json_exists": False,
        "obsidian_json_valid": False,
        "vault_total": 0,
        "vault_existing_path": 0,
        "vault_with_obsidian_dir": 0,
        "vault_with_remotely_save": 0,
        "vault_missing_paths": [],
        "ready": False,
    }

    if obsidian_is_windows_noop(kind):
        report["skipped"] = True
        report["ready"] = True
        return report

    if not app_dir.exists():
        report["errors"].append("diretório do app não existe")
        return report

    obsidian_json_path = app_dir / "obsidian.json"
    if not obsidian_json_path.exists():
        report["errors"].append("obsidian.json não encontrado")
        return report

    report["obsidian_json_exists"] = True
    try:
        payload = json.loads(obsidian_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        report["errors"].append(f"obsidian.json inválido: {exc}")
        return report

    report["obsidian_json_valid"] = True
    vaults = payload.get("vaults", {})
    if not isinstance(vaults, dict):
        report["errors"].append("campo 'vaults' não é objeto")
        return report

    report["vault_total"] = len(vaults)
    for vault_id, vault_info in vaults.items():
        vault_path_raw = str(vault_info.get("path", "")).strip()
        if not vault_path_raw:
            report["vault_missing_paths"].append(f"{vault_id}:<vazio>")
            continue
        vault_path = Path(vault_path_raw).expanduser()
        if vault_path.exists():
            report["vault_existing_path"] += 1
        else:
            report["vault_missing_paths"].append(f"{vault_id}:{vault_path_raw}")
            continue
        obsidian_dir = vault_path / ".obsidian"
        if obsidian_dir.exists():
            report["vault_with_obsidian_dir"] += 1
            if (obsidian_dir / "plugins/remotely-save/data.json").exists():
                report["vault_with_remotely_save"] += 1

    report["ready"] = report["obsidian_json_valid"]
    return report


def print_obsidian_report(title: str, report: dict) -> None:
    obsidian_log(f"{title} | kind={report['kind']} | app={report['app_dir']}")
    if report["skipped"]:
        obsidian_log("Verificação ignorada: windows em Linux (no-op)")
        return
    obsidian_log(
        "Resumo: "
        f"app_dir_exists={report['app_dir_exists']} "
        f"obsidian_json_exists={report['obsidian_json_exists']} "
        f"obsidian_json_valid={report['obsidian_json_valid']} "
        f"vault_total={report['vault_total']} "
        f"vault_existing_path={report['vault_existing_path']} "
        f"vault_with_obsidian_dir={report['vault_with_obsidian_dir']} "
        f"vault_with_remotely_save={report['vault_with_remotely_save']}"
    )
    for err in report["errors"]:
        obsidian_log(f"Erro: {err}")
    missing = report["vault_missing_paths"]
    if missing:
        preview = ", ".join(missing[:5])
        suffix = " ..." if len(missing) > 5 else ""
        obsidian_log(f"Vaults com path ausente/ inválido ({len(missing)}): {preview}{suffix}")


def sanitize_obsidian_folder_name(name: str, fallback: str) -> str:
    clean = INVALID_OBSIDIAN_FS_CHARS.sub("_", name or "")
    clean = re.sub(r"\\s+", " ", clean).strip(" .")
    return clean or fallback


def normalize_relative_path_key(relative_path: str) -> str:
    """Normaliza caminho relativo preservando separadores para índices path-aware."""
    parts = [normalize_filename(part) for part in str(relative_path).replace("\\", "/").split("/") if part and part != "."]
    return "/".join(part for part in parts if part)


def normalize_relative_path_aggressive_key(relative_path: str) -> str:
    """Normaliza caminho relativo agressivamente preservando separadores."""
    parts = [normalize_aggressive(part) for part in str(relative_path).replace("\\", "/").split("/") if part and part != "."]
    return "/".join(part for part in parts if part)


def relpath_from_root(root: str | Path, path: str | Path) -> str:
    """Calcula caminho relativo em formato posix."""
    return os.path.relpath(os.path.abspath(path), os.path.abspath(root)).replace(os.sep, "/")


def fetch_zotero_collections(zot: zotero.Zotero) -> List[dict]:
    """Busca todas as coleções visíveis da biblioteca."""
    return zot.everything(zot.collections())


def build_collection_path_model(collections: List[dict]) -> tuple[dict[str, dict], dict[str | None, list[str]], dict[str, str]]:
    """Monta o modelo de caminhos de coleção a partir da hierarquia do Zotero."""
    by_key: dict[str, dict] = {}
    children: dict[str | None, list[str]] = {}
    for col in collections:
        key = col.get("key")
        data = col.get("data", {})
        if not key:
            continue
        by_key[key] = {
            "key": key,
            "name": data.get("name", ""),
            "parent": data.get("parentCollection") or None,
            "relative_parts": [],
            "relative_path": "",
        }

    for key, payload in by_key.items():
        parent = payload["parent"]
        if parent and parent not in by_key:
            parent = None
            payload["parent"] = None
        children.setdefault(parent, []).append(key)

    def assign(parent_key: str | None, parent_parts: list[str]) -> None:
        sibling_keys = children.get(parent_key, [])
        sibling_keys.sort(key=lambda k: (by_key[k]["name"] or "").casefold())
        used_names: dict[str, int] = {}
        for key in sibling_keys:
            original_name = by_key[key]["name"]
            fallback = f"collection-{key.lower()}"
            safe_name = sanitize_obsidian_folder_name(original_name, fallback)
            if safe_name in used_names:
                used_names[safe_name] += 1
                safe_name = f"{safe_name} ({used_names[safe_name]})"
            else:
                used_names[safe_name] = 1
            rel_parts = [*parent_parts, safe_name]
            by_key[key]["relative_parts"] = rel_parts
            by_key[key]["relative_path"] = "/".join(rel_parts)
            assign(key, rel_parts)

    assign(None, [])
    path_to_key = {
        normalize_relative_path_key(payload["relative_path"]): key
        for key, payload in by_key.items()
        if payload["relative_path"]
    }
    return by_key, children, path_to_key


def select_primary_collection_key(
    collection_keys: List[str],
    collection_by_key: dict[str, dict],
    preferred_key: str | None = None,
) -> str | None:
    """Escolhe a coleção primária de forma estável."""
    valid = [key for key in collection_keys if key in collection_by_key]
    if preferred_key and preferred_key in valid:
        return preferred_key
    if not valid:
        return None
    return sorted(valid, key=lambda key: (collection_by_key[key]["relative_path"], key))[0]


def item_collection_keys_from_context(
    item: dict,
    parent_items_by_key: dict[str, dict],
) -> List[str]:
    """Retorna coleções relevantes de um anexo, priorizando o pai bibliográfico."""
    data = item.get("data", {})
    parent_key = data.get("parentItem")
    if parent_key and parent_key in parent_items_by_key:
        parent_data = parent_items_by_key[parent_key].get("data", {})
        return list(parent_data.get("collections") or [])
    return list(data.get("collections") or [])


def attachment_target_location(
    item: dict,
    filename: str,
    parent_items_by_key: dict[str, dict],
    collection_by_key: dict[str, dict],
    preferred_collection_key: str | None = None,
) -> dict:
    """Calcula coleção primária e caminho relativo esperado para um anexo."""
    collection_key = select_primary_collection_key(
        item_collection_keys_from_context(item, parent_items_by_key),
        collection_by_key,
        preferred_key=preferred_collection_key,
    )
    if collection_key and collection_key in collection_by_key:
        rel_dir = collection_by_key[collection_key]["relative_path"]
        relative_path = f"{rel_dir}/{filename}" if rel_dir else filename
    else:
        relative_path = filename
    return {
        "collection_key": collection_key,
        "relative_path": relative_path,
    }


def infer_collection_key_from_relative_path(
    relative_path: str,
    path_to_collection_key: dict[str, str],
) -> str | None:
    """Infere a coleção mais específica a partir do caminho relativo."""
    normalized = normalize_relative_path_key(relative_path)
    parts = [part for part in normalized.split("/") if part]
    if len(parts) <= 1:
        return None
    for size in range(len(parts) - 1, 0, -1):
        prefix = "/".join(parts[:size])
        if prefix in path_to_collection_key:
            return path_to_collection_key[prefix]
    return None


def ensure_collection_directories(
    collection_by_key: dict[str, dict],
    drive_root: str,
    obsidian_root: Path,
    stats: dict,
) -> None:
    """Garante a existência das pastas espelhadas de coleção no drive e no Obsidian."""
    stats.setdefault("created_drive_collection_dirs", 0)
    stats.setdefault("created_obsidian_collection_dirs", 0)
    for payload in collection_by_key.values():
        relative_path = payload.get("relative_path")
        if not relative_path:
            continue
        drive_dir = os.path.join(drive_root, *relative_path.split("/"))
        if not os.path.isdir(drive_dir):
            os.makedirs(drive_dir, exist_ok=True)
            stats["created_drive_collection_dirs"] += 1
        obsidian_dir = obsidian_root / Path(relative_path)
        if not obsidian_dir.exists():
            obsidian_dir.mkdir(parents=True, exist_ok=True)
            stats["created_obsidian_collection_dirs"] += 1



def ensure_directory_exists(path: str | Path, stats: dict | None = None, counter_key: str | None = None) -> bool:
    """Cria diretório somente quando necessário e atualiza contador opcional."""
    path = str(path)
    if os.path.isdir(path):
        return False
    os.makedirs(path, exist_ok=True)
    if stats is not None and counter_key:
        stats[counter_key] = stats.get(counter_key, 0) + 1
    return True


def remove_empty_directories(root: str | Path, stats: dict, counter_key: str) -> int:
    """Remove diretórios vazios sob a raiz, preservando diretórios internos especiais."""
    root = os.path.abspath(str(root))
    stats.setdefault(counter_key, 0)
    removed = 0
    protected_names = {'.obsidian', '.trash', '.git', '__pycache__'}
    if not os.path.isdir(root):
        return 0
    for current_root, dirnames, _ in os.walk(root, topdown=False):
        for dirname in dirnames:
            dir_path = os.path.join(current_root, dirname)
            if dirname in protected_names:
                continue
            try:
                if not os.path.isdir(dir_path) or os.path.islink(dir_path):
                    continue
                if any(os.scandir(dir_path)):
                    continue
                os.rmdir(dir_path)
                removed += 1
            except OSError:
                continue
    stats[counter_key] += removed
    return removed


def sync_item_collections_to_drive_collection(
    zot: zotero.Zotero,
    item_key: str,
    drive_collection_key: str | None,
    collection_by_key: dict[str, dict],
    item: dict | None = None,
) -> bool:
    """Torna a coleção do drive a fonte de verdade entre as coleções espelhadas."""
    if not item_key or not drive_collection_key or drive_collection_key not in collection_by_key:
        return False
    try:
        current_item = item if item and item.get("data") else zot.item(item_key)
        item_data = dict(current_item.get("data") or current_item)
        current_collections = list(item_data.get("collections") or [])
        unmanaged = [key for key in current_collections if key not in collection_by_key]
        managed = [key for key in current_collections if key in collection_by_key]
        if managed == [drive_collection_key]:
            return False
        new_collections = [*unmanaged, drive_collection_key]
        if new_collections == current_collections:
            return False
        item_data["collections"] = new_collections
        zot.update_item(item_data)
        if item is not None:
            item.setdefault("data", {})["collections"] = new_collections
        logging.info(
            "[COLLECTION] Item %s agora segue a coleção do drive %s (antes=%s, depois=%s).",
            item_key,
            drive_collection_key,
            current_collections,
            new_collections,
        )
        return True
    except Exception as exc:
        logging.warning(
            "[COLLECTION] Falha ao alinhar item %s à coleção do drive %s: %s",
            item_key,
            drive_collection_key,
            exc,
        )
        return False
def collect_nonempty_directory_paths(root: str | Path) -> list[str]:
    """Lista diretórios relativos que têm conteúdo útil sob a raiz."""
    root = os.path.abspath(str(root))
    if not os.path.isdir(root):
        return []
    protected_names = {'.obsidian', '.trash', '.git', '__pycache__'}
    discovered: set[str] = set()
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in protected_names]
        relative_dir = relpath_from_root(root, current_root)
        has_files = any(not name.startswith('.') for name in filenames)
        if has_files and relative_dir != '.':
            discovered.add(relative_dir)
    return sorted(discovered, key=lambda value: (value.count('/'), value.casefold()))


def ensure_drive_content_collections(
    zot: zotero.Zotero,
    drive_root: str,
    collection_by_key: dict[str, dict],
    collection_path_to_key: dict[str, str],
    stats: dict,
) -> bool:
    """Cria coleções Zotero ausentes para pastas não vazias já existentes no drive."""
    stats.setdefault('created_zotero_collections_from_drive', 0)
    changed = False
    for relative_path in collect_nonempty_directory_paths(drive_root):
        normalized = normalize_relative_path_key(relative_path)
        if not normalized or normalized in collection_path_to_key:
            continue

        parent_collection_key = None
        built_parts: list[str] = []
        for part in [part for part in relative_path.split('/') if part]:
            built_parts.append(part)
            partial_path = '/'.join(built_parts)
            normalized_partial = normalize_relative_path_key(partial_path)
            existing_key = collection_path_to_key.get(normalized_partial)
            if existing_key:
                parent_collection_key = existing_key
                continue

            try:
                created = zot.create_collection([
                    {
                        'name': part,
                        'parentCollection': parent_collection_key or '',
                    }
                ])
                created_key = None
                if isinstance(created, dict):
                    created_key = (
                        created.get('successful', {})
                        .get('0', {})
                        .get('key')
                    )
                if not created_key:
                    logging.warning(
                        "[COLLECTION] Coleção '%s' criada sem chave retornada clara para o caminho '%s'.",
                        part,
                        partial_path,
                    )
                    continue
                collection_by_key[created_key] = {
                    'key': created_key,
                    'name': part,
                    'parent': parent_collection_key,
                    'relative_parts': list(built_parts),
                    'relative_path': partial_path,
                }
                collection_path_to_key[normalized_partial] = created_key
                parent_collection_key = created_key
                stats['created_zotero_collections_from_drive'] += 1
                changed = True
                logging.info(
                    "[COLLECTION] Coleção criada a partir do conteúdo do drive: '%s' (key=%s).",
                    partial_path,
                    created_key,
                )
            except Exception as exc:
                logging.warning(
                    "[COLLECTION] Falha ao criar coleção a partir da pasta '%s': %s",
                    partial_path,
                    exc,
                )
                break
    return changed

def build_expected_attachment_path_indexes(
    attachments: List[dict],
    parent_items_by_key: dict[str, dict],
    collection_by_key: dict[str, dict],
) -> tuple[dict[str, dict], dict[str, dict]]:
    """Indexa caminhos esperados de anexos por relative_path."""
    path_index: dict[str, dict] = {}
    path_aggressive_index: dict[str, dict] = {}
    for item in attachments:
        data = item.get("data", {})
        key = item.get("key") or data.get("key")
        filename = get_filename_from_item(item)
        if not key or not filename:
            continue
        filename = os.path.basename(filename)
        location = attachment_target_location(
            item,
            filename,
            parent_items_by_key,
            collection_by_key,
        )
        info = {
            "key": key,
            "original": filename,
            "dateModified": data.get("dateModified"),
            "relative_path": location["relative_path"],
            "collection_key": location["collection_key"],
        }
        rel_basic = normalize_relative_path_key(location["relative_path"])
        rel_aggressive = normalize_relative_path_aggressive_key(location["relative_path"])
        if rel_basic and rel_basic not in path_index:
            path_index[rel_basic] = info
        if rel_aggressive and rel_aggressive not in path_aggressive_index:
            path_aggressive_index[rel_aggressive] = info
    return path_index, path_aggressive_index


def collect_obsidian_ingest_candidates(
    obsidian_root: Path,
    collection_path_to_key: dict[str, str],
) -> List[dict]:
    """Lista PDFs do Obsidian que vivem sob uma pasta mapeada de coleção."""
    candidates: list[dict] = []
    if not obsidian_root.exists():
        return candidates
    for root, dirnames, filenames in os.walk(obsidian_root):
        dirnames[:] = [name for name in dirnames if name not in {'.obsidian', '.git', '__pycache__'}]
        for name in filenames:
            if not name.lower().endswith('.pdf'):
                continue
            source_path = os.path.join(root, name)
            relative_path = relpath_from_root(obsidian_root, source_path)
            collection_key = infer_collection_key_from_relative_path(relative_path, collection_path_to_key)
            if not collection_key:
                continue
            try:
                mtime = os.path.getmtime(source_path)
            except OSError:
                mtime = 0.0
            candidates.append({
                "path": source_path,
                "filename": name,
                "relative_path": relative_path,
                "collection_key": collection_key,
                "mtime": mtime,
            })
    candidates.sort(key=lambda entry: entry["mtime"], reverse=True)
    return candidates


def ingest_obsidian_pdfs_to_drive(
    obsidian_root: Path,
    drive_root: str,
    collection_by_key: dict[str, dict],
    collection_path_to_key: dict[str, str],
    stats: dict,
) -> None:
    """Move PDFs novos do Obsidian para a pasta correspondente no drive do Zotero."""
    stats.setdefault("obsidian_new_pdfs_detected", 0)
    stats.setdefault("obsidian_pdfs_moved_to_drive", 0)
    stats.setdefault("obsidian_pdfs_blocked", 0)
    stats.setdefault("obsidian_pdfs_deduped", 0)

    candidates = collect_obsidian_ingest_candidates(obsidian_root, collection_path_to_key)
    stats["obsidian_new_pdfs_detected"] += len(candidates)
    for entry in candidates:
        collection_key = entry["collection_key"]
        collection_info = collection_by_key.get(collection_key)
        if not collection_info:
            stats["obsidian_pdfs_blocked"] += 1
            logging.warning("[OBSIDIAN->DRIVE] Coleção %s não encontrada para '%s'.", collection_key, entry["path"])
            continue

        dest_dir = os.path.join(drive_root, *collection_info["relative_parts"])
        dest_path = os.path.join(dest_dir, entry["filename"])
        os.makedirs(dest_dir, exist_ok=True)

        source_hash = compute_sha256(entry["path"])
        if not source_hash:
            stats["obsidian_pdfs_blocked"] += 1
            logging.warning("[OBSIDIAN->DRIVE] Não foi possível hashear '%s'.", entry["path"])
            continue

        if os.path.exists(dest_path):
            dest_hash = compute_sha256(dest_path)
            if dest_hash and dest_hash == source_hash:
                try:
                    os.remove(entry["path"])
                    remove_cache_entry(HASH_CACHE, entry["path"])
                    stats["obsidian_pdfs_deduped"] += 1
                    logging.info(
                        "[OBSIDIAN->DRIVE] PDF redundante removido do Obsidian após confirmar cópia no drive: '%s'.",
                        entry["path"],
                    )
                except OSError as exc:
                    stats["obsidian_pdfs_blocked"] += 1
                    logging.warning("[OBSIDIAN->DRIVE] Falha ao remover redundante '%s': %s", entry["path"], exc)
                continue

            stats["obsidian_pdfs_blocked"] += 1
            logging.warning(
                "[OBSIDIAN->DRIVE] Colisão com conteúdo diferente ao mover '%s' para '%s'.",
                entry["path"],
                dest_path,
            )
            continue

        try:
            shutil.move(entry["path"], dest_path)
            rename_cache_entry(HASH_CACHE, entry["path"], dest_path)
            set_cached_hash(dest_path, source_hash, HASH_CACHE)
            stats["obsidian_pdfs_moved_to_drive"] += 1
            logging.info(
                "[OBSIDIAN->DRIVE] PDF movido para o drive da coleção %s: '%s' -> '%s'.",
                collection_key,
                entry["path"],
                dest_path,
            )
        except OSError as exc:
            stats["obsidian_pdfs_blocked"] += 1
            logging.warning(
                "[OBSIDIAN->DRIVE] Falha ao mover '%s' para '%s': %s",
                entry["path"],
                dest_path,
                exc,
            )


def update_item_collection_membership(
    zot: zotero.Zotero,
    item_key: str,
    collection_key: str | None,
    item: dict | None = None,
) -> bool:
    """Adiciona item a uma coleção se ainda não estiver nela."""
    if not item_key or not collection_key:
        return False
    try:
        current_item = item if item and item.get("data") else zot.item(item_key)
        item_data = dict(current_item.get("data") or current_item)
        collections = list(item_data.get("collections") or [])
        if collection_key in collections:
            return False
        item_data["collections"] = sorted(set(collections + [collection_key]))
        zot.update_item(item_data)
        if item is not None:
            item.setdefault("data", {})["collections"] = item_data["collections"]
        logging.info("[COLLECTION] Item %s adicionado à coleção %s.", item_key, collection_key)
        return True
    except Exception as exc:
        logging.warning("[COLLECTION] Falha ao adicionar item %s à coleção %s: %s", item_key, collection_key, exc)
        return False



def resolve_obsidian_mirror_target_root(target_root: str | None) -> Path:
    target_root_raw = (
        target_root
        or os.environ.get("OBSIDIAN_ZOTERO_MIRROR_ROOT", "").strip()
        or str(DEFAULT_OBSIDIAN_TARGET_ROOT)
    )
    return Path(os.path.expanduser(target_root_raw)).resolve()


def mirror_zotero_collections_to_obsidian(
    zot: zotero.Zotero,
    target_root: Path,
    apply_changes: bool,
) -> dict:
    collections = fetch_zotero_collections(zot)
    obsidian_log(f"Coleções encontradas: {len(collections)}")
    obsidian_log(f"Destino Obsidian: {target_root}")
    obsidian_log(f"Modo: {'APPLY' if apply_changes else 'DRY-RUN'}")

    by_key, children, _ = build_collection_path_model(collections)

    created = 0
    existed = 0
    collisions = 0

    def mirror_subtree(parent_key: str | None, base_path: Path) -> None:
        nonlocal created, existed, collisions
        sibling_keys = children.get(parent_key, [])
        sibling_keys.sort(key=lambda k: (by_key[k]["relative_path"], k))
        for key in sibling_keys:
            safe_name = by_key[key]["relative_parts"][-1]
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
    obsidian_log(f"pastas já existentes: {existed}")
    obsidian_log(f"pastas criadas{' (simuladas)' if not apply_changes else ''}: {created}")
    obsidian_log(f"colisões de nome resolvidas: {collisions}")
    return {
        "existing": existed,
        "created": created,
        "collisions": collisions,
        "collection_total": len(collections),
        "target_root": str(target_root),
        "apply": apply_changes,
    }


def run_obsidian_verify_mode(args: argparse.Namespace) -> None:
    if obsidian_is_windows_noop(args.kind):
        obsidian_log("kind=windows em Linux, nenhuma ação executada (no-op)")
        return
    kind, app_dir = resolve_obsidian_app_dir(args.kind, args.app_dir)
    report = inspect_obsidian_config(kind, app_dir)
    print_obsidian_report("Verificação", report)
    if args.strict and not report["ready"]:
        obsidian_fail("Verificação falhou em modo --strict")


def run_obsidian_export_mode(args: argparse.Namespace) -> None:
    if obsidian_is_windows_noop(args.source):
        obsidian_log("source=windows em Linux, nenhuma ação executada (no-op)")
        return
    source_kind, app_dir = resolve_obsidian_app_dir(args.source, args.app_dir)
    source_report = inspect_obsidian_config(source_kind, app_dir)
    print_obsidian_report("Pré-verificação (export)", source_report)
    if not source_report["ready"]:
        obsidian_fail("Configuração de origem inválida para exportar")

    obsidian_json_path = app_dir / "obsidian.json"
    obsidian_json = read_json_file(obsidian_json_path)
    out_dir = Path(args.out).expanduser()
    if out_dir.exists() and not args.force:
        obsidian_fail(f"Diretório de saída já existe: {out_dir}. Use --force para sobrescrever")
    if out_dir.exists() and args.force and not args.dry_run:
        shutil.rmtree(out_dir)

    app_bundle = out_dir / "app"
    vaults_bundle = out_dir / "vaults"
    for candidate in app_dir.glob("*.json"):
        copy_file_checked(candidate, app_bundle / candidate.name, args.dry_run)

    vaults_info: dict[str, dict] = obsidian_json.get("vaults", {})
    exported = 0
    skipped = 0
    for vault_id, info in vaults_info.items():
        vault_path = Path(info.get("path", "")).expanduser()
        obsidian_dir = vault_path / ".obsidian"
        bundle_target = vaults_bundle / vault_id / ".obsidian"
        if obsidian_dir.exists():
            copy_tree_checked(obsidian_dir, bundle_target, args.dry_run)
            exported += 1
        else:
            skipped += 1
            obsidian_log(f"Aviso: vault '{vault_id}' sem pasta .obsidian em {obsidian_dir}")

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_kind": source_kind,
        "source_app_dir": str(app_dir),
        "vault_count": len(vaults_info),
        "exported_vault_count": exported,
        "skipped_vault_count": skipped,
    }
    write_json_file(out_dir / "manifest.json", manifest, args.dry_run)
    obsidian_log(f"Bundle exportado em: {out_dir}")
    obsidian_log(f"Vaults exportados: {exported}, ignorados: {skipped}")


def resolve_target_vault_path(
    original_path: str,
    target_kind: str,
    map_pairs: List[Tuple[str, str]],
) -> str:
    mapped = replace_path_prefix(original_path, map_pairs)
    if target_kind == "windows":
        mapped = windows_style_path(mapped)
    return mapped


def run_obsidian_apply_mode(args: argparse.Namespace) -> None:
    if obsidian_is_windows_noop(args.target):
        obsidian_log("target=windows em Linux, nenhuma ação executada (no-op)")
        return

    bundle_dir = Path(args.bundle).expanduser()
    if not bundle_dir.exists():
        obsidian_fail(f"Bundle não encontrado: {bundle_dir}")
    app_bundle = bundle_dir / "app"
    vaults_bundle = bundle_dir / "vaults"
    source_obsidian_json = read_json_file(app_bundle / "obsidian.json")

    target_kind, target_app_dir = resolve_obsidian_app_dir(args.target, args.app_dir)
    map_pairs = parse_path_map_entries(args.map)
    pre_report = inspect_obsidian_config(target_kind, target_app_dir)
    print_obsidian_report("Pré-verificação (apply)", pre_report)

    if target_app_dir.exists():
        for existing_json in target_app_dir.glob("*.json"):
            backup_existing_path(existing_json, args.dry_run)

    for bundled_json in app_bundle.glob("*.json"):
        if bundled_json.name == "obsidian.json":
            continue
        copy_file_checked(bundled_json, target_app_dir / bundled_json.name, args.dry_run)

    source_vaults: dict[str, dict] = source_obsidian_json.get("vaults", {})
    target_vaults: dict[str, dict] = {}
    for vault_id, vault_info in source_vaults.items():
        original_path = str(vault_info.get("path", "")).strip()
        if not original_path:
            obsidian_log(f"Aviso: vault '{vault_id}' sem path válido. Ignorando")
            continue

        mapped_path = resolve_target_vault_path(original_path, target_kind, map_pairs)
        local_vault_path = Path(mapped_path).expanduser()
        if target_kind == "windows" and os.name == "nt":
            local_vault_path = Path(mapped_path)

        if not local_vault_path.exists():
            if args.create_missing_vaults:
                if args.dry_run:
                    obsidian_log(f"[dry-run] criar vault ausente: {local_vault_path}")
                else:
                    local_vault_path.mkdir(parents=True, exist_ok=True)
            else:
                obsidian_log(
                    f"Aviso: vault '{vault_id}' não existe em {local_vault_path}. Use --create-missing-vaults para criar"
                )
                continue

        target_obsidian_dir = local_vault_path / ".obsidian"
        backup_existing_path(target_obsidian_dir, args.dry_run)
        source_obsidian_dir = vaults_bundle / vault_id / ".obsidian"
        if source_obsidian_dir.exists():
            copy_tree_checked(source_obsidian_dir, target_obsidian_dir, args.dry_run)
        else:
            obsidian_log(f"Aviso: bundle sem .obsidian para vault '{vault_id}'")

        target_vaults[vault_id] = {
            **vault_info,
            "path": mapped_path,
        }

    rewritten = {
        **source_obsidian_json,
        "vaults": target_vaults,
    }
    write_json_file(target_app_dir / "obsidian.json", rewritten, args.dry_run)
    post_report = inspect_obsidian_config(target_kind, target_app_dir)
    print_obsidian_report("Pós-verificação (apply)", post_report)
    obsidian_log(f"Configuração aplicada em: {target_app_dir}")
    obsidian_log(f"Vaults configurados: {len(target_vaults)}")


def run_obsidian_mirror_mode(args: argparse.Namespace) -> None:
    apply_changes = args.apply and not args.dry_run
    target_root = resolve_obsidian_mirror_target_root(args.target_root)
    obsidian_log("Conectando ao Zotero para espelhar coleções...")
    zot = connect_zotero_client()
    mirror_zotero_collections_to_obsidian(zot, target_root, apply_changes)


def run_obsidian_setup_mode(args: argparse.Namespace) -> None:
    dry_run = args.dry_run or not args.apply
    apply_args = argparse.Namespace(
        target=args.target,
        app_dir=args.app_dir,
        bundle=args.bundle,
        map=args.map,
        create_missing_vaults=args.create_missing_vaults,
        dry_run=dry_run,
    )
    mirror_args = argparse.Namespace(
        target_root=args.target_root,
        dry_run=dry_run,
        apply=args.apply,
    )
    run_obsidian_apply_mode(apply_args)
    run_obsidian_mirror_mode(mirror_args)


def run_bootstrap() -> None:
    """Configura um PC Linux novo para sync automático do Zotero."""
    import importlib

    script_path = Path(__file__).resolve()
    config_dir = Path.home() / ".config" / "zotero_sync_webdav"
    env_file = config_dir / "zotero_sync.env"

    print("=" * 60)
    print("  BOOTSTRAP — Zotero Sync WebDAV")
    print("=" * 60)
    print()

    # --- Step 1: System dependencies ---
    print("1/6  Dependências do sistema")
    print("-" * 40)
    sys_deps = {
        "python3": "Runtime Python",
        "rclone": "Mount do Google Drive",
        "pdftotext": "Preview de conteúdo de PDFs (poppler-utils)",
        "zotero": "Zotero Desktop (headless import)",
    }
    missing_sys = []
    for cmd, desc in sys_deps.items():
        found = shutil.which(cmd)
        if found:
            print(f"  ✔ {cmd}: {found}")
        else:
            print(f"  ✗ {cmd}: NÃO ENCONTRADO — {desc}")
            missing_sys.append(cmd)
    if missing_sys:
        print()
        print("  Instale as dependências ausentes:")
        apt_map = {"pdftotext": "poppler-utils", "rclone": "rclone"}
        apt_pkgs = [apt_map.get(m, m) for m in missing_sys if m != "zotero"]
        if apt_pkgs:
            print(f"    sudo apt install {' '.join(apt_pkgs)}")
        if "zotero" in missing_sys:
            print("    Zotero: https://www.zotero.org/download/")
            print("    Depois crie ~/.local/bin/zotero apontando para o binário")
    print()

    # --- Step 2: Python dependencies ---
    print("2/6  Dependências Python")
    print("-" * 40)
    py_deps = ["pyzotero", "python-dotenv"]
    missing_py = []
    for pkg in py_deps:
        mod_name = pkg.replace("-", "_")
        try:
            import_name = "dotenv" if pkg == "python-dotenv" else pkg
            importlib.import_module(import_name)
            print(f"  ✔ {pkg}")
        except ImportError:
            print(f"  ✗ {pkg}: NÃO INSTALADO")
            missing_py.append(pkg)
    if missing_py:
        print()
        print(f"    pip install {' '.join(missing_py)}")
    print()

    # --- Step 3: rclone mount ---
    print("3/6  Mount do Google Drive (rclone)")
    print("-" * 40)
    rclone_svc = subprocess.run(
        ["systemctl", "--user", "is-active", "rclone-google-drive.service"],
        capture_output=True, text=True,
    )
    if rclone_svc.stdout.strip() == "active":
        print("  ✔ rclone-google-drive.service: active")
    else:
        print("  ✗ rclone-google-drive.service: não encontrado ou inativo")
        print()
        print("  Para configurar:")
        print("    1. rclone config  (criar remote 'Google Drive:')")
        print("    2. Criar ~/.config/systemd/user/rclone-google-drive.service")
        print("    3. systemctl --user enable --now rclone-google-drive.service")
    drive_path = Path.home() / "Google Drive" / "zoterodb"
    if drive_path.is_dir():
        print(f"  ✔ Pasta do drive: {drive_path}")
    else:
        print(f"  ✗ Pasta do drive não encontrada: {drive_path}")
    print()

    # --- Step 4: .env / credentials ---
    print("4/6  Credenciais Zotero (.env)")
    print("-" * 40)
    env_ok = True
    if env_file.is_file():
        print(f"  ✔ {env_file}")
    elif Path(".env").is_file():
        print(f"  ✔ .env local (projeto)")
    else:
        env_ok = False
        print(f"  ✗ Nenhum .env encontrado")
        print()
        print("  Criando .env interativamente...")
        try:
            lib_id = input("    ZOTERO_LIBRARY_ID (número): ").strip()
            api_key = input("    ZOTERO_API_KEY: ").strip()
            target = input(
                f"    Pasta de sync [{drive_path}]: "
            ).strip() or str(drive_path)
            config_dir.mkdir(parents=True, exist_ok=True)
            env_content = (
                f"ZOTERO_LIBRARY_ID={lib_id}\n"
                f"ZOTERO_LIBRARY_TYPE=user\n"
                f"ZOTERO_API_KEY={api_key}\n"
                f'ZOTERO_SYNC_TARGET_FOLDER="{target}"\n'
            )
            env_file.write_text(env_content, encoding="utf-8")
            print(f"  ✔ Salvo em {env_file}")
            Path(".env").write_text(env_content, encoding="utf-8")
            print(f"  ✔ Salvo em .env (local)")
            env_ok = True
        except EOFError:
            print("  ✗ Entrada interrompida. Crie manualmente:")
            print(f"    {env_file}")
    print()

    # --- Step 5: Validate Zotero API connection ---
    print("5/6  Conexão com Zotero API")
    print("-" * 40)
    api_ok = False
    if env_ok and not missing_py:
        try:
            from dotenv import load_dotenv as _ld
            _ld(str(env_file) if env_file.is_file() else ".env")
            from pyzotero import zotero as _z
            _lib = os.environ.get("ZOTERO_LIBRARY_ID", "")
            _key = os.environ.get("ZOTERO_API_KEY", "")
            if _lib and _key:
                # Silence httpx debug logs for the connection test
                prev_level = logging.getLogger().getEffectiveLevel()
                logging.getLogger().setLevel(logging.WARNING)
                try:
                    _zot = _z.Zotero(_lib, "user", _key)
                    _zot.key_info()
                finally:
                    logging.getLogger().setLevel(prev_level)
                print(f"  ✔ Conectado à biblioteca {_lib}")
                api_ok = True
            else:
                print("  ✗ ZOTERO_LIBRARY_ID ou ZOTERO_API_KEY vazios")
        except Exception as exc:
            print(f"  ✗ Falha na conexão: {exc}")
    else:
        print("  ⏭️  Pulando (dependências ou .env ausentes)")
    print()

    # --- Step 6: Install systemd services ---
    print("6/6  Serviços systemd (autostart)")
    print("-" * 40)
    timer_active = subprocess.run(
        ["systemctl", "--user", "is-active", "zotero-sync.timer"],
        capture_output=True, text=True,
    ).stdout.strip() == "active"
    if timer_active:
        print("  ✔ zotero-sync.timer: active")
    else:
        print("  ✗ zotero-sync.timer: não instalado ou inativo")
    watcher_ok = subprocess.run(
        ["systemctl", "--user", "is-enabled", "zotero-sync-watch.service"],
        capture_output=True, text=True,
    ).stdout.strip() == "enabled"
    if watcher_ok:
        print("  ✔ zotero-sync-watch.service: enabled")
    else:
        print("  ✗ zotero-sync-watch.service: não instalado")

    if not timer_active or not watcher_ok:
        print()
        if api_ok:
            print("  Instalando serviços...")
            run_setup_autostart_mode([])
        else:
            print("  Resolva os passos anteriores e rode:")
            print(f"    python3 {script_path.name} setup-autostart")
    print()

    # --- Summary ---
    print("=" * 60)
    all_ok = not missing_sys and not missing_py and env_ok and api_ok and timer_active
    if all_ok:
        print("  ✅ Tudo configurado! O Zotero sincroniza sozinho em segundo plano.")
        print()
        print("  Para replicar num outro PC:")
        print(f"    1. git clone <repo>")
        print(f"    2. cd zotero_sync_webdav")
        print(f"    3. python3 {script_path.name} bootstrap")
    else:
        print("  ⚠️  Há itens pendentes acima. Resolva e rode bootstrap novamente.")
    print("=" * 60)
def build_cli_parser() -> argparse.ArgumentParser:
    """Constrói a CLI unificada do workflow Zotero/WebDAV."""
    parser = argparse.ArgumentParser(
        description='Entry point unificado do workflow Zotero/WebDAV',
    )
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('sync', help='Executa a sincronização principal')
    subparsers.add_parser('diagnostico', help='Roda o diagnóstico de duplicatas e ausências')

    remove_parser = subparsers.add_parser(
        'remove-duplicatas',
        help='Detecta e remove duplicatas na biblioteca Zotero',
    )
    remove_parser.add_argument(
        '--executar',
        action='store_true',
        help='Apaga de verdade os anexos duplicados',
    )


    obsidian_verify_parser = subparsers.add_parser(
        'obsidian-verify',
        help='Verifica a configuração atual do Obsidian',
    )
    obsidian_verify_parser.add_argument('--kind', choices=['auto', 'snap', 'deb', 'windows'], default='auto')
    obsidian_verify_parser.add_argument('--app-dir', help='Diretório do app Obsidian (override manual)')
    obsidian_verify_parser.add_argument('--strict', action='store_true', help='Falha se a configuração estiver inválida')

    obsidian_export_parser = subparsers.add_parser(
        'obsidian-export',
        help='Exporta configuração do Obsidian para um bundle',
    )
    obsidian_export_parser.add_argument('--source', choices=['auto', 'snap', 'deb', 'windows'], default='auto')
    obsidian_export_parser.add_argument('--app-dir', help='Diretório do app Obsidian (override manual)')
    obsidian_export_parser.add_argument('--out', required=True, help='Diretório de saída do bundle')
    obsidian_export_parser.add_argument('--force', action='store_true', help='Sobrescreve bundle existente')
    obsidian_export_parser.add_argument('--dry-run', action='store_true', help='Simula sem escrever')

    obsidian_apply_parser = subparsers.add_parser(
        'obsidian-apply',
        help='Aplica um bundle de configuração do Obsidian',
    )
    obsidian_apply_parser.add_argument('--target', choices=['auto', 'snap', 'deb', 'windows'], required=True)
    obsidian_apply_parser.add_argument('--app-dir', help='Diretório do app Obsidian (override manual)')
    obsidian_apply_parser.add_argument('--bundle', required=True, help='Diretório do bundle exportado')
    obsidian_apply_parser.add_argument('--map', action='append', help='Mapeia prefixo de path: antigo=novo')
    obsidian_apply_parser.add_argument('--create-missing-vaults', action='store_true', help='Cria vaults ausentes no destino')
    obsidian_apply_parser.add_argument('--dry-run', action='store_true', help='Simula sem escrever')

    obsidian_mirror_parser = subparsers.add_parser(
        'obsidian-mirror',
        help='Espelha coleções do Zotero como pastas no Obsidian',
    )
    obsidian_mirror_parser.add_argument(
        '--target-root',
        help='Diretório raiz de destino no Obsidian. Padrão: OBSIDIAN_ZOTERO_MIRROR_ROOT ou ~/Documentos/ObsidianLocal',
    )
    obsidian_mirror_parser.add_argument('--dry-run', action='store_true', help='Só mostra o que faria, sem criar pastas')
    obsidian_mirror_parser.add_argument('--apply', action='store_true', help='Aplica de fato a criação das pastas')

    obsidian_setup_parser = subparsers.add_parser(
        'obsidian-setup',
        help='Aplica configuração do Obsidian e espelha coleções do Zotero',
    )
    obsidian_setup_parser.add_argument('--target', choices=['auto', 'snap', 'deb', 'windows'], required=True)
    obsidian_setup_parser.add_argument('--app-dir', help='Diretório do app Obsidian (override manual)')
    obsidian_setup_parser.add_argument('--bundle', required=True, help='Diretório do bundle exportado')
    obsidian_setup_parser.add_argument('--map', action='append', help='Mapeia prefixo de path: antigo=novo')
    obsidian_setup_parser.add_argument('--create-missing-vaults', action='store_true', help='Cria vaults ausentes no destino')
    obsidian_setup_parser.add_argument(
        '--target-root',
        help='Diretório raiz de destino no Obsidian para o espelho das coleções',
    )
    obsidian_setup_parser.add_argument('--dry-run', action='store_true', help='Simula sem escrever')
    obsidian_setup_parser.add_argument('--apply', action='store_true', help='Aplica de fato configuração e espelho')

    setup_parser = subparsers.add_parser(
        'setup-autostart',
        help='Executa o configurador de autostart integrado',
    )
    setup_parser.add_argument(
        'setup_args',
        nargs=argparse.REMAINDER,
        help='Argumentos extras repassados ao configurador embutido',
    )
    recovery_parser = subparsers.add_parser(
        'recover-orphans',
        help='Recupera PDFs órfãos do Zotero que faltam no drive',
    )
    recovery_parser.add_argument('--dry-run', action='store_true', help='Simula sem materializar')

    subparsers.add_parser(
        'bootstrap',
        help='Configura um PC Linux novo: verifica dependências, cria .env, instala serviços systemd',
    )

    subparsers.add_parser(
        'watch-zotero',
        help='Serviço residente que dispara o sync quando o Zotero é aberto',
    )

    return parser



def run_recover_orphans_mode(dry_run: bool = False) -> None:
    """Recupera PDFs órfãos: conhecidos pelo Zotero mas ausentes no drive."""
    check_environment_requirements()
    print("🔍 Recuperação de PDFs órfãos do Zotero")
    print(f"   Modo: {'simulação (dry-run)' if dry_run else 'execução real'}")
    
    zot = connect_zotero_client()
    print("✓ Conexão com a Zotero API bem-sucedida.")
    
    stats = {
        'zotero_attachments_scanned': 0,
        'zotero_unique_filenames': 0,
        'errors': 0,
        'materialized_drive': 0,
        'downloaded_zotero': 0,
        'renamed_webdav': 0,
        'moved_drive_files_to_collection': 0,
    }
    
    (all_attachments, existing_filenames, existing_filenames_aggressive) = collect_all_attachments(zot, stats)
    
    collections = fetch_zotero_collections(zot)
    collection_by_key, children_map, collection_path_to_key = build_collection_path_model(collections)
    
    parent_items = collect_all_bibliographic_items(zot, stats)
    parent_items_by_key = build_item_by_key(parent_items)
    
    drive_name_index, drive_aggressive_index, drive_path_index, drive_path_aggressive_index, drive_hash_index = build_drive_pdf_index(TARGET_FOLDER, stats)
    
    key_to_path: Dict[str, str] = {}
    
    # Find orphaned attachments
    orphan_count = 0
    for item in all_attachments:
        data = item.get('data', {})
        key = item.get('key')
        filename = get_filename_from_item(item)
        if not filename or not filename.lower().endswith('.pdf'):
            continue
        filename = os.path.basename(filename)
        norm = normalize_filename(filename)
        agg = normalize_aggressive(filename)
        if norm in drive_name_index or agg in drive_aggressive_index:
            continue
        orphan_count += 1
    
    print(f"\n📊 Encontrados {orphan_count} PDFs órfãos (no Zotero, ausentes no drive).")
    
    if dry_run:
        print("   (dry-run: nenhum arquivo será materializado)")
        return
    
    if orphan_count == 0:
        print("   Nada a recuperar.")
        return
    
    tie_conflicts: list[dict[str, str]] = []
    materialize_zotero_attachments_to_drive(
        zot,
        all_attachments,
        parent_items_by_key,
        collection_by_key,
        drive_name_index,
        drive_aggressive_index,
        drive_path_index,
        drive_path_aggressive_index,
        drive_hash_index,
        key_to_path,
        stats,
        tie_conflicts,
    )
    
    print(f"\n✅ Recuperação concluída:")
    print(f"   Materializados: {stats['materialized_drive']}")
    print(f"   Baixados do Zotero: {stats['downloaded_zotero']}")
    print(f"   Erros: {stats['errors']}")
    
    if stats['errors'] > 0:
        sys.exit(1)

def preflight_checks() -> list[str]:
    """Valida pré-requisitos antes de iniciar o sync.
    
    Retorna lista de erros. Lista vazia = tudo OK.
    """
    errors: list[str] = []
    
    # 1. Variáveis de ambiente
    try:
        check_environment_requirements()
    except RuntimeError as e:
        errors.append(str(e))
        return errors  # sem config, não faz sentido checar o resto
    
    # 2. Pasta alvo existe e é legível
    if not TARGET_FOLDER:
        errors.append("ZOTERO_SYNC_TARGET_FOLDER está vazio após resolução.")
    elif not os.path.isdir(TARGET_FOLDER):
        errors.append(f"Pasta alvo não encontrada ou não é diretório: {TARGET_FOLDER}")
    elif not os.access(TARGET_FOLDER, os.R_OK):
        errors.append(f"Pasta alvo sem permissão de leitura: {TARGET_FOLDER}")
    
    # 3. Local storage existe e é gravável
    if os.path.isdir(LOCAL_COPY_DIR):
        if not os.access(LOCAL_COPY_DIR, os.W_OK):
            errors.append(f"Pasta de storage local sem permissão de escrita: {LOCAL_COPY_DIR}")
    else:
        try:
            os.makedirs(LOCAL_COPY_DIR, exist_ok=True)
        except OSError as exc:
            errors.append(f"Não foi possível criar pasta de storage local {LOCAL_COPY_DIR}: {exc}")
    
    # 4. Zotero Desktop (opcional, não bloqueia)
    # Apenas informativo — não adicionamos erro aqui.
    
    return errors




def ensure_single_instance() -> None:
    """Garante que apenas uma instância do script rode usando fcntl lock."""
    import fcntl
    import tempfile
    global _SINGLE_INSTANCE_LOCK_FD
    if '_SINGLE_INSTANCE_LOCK_FD' in globals() and _SINGLE_INSTANCE_LOCK_FD is not None:
        return
        
    lock_file = os.path.join(tempfile.gettempdir(), 'zotero_sync_webdav.lock')
    try:
        fd = os.open(lock_file, os.O_CREAT | os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _SINGLE_INSTANCE_LOCK_FD = fd
    except BlockingIOError:
        logging.error("[SYSTEM] Outra instância do Zotero Sync já está em execução. Abortando.")
        print("❌ Sincronização cancelada: Outra instância já está em execução.")
        sys.exit(1)
    except Exception as e:
        logging.warning("[SYSTEM] Não foi possível criar arquivo de lock de instância: %s", e)

def get_registered_folders(target_folder: str) -> dict[str, str]:
    import json
    state_file = os.path.join(target_folder, ".zotero_folders.json")
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def preprocess_drive_duplicate_folders(target_folder: str, stats: dict) -> None:
    import shutil
    logging.info("[DEDUP-FOLDER] Verificando pastas duplicadas no Drive...")
    registered_folders = get_registered_folders(target_folder)
    registered_paths = set(registered_folders.values())
    
    def _get_core_name(name: str) -> str:
        import re
        core = re.sub(r'^[A-Z]{2}\d{4}\s*-\s*', '', name)
        core = re.sub(r'\s*\[.*?\]\s*$', '', core)
        return normalize_aggressive(core)

    for root, dirs, files in os.walk(target_folder, topdown=False):
        if '.obsidian' in root or '.git' in root or 'trash' in root:
            continue
        groups = {}
        for d in dirs:
            if d.startswith('.'): continue
            core = _get_core_name(d)
            if core:
                groups.setdefault(core, []).append(d)
        for core, dup_dirs in groups.items():
            if len(dup_dirs) > 1:
                canon_dir = None
                canon_score = -1
                for d in dup_dirs:
                    full_rel_path = relpath_from_root(target_folder, os.path.join(root, d))
                    score = 0
                    if full_rel_path in registered_paths:
                        score += 1000
                    pdf_count = len([f for f in os.listdir(os.path.join(root, d)) if f.lower().endswith('.pdf')])
                    score += pdf_count
                    if score > canon_score:
                        canon_score = score
                        canon_dir = d
                if canon_dir:
                    dup_dirs.remove(canon_dir)
                    canon_full_path = os.path.join(root, canon_dir)
                    for dup in dup_dirs:
                        dup_full_path = os.path.join(root, dup)
                        for item in os.listdir(dup_full_path):
                            src_item = os.path.join(dup_full_path, item)
                            dst_item = os.path.join(canon_full_path, item)
                            if os.path.isfile(src_item) and item.lower().endswith('.pdf'):
                                if not os.path.exists(dst_item):
                                    shutil.move(src_item, dst_item)
                                else:
                                    src_hash = compute_sha256(src_item)
                                    dst_hash = compute_sha256(dst_item)
                                    if src_hash == dst_hash:
                                        os.remove(src_item)
                                    else:
                                        base, ext = os.path.splitext(item)
                                        shutil.move(src_item, os.path.join(canon_full_path, f"{base} (cópia){ext}"))
                            elif os.path.isfile(src_item) and not os.path.exists(dst_item):
                                shutil.move(src_item, dst_item)
                        try:
                            remaining = os.listdir(dup_full_path)
                            if not remaining or all(f.startswith('.') for f in remaining):
                                shutil.rmtree(dup_full_path)
                                stats.setdefault('pruned_drive_duplicates', 0)
                                stats['pruned_drive_duplicates'] += 1
                        except Exception:
                            pass

def run_sync_mode(notification_policy: dict | None = None):
    """Executa a sincronização observando API do Zotero, drive montado e storage local."""
    notification_policy = notification_policy or {"announce_start": False, "progress": False, "completion": True}
    if notification_policy.get("announce_start"):
        send_sync_progress_notification(build_first_open_sync_notification_body())
    ensure_single_instance()
    configure_pyzotero_upload_transport()
    
    # 0. Preflight
    pf_errors = preflight_checks()
    if pf_errors:
        for e in pf_errors:
            logging.error("[PREFLIGHT] %s", e)
        print("❌ Preflight falhou:")
        for e in pf_errors:
            print(f"  - {e}")
        sys.exit(1)
    
    print("Iniciando o sincronizador Zotero/WebDAV (v2.0)")
    stats = {
        'added': 0,
        'skipped': 0,
        'errors': 0,
        'recoverable_hash_skips': 0,
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
        'mtime_ties': 0,
        'pruned_drive_duplicates': 0,
        'materialized_drive': 0,
        'downloaded_zotero': 0,
        'zotero_bibliographic_scanned': 0,
        'zotero_bibliographic_indexed': 0,
        'attached_to_existing_parent': 0,
        'blocked_duplicate_risk': 0,
        'bibliographic_duplicate_groups': 0,
        'auto_removed_bibliographic_duplicates': 0,
        'auto_duplicate_cleanup_skipped': 0,
        'merged_duplicate_metadata': 0,
        'canonical_attachment_names': 0,
        'normalized_standalone_attachments': 0,
        'desktop_plugin_updates': 0,
        'desktop_recognition_requested': 0,
        'desktop_recognition_processed': 0,
        'desktop_recognition_skipped': 0,
        'desktop_parent_fallbacks': 0,
        'created_drive_collection_dirs': 0,
        'created_obsidian_collection_dirs': 0,
        'created_zotero_collections_from_drive': 0,
        'drive_authoritative_collection_updates': 0,
        'obsidian_new_pdfs_detected': 0,
        'obsidian_pdfs_moved_to_drive': 0,
        'obsidian_pdfs_blocked': 0,
        'obsidian_pdfs_deduped': 0,
        'preprocessed_drive_copy_variants': 0,
        'blocked_drive_copy_variants': 0,
        'removed_empty_drive_dirs': 0,
        'removed_empty_obsidian_dirs': 0,
        'moved_drive_files_to_collection': 0,
        'review_tags_applied': 0,
        'review_tags_removed': 0,
        'current_review_duplicate_keys': set(),
    }
    tie_conflicts: list[dict[str, str]] = []


    # 0.5. Deduplicação e renomeio PRÉVIO de Pastas e Arquivos do Drive
    print("\nExecutando deduplicação e renomeio prévio no Drive...")
    preprocess_drive_duplicate_folders(TARGET_FOLDER, stats)
    
    if os.path.isdir(TARGET_FOLDER):
        _pre_files = collect_all_pdfs(TARGET_FOLDER, stats)
        preprocess_drive_copy_variants(_pre_files, stats)

    # 1. Conectar ao Zotero
    try:
        check_environment_requirements()
        zot = connect_zotero_client()
        print("✓ Conexão com a Zotero API bem-sucedida.")
    except Exception as e:
        logging.error(f"Falha ao conectar à Zotero API. Verifique suas credenciais. Erro: {e}")
        finalize_execution(stats)
        sys.exit(1)

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

    standalone_names_changed = normalize_standalone_attachment_names(
        zot,
        all_attachments,
        stats,
    )
    if standalone_names_changed:
        logging.info("[NOME-STANDALONE] Recarregando anexos após normalização de PDFs standalone.")
        (
            all_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_all_attachments(zot, stats)
        stats['zotero_unique_filenames'] = len(existing_filenames)

    desktop_recognition_changed = recognize_standalone_pdf_attachments(
        all_attachments,
        stats,
    )
    if desktop_recognition_changed:
        logging.info("[DESKTOP] Recarregando anexos após reconhecimento local de PDFs standalone.")
        (
            all_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_all_attachments(zot, stats)
        stats['zotero_unique_filenames'] = len(existing_filenames)

    print("\nColetando itens bibliográficos para evitar anexos soltos duplicadores...")
    try:
        bibliographic_items = collect_all_bibliographic_items(zot, stats)
        bibliographic_parent_index = build_bibliographic_parent_index(bibliographic_items)
        stats['zotero_bibliographic_indexed'] = len(bibliographic_parent_index)
        parent_items_by_key = build_item_by_key(bibliographic_items)
        print(
            f"✓ {stats['zotero_bibliographic_scanned']} itens bibliográficos escaneados | "
            f"{stats['zotero_bibliographic_indexed']} títulos candidatos indexados."
        )
    except Exception as e:
        stats['errors'] += 1
        logging.error(
            "[BIB] Erro ao coletar itens bibliográficos: %s. "
            "Sincronização abortada para evitar criação de anexos soltos que podem virar duplicatas.",
            e,
        )
        finalize_execution(stats)
        return

    canonical_names_changed = enforce_attachment_metadata_filenames(
        zot,
        all_attachments,
        parent_items_by_key,
        stats,
    )
    if canonical_names_changed:
        logging.info("[NOME-CANONICO] Recarregando anexos após normalização por metadados.")
        (
            all_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_all_attachments(zot, stats)
        stats['zotero_unique_filenames'] = len(existing_filenames)

    collections = fetch_zotero_collections(zot)
    collection_by_key, collection_children, collection_path_to_key = build_collection_path_model(collections)
    if ensure_drive_content_collections(
        zot,
        TARGET_FOLDER,
        collection_by_key,
        collection_path_to_key,
        stats,
    ):
        collections = fetch_zotero_collections(zot)
        collection_by_key, collection_children, collection_path_to_key = build_collection_path_model(collections)
    obsidian_root = resolve_obsidian_mirror_target_root(None)
    remove_empty_directories(TARGET_FOLDER, stats, 'removed_empty_drive_dirs')
    remove_empty_directories(obsidian_root, stats, 'removed_empty_obsidian_dirs')
    ensure_collection_directories(collection_by_key, TARGET_FOLDER, obsidian_root, stats)

    ingest_obsidian_pdfs_to_drive(
        obsidian_root,
        TARGET_FOLDER,
        collection_by_key,
        collection_path_to_key,
        stats,
    )

    expected_path_index, expected_path_aggressive_index = build_expected_attachment_path_indexes(
        all_attachments,
        parent_items_by_key,
        collection_by_key,
    )

    attachment_items_by_key = build_item_by_key(all_attachments)


    hash_index, key_to_path = build_local_storage_index(existing_filenames)
    unindexed_local_hashes = build_unindexed_local_storage_hashes(key_to_path)
    drive_name_index_fast, drive_aggressive_index_fast, drive_path_index_fast, drive_path_aggressive_index_fast = build_drive_name_path_indexes(TARGET_FOLDER)
    reconcile_drive_collection_paths(
        zot,
        all_attachments,
        parent_items_by_key,
        collection_by_key,
        collection_path_to_key,
        drive_name_index_fast,
        drive_aggressive_index_fast,
        key_to_path,
        stats,
    )
    desktop_import_available = ensure_desktop_recognizer_available(stats)


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
        #          → Conteúdo do drive é tratado como versão mais recente para a cópia local.
        #
        # CASO 3 — Nome NÃO encontrado, hash encontrado no storage local
        #          → Mesmo conteúdo com nomes diferentes. Decide o nome canônico por mtime/dateModified.
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
            relative_drive_path = relpath_from_root(TARGET_FOLDER, file_path)
            drive_collection_key = infer_collection_key_from_relative_path(
                relative_drive_path,
                collection_path_to_key,
            )
            logging.info("[LOOP] Processando %d/%d: '%s'.", index, total_files_to_process, relative_drive_path)
            norm_local = normalize_filename(file_name)
            norm_local_aggressive = normalize_aggressive(file_name)
            norm_rel = normalize_relative_path_key(relative_drive_path)
            norm_rel_aggressive = normalize_relative_path_aggressive_key(relative_drive_path)

            nome_info = (
                expected_path_index.get(norm_rel)
                or expected_path_aggressive_index.get(norm_rel_aggressive)
                or existing_filenames.get(norm_local)
                or existing_filenames_aggressive.get(norm_local_aggressive)
            )
            nome_encontrado = nome_info is not None and nome_info.get('key') != '__pending__'

            if nome_encontrado:
                zotero_key = nome_info['key']
                local_dir = os.path.join(LOCAL_COPY_DIR, zotero_key)
                attachment_item = attachment_items_by_key.get(zotero_key)
                attachment_parent_key = (attachment_item or {}).get('data', {}).get('parentItem')
                if drive_collection_key:
                    target_item_key = attachment_parent_key or zotero_key
                    target_item = (
                        parent_items_by_key.get(attachment_parent_key)
                        if attachment_parent_key else attachment_item
                    )
                    sync_item_collections_to_drive_collection(
                        zot,
                        target_item_key,
                        drive_collection_key,
                        collection_by_key,
                        item=target_item,
                    )
                expected_filename = os.path.basename(get_filename_from_item(attachment_item)) if attachment_item else file_name
                desired_location = attachment_target_location(
                    attachment_item or {'data': {'key': zotero_key}},
                    expected_filename or file_name,
                    parent_items_by_key,
                    collection_by_key,
                    preferred_collection_key=drive_collection_key,
                )
                desired_relpath = nome_info.get('relative_path') or desired_location['relative_path']
                desired_drive_path = os.path.join(TARGET_FOLDER, *desired_relpath.split('/'))
                desired_collection_key = desired_location['collection_key']
                local_file = get_latest_pdf_path(local_dir)

                if local_file and os.path.exists(local_file):
                    # Temos cópia local — compara hash para detectar atualização de conteúdo
                    local_hash = compute_sha256(local_file)
                    webdav_hash = compute_sha256(file_path)

                    if not local_hash or not webdav_hash:
                        stats['recoverable_hash_skips'] += 1
                        logging.warning(
                            "[HASH] Falha recuperável ao comparar hashes de '%s' (local_hash=%s, webdav_hash=%s). Arquivo ignorado.",
                            file_name,
                            "ok" if local_hash else "falhou",
                            "ok" if webdav_hash else "falhou",
                        )
                        continue

                    if local_hash and webdav_hash and local_hash == webdav_hash:
                        # CASO 1: nome ok, conteúdo igual → já sincronizado
                        if relative_drive_path != desired_relpath:
                            file_path = relocate_drive_file(file_path, desired_drive_path, webdav_hash, stats)
                        logging.info("[CASO 1] '%s' já sincronizado (key=%s).", relative_drive_path, zotero_key)
                        stats['skipped'] += 1
                        stats['hash_matches'] += 1
                        continue

                    elif local_hash and webdav_hash and local_hash != webdav_hash:
                        # CASO 2: nome ok, conteúdo diferente → WebDAV tem versão mais nova
                        logging.info("[CASO 2] '%s' atualizado no WebDAV. Atualizando storage local (key=%s).", relative_drive_path, zotero_key)
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
                        if relative_drive_path != desired_relpath:
                            file_path = relocate_drive_file(file_path, desired_drive_path, webdav_hash, stats)
                        stats['skipped'] += 1
                        continue

                else:
                    # CASO 5: nome encontrado no Zotero mas sem cópia local
                    logging.info("[CASO 5] '%s' existe no Zotero mas sem cópia local. Copiando (key=%s).", relative_drive_path, zotero_key)
                    webdav_hash = compute_sha256(file_path)
                    if not webdav_hash:
                        stats['recoverable_hash_skips'] += 1
                        logging.warning(
                            "[HASH] Falha recuperável ao obter hash de '%s' para recriar cópia local. Arquivo ignorado.",
                            file_name,
                        )
                        continue
                    copy_outcome = copy_to_local_storage(file_path, zotero_key, webdav_hash)
                    if copy_outcome == "copied":
                        stats['local_copies'] += 1
                        new_local = get_latest_pdf_path(local_dir)
                        if new_local:
                            register_local_hash(hash_index, key_to_path, zotero_key, new_local, nome_info)
                    if relative_drive_path != desired_relpath:
                        file_path = relocate_drive_file(file_path, desired_drive_path, webdav_hash, stats)
                    stats['skipped'] += 1
                    continue

            # Nome não encontrado — calcula hash para casos 3 e 4
            file_hash = compute_sha256(file_path)
            if not file_hash:
                stats['recoverable_hash_skips'] += 1
                logging.warning("[HASH] Falha recuperável ao obter hash de '%s'. Arquivo ignorado.", file_name)
                continue

            if DEBUG_DETAILED:
                logging.debug(
                    "[LOCAL] arquivo='%s' | norm='%s' | norm_agg='%s' | hash=%s",
                    file_name, norm_local, norm_local_aggressive, file_hash,
                )
            if file_hash in unindexed_local_hashes:
                logging.info(
                    "[CASO 4] '%s' já foi importado no storage local e aguarda sincronização da API. "
                    "Ignorando para não criar uma cópia duplicada.",
                    relative_drive_path,
                )
                stats['skipped'] += 1
                continue


            hash_matches = hash_index.get(file_hash, [])
            if hash_matches:
                # CASO 3: hash encontrado, nome diferente → reconciliar nomes pelo mtime
                entry = choose_hash_match_entry(
                    hash_matches,
                    file_name,
                    attachment_items_by_key,
                    parent_items_by_key,
                )
                canonical_key = entry['key']
                canonical_path = entry.get('path')
                webdav_name = file_name
                webdav_mtime = os.path.getmtime(file_path)

                if canonical_path and os.path.exists(canonical_path):
                    entry_info = entry.get('info', {}) or {}
                    zotero_name = entry_info.get('original') or os.path.basename(canonical_path)
                    local_copy_name = os.path.basename(canonical_path)
                    canonical_name = zotero_name
                    local_copy_mtime = os.path.getmtime(canonical_path)
                    zotero_date_modified = parse_zotero_date(entry_info.get('dateModified', ''))
                    zotero_mtime = zotero_date_modified.timestamp() if zotero_date_modified else local_copy_mtime

                    logging.info(
                        "[CASO 3] Mesmo conteúdo, nomes diferentes: drive='%s' | zotero='%s' | local_copy='%s' (key=%s).",
                        webdav_name, zotero_name, local_copy_name, canonical_key,
                    )
                    logging.info(
                        "[CASO 3] Datas: drive=%.6f | zotero=%.6f | local_copy=%.6f.",
                        webdav_mtime,
                        zotero_mtime,
                        local_copy_mtime,
                    )

                    metadata_canonical_applied = False
                    attachment_item = attachment_items_by_key.get(canonical_key)
                    attachment_parent_key = (
                        (attachment_item or {}).get('data', {}).get('parentItem')
                    )
                    metadata_name = canonical_parent_pdf_filename(
                        parent_items_by_key.get(attachment_parent_key)
                    )
                    if metadata_name:
                        if local_copy_name != metadata_name:
                            updated_path = rename_local_attachment(zot, canonical_key, canonical_path, metadata_name)
                            if updated_path != canonical_path:
                                entry['path'] = updated_path
                                entry['filename'] = metadata_name
                                key_to_path[canonical_key] = updated_path
                                canonical_path = updated_path
                                local_copy_name = metadata_name
                                stats['renamed_local'] += 1
                        if zotero_name != metadata_name:
                            if update_zotero_attachment_filename(zot, canonical_key, metadata_name, attachment_item):
                                stats['canonical_attachment_names'] += 1
                            zotero_name = metadata_name
                            if attachment_item:
                                attachment_item.setdefault('data', {})['filename'] = metadata_name
                                attachment_item.setdefault('data', {})['title'] = metadata_name
                        new_path = enforce_drive_canonical_name(file_path, metadata_name, file_hash, stats)
                        if new_path != file_path:
                            file_path = new_path
                            file_name = os.path.basename(new_path)
                            logging.info(
                                "[CASO 3] Drive atualizado para nome canônico por metadados: '%s'.",
                                metadata_name,
                            )
                        canonical_name = metadata_name
                        metadata_canonical_applied = True

                    copy_preferred_name = None if metadata_canonical_applied else choose_non_copy_canonical_name(webdav_name, zotero_name)
                    if metadata_canonical_applied:
                        pass
                    elif copy_preferred_name == zotero_name:
                        if local_copy_name != zotero_name:
                            updated_path = rename_local_attachment(zot, canonical_key, canonical_path, zotero_name)
                            if updated_path != canonical_path:
                                entry['path'] = updated_path
                                entry['filename'] = zotero_name
                                key_to_path[canonical_key] = updated_path
                                stats['renamed_local'] += 1

                        new_path = enforce_drive_canonical_name(file_path, zotero_name, file_hash, stats)
                        if new_path != file_path:
                            file_path = new_path
                            file_name = os.path.basename(new_path)
                            logging.info(
                                "[CASO 3] Nome de cópia no drive consolidado para canônico do Zotero: '%s'.",
                                zotero_name,
                            )
                        canonical_name = zotero_name
                    elif copy_preferred_name == webdav_name:
                        updated_path = rename_local_attachment(zot, canonical_key, canonical_path, webdav_name)
                        if updated_path != canonical_path:
                            entry['path'] = updated_path
                            entry['filename'] = webdav_name
                            key_to_path[canonical_key] = updated_path
                            entry_info['original'] = webdav_name
                            entry_info['dateModified'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                            stats['renamed_local'] += 1
                            logging.info("[CASO 3] Zotero atualizado para nome não-cópia do drive: '%s'.", webdav_name)
                        canonical_name = webdav_name
                    elif webdav_mtime > zotero_mtime:
                        updated_path = rename_local_attachment(zot, canonical_key, canonical_path, webdav_name)
                        if updated_path != canonical_path:
                            entry['path'] = updated_path
                            entry['filename'] = webdav_name
                            key_to_path[canonical_key] = updated_path
                            entry_info['original'] = webdav_name
                            entry_info['dateModified'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                            stats['renamed_local'] += 1
                            logging.info("[CASO 3] Zotero atualizado para o nome mais recente do drive: '%s'.", webdav_name)

                        canonical_drive_path = os.path.join(os.path.dirname(file_path), zotero_name)
                        if canonical_drive_path != file_path and os.path.exists(canonical_drive_path):
                            if delete_redundant_webdav_duplicate(canonical_drive_path, file_path, canonical_hash=file_hash):
                                stats['pruned_drive_duplicates'] += 1
                    elif zotero_mtime > webdav_mtime:
                        if local_copy_name != zotero_name:
                            updated_path = rename_local_attachment(zot, canonical_key, canonical_path, zotero_name)
                            if updated_path != canonical_path:
                                entry['path'] = updated_path
                                entry['filename'] = zotero_name
                                key_to_path[canonical_key] = updated_path
                                stats['renamed_local'] += 1

                        new_path = enforce_drive_canonical_name(file_path, zotero_name, file_hash, stats)
                        if new_path != file_path:
                            file_path = new_path
                            file_name = os.path.basename(new_path)
                            logging.info("[CASO 3] Drive atualizado para o nome mais recente do Zotero: '%s'.", zotero_name)
                    else:
                        stats['mtime_ties'] += 1
                        tie_conflicts.append({
                            'key': canonical_key,
                            'drive_name': webdav_name,
                            'zotero_name': zotero_name,
                        })
                        logging.warning(
                            "[CASO 3] Empate de mtime entre drive e Zotero para key=%s. Mantidos os nomes atuais para revisão manual.",
                            canonical_key,
                        )
                else:
                    canonical_name = webdav_name

                norm_local = normalize_filename(file_name)
                norm_local_aggressive = normalize_aggressive(file_name)
                info = {
                    'original': canonical_name,
                    'key': canonical_key,
                    'dateModified': (entry.get('info') or {}).get('dateModified'),
                }
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

            parent_match, parent_candidates = select_parent_for_new_attachment(
                file_name,
                bibliographic_parent_index,
            )
            parent_key = parent_match['key'] if parent_match else None
            if parent_candidates and not parent_match:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['blocked_duplicate_risk'] += 1
                candidate_summary = "; ".join(
                    f"{candidate['key']} score={candidate['score']:.2f} title='{candidate['title'][:90]}'"
                    for candidate in parent_candidates[:5]
                )
                for candidate in parent_candidates[:5]:
                    record_current_review_duplicate(stats, candidate['key'])
                    if add_review_tag_to_item(
                        zot,
                        candidate['key'],
                        f"candidato ambíguo para anexo bloqueado: {file_name}",
                        item=candidate.get('item'),
                    ):
                        stats['review_tags_applied'] += 1
                logging.warning(
                    "[DUP-RISK] '%s' parece pertencer a mais de um item bibliográfico existente. "
                    "Upload bloqueado para não criar nova duplicata. Candidatos: %s",
                    file_name,
                    candidate_summary,
                )
                continue

            if is_copy_variant_filename(file_name) and not parent_key:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['blocked_duplicate_risk'] += 1
                logging.warning(
                    "[DUP-RISK] '%s' tem marcador de cópia e não teve pai bibliográfico único. "
                    "Upload top-level bloqueado para evitar duplicata persistente no Zotero e no drive.",
                    file_name,
                )
                continue



            try:
                if parent_key:
                    logging.info(
                        "[CASO 4] Anexando '%s' ao item bibliográfico existente key=%s score=%.2f title='%s' via Zotero Desktop/WebDAV.",
                        file_name,
                        parent_key,
                        parent_match['score'],
                        parent_match['title'],
                    )
                else:
                    logging.info("[CASO 4] Importando '%s' via Zotero Desktop/WebDAV...", file_name)

                if not desktop_import_available:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats.setdefault('pending_desktop_imports', []).append(file_name)
                    logging.error(
                        "[DESKTOP] Importação bloqueada para '%s': Zotero Desktop/endpoint local indisponível. "
                        "O sync não fará fallback para upload via API porque isso consumiria a quota do Zotero.",
                        file_name,
                    )
                    continue

                desktop_result = import_attachment_via_desktop(
                    file_path,
                    drive_collection_key,
                    parent_key=parent_key,
                    auto_recognize=not parent_key and _HEADLESS_ZOTERO_PROC is None,
                )
                if not desktop_result:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Falha ao importar '%s' via Zotero Desktop/WebDAV.", file_name)
                    continue

                new_key = desktop_result.get("attachmentKey")
                if not new_key:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Chave não retornada pela importação desktop para '%s'. Resposta: %s", file_name, desktop_result)
                    continue

                stats['added'] += 1
                if parent_key:
                    stats['attached_to_existing_parent'] += 1

                final_name = desktop_result.get("attachmentFilename") or file_name
                final_parent_key = desktop_result.get("parentKey") or parent_key or ""
                info = {
                    'original': final_name,
                    'key': new_key,
                    'dateModified': None,
                    'relative_path': relative_drive_path,
                    'collection_key': drive_collection_key,
                }

                if final_name != file_name:
                    new_drive_path = enforce_drive_canonical_name(file_path, final_name, file_hash, stats)
                    if new_drive_path != file_path:
                        existing_filenames.pop(norm_local, None)
                        existing_filenames_aggressive.pop(norm_local_aggressive, None)
                        file_path = new_drive_path
                        file_name = os.path.basename(file_path)
                        norm_local = normalize_filename(file_name)
                        norm_local_aggressive = normalize_aggressive(file_name)
                    info['original'] = file_name

                existing_filenames[norm_local] = info
                existing_filenames_aggressive[norm_local_aggressive] = info
                local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, new_key))
                if local_path and os.path.exists(local_path):
                    register_local_hash(hash_index, key_to_path, new_key, local_path, info)

                if parent_key and drive_collection_key and final_parent_key == parent_key:
                    sync_item_collections_to_drive_collection(
                        zot,
                        parent_key,
                        drive_collection_key,
                        collection_by_key,
                    )

                if final_parent_key and not parent_key:
                    logging.info(
                        "[CASO 4] '%s' importado via Zotero Desktop com parent=%s (attachment=%s).",
                        file_name,
                        final_parent_key,
                        new_key,
                    )
                elif parent_key:
                    logging.info(
                        "[CASO 4] '%s' anexado ao item existente parent=%s com sucesso via desktop (attachment=%s).",
                        file_name,
                        parent_key,
                        new_key,
                    )
                else:
                    logging.info("[CASO 4] '%s' importado como top-level via desktop (attachment=%s).", file_name, new_key)

            except Exception as e:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['errors'] += 1
                logging.error("[ERRO] Exceção ao importar '%s' via Zotero Desktop: %s", file_name, e)



        cleanup_changed = run_safe_bibliographic_duplicate_cleanup(zot, stats, key_to_path)
        if cleanup_changed:
            logging.info("[DUP-BIB] Biblioteca alterada por limpeza automática. Recarregando anexos antes de Zotero -> drive.")
            (
                all_attachments,
                existing_filenames,
                existing_filenames_aggressive,
            ) = collect_all_attachments(zot, stats)
            stats['zotero_unique_filenames'] = len(existing_filenames)
            expected_path_index, expected_path_aggressive_index = build_expected_attachment_path_indexes(
                all_attachments,
                parent_items_by_key,
                collection_by_key,
            )
        try:
            refreshed_bibliographic_items = collect_all_bibliographic_items(zot, stats)
            refreshed_parent_index = build_bibliographic_parent_index(refreshed_bibliographic_items)
            clear_stale_review_duplicate_tags(zot, refreshed_parent_index, stats)
        except Exception as exc:
            stats['errors'] += 1
            logging.warning("[TAG] Falha ao limpar tags de revisão antigas: %s", exc)

        logging.info("[ZOT->DRIVE] Iniciando reconciliação Zotero -> drive para anexos ausentes.")
        drive_name_index, drive_aggressive_index, drive_path_index, drive_path_aggressive_index, drive_hash_index = build_drive_pdf_index(TARGET_FOLDER, stats)
        materialize_zotero_attachments_to_drive(
            zot,
            all_attachments,
            parent_items_by_key,
            collection_by_key,
            drive_name_index,
            drive_aggressive_index,
            drive_path_index,
            drive_path_aggressive_index,
            drive_hash_index,
            key_to_path,
            stats,
            tie_conflicts,
        )
        reconcile_drive_collection_paths(
            zot,
            all_attachments,
            parent_items_by_key,
            collection_by_key,
            collection_path_to_key,
            drive_name_index,
            drive_aggressive_index,
            key_to_path,
            stats,
        )
    except Exception as e:
        logging.error(f"Erro ao processar arquivos da pasta: {e}")
        finalize_execution(stats)
        return

    # 5. Relatório final
    total_verificados = stats['processed'] or stats['folder_checked_pdfs']
    pct_adicionados = ((stats['added'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_ignorados = ((stats['skipped'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_erros = ((stats['errors'] / total_verificados) * 100) if total_verificados > 0 else 0

    tie_summary = ""
    if tie_conflicts:
        tie_lines = ["", f"⚖️ Empates de mtime para revisão manual: {len(tie_conflicts)}"]
        for conflict in tie_conflicts:
            tie_lines.append(
                f"- key={conflict['key']} | drive='{conflict['drive_name']}' | zotero='{conflict['zotero_name']}'"
            )
        tie_summary = "\n".join(tie_lines)

    summary = f"""
╔════════════════════════════════════════════════════════╗
║           RELATÓRIO FINAL  (v2.0)                      ║
╚════════════════════════════════════════════════════════╝

📂 Pasta: {TARGET_FOLDER}
🏠 Cópia local: {LOCAL_COPY_DIR}

┌─── 📊 COLETA DE ANEXOS ──────────────────────────────┐
│ Anexos varridos (total): {stats['zotero_attachments_scanned']:<25} │
│ Nomes únicos indexados:  {stats['zotero_unique_filenames']:<25} │
│ Itens bib. varridos:   {stats['zotero_bibliographic_scanned']:<25} │
│ Títulos bib. indexados:{stats['zotero_bibliographic_indexed']:<25} │
└──────────────────────────────────────────────────────┘

┌─── 📈 RESULTADOS DA VERIFICAÇÃO ───────────────────────┐
│ PDFs totais na pasta: {stats['folder_total_pdfs']:<30} │
│ 🔍 Processados: {total_verificados:<36} │
│ ──────────────────────────────────────────────────── │
│ ✅ Adicionados: {stats['added']} ({pct_adicionados:.1f}%) {' ' * (33 - len(str(stats['added']) + str(round(pct_adicionados,1))))}│
│ 🔗 Anexados a item existente: {stats['attached_to_existing_parent']:<17} │
│ ⏭️  Existentes: {stats['skipped']} ({pct_ignorados:.1f}%) {' ' * (33 - len(str(stats['skipped']) + str(round(pct_ignorados,1))))}│
│ 💾 Cópias locais: {stats['local_copies']:<34} │
│ ❌ Erros: {stats['errors']} ({pct_erros:.1f}%) {' ' * (38 - len(str(stats['errors']) + str(round(pct_erros,1))))}│
│ Hash skips recuperáveis: {stats['recoverable_hash_skips']:<20} │
│ 🔁 Hash reaproveitados: {stats['hash_matches']:<23} │
│ 🔄 Conteúdo atualizado: {stats['updated_content']:<23} │
│ ✏️  Renomes WebDAV: {stats['renamed_webdav']:<27} │
│ 📝 Renomes storage: {stats['renamed_local']:<27} │
│ Nomes canônicos Zotero: {stats['canonical_attachment_names']:<23} │
│ Standalone normalizados: {stats['normalized_standalone_attachments']:<22} │
│ Cópias pré-sync consolidadas: {stats['preprocessed_drive_copy_variants']:<14} │
│ Cópias pré-sync bloqueadas: {stats['blocked_drive_copy_variants']:<16} │
│ Reconhecimento desktop: {stats['desktop_recognition_processed']}/{stats['desktop_recognition_requested']:<23} │
│ Itens pai fallback: {stats['desktop_parent_fallbacks']:<24} │
│ Pastas coleção drive: {stats['created_drive_collection_dirs']:<22} │
│ Pastas coleção Obsidian: {stats['created_obsidian_collection_dirs']:<19} │
│ Coleções criadas do drive: {stats['created_zotero_collections_from_drive']:<14} │
│ PDFs novos no Obsidian: {stats['obsidian_new_pdfs_detected']:<21} │
│ PDFs movidos ao drive: {stats['obsidian_pdfs_moved_to_drive']:<22} │
│ PDFs bloqueados Obsidian: {stats['obsidian_pdfs_blocked']:<18} │
│ PDFs deduplicados Obsidian: {stats['obsidian_pdfs_deduped']:<15} │
│ Arquivos realocados à coleção: {stats['moved_drive_files_to_collection']:<14} │
│ Coleções alinhadas ao drive: {stats['drive_authoritative_collection_updates']:<13} │
│ 🧹 Duplicados removidos: {stats['pruned_drive_duplicates']:<22} │
│ ⬇️  Baixados do Zotero: {stats['downloaded_zotero']:<24} │
│ Pastas vazias remov. drive: {stats['removed_empty_drive_dirs']:<13} │
│ Pastas vazias remov. Obsidian: {stats['removed_empty_obsidian_dirs']:<9} │
│ 📤 Materializados no drive: {stats['materialized_drive']:<20} │
│ Etiquetas de revisão: +{stats['review_tags_applied']:<9} -{stats['review_tags_removed']:<10} │
│ 🛑 Bloqueios anti-duplicata: {stats['blocked_duplicate_risk']:<18} │
│ 🧾 Grupos duplicados bib.: {stats['bibliographic_duplicate_groups']:<20} │
│ 🧹 Duplicatas Zotero remov.: {stats['auto_removed_bibliographic_duplicates']:<17} │
│ 🔀 Metadados mesclados: {stats['merged_duplicate_metadata']:<24} │
│ ⏸️  Limpezas ignoradas: {stats['auto_duplicate_cleanup_skipped']:<24} │
└──────────────────────────────────────────────────────┘
{tie_summary}

✨ Processamento concluído!
"""
    print(summary)
    finalize_execution(stats, summary, notify_completion=bool(notification_policy.get("completion", True)))
    
    # US-004: exit nonzero when critical errors occurred
    if stats.get('errors', 0) > 0:
        sys.exit(1)


def is_zotero_running() -> bool:
    """Detecta processo Zotero em execução (ignora headless e o próprio script)."""
    try:
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore")
            except OSError:
                continue
            # Must contain zotero-bin or be the main zotero app, but not our script and not headless
            if "zotero" in cmdline.lower() and "zotero_sync" not in cmdline.lower() and "--headless" not in cmdline.lower():
                return True
    except OSError:
        return False
    return False

def run_adaptive_sync() -> None:
    """Roda sync enquanto Zotero estiver aberto, notificando só no primeiro ciclo."""
    interval = get_env_int("ZOTERO_SYNC_INTERVAL_SECONDS", 300)
    first = True
    while is_zotero_running():
        run_sync_mode(
            notification_policy={
                "announce_start": first,
                "progress": first,
                "completion": first,
            }
        )
        first = False
        # Sleep between iterations, not just after the first
        time.sleep(interval)




def main(argv: List[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    if args.command in (None, 'sync'):
        run_sync_mode()
        return 0
    if args.command == 'diagnostico':
        run_diagnostic_mode()
        return
    if args.command == 'remove-duplicatas':
        run_duplicate_cleanup_mode(execute=args.executar)
        return
    if args.command == 'setup-autostart':
        run_setup_autostart_mode(args.setup_args)
        return
    if args.command == 'obsidian-verify':
        run_obsidian_verify_mode(args)
        return
    if args.command == 'obsidian-export':
        run_obsidian_export_mode(args)
        return
    if args.command == 'obsidian-apply':
        run_obsidian_apply_mode(args)
        return
    if args.command == 'obsidian-mirror':
        run_obsidian_mirror_mode(args)
        return
    if args.command == 'obsidian-setup':
        run_obsidian_setup_mode(args)
        return
    if args.command == 'recover-orphans':
        run_recover_orphans_mode(dry_run=args.dry_run)
        return
    if args.command == 'bootstrap':
        run_bootstrap()
        return
    if args.command == 'watch-zotero':
        run_zotero_open_watch()
        return


def run_zotero_open_watch() -> None:
    """Serviço residente que dispara o sync assim que o Zotero é aberto."""
    import subprocess
    logging.info("[WATCHER] Watcher de abertura do Zotero iniciado.")
    was_running = is_zotero_running()
    
    while True:
        is_running = is_zotero_running()
        
        if is_running and not was_running:
            logging.info("[WATCHER] Zotero aberto detectado. Disparando sync imediata.")
            try:
                subprocess.Popen(
                    ["python3", str(Path(__file__).resolve()), "sync"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError as exc:
                logging.error("[WATCHER] Falha ao disparar sync: %s", exc)
                
        was_running = is_running
        time.sleep(5)


    parser.error(f'Comando não suportado: {args.command}')


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        logging.error("Erro fatal não tratado: %s", exc, exc_info=True)
        sys.exit(2)

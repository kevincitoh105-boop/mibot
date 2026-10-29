import os
import re
import sys
import asyncio
import sqlite3
import time
import requests
import subprocess
import shutil
import traceback
import html
import uuid
import hashlib
import socket
import tempfile
import itertools
import threading
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote, quote
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import Conflict, NetworkError
from telegram.ext import (Application, CommandHandler, MessageHandler, filters,
                          ContextTypes, CallbackQueryHandler)

# ==================================================
# CONFIGURACIÓN OBLIGATORIA
# ==================================================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("No se encontró BOT_TOKEN en variables de entorno.")

MOODLE_URL = "https://moodle.instec.cu"

# ==================================================
# NUBES DISPONIBLES (/cambiar). Para añadir otra: una entrada nueva aquí.
# ==================================================
CLOUDS = {
    1: {"nombre": "Moodle INSTEC", "url": MOODLE_URL, "requiere_cuenta": True},
    2: {"nombre": "EVA Desoft", "url": os.environ.get("EVA_URL", "https://eva.desoft.cu").rstrip("/"),
        "requiere_cuenta": True,
        # EVA responde 413 con archivos grandes: se sube en partes de este tamaño
        # (si aún da 413 el bot lo reduce solo). Ajustable con EVA_MAX_PART_MB.
        "max_parte": int(os.environ.get("EVA_MAX_PART_MB", "50")) * 1024 * 1024},
}
NUBE_POR_DEFECTO = 1
ADMIN_IDS = [5293884821]

# Límites
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024   # 10 GB
MAX_SPLIT_SIZE = 1024 * 1024 * 1024       # 1 GB (para dividir)

# --- Concurrencia y colas (todo ajustable por variables de entorno) ---
# Subidas que pueden correr a la vez entre TODOS los usuarios (protege RAM/disco/ancho de banda).
MAX_SUBIDAS_SIMULTANEAS = int(os.environ.get("MAX_SUBIDAS_SIMULTANEAS", "2"))
# Cada usuario sube de 1 en 1; esto es cuántos enlaces puede tener esperando como máximo.
MAX_COLA_POR_USUARIO = int(os.environ.get("MAX_COLA_POR_USUARIO", "10"))
MAX_ENLACES_POR_MENSAJE = 10
# Updates de Telegram que se procesan en paralelo (para que /cola, /files, etc. respondan siempre).
CONCURRENT_UPDATES = int(os.environ.get("CONCURRENT_UPDATES", "16"))
# Tiempo máximo de un trabajo completo (descarga + subida), en segundos.
JOB_TIMEOUT = int(os.environ.get("JOB_TIMEOUT_S", str(4 * 3600)))
DESCARGA_INTENTOS = 4
SUBIDA_INTENTOS = 3
# Descartar mensajes acumulados mientras el bot estuvo apagado (por defecto no).
DROP_PENDING = os.environ.get("DROP_PENDING_UPDATES", "0") == "1"

DB_PATH = 'moodle_bot.db'
TEMP_ROOT = "temp_downloads"
MARGEN_DISCO = 200 * 1024 * 1024  # 200 MB libres que nunca se tocan

# Cifrado Fernet
from cryptography.fernet import Fernet
CIPHER_KEY = os.environ.get("CIPHER_KEY", "")

def get_fernet():
    if not CIPHER_KEY:
        return None
    return Fernet(CIPHER_KEY.encode())

def encrypt(text: str) -> str:
    f = get_fernet()
    if not f:
        return text
    return f.encrypt(text.encode()).decode()

def decrypt(text: str) -> str:
    f = get_fernet()
    if not f:
        return text
    return f.decrypt(text.encode()).decode()

# ==================================================
# UTILIDADES
# ==================================================
URL_RE = re.compile(r'https?://[^\s<>"\']+')

class JobCancelado(Exception):
    """El trabajo fue cancelado (por el usuario, por timeout o por apagado del bot)."""

def ahora() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def escape_markdown(text: str) -> str:
    """Escapa solo lo que Telegram (Markdown clásico) necesita: _ * ` ["""
    return re.sub(r'([_*`\[])', r'\\\1', str(text))

def h(text) -> str:
    """Escapa texto para usarlo dentro de mensajes parse_mode='HTML'."""
    return html.escape(str(text), quote=False)

def sanitize_filename(name: str) -> str:
    """Elimina caracteres peligrosos y evita nombres como '..' o que empiecen con '-'."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(" .")
    name = name.lstrip("-")
    return name

# ==================================================
# BASE DE DATOS
# ==================================================
@contextmanager
def get_db_conn():
    """Abre una conexión, confirma al salir (o deshace si hubo error) y SIEMPRE la cierra."""
    conn = sqlite3.connect(DB_PATH, timeout=20)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")  # lecturas y escrituras simultáneas sin bloqueos
        c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                     (telegram_id INTEGER PRIMARY KEY, username TEXT, nombre TEXT, 
                      es_admin INTEGER DEFAULT 0, fecha_registro TIMESTAMP, ultimo_uso TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS credenciales_moodle
                     (telegram_id INTEGER PRIMARY KEY, usuario TEXT, contraseña TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS archivos
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id INTEGER, 
                      nombre_original TEXT, nombre_en_moodle TEXT, itemid INTEGER, userid INTEGER,
                      enlace TEXT, tamano_bytes INTEGER, es_parte_de TEXT, numero_parte INTEGER,
                      fecha_subida TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id INTEGER, 
                      accion TEXT, detalle TEXT, fecha TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS credenciales_nube
                     (telegram_id INTEGER, nube INTEGER, usuario TEXT, contraseña TEXT,
                      PRIMARY KEY (telegram_id, nube))''')
        c.execute('''CREATE TABLE IF NOT EXISTS preferencias
                     (telegram_id INTEGER PRIMARY KEY, nube INTEGER)''')
        # Migración: las credenciales Moodle que ya tenías pasan a la nube 1
        c.execute('''INSERT OR IGNORE INTO credenciales_nube (telegram_id, nube, usuario, contraseña)
                     SELECT telegram_id, 1, usuario, contraseña FROM credenciales_moodle''')
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_fecha ON logs(fecha)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_telegram ON logs(telegram_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_archivos_user ON archivos(telegram_id)")
    os.makedirs(TEMP_ROOT, exist_ok=True)

def log_action(telegram_id, accion, detalle=""):
    try:
        with get_db_conn() as conn:
            conn.execute("INSERT INTO logs (telegram_id, accion, detalle, fecha) VALUES (?, ?, ?, ?)",
                         (telegram_id, accion, detalle, ahora()))
    except Exception as e:
        print(f"⚠️ No se pudo guardar log: {e}")

def log_error(telegram_id, error_msg, traceback_str):
    detalle = f"{error_msg}\n{traceback_str}"[:500]
    log_action(telegram_id, "error", detalle)
    print(f"❌ ERROR (user {telegram_id}): {error_msg}\n{traceback_str}")

def limpiar_logs_antiguos(dias=30):
    with get_db_conn() as conn:
        limite = (datetime.now() - timedelta(days=dias)).strftime('%Y-%m-%d %H:%M:%S')
        c = conn.execute("DELETE FROM logs WHERE fecha < ?", (limite,))
        print(f"🧹 Limpiados {c.rowcount} logs antiguos (> {dias} días)")

def es_admin(telegram_id):
    return telegram_id in ADMIN_IDS

def obtener_nube_activa(telegram_id):
    with get_db_conn() as conn:
        r = conn.execute("SELECT nube FROM preferencias WHERE telegram_id = ?", (telegram_id,)).fetchone()
    return r[0] if r and r[0] in CLOUDS else NUBE_POR_DEFECTO

def guardar_nube_activa(telegram_id, nube):
    with get_db_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO preferencias (telegram_id, nube) VALUES (?, ?)",
                     (telegram_id, nube))

def obtener_credenciales_moodle(telegram_id, nube=None):
    if nube is None:
        nube = obtener_nube_activa(telegram_id)
    with get_db_conn() as conn:
        resultado = conn.execute(
            "SELECT usuario, contraseña FROM credenciales_nube WHERE telegram_id = ? AND nube = ?",
            (telegram_id, nube)).fetchone()
    if resultado:
        usuario = resultado[0]
        try:
            contraseña = decrypt(resultado[1])
        except Exception:
            log_error(telegram_id, "Error al desencriptar", traceback.format_exc())
            contraseña = resultado[1]
        return (usuario, contraseña)
    return (None, None)

def guardar_credenciales_moodle(telegram_id, usuario, contraseña, nube=None):
    if nube is None:
        nube = obtener_nube_activa(telegram_id)
    if CIPHER_KEY:
        contraseña = encrypt(contraseña)
    with get_db_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO credenciales_nube (telegram_id, nube, usuario, contraseña) VALUES (?, ?, ?, ?)",
                     (telegram_id, nube, usuario, contraseña))

# ==================================================
# ARCHIVOS TEMPORALES
# Cada trabajo tiene su PROPIA carpeta temp_downloads/<usuario>_<job>/ que se borra
# entera al terminar (bien, mal o cancelado). Así nunca quedan restos mezclados.
# ==================================================
DIRS_ACTIVOS = set()  # carpetas de trabajos en curso: la limpieza periódica no las toca

def limpiar_temporales(todo=False, horas=6):
    """todo=True (arranque/apagado): borra todo, ningún trabajo sobrevive a un reinicio.
    todo=False (periódica): borra solo lo huérfano con más de `horas` horas."""
    os.makedirs(TEMP_ROOT, exist_ok=True)
    ahora_t = time.time()
    for nombre in os.listdir(TEMP_ROOT):
        ruta = os.path.join(TEMP_ROOT, nombre)
        if ruta in DIRS_ACTIVOS:
            continue
        try:
            if not todo and (ahora_t - os.path.getmtime(ruta)) < horas * 3600:
                continue
            if os.path.isdir(ruta):
                shutil.rmtree(ruta, ignore_errors=True)
            else:
                os.remove(ruta)
            print(f"🧹 Eliminado temporal: {ruta}")
        except Exception as e:
            print(f"⚠️ No se pudo eliminar {ruta}: {e}")

async def bucle_limpieza():
    while True:
        await asyncio.sleep(1800)
        try:
            limpiar_temporales(todo=False, horas=(JOB_TIMEOUT / 3600) + 1)
        except Exception as e:
            print(f"⚠️ Error en limpieza periódica: {e}")

# ==================================================
# FUNCIONES DE MOODLE CON REINTENTOS
# ==================================================
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session():
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount('http://', HTTPAdapter(max_retries=retries))
    s.mount('https://', HTTPAdapter(max_retries=retries))
    return s

class MoodleError(Exception):
    """Error al hablar con Moodle. `usuario_msg` es el texto que se muestra en Telegram
    (sin Markdown); `detalle` es el detalle técnico para los logs."""
    def __init__(self, usuario_msg, detalle=""):
        super().__init__(detalle or usuario_msg)
        self.usuario_msg = usuario_msg
        self.detalle = detalle or usuario_msg

class MoodleConexionError(MoodleError):
    """Moodle no responde: caído, rechaza la conexión, timeout, DNS, SSL, error 5xx o bloqueo."""

class MoodleCredencialesError(MoodleError):
    """Moodle SÍ respondió y rechazó el usuario/contraseña (o la cuenta está bloqueada)."""

class MoodleRespuestaError(MoodleError):
    """Moodle respondió, pero la página no tiene el formato esperado."""

_SIN_VERIFICAR = "No pude verificar tus credenciales."

def clasificar_error_conexion(e):
    """Convierte una excepción de `requests` en un MoodleConexionError con un mensaje claro."""
    texto = str(e)
    bajo = texto.lower()
    if isinstance(e, requests.exceptions.HTTPError) and e.response is not None:
        code = e.response.status_code
        if code in (401, 403):
            msg = (f"⛔ Moodle respondió {code} (acceso denegado). Parece que bloquea al servidor "
                   f"del bot; no es un problema de tu contraseña. {_SIN_VERIFICAR}")
        elif code == 404:
            msg = (f"❓ Moodle respondió 404: no encuentra la página de login. "
                   f"Puede haber cambiado la dirección. {_SIN_VERIFICAR}")
        elif code >= 500:
            msg = (f"🛠️ Moodle devolvió un error {code}: está caído o en mantenimiento. "
                   f"Intenta de nuevo más tarde. {_SIN_VERIFICAR}")
        else:
            msg = f"⚠️ Moodle respondió con HTTP {code}. {_SIN_VERIFICAR}"
    elif isinstance(e, requests.exceptions.RetryError):
        msg = (f"🛠️ Moodle respondió con errores 502/503/504 varias veces seguidas: está caído "
               f"o sobrecargado. Intenta de nuevo más tarde. {_SIN_VERIFICAR}")
    elif isinstance(e, requests.exceptions.SSLError):
        msg = f"🔒 Error de certificado SSL al conectar con Moodle. {_SIN_VERIFICAR}"
    elif isinstance(e, requests.exceptions.Timeout):
        msg = (f"⏱️ Moodle tardó demasiado en responder (timeout): está muy lento o caído. "
               f"{_SIN_VERIFICAR}")
    elif isinstance(e, requests.exceptions.ConnectionError):
        if "connection refused" in bajo or "errno 111" in bajo:
            msg = (f"🔌 Moodle rechazó la conexión: está caído o no acepta conexiones desde el "
                   f"servidor del bot. No es un problema de tu contraseña. {_SIN_VERIFICAR}")
        elif any(p in bajo for p in ("name or service not known", "nameresolutionerror",
                                     "temporary failure in name resolution", "getaddrinfo")):
            msg = (f"🌐 No se pudo resolver la dirección de Moodle (DNS). Puede estar caído. "
                   f"{_SIN_VERIFICAR}")
        elif "connection reset" in bajo or "connection aborted" in bajo:
            msg = f"🔌 Moodle cortó la conexión de golpe. Intenta de nuevo. {_SIN_VERIFICAR}"
        else:
            msg = (f"🔌 No pude conectar con Moodle: parece caído o inaccesible. "
                   f"{_SIN_VERIFICAR}")
    else:
        msg = f"⚠️ Error inesperado al contactar a Moodle ({type(e).__name__}). {_SIN_VERIFICAR}"
    return MoodleConexionError(msg, f"{type(e).__name__}: {texto}")

def login_moodle(usuario, contraseña, base_url=None):
    """Inicia sesión en Moodle y devuelve la sesión (o lanza MoodleError con el motivo exacto)."""
    base_url = (base_url or MOODLE_URL).rstrip("/")
    sesion = create_session()
    login_url = f"{base_url}/login/index.php"

    try:
        login_page = sesion.get(login_url, timeout=30)
        login_page.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Login GET error: {type(e).__name__}: {e}")
        raise clasificar_error_conexion(e) from e

    match = (re.search(r'name="logintoken"[^>]*value="([^"]+)"', login_page.text)
             or re.search(r'value="([^"]+)"[^>]*name="logintoken"', login_page.text))
    if not match:
        print("No se encontró logintoken en la página de login")
        raise MoodleRespuestaError(
            f"⚠️ Moodle respondió, pero la página de login no tiene el formato esperado "
            f"(¿mantenimiento o la página cambió?). {_SIN_VERIFICAR}",
            "logintoken no encontrado")
    payload = {
        'username': usuario,
        'password': contraseña,
        'logintoken': match.group(1),
        'anchor': ''
    }

    try:
        response = sesion.post(login_url, data=payload, allow_redirects=True, timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Login POST error: {type(e).__name__}: {e}")
        raise clasificar_error_conexion(e) from e

    if '/login/index.php' in response.url:
        texto = response.text.lower()
        print("Moodle devolvió la página de login: credenciales rechazadas")
        if re.search(r'(account[^<]{0,40}locked|cuenta[^<]{0,40}bloquead)', texto):
            raise MoodleCredencialesError(
                "🔒 Moodle dice que tu cuenta está bloqueada (probablemente por demasiados "
                "intentos fallidos). Espera un rato o contacta al administrador de Moodle.",
                "cuenta bloqueada")
        raise MoodleCredencialesError(
            "🔑 Moodle respondió y rechazó el usuario o la contraseña. Revisa mayúsculas, "
            "espacios y que sean los de Moodle. Usa /setmoodle usuario contraseña.",
            "credenciales rechazadas")
    if not any(k.startswith('MoodleSession') for k in sesion.cookies.get_dict()):
        print("No se encontró cookie MoodleSession")
        raise MoodleRespuestaError(
            f"⚠️ Moodle respondió, pero no abrió una sesión (sin cookie de sesión). "
            f"{_SIN_VERIFICAR}",
            "sin cookie MoodleSession")
    # upload.php exige un token de servicio web (la cookie de sesion no basta)
    sesion.moodle_token = None
    try:
        r = sesion.post(f"{base_url}/login/token.php",
                        data={'username': usuario, 'password': contraseña,
                              'service': 'moodle_mobile_app'}, timeout=30)
        datos = r.json()
        if isinstance(datos, dict) and datos.get('token'):
            sesion.moodle_token = datos['token']
        else:
            motivo = datos.get('errorcode') or datos.get('error') if isinstance(datos, dict) else datos
            print(f"Moodle no entrego token de servicio: {motivo}")
    except Exception as e:
        print(f"No se pudo pedir el token de servicio: {type(e).__name__}: {e}")
    return sesion

# --------------------------------------------------
# PROGRESO EN VIVO
# --------------------------------------------------
class Progreso:
    """Contador compartido entre el hilo que descarga/sube y la tarea que edita el mensaje.
    `cancelar` es un threading.Event: los hilos lo consultan para abortar rápido."""
    def __init__(self, total=0, cancelar=None):
        self.total = total
        self.hecho = 0
        self.t0 = time.time()
        self.cancelar = cancelar or threading.Event()

    def reiniciar(self):
        self.hecho = 0
        self.t0 = time.time()

class _CuerpoMultipart:
    """Cuerpo multipart/form-data en streaming que suma los bytes enviados en `progreso.hecho`
    y se interrumpe si el trabajo se cancela."""
    def __init__(self, ruta, campo, progreso=None):
        self.boundary = uuid.uuid4().hex
        nombre = os.path.basename(ruta).replace('"', '_')
        self.cabecera = (f'--{self.boundary}\r\n'
                         f'Content-Disposition: form-data; name="{campo}"; filename="{nombre}"\r\n'
                         f'Content-Type: application/octet-stream\r\n\r\n').encode('utf-8')
        self.pie = f'\r\n--{self.boundary}--\r\n'.encode('utf-8')
        self.f = open(ruta, "rb")
        self.progreso = progreso
        self.total = len(self.cabecera) + os.path.getsize(ruta) + len(self.pie)
        self.fase = 0

    def __len__(self):
        return self.total

    def __iter__(self):
        return iter(lambda: self.read(256 * 1024), b'')

    def read(self, size=-1):
        if self.progreso and self.progreso.cancelar.is_set():
            raise JobCancelado()
        if size is None or size < 0:
            size = 256 * 1024
        if self.fase == 0:
            self.fase = 1
            return self.cabecera
        if self.fase == 1:
            datos = self.f.read(size)
            if datos:
                if self.progreso:
                    self.progreso.hecho += len(datos)
                return datos
            self.fase = 2
        if self.fase == 2:
            self.fase = 3
            return self.pie
        return b''

    def close(self):
        self.f.close()

def subir_a_moodle(sesion, ruta_archivo, base_url=None, progreso=None):
    url_subida = f"{(base_url or MOODLE_URL).rstrip('/')}/webservice/upload.php"
    token = getattr(sesion, 'moodle_token', None)
    if not token:
        return {"error": "Moodle no entregó un token de servicio (el servicio móvil "
                         "'moodle_mobile_app' puede estar desactivado en este Moodle).",
                "reintentable": False}
    cuerpo = _CuerpoMultipart(ruta_archivo, 'file_1', progreso)
    try:
        respuesta = sesion.post(url_subida, params={'token': token}, data=cuerpo,
                                headers={'Content-Type': f'multipart/form-data; boundary={cuerpo.boundary}'},
                                timeout=(30, 900))
        respuesta.raise_for_status()
    except Exception as e:
        if progreso is not None and progreso.cancelar.is_set():
            return {"error": "cancelado", "cancelado": True}
        # Errores de red / 5xx: se pueden reintentar. 413, 4xx y demás no.
        reintentable = isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))
        if isinstance(e, requests.exceptions.HTTPError) and e.response is not None \
                and e.response.status_code >= 500:
            reintentable = True
        return {"error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc(),
                "reintentable": reintentable}
    finally:
        cuerpo.close()
    try:
        datos = respuesta.json()
        if isinstance(datos, dict) and 'error' in datos:
            return datos
        if isinstance(datos, list) and len(datos) > 0:
            return datos[0]
        return None
    except Exception as e:
        return {"error": f"JSON decode: {e}", "traceback": traceback.format_exc()}

def dividir_archivo(ruta_archivo, tamano_bytes=1024 * 1024 * 1024):
    """Divide con 7z en modo 'store' (-mx=0, sin comprimir: mucho más rápido y los archivos
    suelen venir ya comprimidos). Devuelve la lista de partes o [] si falla."""
    if not shutil.which('7z'):
        return []
    directorio = os.path.dirname(os.path.abspath(ruta_archivo))
    base = os.path.basename(ruta_archivo)
    archivo_7z = base + ".7z"
    patron = re.compile(r'^' + re.escape(archivo_7z) + r'\.\d{3,}$')

    def borrar_partes():
        for f in os.listdir(directorio):
            if patron.match(f):
                try:
                    os.remove(os.path.join(directorio, f))
                except OSError:
                    pass

    cmd = ['7z', 'a', '-mx=0', '-y', '-bd', f'-v{int(tamano_bytes)}b', '--', archivo_7z, base]
    try:
        resultado = subprocess.run(cmd, capture_output=True, timeout=3600, cwd=directorio)
        if resultado.returncode != 0:
            print(f"7z error (returncode {resultado.returncode}): "
                  f"{resultado.stderr.decode('utf-8', errors='ignore')}")
            borrar_partes()
            return []
    except subprocess.TimeoutExpired:
        print(f"7z timeout dividiendo {ruta_archivo}")
        borrar_partes()
        return []
    except Exception as e:
        print(f"7z exception: {e}\n{traceback.format_exc()}")
        borrar_partes()
        return []
    return sorted(os.path.join(directorio, f) for f in os.listdir(directorio) if patron.match(f))

# ==================================================
# DESCARGA / VERIFICACIÓN (hilos aparte para no bloquear el bot)
# ==================================================
async def verificar_url(url):
    """HEAD (o GET de solo cabeceras si el servidor no admite HEAD): tamaño y tipo."""
    loop = asyncio.get_running_loop()
    def sync_head():
        r = requests.head(url, allow_redirects=True, timeout=30)
        if r.status_code in (400, 403, 405, 501):
            r = requests.get(url, allow_redirects=True, timeout=30, stream=True)
            r.close()
        r.raise_for_status()
        try:
            size = int(r.headers.get("Content-Length", 0) or 0)
        except ValueError:
            size = 0
        if size > MAX_FILE_SIZE:
            raise Exception(f"Archivo demasiado grande ({size/(1024**3):.2f} GB > {MAX_FILE_SIZE/(1024**3):.0f} GB)")
        if "text/html" in r.headers.get("Content-Type", "").lower():
            raise Exception("La URL apunta a una página web, no a un archivo directo")
        return size
    return await loop.run_in_executor(None, sync_head)

def fmt_bytes(n):
    n = float(n)
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.2f} GB"
    return f"{n / 1024 ** 2:.1f} MB"

def fmt_tiempo(seg):
    seg = int(max(seg, 0))
    m, s = divmod(seg, 60)
    hh, m = divmod(m, 60)
    return f"{hh}:{m:02d}:{s:02d}" if hh else f"{m}:{s:02d}"

def texto_progreso(titulo, prog):
    dt = max(time.time() - prog.t0, 0.001)
    vel = prog.hecho / dt
    if prog.total > 0:
        pct = min(100.0, prog.hecho * 100 / prog.total)
        llenos = int(pct * 12 / 100)
        barra = "█" * llenos + "░" * (12 - llenos)
        eta = (prog.total - prog.hecho) / vel if vel > 0 else 0
        return (f"{titulo}\n[{barra}] {pct:.0f}%\n"
                f"{fmt_bytes(prog.hecho)} / {fmt_bytes(prog.total)}\n"
                f"⚡ {fmt_bytes(vel)}/s · ⏳ {fmt_tiempo(eta)}")
    return f"{titulo}\n{fmt_bytes(prog.hecho)} · ⚡ {fmt_bytes(vel)}/s"

async def decir(bot, chat_id, texto, **kw):
    """Envía un mensaje sin romper el trabajo si Telegram falla. Devuelve el mensaje o None."""
    try:
        return await bot.send_message(chat_id, texto, **kw)
    except Exception as e:
        print(f"⚠️ No se pudo enviar mensaje a {chat_id}: {type(e).__name__}: {e}")
        return None

async def editar_seguro(msg, texto, **kw):
    if msg is None:
        return
    try:
        await msg.edit_text(texto, **kw)
    except Exception:
        pass

async def _bucle_progreso(msg, titulo, prog, intervalo=3):
    ultimo = ""
    while True:
        await asyncio.sleep(intervalo)
        texto = texto_progreso(titulo, prog)
        if texto != ultimo:
            try:
                await msg.edit_text(texto)
                ultimo = texto
            except Exception:
                pass

async def con_progreso(msg, titulo, prog, trabajo):
    """Ejecuta `trabajo` (corrutina) mientras actualiza `msg` cada pocos segundos."""
    if msg is None:
        return await trabajo
    tarea = asyncio.create_task(_bucle_progreso(msg, titulo, prog))
    try:
        return await trabajo
    finally:
        tarea.cancel()
        try:
            await tarea
        except asyncio.CancelledError:
            pass

def _descargar_sync(url, destino, prog):
    """Descarga a `destino.part` con REANUDACIÓN (Range) si se corta la conexión,
    y renombra a `destino` solo cuando terminó completa."""
    parcial = destino + ".part"
    ultimo_error = None
    for intento in range(1, DESCARGA_INTENTOS + 1):
        if prog.cancelar.is_set():
            raise JobCancelado()
        pos = os.path.getsize(parcial) if os.path.exists(parcial) else 0
        headers = {"Range": f"bytes={pos}-"} if pos else {}
        try:
            with requests.get(url, headers=headers, timeout=(30, 60), stream=True) as r:
                if pos and r.status_code == 416:      # ya estaba completo
                    break
                r.raise_for_status()
                if pos and r.status_code == 206:
                    modo = "ab"
                    if not prog.total:
                        prog.total = pos + int(r.headers.get("Content-Length", 0) or 0)
                else:                                  # sin soporte de Range: empezar de cero
                    pos, modo = 0, "wb"
                    if not prog.total:
                        prog.total = int(r.headers.get("Content-Length", 0) or 0)
                prog.hecho = pos
                escritos = 0
                with open(parcial, modo) as f:
                    for chunk in r.iter_content(chunk_size=256 * 1024):
                        if prog.cancelar.is_set():
                            raise JobCancelado()
                        if not chunk:
                            continue
                        f.write(chunk)
                        prog.hecho += len(chunk)
                        escritos += 1
                        if escritos % 64 == 0:  # cada ~16 MB: protege el disco y el límite
                            if prog.hecho > MAX_FILE_SIZE:
                                raise Exception("El archivo supera el límite de tamaño permitido")
                            if shutil.disk_usage(os.path.dirname(parcial) or ".").free < MARGEN_DISCO:
                                raise Exception("Se agotó el espacio en disco durante la descarga")
            break  # descarga completa
        except JobCancelado:
            raise
        except requests.exceptions.RequestException as e:
            ultimo_error = e
            print(f"⚠️ Descarga cortada (intento {intento}/{DESCARGA_INTENTOS}): {type(e).__name__}: {e}")
            if intento == DESCARGA_INTENTOS:
                raise
            time.sleep(min(5 * intento, 20))
    os.replace(parcial, destino)
    return os.path.getsize(destino)

async def descargar_archivo(url, destino, prog):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _descargar_sync, url, destino, prog)

async def subir_archivo_a_moodle(sesion, ruta, base_url=None, prog=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, subir_a_moodle, sesion, ruta, base_url, prog)

async def dividir_archivo_async(ruta, tamano_bytes=1024 * 1024 * 1024):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, dividir_archivo, ruta, tamano_bytes)

# ==================================================
# COLAS: una por usuario (1 subida a la vez por usuario) + límite global
# ==================================================
@dataclass
class Job:
    id: int
    user_id: int
    chat_id: int
    url: str
    nube: int
    nombre_base: str
    size: int
    estado: str = "en cola"
    motivo: str = "usuario"            # por qué se canceló: "usuario" | "timeout"
    cancelar: threading.Event = field(default_factory=threading.Event)
    dir: str = ""

    def comprobar(self):
        if self.cancelar.is_set():
            raise JobCancelado()

class ColaUsuario:
    def __init__(self):
        self.pendientes = deque()
        self.actual = None
        self.tarea = None

COLAS = {}                       # user_id -> ColaUsuario
_CONTADOR_JOBS = itertools.count(1)
_SEM = None

def semaforo():
    """Límite GLOBAL de subidas simultáneas (se crea ya dentro del bucle de eventos)."""
    global _SEM
    if _SEM is None:
        _SEM = asyncio.Semaphore(MAX_SUBIDAS_SIMULTANEAS)
    return _SEM

def encolar(bot, job):
    """Devuelve ("ok", posicion) | ("dup", 0) | ("llena", 0). posicion 0 = empieza ya."""
    cola = COLAS.get(job.user_id)
    if cola is None:
        cola = COLAS[job.user_id] = ColaUsuario()
    existentes = list(cola.pendientes) + ([cola.actual] if cola.actual else [])
    if any(j.url == job.url for j in existentes):
        return "dup", 0
    if len(existentes) >= MAX_COLA_POR_USUARIO:
        return "llena", 0
    cola.pendientes.append(job)
    if cola.tarea is None or cola.tarea.done():
        cola.tarea = asyncio.create_task(_worker_usuario(bot, job.user_id, cola))
    return "ok", len(existentes)

async def _worker_usuario(bot, user_id, cola):
    """Procesa los trabajos de UN usuario uno tras otro. Termina (y se borra) cuando no queda nada."""
    try:
        while cola.pendientes:
            job = cola.pendientes.popleft()
            if job.cancelar.is_set():
                continue
            cola.actual = job
            try:
                await _ejecutar_con_limite(bot, job)
            except asyncio.CancelledError:
                raise
            except Exception:
                log_error(user_id, f"Fallo no controlado en job {job.id}", traceback.format_exc())
                await decir(bot, job.chat_id, f"❌ Error interno procesando {job.nombre_base}.")
            finally:
                cola.actual = None
    finally:
        # sin awaits entre el while y esto: no hay carrera con encolar()
        if COLAS.get(user_id) is cola and not cola.pendientes and cola.actual is None:
            del COLAS[user_id]

async def _ejecutar_con_limite(bot, job):
    sem = semaforo()
    if sem.locked():
        await decir(bot, job.chat_id,
                    f"⏳ {job.nombre_base}: hay {MAX_SUBIDAS_SIMULTANEAS} subidas en curso de otros "
                    f"usuarios. Empezará en cuanto haya un hueco.")
    async with sem:
        if job.cancelar.is_set():
            return
        # Tiempo máximo del trabajo: se avisa a los hilos con el Event (cancelación limpia)
        def _timeout():
            job.motivo = "timeout"
            job.cancelar.set()
        timer = asyncio.get_running_loop().call_later(JOB_TIMEOUT, _timeout)
        try:
            await procesar_job(bot, job)
        finally:
            timer.cancel()

# ==================================================
# EL TRABAJO EN SÍ (descargar -> [dividir] -> subir -> registrar), siempre con limpieza
# ==================================================
async def enviar_lista_html(say, cabecera, lineas):
    bloque = cabecera
    for l in lineas:
        if len(bloque) + len(l) + 1 > 3500:
            await say(bloque, parse_mode='HTML')
            bloque = ""
        bloque += l + "\n"
    if bloque.strip():
        await say(bloque, parse_mode='HTML')

def _es_413(res):
    return isinstance(res, dict) and '413' in str(res.get('error', ''))

async def procesar_job(bot, job):
    uid = job.user_id
    cfg = CLOUDS[job.nube]
    base_url = cfg["url"]
    nombre_base = job.nombre_base

    async def say(texto, **kw):
        return await decir(bot, job.chat_id, texto, **kw)

    usuario, contraseña = obtener_credenciales_moodle(uid, job.nube)
    if not usuario:
        await say(f"❌ {nombre_base}: ya no hay credenciales guardadas para {cfg['nombre']}. Usa /setmoodle.")
        return

    # --- Espacio en disco (se comprueba AL EMPEZAR, no al encolar) ---
    limite = cfg.get("max_parte") or MAX_SPLIT_SIZE
    if job.size:
        necesario = job.size * (2 if job.size > limite else 1) + MARGEN_DISCO
        libre = shutil.disk_usage(TEMP_ROOT).free
        if necesario > libre:
            await say(f"❌ {nombre_base}: no hay espacio en disco ahora mismo "
                      f"(hacen falta {fmt_bytes(necesario)}, libres {fmt_bytes(libre)}). Prueba más tarde.")
            return

    job.dir = os.path.join(TEMP_ROOT, f"{uid}_{job.id}")
    os.makedirs(job.dir, exist_ok=True)
    DIRS_ACTIVOS.add(job.dir)
    ruta = os.path.join(job.dir, nombre_base)

    def subida_ok(res):
        return isinstance(res, dict) and 'itemid' in res and 'error' not in res

    try:
        # 1. Login ANTES de descargar (si la nube está caída o las credenciales mal, fallamos ya)
        job.estado = "iniciando sesión"
        await say(f"🔐 {nombre_base}: iniciando sesión en {cfg['nombre']}...")
        try:
            sesion = await asyncio.to_thread(login_moodle, usuario, contraseña, base_url)
        except MoodleError as e:
            log_action(uid, "login_error", f"{type(e).__name__}: {e.detalle}"[:300])
            await say(e.usuario_msg)
            return
        job.comprobar()

        # 2. Descarga con progreso, reanudación y escritura atómica
        job.estado = "descargando"
        prog_dl = Progreso(job.size, job.cancelar)
        titulo_dl = f"📥 Descargando {nombre_base}"
        msg_dl = await say(texto_progreso(titulo_dl, prog_dl))
        try:
            tamano = await con_progreso(msg_dl, titulo_dl, prog_dl, descargar_archivo(job.url, ruta, prog_dl))
        except JobCancelado:
            raise
        except Exception as e:
            await editar_seguro(msg_dl, f"❌ Falló la descarga de {nombre_base}")
            log_error(uid, f"Descarga fallida: {e}", traceback.format_exc())
            await say(f"❌ No pude descargar {nombre_base}: {str(e)[:300]}")
            return
        await editar_seguro(msg_dl, f"✅ Descargado: {nombre_base} ({fmt_bytes(tamano)}) 100%")
        job.comprobar()

        # 3. Subida (con reintentos y re-login si se corta la conexión)
        async def subir_con_progreso(ruta_local, etiqueta):
            nonlocal sesion
            res = None
            for intento in range(1, SUBIDA_INTENTOS + 1):
                job.comprobar()
                prog = Progreso(os.path.getsize(ruta_local), job.cancelar)
                titulo = f"☁️ Subiendo {etiqueta} a {cfg['nombre']}"
                msg = await say(texto_progreso(titulo, prog))
                res = await con_progreso(msg, titulo, prog,
                                         subir_archivo_a_moodle(sesion, ruta_local, base_url, prog))
                if subida_ok(res):
                    await editar_seguro(msg, f"✅ {etiqueta} subido (100%)")
                    return res
                job.comprobar()
                reintentar = isinstance(res, dict) and res.get("reintentable") and intento < SUBIDA_INTENTOS
                sufijo = f" — reintentando ({intento}/{SUBIDA_INTENTOS})" if reintentar else ""
                await editar_seguro(msg, f"❌ Falló la subida de {etiqueta}{sufijo}")
                if not reintentar:
                    return res
                await asyncio.sleep(5 * intento)
                try:  # sesión nueva: la anterior pudo morir con la conexión
                    sesion = await asyncio.to_thread(login_moodle, usuario, contraseña, base_url)
                except MoodleError as e:
                    return {"error": e.usuario_msg}
            return res

        while True:
            job.comprobar()
            dividir = tamano > limite
            if dividir:
                if not shutil.which('7z'):
                    await say("❌ El servidor no tiene '7z' instalado. No puedo dividir el archivo.")
                    return
                if shutil.disk_usage(job.dir).free < tamano + MARGEN_DISCO:
                    await say("❌ No hay espacio en disco para dividir el archivo.")
                    return
                job.estado = "dividiendo"
                await say(f"📦 Dividiendo {nombre_base} en partes de {fmt_bytes(limite)}...")
                partes = await dividir_archivo_async(ruta, limite)
                if not partes:
                    await say("❌ Error al dividir el archivo. Ver logs del servidor.")
                    return
            else:
                partes = [ruta]

            job.estado = "subiendo"
            n = len(partes)
            filas, enlaces = [], []
            resultado, detalle_error = "ok", ""
            try:
                for i, parte in enumerate(partes, 1):
                    job.comprobar()
                    etiqueta = nombre_base if not dividir else f"parte {i}/{n}"
                    res = await subir_con_progreso(parte, etiqueta)
                    if dividir:  # liberar disco a medida que se sube
                        try:
                            os.remove(parte)
                        except OSError:
                            pass
                    if subida_ok(res):
                        nom = os.path.basename(parte)
                        # El enlace de webservice/pluginfile.php usa el contextid y exige el token
                        ctx_id = res.get('contextid') or res['userid']
                        url = f"{base_url}/webservice/pluginfile.php/{ctx_id}/user/draft/{res['itemid']}/{quote(nom)}"
                        tok_srv = getattr(sesion, 'moodle_token', None)
                        if tok_srv:
                            url += f"?token={tok_srv}"
                        enlaces.append(url)
                        filas.append((uid, f"{nombre_base}.part{i}" if dividir else nombre_base, nom,
                                      res['itemid'], res['userid'], url,
                                      os.path.getsize(parte) if os.path.exists(parte) else (tamano if not dividir else 0),
                                      ahora()))
                    elif _es_413(res):
                        resultado = "413"
                        break
                    else:
                        resultado = "fallo"
                        if isinstance(res, dict):
                            detalle_error = str(res.get('error', 'Desconocido'))[:500]
                            log_error(uid, f"Subida falló ({etiqueta})", res.get('traceback', ''))
                        else:
                            detalle_error = "respuesta inesperada de la nube"
                        break
            finally:
                if dividir:  # restos de partes que no llegaron a subirse
                    for p in partes:
                        if os.path.exists(p):
                            try:
                                os.remove(p)
                            except OSError:
                                pass

            if resultado == "ok":
                # TODO O NADA: los registros se guardan solo si TODAS las partes subieron
                with get_db_conn() as conn:
                    conn.executemany('''INSERT INTO archivos (telegram_id, nombre_original, nombre_en_moodle,
                                        itemid, userid, enlace, tamano_bytes, fecha_subida)
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', filas)
                log_action(uid, "subida", f"{nombre_base} ({tamano/(1024**2):.1f}MB, {n} parte(s))")
                if dividir:
                    await enviar_lista_html(say, f"📎 <b>{h(nombre_base)}</b> - Partes (únelas con 7-Zip):\n\n",
                                            [f"<code>{h(e)}</code>" for e in enlaces])
                else:
                    await say(f"✅ <b>Subido exitosamente</b>\n\n<code>{h(enlaces[0])}</code>", parse_mode='HTML')
                return

            if resultado == "fallo":
                aviso = f"❌ Error de {cfg['nombre']} subiendo {nombre_base}: {detalle_error}"
                if enlaces:
                    aviso += (f"\n\n⚠️ Se subieron {len(enlaces)}/{n} partes, pero como el archivo quedó "
                              f"incompleto NO se registró. Vuelve a enviar el enlace.")
                await say(aviso[:1500])
                return

            # resultado == "413": el servidor no acepta partes de este tamaño -> reducir a la mitad
            nuevo = min(limite, tamano) // 2
            if nuevo < 5 * 1024 * 1024:
                await say(f"❌ {cfg['nombre']} rechaza incluso partes pequeñas (413). No puedo subir {nombre_base}.")
                return
            limite = nuevo
            cfg["max_parte"] = nuevo  # se recuerda para los próximos archivos
            await say(f"⚠️ El servidor rechaza ese tamaño (413). Reintentando en partes de {fmt_bytes(nuevo)}...")

    except JobCancelado:
        if job.motivo == "timeout":
            await say(f"⏱️ {nombre_base}: se superó el tiempo máximo ({fmt_tiempo(JOB_TIMEOUT)}). Trabajo abortado y archivos temporales borrados.")
        else:
            await say(f"🚫 {nombre_base}: cancelado. Archivos temporales borrados.")
        log_action(uid, "cancelado", f"{nombre_base} ({job.motivo})")
    except asyncio.CancelledError:
        # el bot se está apagando: los hilos se detienen con el Event y la carpeta se borra abajo
        job.cancelar.set()
        await say(f"⚠️ El bot se está reiniciando: {nombre_base} no se completó. Reenvía el enlace en un momento.")
        raise
    except Exception as e:
        log_error(uid, f"Error procesando enlace: {e}", traceback.format_exc())
        await say(f"❌ Error: {str(e)}"[:1000])
    finally:
        job.cancelar.set()  # por si algún hilo sigue vivo: que termine ya
        shutil.rmtree(job.dir, ignore_errors=True)
        DIRS_ACTIVOS.discard(job.dir)
        job.estado = "terminado"

# ==================================================
# COMANDOS
# ==================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    username = update.effective_user.username
    try:
        with get_db_conn() as conn:
            conn.execute("INSERT OR IGNORE INTO usuarios (telegram_id, username, fecha_registro, ultimo_uso) VALUES (?, ?, ?, ?)",
                         (user_id, username, ahora(), ahora()))
            conn.execute("UPDATE usuarios SET ultimo_uso = ? WHERE telegram_id = ?", (ahora(), user_id))
        nube = obtener_nube_activa(user_id)
        user, _ = obtener_credenciales_moodle(user_id, nube)
        nombre_nube = CLOUDS[nube]["nombre"]
        estado = (f"☁️ Nube activa: {nombre_nube}\n"
                  + ("✅ Cuenta conectada" if user else "❌ Usa /setmoodle usuario contraseña"))
        await update.message.reply_text(
            f"🤖 *Bot de Nube Moodle*\n\n"
            f"{estado}\n\n"
            f"📤 *Comandos:*\n"
            f"/files - Ver archivos\n"
            f"/txt `ID` - Obtener enlace\n"
            f"/del `ID` - Borrar registro\n"
            f"/delall - Borrar todos tus registros\n"
            f"/cola - Ver tus subidas en curso y en espera\n"
            f"/cancelar - Cancelar todo (o `/cancelar ID`)\n"
            f"/mystats - Estadísticas\n"
            f"/setmoodle - Guardar cuenta de la nube activa\n"
            f"/cambiar - Cambiar de nube\n\n"
            f"💬 Envíame uno o varios *ENLACES*: se suben de uno en uno, en orden\n"
            f"_Máximo 10 GB por archivo_",
            parse_mode='Markdown'
        )
    except Exception:
        log_error(user_id, "Error en start", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

async def cmd_cola(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    cola = COLAS.get(update.effective_user.id)
    jobs = []
    if cola:
        if cola.actual:
            jobs.append(cola.actual)
        jobs.extend(cola.pendientes)
    if not jobs:
        await update.message.reply_text("📭 No tienes subidas en curso ni en espera.")
        return
    lineas = ["📋 Tus subidas:\n"]
    for pos, j in enumerate(jobs):
        tam = f" • {fmt_bytes(j.size)}" if j.size else ""
        lineas.append(f"#{j.id} • {j.nombre_base[:40]}{tam} • {j.estado}"
                      + ("" if pos == 0 and j is (cola.actual if cola else None) else f" (turno {pos + 1})"))
    lineas.append("\nCancelar: /cancelar o /cancelar ID")
    await update.message.reply_text("\n".join(lineas)[:4000])

async def cmd_cancelar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    cola = COLAS.get(update.effective_user.id)
    if not cola or (not cola.actual and not cola.pendientes):
        await update.message.reply_text("📭 No tienes nada que cancelar.")
        return
    todos = ([cola.actual] if cola.actual else []) + list(cola.pendientes)
    if context.args:
        try:
            objetivo = int(context.args[0].lstrip('#'))
        except ValueError:
            await update.message.reply_text("❌ Uso: /cancelar o /cancelar ID (el ID sale en /cola)")
            return
        targets = [j for j in todos if j.id == objetivo]
        if not targets:
            await update.message.reply_text(f"❌ No encontré la subida #{objetivo} en tu cola.")
            return
    else:
        targets = todos
    for j in targets:
        j.cancelar.set()
        if j in cola.pendientes:
            cola.pendientes.remove(j)
    await update.message.reply_text(f"🚫 Cancelando {len(targets)} subida(s)...")
    log_action(update.effective_user.id, "cancelar", ",".join(f"#{j.id}" for j in targets))

async def cmd_cambiar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    activa = obtener_nube_activa(update.effective_user.id)
    lineas = ["☁️ Elige la nube de subida:\n"]
    for k, cfg in CLOUDS.items():
        marca = " ✅ (activa)" if k == activa else ""
        extra = "" if cfg["requiere_cuenta"] else " (sin credenciales)"
        lineas.append(f"/{k} - {cfg['nombre']}{extra}{marca}")
    await update.message.reply_text("\n".join(lineas))

async def cmd_elegir_nube(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Maneja /1, /2, ... (acepta también /1@nombre_bot)."""
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    m = re.match(r'^/(\d+)', update.message.text.strip())
    nube = int(m.group(1)) if m else None
    if nube not in CLOUDS:
        await update.message.reply_text("❌ Esa nube no existe. Usa /cambiar para ver las disponibles.")
        return
    try:
        guardar_nube_activa(user_id, nube)
        cfg = CLOUDS[nube]
        usuario, _ = obtener_credenciales_moodle(user_id, nube)
        if cfg["requiere_cuenta"] and not usuario:
            aviso = "\n❌ Aún no tienes cuenta guardada aquí. Usa /setmoodle usuario contraseña"
        elif cfg["requiere_cuenta"]:
            aviso = f"\n✅ Cuenta guardada: {usuario}"
        else:
            aviso = "\n✅ No necesita credenciales"
        await update.message.reply_text(f"☁️ Nube activa: {cfg['nombre']}{aviso}\n\nEnvíame un enlace para subirlo.")
        log_action(user_id, "cambiar_nube", cfg["nombre"])
    except Exception:
        log_error(user_id, "Error en cambiar nube", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

async def set_moodle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if len(context.args) != 2:
        await update.message.reply_text("❌ Uso: /setmoodle usuario contraseña", parse_mode='Markdown')
        return
    usuario, contraseña = context.args[0], context.args[1]
    nube = obtener_nube_activa(user_id)
    cfg = CLOUDS[nube]
    await update.message.reply_text(f"🔐 Probando conexión con {cfg['nombre']}...")
    try:
        await asyncio.to_thread(login_moodle, usuario, contraseña, cfg["url"])
        guardar_credenciales_moodle(user_id, usuario, contraseña, nube)
        await update.message.reply_text(f"✅ Credenciales de {cfg['nombre']} guardadas para: `{escape_markdown(usuario)}`", parse_mode='Markdown')
        log_action(user_id, "set_moodle", usuario)
    except MoodleError as e:
        log_action(user_id, "login_error", f"{type(e).__name__}: {e.detalle}"[:300])
        await update.message.reply_text(e.usuario_msg)
    except Exception:
        log_error(user_id, "Error en set_moodle", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

async def listar_archivos(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            archivos = conn.execute("SELECT id, nombre_original, tamano_bytes, fecha_subida FROM archivos WHERE telegram_id = ? ORDER BY fecha_subida DESC", (user_id,)).fetchall()
        if not archivos:
            await update.message.reply_text("📂 No tienes archivos", parse_mode='Markdown')
            return
        mensaje = "📁 *Tus archivos:*\n\n"
        for a in archivos:
            mb = a[2] // (1024*1024) if a[2] else 0
            fecha = str(a[3])[:10] if a[3] else "?"
            nombre_escapado = escape_markdown(a[1][:30])
            mensaje += f"`{a[0]}` • {nombre_escapado} • {mb}MB • {fecha}\n"
        await update.message.reply_text(mensaje[:4000], parse_mode='Markdown')
    except Exception:
        log_error(user_id, "Error en listar_archivos", traceback.format_exc())
        await update.message.reply_text("❌ Error al listar archivos.")

async def cmd_txt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("❌ Uso: /txt ID", parse_mode='Markdown')
        return
    try:
        archivo_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ El ID debe ser un número", parse_mode='Markdown')
        return
    try:
        with get_db_conn() as conn:
            resultado = conn.execute("SELECT enlace, nombre_original FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id)).fetchone()
        if not resultado:
            await update.message.reply_text(f"❌ Archivo con ID {archivo_id} no encontrado", parse_mode='Markdown')
            return
        enlace, nombre = resultado
        await update.message.reply_text(f"📄 <b>{h(nombre)}</b>\n\n<code>{h(enlace)}</code>", parse_mode='HTML')
    except Exception:
        log_error(user_id, f"Error en txt {archivo_id}", traceback.format_exc())
        await update.message.reply_text("❌ Error al obtener enlace.")

async def cmd_del(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("❌ Uso: /del ID", parse_mode='Markdown')
        return
    try:
        archivo_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ El ID debe ser un número", parse_mode='Markdown')
        return
    try:
        with get_db_conn() as conn:
            archivo = conn.execute("SELECT nombre_original FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id)).fetchone()
            if not archivo:
                await update.message.reply_text(f"❌ Archivo con ID {archivo_id} no encontrado", parse_mode='Markdown')
                return
            afectados = conn.execute("DELETE FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id)).rowcount
        if afectados:
            await update.message.reply_text(f"✅ *Registro eliminado:* {escape_markdown(archivo[0])}\n_Nota: El archivo sigue en la nube_", parse_mode='Markdown')
            log_action(user_id, "borrar", f"ID:{archivo_id} {archivo[0]}")
        else:
            await update.message.reply_text("❌ No se eliminó ningún registro.")
    except Exception:
        log_error(user_id, f"Error en del {archivo_id}", traceback.format_exc())
        await update.message.reply_text("❌ Error al eliminar.")

async def borrar_todos(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            afectados = conn.execute("DELETE FROM archivos WHERE telegram_id = ?", (user_id,)).rowcount
        await update.message.reply_text(f"✅ Eliminados {afectados} registros (los archivos en la nube permanecen)", parse_mode='Markdown')
        log_action(user_id, "borrar_todos", str(afectados))
    except Exception:
        log_error(user_id, "Error en borrar_todos", traceback.format_exc())
        await update.message.reply_text("❌ Error al eliminar todos.")

async def mis_estadisticas(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            count, total = conn.execute("SELECT COUNT(*), SUM(tamano_bytes) FROM archivos WHERE telegram_id = ?", (user_id,)).fetchone()
            subidas = conn.execute("SELECT COUNT(*) FROM logs WHERE telegram_id = ? AND accion = 'subida'", (user_id,)).fetchone()[0]
        gb = (total or 0) / (1024**3)
        await update.message.reply_text(f"📊 *Estadísticas*\n\n📁 Archivos: {count or 0}\n💾 Total: {gb:.2f} GB\n📤 Subidas: {subidas}", parse_mode='Markdown')
    except Exception:
        log_error(user_id, "Error en mystats", traceback.format_exc())
        await update.message.reply_text("❌ Error al obtener estadísticas.")

# ==================================================
# ADMIN
# ==================================================
async def panel_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    if not es_admin(update.effective_user.id):
        await update.message.reply_text("❌ Solo administradores", parse_mode='Markdown')
        return
    keyboard = [
        [InlineKeyboardButton("📋 Logs", callback_data="adm_logs")],
        [InlineKeyboardButton("👥 Usuarios", callback_data="adm_users")],
        [InlineKeyboardButton("📤 Subidas", callback_data="adm_uploads")],
        [InlineKeyboardButton("⏳ Colas activas", callback_data="adm_queue")],
        [InlineKeyboardButton("🗑️ Eliminaciones", callback_data="adm_deletes")],
        [InlineKeyboardButton("🌩️ Todas las nubes", callback_data="adm_allclouds")],
        [InlineKeyboardButton("🧹 Limpiar logs antiguos", callback_data="adm_cleardata")],
        [InlineKeyboardButton("☢️ NUKE (todo)", callback_data="adm_nuke_confirm")],
    ]
    await update.message.reply_text("🔧 *Panel de Administración*", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not es_admin(query.from_user.id):
        await query.edit_message_text("❌ No autorizado", parse_mode='Markdown')
        return
    data = query.data
    try:
        if data == "adm_queue":
            msg = f"⏳ Colas activas (límite global: {MAX_SUBIDAS_SIMULTANEAS} simultáneas)\n\n"
            if not COLAS:
                msg += "Vacío."
            for uid, cola in list(COLAS.items()):
                act = f"#{cola.actual.id} {cola.actual.nombre_base[:25]} [{cola.actual.estado}]" if cola.actual else "—"
                msg += f"U{uid}: ahora {act} | en espera: {len(cola.pendientes)}\n"
            await query.edit_message_text(msg[:4000])
            return
        with get_db_conn() as conn:
            c = conn.cursor()
            if data == "adm_logs":
                logs = c.execute("SELECT fecha, telegram_id, accion, detalle FROM logs ORDER BY fecha DESC LIMIT 30").fetchall()
                msg = "📋 Últimos logs:\n\n"
                for l in logs:
                    msg += f"{str(l[0])[:16]} U{l[1]}: {l[2]} {str(l[3])[:100]}\n"
                await query.edit_message_text(msg[:4000])  # sin Markdown: los logs traen caracteres raros
            elif data == "adm_users":
                users = c.execute("SELECT telegram_id, username, fecha_registro FROM usuarios ORDER BY fecha_registro DESC").fetchall()
                msg = "👥 *Usuarios:*\n\n"
                for u in users:
                    msg += f"ID: `{u[0]}` • @{escape_markdown(u[1] or '?')} • {str(u[2])[:10]}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_uploads":
                subs = c.execute("SELECT id, telegram_id, nombre_original, tamano_bytes, fecha_subida FROM archivos ORDER BY fecha_subida DESC LIMIT 20").fetchall()
                msg = "📤 *Últimas subidas:*\n\n"
                for s in subs:
                    mb = s[3] // (1024*1024) if s[3] else 0
                    msg += f"ID:`{s[0]}` U{s[1]}: {escape_markdown(s[2][:20])} ({mb}MB) {str(s[4])[:16]}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_deletes":
                dels = c.execute("SELECT fecha, telegram_id, detalle FROM logs WHERE accion='borrar' OR accion='borrar_todos' ORDER BY fecha DESC LIMIT 20").fetchall()
                msg = "🗑️ *Eliminaciones:*\n\n"
                for d in dels:
                    msg += f"{str(d[0])[:16]} U{d[1]}: {escape_markdown(d[2])}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_allclouds":
                nubes = c.execute("SELECT telegram_id, COUNT(*), SUM(tamano_bytes) FROM archivos GROUP BY telegram_id").fetchall()
                msg = "🌩️ *Almacenamiento por usuario:*\n\n"
                for n in nubes:
                    gb = (n[2] or 0) / (1024**3)
                    msg += f"U{n[0]}: {n[1]} archivos, {gb:.2f} GB\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_cleardata":
                limite = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
                eliminados = c.execute("DELETE FROM logs WHERE fecha < ?", (limite,)).rowcount
                await query.edit_message_text(f"✅ Limpiados {eliminados} logs antiguos (más de 7 días)", parse_mode='Markdown')
            elif data == "adm_nuke_confirm":
                keyboard = [
                    [InlineKeyboardButton("💀 SÍ, destruir todo", callback_data="adm_nuke_do")],
                    [InlineKeyboardButton("❌ Cancelar", callback_data="adm_nuke_cancel")],
                ]
                await query.edit_message_text("⚠️ *¿REALMENTE quieres borrar TODOS los datos?*\n(archivos en BD, usuarios, credenciales, logs)\n\n*No se puede deshacer.*", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')
            elif data == "adm_nuke_do":
                for tabla in ("archivos", "logs", "usuarios", "credenciales_moodle", "credenciales_nube", "preferencias"):
                    c.execute(f"DELETE FROM {tabla}")
                await query.edit_message_text("💀 *NUKE COMPLETO* - Todos los datos eliminados.", parse_mode='Markdown')
            elif data == "adm_nuke_cancel":
                await query.edit_message_text("❌ Operación cancelada.", parse_mode='Markdown')
    except Exception:
        log_error(query.from_user.id, "Error en admin_callback", traceback.format_exc())
        await query.edit_message_text("❌ Error interno. Revisa logs.")

# ==================================================
# RECIBIR ENLACES: solo valida y ENCOLA (responde al instante, no bloquea nada)
# ==================================================
async def procesar_enlace(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    texto = update.message.text.strip()
    if texto.startswith("/") or not texto.startswith("http"):
        return
    urls = list(dict.fromkeys(URL_RE.findall(texto)))[:MAX_ENLACES_POR_MENSAJE]  # sin repetidos
    if not urls:
        return
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    nube = obtener_nube_activa(user_id)
    cfg = CLOUDS[nube]
    usuario, _ = obtener_credenciales_moodle(user_id, nube)
    if not usuario:
        await update.message.reply_text(f"❌ Nube activa: {cfg['nombre']}. Primero usa /setmoodle usuario contraseña (o /cambiar para elegir otra nube)")
        return

    for url in urls:
        parsed = urlparse(url)
        nombre_base = unquote(parsed.path.split("/")[-1]) if parsed.path else ""
        nombre_base = sanitize_filename(nombre_base)
        if not nombre_base or len(nombre_base) > 100:
            nombre_base = f"archivo_{int(time.time())}"
        try:
            size = await verificar_url(url)
        except Exception as e:
            await update.message.reply_text(f"❌ {nombre_base}: {str(e)[:300]}")
            continue
        job = Job(id=next(_CONTADOR_JOBS), user_id=user_id, chat_id=chat_id, url=url,
                  nube=nube, nombre_base=nombre_base, size=size)
        estado, pos = encolar(context.bot, job)
        if estado == "dup":
            await update.message.reply_text(f"♻️ {nombre_base} ya está en tu cola.")
        elif estado == "llena":
            await update.message.reply_text(f"🚫 Tu cola está llena ({MAX_COLA_POR_USUARIO} enlaces). Espera a que termine alguno.")
            break
        elif pos == 0:
            await update.message.reply_text(f"✅ #{job.id} {nombre_base} ({fmt_bytes(size) if size else 'tamaño desconocido'}): empezando ahora.")
        else:
            await update.message.reply_text(f"⏳ #{job.id} {nombre_base} ({fmt_bytes(size) if size else 'tamaño desconocido'}): en cola, turno {pos + 1}. Ver /cola · cancelar /cancelar {job.id}")

# ==================================================
# SERVIDOR DE SALUD (Render Web Service necesita un puerto abierto)
# ==================================================
from http.server import BaseHTTPRequestHandler, HTTPServer

class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"ok")
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass

def iniciar_servidor_salud():
    port = os.environ.get("PORT")
    if not port:
        return
    srv = HTTPServer(("0.0.0.0", int(port)), _Health)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"🌐 Servidor de salud en puerto {port}")

# ==================================================
# CONFLICTO DE POLLING ("terminated by other getUpdates request")
# ==================================================
# Telegram solo permite UN consumidor de getUpdates por token. Si hay dos, cada uno
# "echa" al otro y aparece telegram.error.Conflict. Causas típicas:
#   1) Dos procesos en la MISMA máquina (script lanzado dos veces)   -> lo evita el bloqueo de abajo.
#   2) Un despliegue en Render/Railway: la instancia nueva arranca mientras la vieja aún vive.
#   3) Probar en tu PC con el mismo BOT_TOKEN que está en producción.
#   4) Un webhook configurado para ese token (se borra en post_init).
#   5) Dos servicios/réplicas con el mismo token (escala > 1).
_LOCK_FILE = None
_ULTIMO_AVISO_CONFLICTO = 0.0
_CONFLICTOS = 0

def identidad_instancia():
    return (f"host={socket.gethostname()} pid={os.getpid()} "
            f"render_instance={os.environ.get('RENDER_INSTANCE_ID', '-')} "
            f"render_service={os.environ.get('RENDER_SERVICE_ID', '-')}")

def adquirir_bloqueo_instancia():
    """Bloqueo de archivo: impide arrancar dos copias del bot en la misma máquina."""
    global _LOCK_FILE
    try:
        import fcntl
    except ImportError:  # Windows
        return True
    clave = hashlib.sha256(BOT_TOKEN.encode()).hexdigest()[:12]
    ruta = os.path.join(tempfile.gettempdir(), f"telegram_bot_{clave}.lock")
    _LOCK_FILE = open(ruta, "w")
    try:
        fcntl.flock(_LOCK_FILE, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"⛔ Ya hay otra copia de este bot corriendo en esta máquina (lock: {ruta}). Saliendo.")
        return False
    _LOCK_FILE.write(str(os.getpid()))
    _LOCK_FILE.flush()
    return True

async def manejar_error(update, context: ContextTypes.DEFAULT_TYPE):
    global _ULTIMO_AVISO_CONFLICTO, _CONFLICTOS
    err = context.error
    if isinstance(err, Conflict):
        _CONFLICTOS += 1
        if time.time() - _ULTIMO_AVISO_CONFLICTO > 60:  # no inundar el log
            _ULTIMO_AVISO_CONFLICTO = time.time()
            print(f"⚠️ CONFLICTO de Telegram #{_CONFLICTOS}: otra instancia está haciendo getUpdates con el "
                  f"mismo BOT_TOKEN. Esta instancia: {identidad_instancia()}.\n"
                  f"   Revisa: despliegue de Render con instancia vieja aún viva, bot corriendo en tu PC, "
                  f"réplicas > 1, o un segundo servicio con el mismo token.")
        return  # PTB reintenta solo; si la otra instancia muere, se resuelve sola
    if isinstance(err, NetworkError):
        print(f"🌐 Error de red transitorio con Telegram: {type(err).__name__}: {err}")
        return
    print(f"❌ Error no controlado: {type(err).__name__}: {err}")
    traceback.print_exception(type(err), err, err.__traceback__)

_TAREA_LIMPIEZA = None

async def post_init(app: Application):
    global _TAREA_LIMPIEZA
    # Un webhook activo también provoca Conflict con getUpdates: se elimina por si acaso
    try:
        await app.bot.delete_webhook(drop_pending_updates=False)
    except Exception as e:
        print(f"⚠️ No se pudo borrar webhook: {e}")
    semaforo()  # crear el semáforo dentro del bucle de eventos
    _TAREA_LIMPIEZA = asyncio.create_task(bucle_limpieza())
    print(f"🆔 Instancia: {identidad_instancia()}")

async def post_shutdown(app: Application):
    """Apagado ordenado: cancela trabajos, espera a que limpien y borra temporales."""
    tareas = []
    for cola in list(COLAS.values()):
        for j in list(cola.pendientes) + ([cola.actual] if cola.actual else []):
            j.cancelar.set()
        cola.pendientes.clear()
        if cola.tarea:
            tareas.append(cola.tarea)
    for t in tareas:
        t.cancel()
    if tareas:
        await asyncio.gather(*tareas, return_exceptions=True)
    if _TAREA_LIMPIEZA:
        _TAREA_LIMPIEZA.cancel()
    limpiar_temporales(todo=True)

# ==================================================
# MAIN
# ==================================================
def main():
    if not adquirir_bloqueo_instancia():
        sys.exit(1)
    init_db()
    limpiar_temporales(todo=True)   # ningún trabajo sobrevive a un reinicio: todo lo que haya es basura
    limpiar_logs_antiguos(dias=30)
    if not shutil.which('7z'):
        print("⚠️ ADVERTENCIA: '7z' no está instalado. No podrás dividir archivos grandes.")
        print("   Instala con: sudo apt install p7zip-full")
    iniciar_servidor_salud()
    app = (Application.builder()
           .token(BOT_TOKEN)
           .concurrent_updates(CONCURRENT_UPDATES)   # los comandos se atienden aunque haya subidas en curso
           .post_init(post_init)
           .post_shutdown(post_shutdown)
           .build())
    app.add_error_handler(manejar_error)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("setmoodle", set_moodle))
    app.add_handler(CommandHandler("cambiar", cmd_cambiar))
    app.add_handler(CommandHandler("cola", cmd_cola))
    app.add_handler(CommandHandler("cancelar", cmd_cancelar))
    app.add_handler(MessageHandler(filters.Regex(r'^/\d+(@\w+)?\s*$'), cmd_elegir_nube))
    app.add_handler(CommandHandler("files", listar_archivos))
    app.add_handler(CommandHandler("txt", cmd_txt))
    app.add_handler(CommandHandler("del", cmd_del))
    app.add_handler(CommandHandler("delall", borrar_todos))
    app.add_handler(CommandHandler("mystats", mis_estadisticas))
    app.add_handler(CommandHandler("admin", panel_admin))
    app.add_handler(CallbackQueryHandler(admin_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, procesar_enlace))
    print("🤖 Bot iniciado.")
    print(f"Subidas simultáneas globales: {MAX_SUBIDAS_SIMULTANEAS} · cola por usuario: {MAX_COLA_POR_USUARIO} "
          f"· límite de archivo: 10 GB")
    app.run_polling(drop_pending_updates=DROP_PENDING,
                    allowed_updates=["message", "callback_query"])

if __name__ == "__main__":
    main()

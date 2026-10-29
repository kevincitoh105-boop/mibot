import os
import re
import asyncio
import sqlite3
import time
import requests
import subprocess
import shutil
import traceback
import html
import uuid
from urllib.parse import urlparse, unquote
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler

# ==================================================
# CONFIGURACIÓN OBLIGATORIA
# ==================================================
BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("No se encontró BOT_TOKEN en variables de entorno.")

MOODLE_URL = "https://moodle.instec.cu"

# ==================================================
# NUBES DISPONIBLES (/cambiar). Para añadir otra: una entrada nueva aquí.
#   requiere_cuenta=True  -> pide usuario/contraseña (/setmoodle)
#   requiere_cuenta=False -> reservado para nubes sin credenciales (aún no hay ninguna)
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

# Límites (cambio obligatorio 1 y 2)
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024   # 10 GB
MAX_SPLIT_SIZE = 1024 * 1024 * 1024       # 1 GB (para dividir)

# Cifrado Fernet (cambio obligatorio 1)
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
def escape_markdown(text: str) -> str:
    """Escapa solo lo que Telegram (Markdown clásico) necesita: _ * ` [
    (antes escapaba de más y se veían barras '\\' en los mensajes)."""
    return re.sub(r'([_*`\[])', r'\\\1', str(text))

def h(text) -> str:
    """Escapa texto para usarlo dentro de mensajes parse_mode='HTML'."""
    return html.escape(str(text), quote=False)

def sanitize_filename(name: str) -> str:
    """Elimina caracteres peligrosos (cambio obligatorio 3)"""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)

# ==================================================
# BASE DE DATOS (sin check_same_thread)
# ==================================================
def get_db_conn():
    return sqlite3.connect('moodle_bot.db', timeout=20)  # sin check_same_thread

def init_db():
    with get_db_conn() as conn:
        c = conn.cursor()
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
    os.makedirs("temp_downloads", exist_ok=True)

def log_action(telegram_id, accion, detalle=""):
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO logs (telegram_id, accion, detalle, fecha) VALUES (?, ?, ?, ?)",
                  (telegram_id, accion, detalle, datetime.now()))

def log_error(telegram_id, error_msg, traceback_str):
    detalle = f"{error_msg}\n{traceback_str}"[:500]
    log_action(telegram_id, "error", detalle)
    print(f"❌ ERROR (user {telegram_id}): {error_msg}\n{traceback_str}")

def limpiar_logs_antiguos(dias=30):
    with get_db_conn() as conn:
        c = conn.cursor()
        limite = datetime.now() - timedelta(days=dias)
        c.execute("DELETE FROM logs WHERE fecha < ?", (limite,))
        print(f"🧹 Limpiados {c.rowcount} logs antiguos (> {dias} días)")

def limpiar_archivos_temporales_antiguos(horas=1):
    ahora = time.time()
    os.makedirs("temp_downloads", exist_ok=True)
    for f in os.listdir("temp_downloads"):
        ruta = os.path.join("temp_downloads", f)
        if os.path.isfile(ruta) and (ahora - os.path.getmtime(ruta)) > horas * 3600:
            try:
                os.remove(ruta)
                print(f"🧹 Eliminado temporal antiguo: {ruta}")
            except Exception as e:
                print(f"⚠️ No se pudo eliminar {ruta}: {e}")

def es_admin(telegram_id):
    return telegram_id in ADMIN_IDS

def obtener_nube_activa(telegram_id):
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT nube FROM preferencias WHERE telegram_id = ?", (telegram_id,))
        r = c.fetchone()
    return r[0] if r and r[0] in CLOUDS else NUBE_POR_DEFECTO

def guardar_nube_activa(telegram_id, nube):
    with get_db_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO preferencias (telegram_id, nube) VALUES (?, ?)",
                     (telegram_id, nube))

def obtener_credenciales_moodle(telegram_id, nube=None):
    if nube is None:
        nube = obtener_nube_activa(telegram_id)
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT usuario, contraseña FROM credenciales_nube WHERE telegram_id = ? AND nube = ?",
                  (telegram_id, nube))
        resultado = c.fetchone()
    if resultado:
        usuario = resultado[0]
        try:
            contraseña = decrypt(resultado[1])
        except Exception as e:
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
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO credenciales_nube (telegram_id, nube, usuario, contraseña) VALUES (?, ?, ?, ?)",
                  (telegram_id, nube, usuario, contraseña))

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

# --------------------------------------------------
# Errores de Moodle: cada tipo de fallo tiene su propia clase y su propio
# mensaje, para no decir "contraseña incorrecta" cuando Moodle está caído.
# --------------------------------------------------
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
    """Inicia sesión en Moodle y devuelve la sesión.

    Si falla, lanza una excepción que dice exactamente qué pasó:
      - MoodleConexionError:    Moodle no responde (las credenciales ni se probaron)
      - MoodleRespuestaError:   Moodle responde pero la página no es la esperada
      - MoodleCredencialesError: Moodle respondió y rechazó usuario/contraseña
    """
    base_url = (base_url or MOODLE_URL).rstrip("/")
    sesion = create_session()
    login_url = f"{base_url}/login/index.php"

    # 1. Pedir la página de login (aquí se nota si Moodle está caído o bloquea)
    try:
        login_page = sesion.get(login_url, timeout=30)
        login_page.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Login GET error: {type(e).__name__}: {e}")
        raise clasificar_error_conexion(e) from e

    # 2. Sacar el logintoken del formulario
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

    # 3. Enviar usuario y contraseña
    try:
        response = sesion.post(login_url, data=payload, allow_redirects=True, timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Login POST error: {type(e).__name__}: {e}")
        raise clasificar_error_conexion(e) from e

    # 4. Interpretar la respuesta. Si Moodle nos devuelve a la página de login,
    #    sí respondió y rechazó el usuario/contraseña.
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
    return sesion

class _CuerpoMultipart:
    """Cuerpo multipart/form-data que se envía en streaming y va sumando
    los bytes enviados en `progreso.hecho` (para el porcentaje en vivo)."""
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
    cuerpo = _CuerpoMultipart(ruta_archivo, 'file_1', progreso)
    try:
        # timeout=(conexión, lectura): la lectura es la espera de la respuesta del servidor
        # una vez enviado todo el archivo (antes 120s era muy poco para archivos grandes).
        respuesta = sesion.post(url_subida, data=cuerpo,
                                headers={'Content-Type': f'multipart/form-data; boundary={cuerpo.boundary}'},
                                timeout=(30, 900))
        respuesta.raise_for_status()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "traceback": traceback.format_exc()}
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
    if not shutil.which('7z'):
        return []
    nombre_base = ruta_archivo + ".7z"
    cmd = ['7z', 'a', '-v{}b'.format(tamano_bytes), nombre_base, ruta_archivo]
    try:
        # Timeout de 1 hora
        resultado = subprocess.run(cmd, capture_output=True, timeout=3600,
                                   cwd=os.path.dirname(ruta_archivo) or ".")
        if resultado.returncode != 0:
            error_msg = resultado.stderr.decode('utf-8', errors='ignore')
            print(f"7z error (returncode {resultado.returncode}): {error_msg}")
            return []
    except subprocess.TimeoutExpired:
        print(f"7z timeout dividiendo {ruta_archivo}")
        return []
    except Exception as e:
        print(f"7z exception: {e}\n{traceback.format_exc()}")
        return []
    partes = []
    directorio = os.path.dirname(ruta_archivo) or "."
    for f in os.listdir(directorio):
        if f.startswith(os.path.basename(nombre_base)) and f != os.path.basename(nombre_base):
            partes.append(os.path.join(directorio, f))
    # Eliminar basura .7z base
    if os.path.exists(nombre_base):
        os.remove(nombre_base)
    return sorted(partes)

# ==================================================
# TAREAS BLOQUEANTES (con HEAD para tamaño)
# ==================================================
async def verificar_url(url):
    """Hace HEAD y comprueba tamaño, espacio y tipo (cambios 1,2 y extra)"""
    loop = asyncio.get_running_loop()
    def sync_head():
        head = requests.head(url, allow_redirects=True, timeout=30)
        head.raise_for_status()
        size = int(head.headers.get("Content-Length", 0))
        if size > MAX_FILE_SIZE:
            raise Exception(f"Archivo demasiado grande ({size/(1024**3):.2f} GB > {MAX_FILE_SIZE/(1024**3)} GB)")
        free = shutil.disk_usage("/").free
        if size > free:
            raise Exception(f"No hay suficiente espacio en disco (necesitas {size/(1024**3):.2f} GB)")
        # Opcional: evitar HTML
        content_type = head.headers.get("Content-Type", "")
        if "text/html" in content_type.lower():
            raise Exception("La URL apunta a una página web, no a un archivo directo")
        return size
    return await loop.run_in_executor(None, sync_head)

# --------------------------------------------------
# PROGRESO EN VIVO (porcentaje, velocidad y tiempo restante)
# --------------------------------------------------
class Progreso:
    """Contador compartido entre el hilo que descarga/sube y la tarea que edita el mensaje."""
    def __init__(self, total=0):
        self.total = total
        self.hecho = 0
        self.t0 = time.time()

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

async def editar_seguro(msg, texto, **kw):
    """Edita un mensaje sin romper el flujo si Telegram se queja (mismo texto, límite, etc.)."""
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
    tarea = asyncio.create_task(_bucle_progreso(msg, titulo, prog))
    try:
        return await trabajo
    finally:
        tarea.cancel()
        try:
            await tarea
        except asyncio.CancelledError:
            pass

async def descargar_archivo(url, destino, prog=None):
    loop = asyncio.get_running_loop()
    def sync_download():
        # Ya verificamos tamaño antes, aquí solo descargamos
        respuesta = requests.get(url, timeout=(30, 180), stream=True)
        respuesta.raise_for_status()
        if prog is not None and not prog.total:
            prog.total = int(respuesta.headers.get("Content-Length", 0) or 0)
        with open(destino, "wb") as f:
            for chunk in respuesta.iter_content(chunk_size=256 * 1024):
                if chunk:
                    f.write(chunk)
                    if prog is not None:
                        prog.hecho += len(chunk)
        return os.path.getsize(destino)
    return await loop.run_in_executor(None, sync_download)

async def subir_archivo_a_moodle(sesion, ruta, base_url=None, prog=None):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, subir_a_moodle, sesion, ruta, base_url, prog)

async def dividir_archivo_async(ruta, tamano_bytes=1024 * 1024 * 1024):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, dividir_archivo, ruta, tamano_bytes)

# ==================================================
# COMANDOS (con los 6 cambios aplicados)
# ==================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    username = update.effective_user.username
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO usuarios (telegram_id, username, fecha_registro, ultimo_uso) VALUES (?, ?, ?, ?)",
                      (user_id, username, datetime.now(), datetime.now()))
            c.execute("UPDATE usuarios SET ultimo_uso = ? WHERE telegram_id = ?", (datetime.now(), user_id))
        nube = obtener_nube_activa(user_id)
        user, pwd = obtener_credenciales_moodle(user_id, nube)
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
            f"/mystats - Estadísticas\n"
            f"/setmoodle - Guardar cuenta de la nube activa\n"
            f"/cambiar - Cambiar de nube\n\n"
            f"💬 Envíame un *ENLACE* para subirlo\n"
            f"_Máximo 10 GB por archivo_",
            parse_mode='Markdown'
        )
    except Exception as e:
        log_error(user_id, "Error en start", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

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
        # En un hilo aparte para no bloquear al bot mientras la nube responde
        await asyncio.to_thread(login_moodle, usuario, contraseña, cfg["url"])
        guardar_credenciales_moodle(user_id, usuario, contraseña, nube)
        await update.message.reply_text(f"✅ Credenciales de {cfg['nombre']} guardadas para: `{escape_markdown(usuario)}`", parse_mode='Markdown')
        log_action(user_id, "set_moodle", usuario)
    except MoodleError as e:
        log_action(user_id, "login_error", f"{type(e).__name__}: {e.detalle}"[:300])
        await update.message.reply_text(e.usuario_msg)
    except Exception as e:
        log_error(user_id, "Error en set_moodle", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

async def listar_archivos(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT id, nombre_original, tamano_bytes, fecha_subida FROM archivos WHERE telegram_id = ? ORDER BY fecha_subida DESC", (user_id,))
            archivos = c.fetchall()
        if not archivos:
            await update.message.reply_text("📂 No tienes archivos", parse_mode='Markdown')
            return
        mensaje = "📁 *Tus archivos:*\n\n"
        for a in archivos:
            mb = a[2] // (1024*1024) if a[2] else 0
            fecha = a[3][:10] if a[3] else "?"
            nombre_escapado = escape_markdown(a[1][:30])
            mensaje += f"`{a[0]}` • {nombre_escapado} • {mb}MB • {fecha}\n"
        await update.message.reply_text(mensaje[:4000], parse_mode='Markdown')
    except Exception as e:
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
            c = conn.cursor()
            c.execute("SELECT enlace, nombre_original FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id))
            resultado = c.fetchone()
        if not resultado:
            await update.message.reply_text(f"❌ Archivo con ID {archivo_id} no encontrado", parse_mode='Markdown')
            return
        enlace, nombre = resultado
        await update.message.reply_text(f"📄 *{escape_markdown(nombre)}*\n\n`{enlace}`", parse_mode='Markdown')
    except Exception as e:
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
            c = conn.cursor()
            c.execute("SELECT nombre_original FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id))
            archivo = c.fetchone()
            if not archivo:
                await update.message.reply_text(f"❌ Archivo con ID {archivo_id} no encontrado", parse_mode='Markdown')
                return
            c.execute("DELETE FROM archivos WHERE id = ? AND telegram_id = ?", (archivo_id, user_id))
            afectados = c.rowcount
        if afectados:
            await update.message.reply_text(f"✅ *Registro eliminado:* {escape_markdown(archivo[0])}\n_Nota: El archivo sigue en Moodle_", parse_mode='Markdown')
            log_action(user_id, "borrar", f"ID:{archivo_id} {archivo[0]}")
        else:
            await update.message.reply_text("❌ No se eliminó ningún registro.")
    except Exception as e:
        log_error(user_id, f"Error en del {archivo_id}", traceback.format_exc())
        await update.message.reply_text("❌ Error al eliminar.")

async def borrar_todos(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM archivos WHERE telegram_id = ?", (user_id,))
            afectados = c.rowcount
        await update.message.reply_text(f"✅ Eliminados {afectados} registros (los archivos en Moodle permanecen)", parse_mode='Markdown')
        log_action(user_id, "borrar_todos", str(afectados))
    except Exception as e:
        log_error(user_id, "Error en borrar_todos", traceback.format_exc())
        await update.message.reply_text("❌ Error al eliminar todos.")

async def mis_estadisticas(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    try:
        with get_db_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*), SUM(tamano_bytes) FROM archivos WHERE telegram_id = ?", (user_id,))
            count, total = c.fetchone()
            c.execute("SELECT COUNT(*) FROM logs WHERE telegram_id = ? AND accion = 'subida'", (user_id,))
            subidas = c.fetchone()[0]
        gb = (total or 0) / (1024**3)
        await update.message.reply_text(f"📊 *Estadísticas*\n\n📁 Archivos: {count or 0}\n💾 Total: {gb:.2f} GB\n📤 Subidas: {subidas}", parse_mode='Markdown')
    except Exception as e:
        log_error(user_id, "Error en mystats", traceback.format_exc())
        await update.message.reply_text("❌ Error al obtener estadísticas.")

# ==================================================
# ADMIN (con tracebacks)
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
        with get_db_conn() as conn:
            c = conn.cursor()
            if data == "adm_logs":
                c.execute("SELECT fecha, telegram_id, accion, detalle FROM logs ORDER BY fecha DESC LIMIT 30")
                logs = c.fetchall()
                msg = "📋 *Últimos logs:*\n\n"
                for l in logs:
                    msg += f"{l[0][:16]} U{l[1]}: {l[2]} {l[3][:100]}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_users":
                c.execute("SELECT telegram_id, username, fecha_registro FROM usuarios ORDER BY fecha_registro DESC")
                users = c.fetchall()
                msg = "👥 *Usuarios:*\n\n"
                for u in users:
                    msg += f"ID: `{u[0]}` • @{escape_markdown(u[1] or '?')} • {u[2][:10]}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_uploads":
                c.execute("SELECT id, telegram_id, nombre_original, tamano_bytes, fecha_subida FROM archivos ORDER BY fecha_subida DESC LIMIT 20")
                subs = c.fetchall()
                msg = "📤 *Últimas subidas:*\n\n"
                for s in subs:
                    mb = s[3] // (1024*1024) if s[3] else 0
                    nombre_escapado = escape_markdown(s[2][:20])
                    msg += f"ID:`{s[0]}` U{s[1]}: {nombre_escapado} ({mb}MB) {s[4][:16]}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_deletes":
                c.execute("SELECT fecha, telegram_id, detalle FROM logs WHERE accion='borrar' OR accion='borrar_todos' ORDER BY fecha DESC LIMIT 20")
                dels = c.fetchall()
                msg = "🗑️ *Eliminaciones:*\n\n"
                for d in dels:
                    msg += f"{d[0][:16]} U{d[1]}: {escape_markdown(d[2])}\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_allclouds":
                c.execute("SELECT telegram_id, COUNT(*), SUM(tamano_bytes) FROM archivos GROUP BY telegram_id")
                nubes = c.fetchall()
                msg = "🌩️ *Almacenamiento por usuario:*\n\n"
                for n in nubes:
                    gb = (n[2] or 0) / (1024**3)
                    msg += f"U{n[0]}: {n[1]} archivos, {gb:.2f} GB\n"
                await query.edit_message_text(msg[:4000], parse_mode='Markdown')
            elif data == "adm_cleardata":
                limite = datetime.now() - timedelta(days=7)
                c.execute("DELETE FROM logs WHERE fecha < ?", (limite,))
                eliminados = c.rowcount
                await query.edit_message_text(f"✅ Limpiados {eliminados} logs antiguos (más de 7 días)", parse_mode='Markdown')
            elif data == "adm_nuke_confirm":
                keyboard = [
                    [InlineKeyboardButton("💀 SÍ, destruir todo", callback_data="adm_nuke_do")],
                    [InlineKeyboardButton("❌ Cancelar", callback_data="adm_nuke_cancel")],
                ]
                await query.edit_message_text("⚠️ *¿REALMENTE quieres borrar TODOS los datos?*\n(archivos en BD, usuarios, credenciales, logs)\n\n*No se puede deshacer.*", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')
            elif data == "adm_nuke_do":
                c.execute("DELETE FROM archivos")
                c.execute("DELETE FROM logs")
                c.execute("DELETE FROM usuarios")
                c.execute("DELETE FROM credenciales_moodle")
                c.execute("DELETE FROM credenciales_nube")
                c.execute("DELETE FROM preferencias")
                await query.edit_message_text("💀 *NUKE COMPLETO* - Todos los datos eliminados.", parse_mode='Markdown')
            elif data == "adm_nuke_cancel":
                await query.edit_message_text("❌ Operación cancelada.", parse_mode='Markdown')
    except Exception as e:
        log_error(query.from_user.id, "Error en admin_callback", traceback.format_exc())
        await query.edit_message_text("❌ Error interno. Revisa logs.")

# ==================================================
# PROCESAR ENLACES (con HEAD y sanitizado)
# ==================================================
async def procesar_enlace(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    enlace = update.message.text
    if enlace.startswith("/") or not enlace.startswith("http"):
        return
    nube = obtener_nube_activa(user_id)
    cfg = CLOUDS[nube]
    base_url = cfg["url"]
    usuario, contraseña = obtener_credenciales_moodle(user_id, nube)
    if not usuario:
        await update.message.reply_text(f"❌ Nube activa: {cfg['nombre']}. Primero usa /setmoodle usuario contraseña (o /cambiar para elegir otra nube)")
        return

    # 1. Extraer nombre base
    parsed = urlparse(enlace)
    nombre_base = unquote(parsed.path.split("/")[-1]) if parsed.path else ""
    if not nombre_base or len(nombre_base) > 100:
        nombre_base = f"archivo_{int(time.time())}"
    # Sanitizar nombre (cambio obligatorio 3)
    nombre_base = sanitize_filename(nombre_base)

    # 2. Verificar tamaño, espacio y tipo (cambios obligatorios 1,2 y extra)
    try:
        await update.message.reply_text("📏 Verificando tamaño y disponibilidad...")
        size = await verificar_url(enlace)
        await update.message.reply_text(f"✅ Tamaño del archivo: {fmt_bytes(size)}")
    except Exception as e:
        await update.message.reply_text(f"❌ {str(e)}")
        return

    # 3. Login ANTES de descargar: si la nube está caída o las credenciales están mal,
    #    fallamos ya, sin gastar tiempo ni disco descargando el archivo.
    try:
        await update.message.reply_text(f"🔐 Iniciando sesión en {cfg['nombre']}...")
        sesion = await asyncio.to_thread(login_moodle, usuario, contraseña, base_url)
    except MoodleError as e:
        log_action(user_id, "login_error", f"{type(e).__name__}: {e.detalle}"[:300])
        await update.message.reply_text(e.usuario_msg)
        return
    except Exception as e:
        log_error(user_id, f"Error inesperado en login: {str(e)}", traceback.format_exc())
        await update.message.reply_text("❌ Error interno al iniciar sesión en Moodle.")
        return

    # Nombre único para evitar colisiones
    nombre_archivo = f"{user_id}_{int(time.time())}_{nombre_base}"
    ruta = os.path.join("temp_downloads", nombre_archivo)

    def subida_ok(res):
        return isinstance(res, dict) and 'itemid' in res and 'error' not in res

    async def subir_con_progreso(ruta_local, etiqueta):
        """Sube un archivo mostrando el porcentaje en vivo en un mensaje que se va editando."""
        prog = Progreso(os.path.getsize(ruta_local))
        titulo = f"☁️ Subiendo {etiqueta} a {cfg['nombre']}"
        msg = await update.message.reply_text(texto_progreso(titulo, prog))
        res = await con_progreso(msg, titulo, prog,
                                 subir_archivo_a_moodle(sesion, ruta_local, base_url, prog))
        if subida_ok(res):
            await editar_seguro(msg, f"✅ {etiqueta} subido (100%)")
        else:
            await editar_seguro(msg, f"❌ Falló la subida de {etiqueta}")
        return res

    try:
        # --- DESCARGA con progreso en vivo ---
        prog_dl = Progreso(size)
        titulo_dl = f"📥 Descargando {nombre_base}"
        msg_dl = await update.message.reply_text(texto_progreso(titulo_dl, prog_dl))
        tamano = await con_progreso(msg_dl, titulo_dl, prog_dl, descargar_archivo(enlace, ruta, prog_dl))
        await editar_seguro(msg_dl, f"✅ Descargado: {nombre_base} ({fmt_bytes(tamano)}) 100%")

        limite = cfg.get("max_parte") or MAX_SPLIT_SIZE
        while True:
            demasiado_grande = False  # el servidor respondió 413
            if tamano > limite:
                if not shutil.which('7z'):
                    await update.message.reply_text("❌ El VPS no tiene '7z' instalado. No puedo dividir el archivo.")
                    os.remove(ruta)
                    return
                await update.message.reply_text(f"📦 Dividiendo en partes de {fmt_bytes(limite)}...")
                partes = await dividir_archivo_async(ruta, limite)
                if not partes:
                    await update.message.reply_text("❌ Error al dividir el archivo. Ver logs del VPS.")
                    os.remove(ruta)
                    return
                enlaces = []
                for i, parte in enumerate(partes, 1):
                    try:
                        res = await subir_con_progreso(parte, f"parte {i}/{len(partes)}")
                        if subida_ok(res):
                            url = f"{base_url}/webservice/pluginfile.php/{res['userid']}/user/draft/{res['itemid']}/{os.path.basename(parte)}"
                            enlaces.append(url)
                            with get_db_conn() as conn:
                                c = conn.cursor()
                                c.execute('''INSERT INTO archivos (telegram_id, nombre_original, nombre_en_moodle, itemid, userid, enlace, tamano_bytes, fecha_subida)
                                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                          (user_id, f"{nombre_base}.part{i}", os.path.basename(parte), res['itemid'], res['userid'], url, os.path.getsize(parte), datetime.now()))
                            log_action(user_id, "subida", f"Parte {i} de {nombre_base}")
                        elif isinstance(res, dict) and 'error' in res:
                            if '413' in str(res.get('error')):
                                demasiado_grande = True
                                break
                            await update.message.reply_text(f"⚠️ Error de {cfg['nombre']} en la parte {i}: {str(res.get('error', 'Desconocido'))[:500]}")
                            log_error(user_id, f"Subida parte {i} falló", res.get('traceback', ''))
                        else:
                            await update.message.reply_text(f"⚠️ Error subiendo parte {i}")
                    finally:
                        if os.path.exists(parte):
                            os.remove(parte)
                for p in partes:  # limpiar las que no se llegaron a subir
                    if os.path.exists(p):
                        os.remove(p)
                if not demasiado_grande:
                    os.remove(ruta)
                    if enlaces:
                        msg = f"📎 <b>{h(nombre_base)}</b> - Partes (únelas con 7-Zip):\n\n" + "\n".join(f"<code>{h(e)}</code>" for e in enlaces)
                        await update.message.reply_text(msg[:4000], parse_mode='HTML')
                    else:
                        await update.message.reply_text("❌ No se pudo subir ninguna parte")
                    return
            else:
                res = await subir_con_progreso(ruta, nombre_base)
                if subida_ok(res):
                    url = f"{base_url}/webservice/pluginfile.php/{res['userid']}/user/draft/{res['itemid']}/{nombre_base}"
                    with get_db_conn() as conn:
                        c = conn.cursor()
                        c.execute('''INSERT INTO archivos (telegram_id, nombre_original, nombre_en_moodle, itemid, userid, enlace, tamano_bytes, fecha_subida)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                  (user_id, nombre_base, nombre_base, res['itemid'], res['userid'], url, tamano, datetime.now()))
                    await update.message.reply_text(f"✅ <b>Subido exitosamente</b>\n\n<code>{h(url)}</code>", parse_mode='HTML')
                    log_action(user_id, "subida", f"{nombre_base} ({tamano/(1024**2):.1f}MB)")
                    os.remove(ruta)
                    return
                elif isinstance(res, dict) and 'error' in res:
                    if '413' in str(res.get('error')):
                        demasiado_grande = True
                    else:
                        await update.message.reply_text(f"❌ Error de {cfg['nombre']}: {str(res.get('error', 'Desconocido'))[:500]}")
                        log_error(user_id, "Error de la nube en subida", res.get('traceback', ''))
                        os.remove(ruta)
                        return
                else:
                    await update.message.reply_text(f"❌ Error al subir a {cfg['nombre']}")
                    os.remove(ruta)
                    return

            # Llegamos aquí solo con 413: el servidor no acepta partes de este tamaño -> reducir a la mitad
            nuevo = min(limite, tamano) // 2
            if nuevo < 5 * 1024 * 1024:
                await update.message.reply_text(f"❌ {cfg['nombre']} rechaza incluso partes pequeñas (413). No puedo subir este archivo.")
                os.remove(ruta)
                return
            limite = nuevo
            cfg["max_parte"] = nuevo  # se recuerda para los próximos archivos
            await update.message.reply_text(f"⚠️ El servidor rechaza ese tamaño (413). Reintentando en partes de {fmt_bytes(nuevo)}...")
    except Exception as e:
        tb = traceback.format_exc()
        log_error(user_id, f"Error procesando enlace: {str(e)}", tb)
        await update.message.reply_text(f"❌ Error: {str(e)}"[:1000])  # sin parse_mode
        try:
            if os.path.exists(ruta):
                os.remove(ruta)
        except:
            pass

# ==================================================
# SERVIDOR DE SALUD (Render Web Service necesita un puerto abierto)
# ==================================================
import threading
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
# MAIN
# ==================================================
def main():
    init_db()
    limpiar_archivos_temporales_antiguos(horas=1)
    limpiar_logs_antiguos(dias=30)
    if not shutil.which('7z'):
        print("⚠️ ADVERTENCIA: '7z' no está instalado. No podrás dividir archivos >1GB.")
        print("   Instala con: sudo apt install p7zip-full")
    iniciar_servidor_salud()
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("setmoodle", set_moodle))
    app.add_handler(CommandHandler("cambiar", cmd_cambiar))
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
    print("Límite de archivo: 10 GB. Sanitización de nombres activada.")
    app.run_polling()

if __name__ == "__main__":
    main()

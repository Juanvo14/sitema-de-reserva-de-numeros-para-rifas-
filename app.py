from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
import sqlite3, os, time, base64, hashlib, hmac, struct, secrets, re
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_FILE    = os.environ.get('DB_PATH', 'rifos.db')
VAPID_FILE = 'vapid_keys.json'

# ─── EMAIL CONFIG ─────────────────────────────────────────────────────────────
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')       # tu Gmail
SMTP_PASS = os.environ.get('SMTP_PASS', '')       # contraseña de app Gmail
EMAIL_FROM = os.environ.get('EMAIL_FROM', SMTP_USER)

# ─── VAPID ────────────────────────────────────────────────────────────────────

def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def load_or_create_vapid():
    if os.path.exists(VAPID_FILE):
        with open(VAPID_FILE) as f:
            import json; return json.load(f)
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_bytes = priv.public_key().public_bytes(serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint)
    priv_raw = priv.private_numbers().private_value.to_bytes(32, 'big')
    import json
    keys = {'public': b64url(pub_bytes), 'private': b64url(priv_raw)}
    with open(VAPID_FILE, 'w') as f: json.dump(keys, f)
    return keys

VAPID_KEYS = load_or_create_vapid()

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            name        TEXT    NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS otp_codes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    NOT NULL,
            code        TEXT    NOT NULL,
            purpose     TEXT    NOT NULL,
            expires_at  INTEGER NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS rifas (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            slug        TEXT    UNIQUE NOT NULL,
            titulo      TEXT    NOT NULL,
            premio      TEXT    NOT NULL DEFAULT '',
            valor       INTEGER NOT NULL DEFAULT 10000,
            fecha       TEXT    NOT NULL DEFAULT '',
            activa      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS numeros (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rifa_id     INTEGER NOT NULL REFERENCES rifas(id),
            numero      INTEGER NOT NULL,
            estado      TEXT    NOT NULL DEFAULT 'reservado',
            nombre      TEXT    NOT NULL,
            telefono    TEXT    NOT NULL,
            fecha       TEXT    NOT NULL,
            UNIQUE(rifa_id, numero)
        );
        CREATE TABLE IF NOT EXISTS push_subs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            endpoint    TEXT    NOT NULL UNIQUE,
            p256dh      TEXT    NOT NULL,
            auth        TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        );
        """)

init_db()

# ─── EMAIL / OTP ──────────────────────────────────────────────────────────────

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)  # 6 digits

def save_otp(email, purpose):
    code = generate_otp()
    expires = int(time.time()) + 600  # 10 minutes
    with get_db() as db:
        # Invalidate previous codes for same email+purpose
        db.execute('UPDATE otp_codes SET used=1 WHERE email=? AND purpose=? AND used=0',
                   (email, purpose))
        db.execute('INSERT INTO otp_codes(email,code,purpose,expires_at,used) VALUES(?,?,?,?,0)',
                   (email, code, purpose, expires))
    return code

def verify_otp(email, code, purpose):
    now = int(time.time())
    with get_db() as db:
        row = db.execute(
            'SELECT * FROM otp_codes WHERE email=? AND code=? AND purpose=? AND used=0 AND expires_at>?',
            (email, code, purpose, now)).fetchone()
        if row:
            db.execute('UPDATE otp_codes SET used=1 WHERE id=?', (row['id'],))
            return True
    return False

def send_email(to, subject, html_body):
    if not SMTP_USER or not SMTP_PASS:
        print(f"[EMAIL SKIP — no SMTP config] To: {to} | Subject: {subject}")
        return False
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = f"RifOs <{EMAIL_FROM}>"
        msg['To']      = to
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(EMAIL_FROM, to, msg.as_string())
        return True
    except Exception as ex:
        print(f"[EMAIL ERROR] {ex}")
        return False

def send_otp_email(to, code, purpose, name=''):
    action = 'verificar tu cuenta' if purpose == 'register' else 'iniciar sesión'
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin:0;padding:0;background:#080c12;font-family:'Segoe UI',Arial,sans-serif">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#080c12;padding:40px 20px">
        <tr><td align="center">
          <table width="480" cellpadding="0" cellspacing="0" style="background:#0f1923;border:1px solid #1a2840;border-radius:12px;overflow:hidden">
            <tr><td style="background:linear-gradient(90deg,#080c12,#00d4ff22,#080c12);height:3px"></td></tr>
            <tr><td style="padding:36px 40px;text-align:center">
              <div style="font-size:2rem;margin-bottom:8px">🎟️</div>
              <div style="font-family:monospace;font-size:1.4rem;font-weight:900;color:#00d4ff;letter-spacing:4px;margin-bottom:4px">RIFOS</div>
              <div style="font-size:.75rem;color:#4a6080;letter-spacing:3px;font-family:monospace;margin-bottom:32px">SISTEMA DE RIFAS</div>
              <div style="font-size:1rem;color:#c8d8e8;margin-bottom:8px">{'Hola ' + name + ',' if name else 'Hola,'}</div>
              <div style="font-size:.9rem;color:#4a6080;margin-bottom:28px">Tu código para {action} es:</div>
              <div style="background:#080c12;border:1px solid #00d4ff44;border-radius:10px;padding:20px 30px;display:inline-block;margin-bottom:28px">
                <div style="font-family:monospace;font-size:2.8rem;font-weight:900;color:#00d4ff;letter-spacing:12px;text-shadow:0 0 20px #00d4ff88">{code}</div>
              </div>
              <div style="font-size:.78rem;color:#4a6080;margin-bottom:8px">Este código expira en <strong style="color:#c8d8e8">10 minutos</strong>.</div>
              <div style="font-size:.75rem;color:#2a3850">Si no solicitaste este código, ignora este mensaje.</div>
            </td></tr>
            <tr><td style="background:#080c12;padding:16px;text-align:center">
              <div style="font-size:.7rem;color:#2a3850;font-family:monospace;letter-spacing:1px">© RIFOS — Sistema de Rifas</div>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """
    subject = f"RifOs — Tu código de verificación: {code}"
    return send_email(to, subject, html)

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────

def hash_password(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000)
    return f"{salt}${h.hex()}"

def check_password(pw, stored):
    try:
        salt, h = stored.split('$')
        return secrets.compare_digest(
            hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260000).hex(), h)
    except: return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_rifa_or_404(slug, check_owner=False):
    with get_db() as db:
        rifa = db.execute('SELECT * FROM rifas WHERE slug=?', (slug,)).fetchone()
    if not rifa: abort(404)
    if check_owner and rifa['user_id'] != session.get('user_id'): abort(403)
    return rifa

def get_numeros(rifa_id):
    with get_db() as db:
        rows = db.execute('SELECT * FROM numeros WHERE rifa_id=?', (rifa_id,)).fetchall()
    return {str(r['numero']): dict(r) for r in rows}

def make_slug():
    while True:
        slug = secrets.token_urlsafe(8)
        with get_db() as db:
            exists = db.execute('SELECT 1 FROM rifas WHERE slug=?', (slug,)).fetchone()
        if not exists: return slug

# ─── PUSH ─────────────────────────────────────────────────────────────────────

def send_push(sub_row, title, body):
    import json, urllib.request, urllib.error
    try:
        endpoint = sub_row['endpoint']
        p256dh   = b64url_decode(sub_row['p256dh'])
        auth_raw = b64url_decode(sub_row['auth'])
        payload  = json.dumps({"title": title, "body": body,
                                "timestamp": int(time.time()*1000)}).encode()
        eph = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph.public_key().public_bytes(serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint)
        recv_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
        shared   = eph.exchange(ec.ECDH(), recv_pub)
        def hkdf_e(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
        def hkdf_x(prk, info, n):
            t,o = b'',b''
            for i in range(1,(n+31)//32+1):
                t = hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest(); o+=t
            return o[:n]
        ikm   = hkdf_x(hkdf_e(auth_raw, shared), b"WebPush: info\x00"+p256dh+eph_pub, 32)
        salt  = os.urandom(16)
        prk   = hkdf_e(salt, ikm)
        cek   = hkdf_x(prk, b"Content-Encoding: aes128gcm\x00", 16)
        nonce = hkdf_x(prk, b"Content-Encoding: nonce\x00", 12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(cek).encrypt(nonce, payload+b'\x02', None)
        body_bytes = salt+struct.pack('>I',4096)+bytes([len(eph_pub)])+eph_pub+ct
        vp = ec.derive_private_key(int.from_bytes(b64url_decode(VAPID_KEYS['private']),'big'),
                                    ec.SECP256R1(), default_backend())
        from urllib.parse import urlparse
        aud = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}"
        exp = int(time.time())+43200
        jh = b64url(json.dumps({"typ":"JWT","alg":"ES256"}).encode())
        jp = b64url(json.dumps({"aud":aud,"exp":exp,"sub":"mailto:admin@rifos.com"}).encode())
        sig = vp.sign(f"{jh}.{jp}".encode(), ec.ECDSA(hashes.SHA256()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r,s = decode_dss_signature(sig)
        jwt = f"{jh}.{jp}.{b64url(r.to_bytes(32,'big')+s.to_bytes(32,'big'))}"
        req = urllib.request.Request(endpoint, data=body_bytes, method='POST',
            headers={'Authorization': f"vapid t={jwt},k={VAPID_KEYS['public']}",
                     'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream','TTL':'86400'})
        try:
            with urllib.request.urlopen(req, timeout=8) as r: return r.status in (200,201,202)
        except urllib.error.HTTPError as e:
            return 'expired' if e.code==410 else False
    except Exception as ex:
        print(f"[Push] {ex}"); return False

def notify_admin(user_id, title, body):
    with get_db() as db:
        subs = db.execute('SELECT * FROM push_subs WHERE user_id=?', (user_id,)).fetchall()
    expired = []
    for sub in subs:
        if send_push(sub, title, body) == 'expired':
            expired.append(sub['id'])
    if expired:
        with get_db() as db:
            db.execute(f"DELETE FROM push_subs WHERE id IN ({','.join('?'*len(expired))})", expired)

# ─── PUBLIC ROUTES ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if session.get('user_id'): return redirect(url_for('dashboard'))
    return render_template('home.html')

# ── REGISTER ──────────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        name  = request.form.get('name','').strip()
        email = request.form.get('email','').strip().lower()
        pw    = request.form.get('password','')
        pw2   = request.form.get('password2','')
        if not name or not email or not pw:
            error = 'Todos los campos son obligatorios'
        elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = 'Email inválido'
        elif len(pw) < 6:
            error = 'La contraseña debe tener mínimo 6 caracteres'
        elif pw != pw2:
            error = 'Las contraseñas no coinciden'
        else:
            with get_db() as db:
                exists = db.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone()
            if exists:
                error = 'Este email ya está registrado'
            else:
                with get_db() as db:
                    db.execute('INSERT INTO users(email,password,name,verified,created_at) VALUES(?,?,?,1,?)',
                               (email, hash_password(pw), name, datetime.now().isoformat()))
                    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
                session['user_id']   = user['id']
                session['user_name'] = user['name']
                return redirect(url_for('dashboard'))
    return render_template('register.html', error=error)

# ── LOGIN ─────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        pw    = request.form.get('password','')
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if user and check_password(pw, user['password']):
            session['user_id']   = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('dashboard'))
        error = 'Email o contraseña incorrectos'
    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ─── DASHBOARD ────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as db:
        rifas = db.execute(
            'SELECT r.*, (SELECT COUNT(*) FROM numeros WHERE rifa_id=r.id) as total_reservas '
            'FROM rifas r WHERE r.user_id=? ORDER BY r.created_at DESC',
            (session['user_id'],)).fetchall()
    sub    = get_suscripcion(session['user_id'])
    plan   = PLANES.get(sub['plan'], PLANES['basico'])
    usadas, limite, puede_crear = rifas_disponibles(session['user_id'])
    activa = sub_activa(session['user_id'])
    dias_restantes = None
    if sub['fecha_vence']:
        from datetime import datetime as dt
        diff = dt.fromisoformat(sub['fecha_vence']) - dt.now()
        dias_restantes = max(0, diff.days)
    return render_template('dashboard.html', rifas=rifas, user_name=session['user_name'],
                           sub=sub, plan=plan, usadas=usadas, limite=limite,
                           puede_crear=puede_crear, activa=activa,
                           dias_restantes=dias_restantes, planes=PLANES)

@app.route('/dashboard/nueva-rifa', methods=['GET','POST'])
@login_required
def nueva_rifa():
    usadas, limite, puede_crear = rifas_disponibles(session['user_id'])
    if not puede_crear:
        return redirect(url_for('suscripcion'))
    error = None
    if request.method == 'POST':
        titulo = request.form.get('titulo','').strip()
        premio = request.form.get('premio','').strip()
        valor  = request.form.get('valor','10000').strip()
        fecha  = request.form.get('fecha','').strip()
        # Re-check limit on POST
        usadas2, limite2, puede2 = rifas_disponibles(session['user_id'])
        if not puede2:
            return redirect(url_for('suscripcion'))
        if not titulo:
            error = 'El título es obligatorio'
        else:
            slug = make_slug()
            with get_db() as db:
                db.execute('INSERT INTO rifas(user_id,slug,titulo,premio,valor,fecha,created_at) VALUES(?,?,?,?,?,?,?)',
                           (session['user_id'], slug, titulo, premio, int(valor), fecha, datetime.now().isoformat()))
            return redirect(url_for('admin_rifa', slug=slug))
    return render_template('nueva_rifa.html', error=error, usadas=usadas, limite=limite)

# ─── ADMIN RIFA ───────────────────────────────────────────────────────────────

@app.route('/admin/rifa/<slug>')
@login_required
def admin_rifa(slug):
    rifa    = get_rifa_or_404(slug, check_owner=True)
    numeros = get_numeros(rifa['id'])
    stats = {
        'libres':     100 - len(numeros),
        'reservados': sum(1 for v in numeros.values() if v['estado']=='reservado'),
        'en_veremos': sum(1 for v in numeros.values() if v['estado']=='en_veremos'),
    }
    with get_db() as db:
        push_count = db.execute('SELECT COUNT(*) FROM push_subs WHERE user_id=?',
                                 (session['user_id'],)).fetchone()[0]
    public_url = request.host_url + f"r/{slug}"
    return render_template('admin_rifa.html', rifa=rifa, numeros=numeros,
                           stats=stats, push_count=push_count,
                           vapid_public=VAPID_KEYS['public'],
                           public_url=public_url)

@app.route('/admin/rifa/<slug>/config', methods=['POST'])
@login_required
def admin_rifa_config(slug):
    rifa = get_rifa_or_404(slug, check_owner=True)
    with get_db() as db:
        db.execute('UPDATE rifas SET titulo=?,premio=?,valor=?,fecha=? WHERE id=?',
                   (request.form.get('titulo', rifa['titulo']),
                    request.form.get('premio', rifa['premio']),
                    int(request.form.get('valor', rifa['valor'])),
                    request.form.get('fecha', rifa['fecha']),
                    rifa['id']))
    return redirect(url_for('admin_rifa', slug=slug))

@app.route('/admin/rifa/<slug>/numero/<int:num>', methods=['POST'])
@login_required
def admin_numero(slug, num):
    rifa   = get_rifa_or_404(slug, check_owner=True)
    accion = request.json.get('accion')
    key    = num
    with get_db() as db:
        existing = db.execute('SELECT * FROM numeros WHERE rifa_id=? AND numero=?',
                               (rifa['id'], key)).fetchone()
        if accion == 'liberar' and existing:
            db.execute('DELETE FROM numeros WHERE rifa_id=? AND numero=?', (rifa['id'], key))
        elif accion == 'reservar':
            nombre   = request.json.get('nombre','Admin')
            telefono = request.json.get('telefono','')
            if existing:
                db.execute('UPDATE numeros SET estado=?,nombre=?,telefono=?,fecha=? WHERE rifa_id=? AND numero=?',
                           ('reservado',nombre,telefono,datetime.now().strftime('%Y-%m-%d %H:%M'),rifa['id'],key))
            else:
                db.execute('INSERT INTO numeros(rifa_id,numero,estado,nombre,telefono,fecha) VALUES(?,?,?,?,?,?)',
                           (rifa['id'],key,'reservado',nombre,telefono,datetime.now().strftime('%Y-%m-%d %H:%M')))
        elif accion == 'confirmar' and existing:
            db.execute('UPDATE numeros SET estado=? WHERE rifa_id=? AND numero=?',
                       ('reservado', rifa['id'], key))
        elif accion == 'en_veremos' and existing:
            db.execute('UPDATE numeros SET estado=? WHERE rifa_id=? AND numero=?',
                       ('en_veremos', rifa['id'], key))
    return jsonify({'ok': True})

@app.route('/admin/rifa/<slug>/lista')
@login_required
def admin_lista(slug):
    rifa = get_rifa_or_404(slug, check_owner=True)
    with get_db() as db:
        reservas = db.execute('SELECT * FROM numeros WHERE rifa_id=? ORDER BY numero',
                               (rifa['id'],)).fetchall()
    return render_template('admin_lista.html', rifa=rifa, reservas=reservas)

@app.route('/admin/rifa/<slug>/eliminar', methods=['POST'])
@login_required
def eliminar_rifa(slug):
    rifa = get_rifa_or_404(slug, check_owner=True)
    with get_db() as db:
        db.execute('DELETE FROM numeros WHERE rifa_id=?', (rifa['id'],))
        db.execute('DELETE FROM rifas WHERE id=?', (rifa['id'],))
    return redirect(url_for('dashboard'))

# ─── PUBLIC RIFA ──────────────────────────────────────────────────────────────

@app.route('/r/<slug>', methods=['GET','POST'])
def rifa_publica(slug):
    rifa = get_rifa_or_404(slug)
    if not rifa['activa']:
        return render_template('rifa_cerrada.html', rifa=rifa)
    error = None
    if request.method == 'POST':
        nombre   = request.form.get('nombre','').strip()
        telefono = request.form.get('telefono','').strip()
        if nombre and telefono and telefono.isdigit() and len(telefono) >= 7:
            session[f'cliente_{slug}'] = {'nombre': nombre, 'telefono': telefono}
            return redirect(url_for('reservar_numeros', slug=slug))
        error = 'Ingresa un nombre y teléfono válido'
    return render_template('rifa_entrada.html', rifa=rifa, error=error)

@app.route('/r/<slug>/reservar')
def reservar_numeros(slug):
    rifa    = get_rifa_or_404(slug)
    cliente = session.get(f'cliente_{slug}')
    if not cliente: return redirect(url_for('rifa_publica', slug=slug))
    numeros = get_numeros(rifa['id'])
    return render_template('reservar.html', rifa=rifa, numeros=numeros,
                           nombre=cliente['nombre'], telefono=cliente['telefono'])

@app.route('/api/r/<slug>/reservar', methods=['POST'])
def api_reservar(slug):
    rifa    = get_rifa_or_404(slug)
    cliente = session.get(f'cliente_{slug}')
    if not cliente: return jsonify({'error':'Sin sesión'}), 403
    numero = request.json.get('numero')
    if not numero or not (1 <= numero <= 100):
        return jsonify({'error': 'Número inválido'}), 400
    with get_db() as db:
        existing = db.execute('SELECT 1 FROM numeros WHERE rifa_id=? AND numero=?',
                               (rifa['id'], numero)).fetchone()
        if existing: return jsonify({'error': 'Número ya tomado'}), 400
        db.execute('INSERT INTO numeros(rifa_id,numero,estado,nombre,telefono,fecha) VALUES(?,?,?,?,?,?)',
                   (rifa['id'], numero, 'en_veremos',
                    cliente['nombre'], cliente['telefono'],
                    datetime.now().strftime('%Y-%m-%d %H:%M')))
    notify_admin(rifa['user_id'],
                 f"🎟️ Reserva N° {numero} — {rifa['titulo']}",
                 f"{cliente['nombre']} · {cliente['telefono']} reservó el N° {numero}")
    return jsonify({'ok': True, 'numero': numero})

@app.route('/api/r/<slug>/estado')
def api_estado(slug):
    rifa = get_rifa_or_404(slug)
    return jsonify(get_numeros(rifa['id']))

# ─── PUSH API ─────────────────────────────────────────────────────────────────

@app.route('/api/vapid-public-key')
def vapid_public_key():
    import json
    return jsonify({'publicKey': VAPID_KEYS['public']})

@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    sub = request.json
    with get_db() as db:
        try:
            db.execute('INSERT INTO push_subs(user_id,endpoint,p256dh,auth,created_at) VALUES(?,?,?,?,?)',
                       (session['user_id'], sub['endpoint'],
                        sub['keys']['p256dh'], sub['keys']['auth'],
                        datetime.now().isoformat()))
        except sqlite3.IntegrityError: pass
        old = db.execute(
            'SELECT id FROM push_subs WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 5',
            (session['user_id'],)).fetchall()
        if old:
            db.execute(f"DELETE FROM push_subs WHERE id IN ({','.join('?'*len(old))})",
                       [r['id'] for r in old])
    return jsonify({'ok': True})

@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def push_unsubscribe():
    ep = request.json.get('endpoint')
    with get_db() as db:
        db.execute('DELETE FROM push_subs WHERE user_id=? AND endpoint=?',
                   (session['user_id'], ep))
    return jsonify({'ok': True})

@app.route('/sw.js')
def sw_js():
    from flask import send_from_directory
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

# ─── ERRORS ───────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

# ─── PLANES Y SUSCRIPCIÓN ─────────────────────────────────────────────────────

PLANES = {
    'basico':     {'nombre': 'Básico',     'rifas': 3,   'precio': 9900,  'color': '#00d4ff'},
    'pro':        {'nombre': 'Pro',        'rifas': 15,  'precio': 29900, 'color': '#a855f7'},
    'enterprise': {'nombre': 'Enterprise', 'rifas': None,'precio': 59900, 'color': '#00ff88'},
}
GRACE_DAYS = 7

def init_subs_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS suscripciones (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER UNIQUE NOT NULL REFERENCES users(id),
            plan            TEXT    NOT NULL DEFAULT 'basico',
            estado          TEXT    NOT NULL DEFAULT 'trial',
            fecha_inicio    TEXT,
            fecha_vence     TEXT,
            mp_payment_id   TEXT,
            mp_sub_id       TEXT,
            created_at      TEXT    NOT NULL
        );
        """)

init_subs_db()

def init_wompi_refs_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS wompi_refs (
            reference  TEXT PRIMARY KEY,
            user_id    INTEGER NOT NULL,
            plan       TEXT NOT NULL,
            created_at TEXT NOT NULL
        )''')

init_wompi_refs_db()

def get_suscripcion(user_id):
    with get_db() as db:
        sub = db.execute('SELECT * FROM suscripciones WHERE user_id=?', (user_id,)).fetchone()
    if not sub:
        # Auto-create trial for new users (7 days free)
        from datetime import timedelta
        inicio = datetime.now()
        vence  = inicio + timedelta(days=GRACE_DAYS)
        with get_db() as db:
            db.execute(
                'INSERT INTO suscripciones(user_id,plan,estado,fecha_inicio,fecha_vence,created_at) VALUES(?,?,?,?,?,?)',
                (user_id, 'basico', 'trial',
                 inicio.isoformat(), vence.isoformat(), inicio.isoformat()))
        return get_suscripcion(user_id)
    return sub

def sub_activa(user_id):
    """Returns True if user can create rifas."""
    sub = get_suscripcion(user_id)
    if sub['estado'] in ('activa', 'trial'):
        from datetime import datetime as dt
        if sub['fecha_vence']:
            vence = dt.fromisoformat(sub['fecha_vence'])
            if dt.now() <= vence:
                return True
        else:
            return True
    # Grace period: even expired subs get 7 extra days
    if sub['estado'] == 'vencida' and sub['fecha_vence']:
        from datetime import datetime as dt, timedelta
        vence = dt.fromisoformat(sub['fecha_vence'])
        if dt.now() <= vence + timedelta(days=GRACE_DAYS):
            return True
    return False

def rifas_disponibles(user_id):
    """Returns (usadas, limite, puede_crear)."""
    sub  = get_suscripcion(user_id)
    plan = PLANES.get(sub['plan'], PLANES['basico'])
    with get_db() as db:
        usadas = db.execute('SELECT COUNT(*) FROM rifas WHERE user_id=?', (user_id,)).fetchone()[0]
    limite = plan['rifas']  # None = ilimitado
    activa = sub_activa(user_id)
    if not activa:
        return usadas, limite, False
    if limite is None:
        return usadas, None, True
    return usadas, limite, usadas < limite

# ─── WOMPI ────────────────────────────────────────────────────────────────────

import urllib.request, urllib.parse, urllib.error, hashlib, hmac as hmac_mod

WOMPI_PUB_KEY    = os.environ.get('WOMPI_PUB_KEY', '')
WOMPI_PRIV_KEY   = os.environ.get('WOMPI_PRIV_KEY', '')
WOMPI_EVT_SECRET = os.environ.get('WOMPI_EVT_SECRET', '')
WOMPI_INTEG_KEY  = os.environ.get('WOMPI_INTEG_KEY', '')

def wompi_signature(reference, amount_cents, currency, integrity_key):
    raw = f"{reference}{amount_cents}{currency}{integrity_key}"
    return hashlib.sha256(raw.encode()).hexdigest()

def activar_suscripcion(user_id, plan_key, payment_id):
    from datetime import timedelta
    inicio = datetime.now()
    vence  = inicio + timedelta(days=30)
    with get_db() as db:
        existing = db.execute('SELECT 1 FROM suscripciones WHERE user_id=?', (user_id,)).fetchone()
        if existing:
            db.execute(
                'UPDATE suscripciones SET plan=?,estado=?,fecha_inicio=?,fecha_vence=?,mp_payment_id=? WHERE user_id=?',
                (plan_key, 'activa', inicio.isoformat(), vence.isoformat(), payment_id, user_id))
        else:
            db.execute(
                'INSERT INTO suscripciones(user_id,plan,estado,fecha_inicio,fecha_vence,mp_payment_id,created_at) VALUES(?,?,?,?,?,?,?)',
                (user_id, plan_key, 'activa', inicio.isoformat(), vence.isoformat(), payment_id, inicio.isoformat()))

# ─── RUTAS DE SUSCRIPCIÓN ─────────────────────────────────────────────────────

@app.route('/precios')
def precios():
    sub = get_suscripcion(session['user_id']) if session.get('user_id') else None
    return render_template('precios.html', planes=PLANES, sub=sub)

@app.route('/suscripcion')
@login_required
def suscripcion():
    sub   = get_suscripcion(session['user_id'])
    plan  = PLANES.get(sub['plan'], PLANES['basico'])
    usadas, limite, puede = rifas_disponibles(session['user_id'])
    activa = sub_activa(session['user_id'])
    dias_restantes = None
    if sub['fecha_vence']:
        from datetime import datetime as dt
        diff = dt.fromisoformat(sub['fecha_vence']) - dt.now()
        dias_restantes = max(0, diff.days)
    return render_template('suscripcion.html', sub=sub, plan=plan,
                           planes=PLANES, usadas=usadas, limite=limite,
                           activa=activa, dias_restantes=dias_restantes)

@app.route('/pagar/<plan_key>')
@login_required
def pagar(plan_key):
    if plan_key not in PLANES:
        abort(404)
    if not WOMPI_PUB_KEY or not WOMPI_INTEG_KEY:
        return render_template('pago_error.html',
            msg='Pasarela de pago no configurada. Contacta al administrador.')
    plan      = PLANES[plan_key]
    base_url  = os.environ.get('BASE_URL', request.host_url.rstrip('/'))
    reference = f"rifos-{session['user_id']}-{plan_key}-{int(datetime.now().timestamp())}"
    amount    = plan['precio'] * 100   # Wompi usa centavos
    currency  = 'COP'
    signature = wompi_signature(reference, amount, currency, WOMPI_INTEG_KEY)
    redirect_url = f"{base_url}/pago/exitoso"
    wompi_url = (
        f"https://checkout.wompi.co/p/"
        f"?public-key={WOMPI_PUB_KEY}"
        f"&currency={currency}"
        f"&amount-in-cents={amount}"
        f"&reference={reference}"
        f"&signature:integrity={signature}"
        f"&redirect-url={urllib.parse.quote(redirect_url, safe='')}"
    )
    # Save reference so webhook can identify the user+plan
    with get_db() as db:
        db.execute('CREATE TABLE IF NOT EXISTS wompi_refs (reference TEXT PRIMARY KEY, user_id INTEGER, plan TEXT, created_at TEXT)')
        db.execute('INSERT OR REPLACE INTO wompi_refs(reference,user_id,plan,created_at) VALUES(?,?,?,?)',
                   (reference, session['user_id'], plan_key, datetime.now().isoformat()))
    return redirect(wompi_url)

@app.route('/pago/exitoso')
@login_required
def pago_exitoso():
    import json
    transaction_id = request.args.get('id', '')
    # Wompi sends transaction id — verify and activate
    if transaction_id and WOMPI_PRIV_KEY:
        try:
            req = urllib.request.Request(
                f"https://sandbox.wompi.co/v1/transactions/{transaction_id}",
                headers={'Authorization': f'Bearer {WOMPI_PRIV_KEY}'})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read()).get('data', {})
            if data.get('status') == 'APPROVED':
                reference = data.get('reference', '')
                with get_db() as db:
                    row = db.execute('SELECT * FROM wompi_refs WHERE reference=?', (reference,)).fetchone()
                if row:
                    activar_suscripcion(row['user_id'], row['plan'], transaction_id)
        except Exception as ex:
            print(f"[Wompi verify] {ex}")
    sub  = get_suscripcion(session['user_id'])
    plan = PLANES.get(sub['plan'], PLANES['basico'])
    return render_template('pago_exitoso.html', sub=sub, plan=plan, dev_mode=False)

@app.route('/pago/fallido')
@login_required
def pago_fallido():
    return render_template('pago_error.html', msg='El pago no fue completado. Intenta de nuevo.')

@app.route('/pago/pendiente')
@login_required
def pago_pendiente():
    return render_template('pago_error.html', msg='Tu pago está pendiente de confirmación. Te notificaremos por email.')

@app.route('/webhooks/wompi', methods=['POST'])
def webhook_wompi():
    import json
    # Verify Wompi signature
    signature_header = request.headers.get('X-Event-Checksum', '')
    if WOMPI_EVT_SECRET and signature_header:
        body = request.get_data()
        expected = hmac_mod.new(
            WOMPI_EVT_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac_mod.compare_digest(expected, signature_header):
            return jsonify({'error': 'Invalid signature'}), 401

    data  = request.json or {}
    event = data.get('event', '')
    if event == 'transaction.updated':
        tx = data.get('data', {}).get('transaction', {})
        if tx.get('status') == 'APPROVED':
            reference = tx.get('reference', '')
            tx_id     = tx.get('id', '')
            with get_db() as db:
                row = db.execute('SELECT * FROM wompi_refs WHERE reference=?',
                                 (reference,)).fetchone()
            if row:
                activar_suscripcion(row['user_id'], row['plan'], tx_id)
    return jsonify({'ok': True}), 200


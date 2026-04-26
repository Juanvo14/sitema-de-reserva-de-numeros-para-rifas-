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
            created_at  TEXT    NOT NULL
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

def get_current_user():
    if not session.get('user_id'): return None
    with get_db() as db:
        return db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()

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

        ikm   = hkdf_x(hkdf_e(auth_raw, shared),
                        b"WebPush: info\x00"+p256dh+eph_pub, 32)
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
            try:
                with get_db() as db:
                    db.execute('INSERT INTO users(email,password,name,created_at) VALUES(?,?,?,?)',
                               (email, hash_password(pw), name, datetime.now().isoformat()))
                    user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                error = 'Este email ya está registrado'
    return render_template('register.html', error=error)

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

# ─── DASHBOARD (admin) ────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as db:
        rifas = db.execute(
            'SELECT r.*, (SELECT COUNT(*) FROM numeros WHERE rifa_id=r.id) as total_reservas '
            'FROM rifas r WHERE r.user_id=? ORDER BY r.created_at DESC',
            (session['user_id'],)).fetchall()
    return render_template('dashboard.html', rifas=rifas, user_name=session['user_name'])

@app.route('/dashboard/nueva-rifa', methods=['GET','POST'])
@login_required
def nueva_rifa():
    error = None
    if request.method == 'POST':
        titulo = request.form.get('titulo','').strip()
        premio = request.form.get('premio','').strip()
        valor  = request.form.get('valor','10000').strip()
        fecha  = request.form.get('fecha','').strip()
        if not titulo:
            error = 'El título es obligatorio'
        else:
            slug = make_slug()
            with get_db() as db:
                db.execute('INSERT INTO rifas(user_id,slug,titulo,premio,valor,fecha,created_at) VALUES(?,?,?,?,?,?,?)',
                           (session['user_id'], slug, titulo, premio, int(valor), fecha, datetime.now().isoformat()))
            return redirect(url_for('admin_rifa', slug=slug))
    return render_template('nueva_rifa.html', error=error)

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
    rifa    = get_rifa_or_404(slug, check_owner=True)
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

# ─── PUBLIC RIFA (clientes) ───────────────────────────────────────────────────

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
    if not cliente:
        return redirect(url_for('rifa_publica', slug=slug))
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
        except sqlite3.IntegrityError: pass  # already subscribed
        # keep only last 5 per user
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

# ─── ERROR PAGES ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

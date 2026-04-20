from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json, os, time, base64, hashlib, hmac, struct
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = 'rifa_neo_secret_2024'

DATA_FILE  = 'data.json'
VAPID_FILE = 'vapid_keys.json'

# ─── VAPID KEYS ───────────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def load_or_create_vapid():
    if os.path.exists(VAPID_FILE):
        with open(VAPID_FILE) as f:
            return json.load(f)
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub  = priv.public_key()
    pub_bytes = pub.public_bytes(serialization.Encoding.X962,
                                  serialization.PublicFormat.UncompressedPoint)
    priv_raw  = priv.private_numbers().private_value.to_bytes(32, 'big')
    keys = {'public': b64url(pub_bytes), 'private': b64url(priv_raw)}
    with open(VAPID_FILE, 'w') as f:
        json.dump(keys, f)
    return keys

VAPID_KEYS = load_or_create_vapid()

# ─── DATA ─────────────────────────────────────────────────────────────────────

def load_data():
    if not os.path.exists(DATA_FILE):
        data = {
            "admin": {"username": "admin", "password": "admin123"},
            "rifa":  {"titulo": "Gran Rifa 2024", "premio": "Premio especial",
                      "valor": 10000, "fecha": ""},
            "numeros": {},
            "push_subscriptions": []
        }
        save_data(data)
        return data
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ─── PUSH ENGINE (pure Python / RFC 8291 + RFC 8292) ─────────────────────────

def send_push_notification(subscription, title, body):
    try:
        import urllib.request, urllib.error
        endpoint = subscription['endpoint']
        p256dh   = b64url_decode(subscription['keys']['p256dh'])
        auth_raw = b64url_decode(subscription['keys']['auth'])

        payload = json.dumps({"title": title, "body": body,
                               "timestamp": int(time.time()*1000)}).encode()

        # Ephemeral key pair
        eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub_bytes = eph_priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        recv_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
        shared   = eph_priv.exchange(ec.ECDH(), recv_pub)

        def hkdf_extract(salt, ikm):
            return hmac.new(salt, ikm, hashlib.sha256).digest()
        def hkdf_expand(prk, info, length):
            t, okm = b'', b''
            for i in range(1, (length+31)//32 + 1):
                t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
                okm += t
            return okm[:length]

        prk_key = hkdf_extract(auth_raw, shared)
        ikm     = hkdf_expand(prk_key, b"WebPush: info\x00" + p256dh + eph_pub_bytes, 32)
        salt    = os.urandom(16)
        prk     = hkdf_extract(salt, ikm)
        cek     = hkdf_expand(prk, b"Content-Encoding: aes128gcm\x00", 16)
        nonce   = hkdf_expand(prk, b"Content-Encoding: nonce\x00", 12)

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ciphertext = AESGCM(cek).encrypt(nonce, payload + b'\x02', None)
        body_bytes = (salt + struct.pack('>I', 4096)
                      + bytes([len(eph_pub_bytes)]) + eph_pub_bytes + ciphertext)

        # VAPID JWT
        vapid_priv = ec.derive_private_key(
            int.from_bytes(b64url_decode(VAPID_KEYS['private']), 'big'),
            ec.SECP256R1(), default_backend())
        from urllib.parse import urlparse
        audience = f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}"
        exp      = int(time.time()) + 43200
        jh = b64url(json.dumps({"typ":"JWT","alg":"ES256"}).encode())
        jp = b64url(json.dumps({"aud":audience,"exp":exp,
                                 "sub":"mailto:admin@neorifa.com"}).encode())
        sig_der = vapid_priv.sign(f"{jh}.{jp}".encode(), ec.ECDSA(hashes.SHA256()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(sig_der)
        jwt = f"{jh}.{jp}.{b64url(r.to_bytes(32,'big')+s.to_bytes(32,'big'))}"

        req = urllib.request.Request(endpoint, data=body_bytes, method='POST',
            headers={'Authorization': f"vapid t={jwt},k={VAPID_KEYS['public']}",
                     'Content-Encoding': 'aes128gcm',
                     'Content-Type': 'application/octet-stream',
                     'TTL': '86400'})
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status in (200, 201, 202)
        except urllib.error.HTTPError as e:
            return 'expired' if e.code == 410 else False
    except Exception as ex:
        print(f"[Push error] {ex}")
        return False

def notify_admin(title, body):
    data = load_data()
    subs = data.get('push_subscriptions', [])
    if not subs: return
    alive = [s for s in subs if send_push_notification(s, title, body) != 'expired']
    if len(alive) != len(subs):
        data['push_subscriptions'] = alive
        save_data(data)

# ─── AUTH ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index(): return redirect(url_for('login_selector'))

@app.route('/login')
def login_selector(): return render_template('login_selector.html')

@app.route('/login/admin', methods=['GET','POST'])
def login_admin():
    error = None
    if request.method == 'POST':
        data = load_data()
        if (request.form.get('username') == data['admin']['username'] and
                request.form.get('password') == data['admin']['password']):
            session['role'] = 'admin'
            session['username'] = request.form['username']
            return redirect(url_for('admin_panel'))
        error = 'Credenciales incorrectas'
    return render_template('login_admin.html', error=error)

@app.route('/login/usuario', methods=['GET','POST'])
def login_usuario():
    error = None
    if request.method == 'POST':
        nombre   = request.form.get('nombre','').strip()
        telefono = request.form.get('telefono','').strip()
        if nombre and telefono and telefono.isdigit() and len(telefono) >= 7:
            session.update({'role':'usuario','nombre':nombre,'telefono':telefono})
            return redirect(url_for('reservar'))
        error = 'Por favor ingresa un nombre válido y número telefónico correcto'
    return render_template('login_usuario.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_selector'))

# ─── PUSH API ─────────────────────────────────────────────────────────────────

@app.route('/api/vapid-public-key')
def vapid_public_key():
    return jsonify({'publicKey': VAPID_KEYS['public']})

@app.route('/api/push/subscribe', methods=['POST'])
def push_subscribe():
    if session.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    sub  = request.json
    data = load_data()
    subs = data.setdefault('push_subscriptions', [])
    if sub['endpoint'] not in [s['endpoint'] for s in subs]:
        subs.append(sub)
        data['push_subscriptions'] = subs[-5:]   # keep last 5 devices
        save_data(data)
    return jsonify({'ok': True})

@app.route('/api/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    if session.get('role') != 'admin':
        return jsonify({'error': 'No autorizado'}), 403
    ep   = request.json.get('endpoint')
    data = load_data()
    data['push_subscriptions'] = [s for s in data.get('push_subscriptions',[])
                                   if s['endpoint'] != ep]
    save_data(data)
    return jsonify({'ok': True})

# ─── ADMIN ────────────────────────────────────────────────────────────────────

@app.route('/admin')
def admin_panel():
    if session.get('role') != 'admin': return redirect(url_for('login_admin'))
    data    = load_data()
    numeros = data.get('numeros', {})
    stats   = {
        'libres':     sum(1 for i in range(1,101) if str(i) not in numeros),
        'reservados': sum(1 for v in numeros.values() if v['estado']=='reservado'),
        'en_veremos': sum(1 for v in numeros.values() if v['estado']=='en_veremos'),
    }
    return render_template('admin_panel.html', data=data, numeros=numeros,
                           stats=stats, push_count=len(data.get('push_subscriptions',[])),
                           vapid_public=VAPID_KEYS['public'])

@app.route('/admin/config', methods=['POST'])
def admin_config():
    if session.get('role') != 'admin': return jsonify({'error':'No autorizado'}), 403
    data = load_data()
    for k in ('titulo','premio','fecha'): data['rifa'][k] = request.form.get(k, data['rifa'][k])
    data['rifa']['valor'] = int(request.form.get('valor', data['rifa']['valor']))
    save_data(data)
    return redirect(url_for('admin_panel'))

@app.route('/admin/cambiar_password', methods=['POST'])
def cambiar_password():
    if session.get('role') != 'admin': return jsonify({'error':'No autorizado'}), 403
    data = load_data()
    nueva = request.form.get('nueva_password','').strip()
    if nueva:
        data['admin']['password'] = nueva
        save_data(data)
    return redirect(url_for('admin_panel'))

@app.route('/admin/numero/<int:num>', methods=['POST'])
def admin_numero(num):
    if session.get('role') != 'admin': return jsonify({'error':'No autorizado'}), 403
    data   = load_data()
    accion = request.json.get('accion')
    key    = str(num)
    if   accion == 'liberar'   and key in data['numeros']: del data['numeros'][key]
    elif accion == 'reservar':
        data['numeros'][key] = {'estado':'reservado',
            'nombre':request.json.get('nombre','Admin'),
            'telefono':request.json.get('telefono',''),
            'fecha':datetime.now().strftime('%Y-%m-%d %H:%M')}
    elif accion == 'en_veremos' and key in data['numeros']:
        data['numeros'][key]['estado'] = 'en_veremos'
    elif accion == 'confirmar'  and key in data['numeros']:
        data['numeros'][key]['estado'] = 'reservado'
    save_data(data)
    return jsonify({'ok': True})

@app.route('/admin/lista')
def admin_lista():
    if session.get('role') != 'admin': return redirect(url_for('login_admin'))
    data     = load_data()
    reservas = [{'numero':k,**v} for k,v in
                sorted(data['numeros'].items(), key=lambda x: int(x[0]))]
    return render_template('admin_lista.html', reservas=reservas, data=data)

# ─── USUARIO ──────────────────────────────────────────────────────────────────

@app.route('/reservar')
def reservar():
    if session.get('role') != 'usuario': return redirect(url_for('login_usuario'))
    data = load_data()
    return render_template('reservar.html', data=data,
                           nombre=session['nombre'], telefono=session['telefono'],
                           numeros=data.get('numeros', {}))

@app.route('/api/reservar', methods=['POST'])
def api_reservar():
    if session.get('role') != 'usuario': return jsonify({'error':'No autorizado'}), 403
    data   = load_data()
    numero = str(request.json.get('numero'))
    if numero in data['numeros']: return jsonify({'error':'Número ya tomado'}), 400
    if not (1 <= int(numero) <= 100): return jsonify({'error':'Número inválido'}), 400
    nombre, telefono = session['nombre'], session['telefono']
    data['numeros'][numero] = {'estado':'en_veremos','nombre':nombre,
        'telefono':telefono,'fecha':datetime.now().strftime('%Y-%m-%d %H:%M')}
    save_data(data)
    notify_admin(f"🎟️ Reserva N° {numero}", f"{nombre} · {telefono} reservó el N° {numero}")
    return jsonify({'ok': True, 'numero': numero})

@app.route('/api/estado')
def api_estado():
    return jsonify(load_data().get('numeros', {}))


# ─── SERVE SW.JS FROM ROOT (required by browsers for full scope) ──────────────
@app.route('/sw.js')
def sw_js():
    from flask import send_from_directory
    return send_from_directory('static', 'sw.js',
                               mimetype='application/javascript')

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

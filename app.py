from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_from_directory, abort, send_file
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
import time
import uuid
import base64

APP_SECRET = os.environ.get("APP_SECRET", "change-me")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config['DATABASE'] = os.path.join(BASE_DIR, 'messenger.db')
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
socketio = SocketIO(app, async_mode='threading')

def db_conn():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db():
    with db_conn() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, text TEXT NOT NULL, timestamp DATETIME NOT NULL, message_id TEXT UNIQUE NOT NULL, reply_to TEXT, FOREIGN KEY(reply_to) REFERENCES messages(message_id))')
        conn.execute('CREATE TABLE IF NOT EXISTS profiles (username TEXT PRIMARY KEY, avatar TEXT, status TEXT, bio TEXT, FOREIGN KEY(username) REFERENCES users(username))')
        conn.commit()

if not os.path.exists(app.config['DATABASE']):
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()

def generate_message_id():
    return f"{int(time.time()*1000)}-{uuid.uuid4().hex[:8]}"

def clamp_text(s, max_len=2000):
    if s is None:
        return ""
    s = s.strip()
    return s[:max_len]

def save_message(username, text, message_id, reply_to=None):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with db_conn() as conn:
            conn.execute('INSERT INTO messages (username, text, timestamp, message_id, reply_to) VALUES (?, ?, ?, ?, ?)', (username, text, ts, message_id, reply_to))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_message_history(limit=200):
    try:
        with db_conn() as conn:
            rows = conn.execute('SELECT m1.username, m1.text, m1.timestamp, m1.message_id, m1.reply_to, m2.username AS reply_username, m2.text AS reply_text FROM messages m1 LEFT JOIN messages m2 ON m1.reply_to = m2.message_id ORDER BY m1.id DESC LIMIT ?', (limit,)).fetchall()
            res = []
            for m in rows:
                res.append({
                    'username': m['username'],
                    'text': m['text'],
                    'timestamp': datetime.strptime(m['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%H:%M'),
                    'fulldate': m['timestamp'],
                    'id': m['message_id'],
                    'replyTo': m['reply_to'],
                    'replyUsername': m['reply_username'],
                    'replyText': m['reply_text']
                })
            return res
    except Exception:
        return []

def get_profile(username):
    try:
        with db_conn() as conn:
            profile = conn.execute('SELECT avatar, status, bio FROM profiles WHERE username = ?', (username,)).fetchone()
        avatar_url = '/static/default_avatar.png'
        if profile and profile['avatar']:
            if profile['avatar'].startswith('http'):
                avatar_url = profile['avatar']
            else:
                abs_path = os.path.join(app.config['UPLOAD_FOLDER'], profile['avatar'])
                if os.path.exists(abs_path):
                    avatar_url = f'/uploads/{profile["avatar"]}'
        return {'username': username, 'avatar': avatar_url, 'status': profile['status'] if profile else 'Online', 'bio': profile['bio'] if profile else 'Пользователь DUMB'}
    except Exception:
        return {'username': username, 'avatar': '/static/default_avatar.png', 'status': 'Online', 'bio': 'Пользователь DUMB'}

def update_avatar(username, avatar_data):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        with db_conn() as conn:
            old = conn.execute('SELECT avatar FROM profiles WHERE username = ?', (username,)).fetchone()
        if old and old['avatar'] and not old['avatar'].startswith('http'):
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], old['avatar'])
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except Exception:
                    pass
        filename = f"{username}_{uuid.uuid4().hex}.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if ',' in avatar_data:
            avatar_data = avatar_data.split(',', 1)[1]
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(avatar_data))
        with db_conn() as conn:
            conn.execute('INSERT OR REPLACE INTO profiles (username, avatar, status, bio) VALUES (?, ?, COALESCE((SELECT status FROM profiles WHERE username=?), "Online"), COALESCE((SELECT bio FROM profiles WHERE username=?), "Пользователь DUMB"))', (username, filename, username, username))
            conn.commit()
        return f'/uploads/{filename}'
    except Exception:
        return None

def authenticate(username, password):
    with db_conn() as conn:
        row = conn.execute('SELECT password_hash FROM users WHERE username = ?', (username,)).fetchone()
        return row and check_password_hash(row['password_hash'], password)

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    return render_template('chat.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if authenticate(username, password):
            resp = redirect(url_for('index'))
            resp.set_cookie('username', username, httponly=False, samesite='Lax', secure=False, max_age=60*60*24*30)
            return resp
        flash('Неверные данные')
    return render_template('auth.html', title="Авторизация", button_text="Войти", mode="login")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            flash('Введите имя')
            return render_template('auth.html', title="Регистрация", button_text="Создать", mode="register")
        password_hash = generate_password_hash(request.form.get('password', ''))
        try:
            with db_conn() as conn:
                conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
                conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя занято')
    return render_template('auth.html', title="Регистрация", button_text="Создать", mode="register")

@app.route('/logout')
def logout():
    resp = redirect(url_for('login'))
    resp.set_cookie('username', '', expires=0)
    return resp

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.commonprefix([os.path.abspath(safe_path), app.config['UPLOAD_FOLDER']]) == app.config['UPLOAD_FOLDER']:
        abort(404)
    if not os.path.exists(safe_path):
        abort(404)
    return send_file(safe_path)

@app.route('/_get_avatar')
def get_avatar_image():
    username = request.args.get('username', '').strip()
    if not username:
        return send_file(os.path.join(BASE_DIR, 'static', 'default_avatar.png'))
    info = get_profile(username)
    if info['avatar'].startswith('/uploads/'):
        path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(info['avatar']))
        if os.path.exists(path):
            return send_file(path)
    if info['avatar'].startswith('http'):
        return redirect(info['avatar'])
    default_path = os.path.join(BASE_DIR, 'static', 'default_avatar.png')
    if os.path.exists(default_path):
        return send_file(default_path)
    abort(404)

@socketio.on('send_message')
def handle_message(data):
    username = request.cookies.get('username')
    if not username:
        return
    text = clamp_text(str(data.get('text', '')))
    if not text:
        return
    message_id = generate_message_id()
    now = datetime.now()
    payload = {'username': username, 'text': text, 'timestamp': now.strftime('%H:%M'), 'fulldate': now.strftime('%Y-%m-%d %H:%M:%S'), 'id': message_id, 'replyTo': data.get('replyTo')}
    if save_message(username, text, message_id, data.get('replyTo')):
        socketio.emit('new_message', payload)

@socketio.on('get_history')
def handle_history():
    emit('message_history', get_message_history())

@socketio.on('get_profile')
def handle_get_profile(username, callback=None):
    profile = get_profile(username)
    if callback:
        callback(profile)
    else:
        emit('profile_data', profile)

@socketio.on('update_avatar')
def handle_update_avatar(avatar_data):
    username = request.cookies.get('username')
    if not username:
        return False
    new_avatar = update_avatar(username, avatar_data)
    if new_avatar:
        emit('avatar_updated', {'username': username, 'avatar': new_avatar}, broadcast=True)
        return True
    return False

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'static'), exist_ok=True)
    default_avatar = os.path.join(BASE_DIR, 'static', 'default_avatar.png')
    if not os.path.exists(default_avatar):
        with open(default_avatar, 'wb') as f:
            f.write(base64.b64decode(b'iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAYAAACNMs+9AAAAIElEQVQoU2NkYGD4z0AeYKSIEU0wCkY1Ew0DA0E0Dg0AAAZoAq6pQ2+9AAAAAElFTkSuQmCC'))
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

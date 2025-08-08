from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_from_directory
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os
import time
import uuid
import base64

app = Flask(__name__)
app.secret_key = 'super-secret-key'
app.config['DATABASE'] = 'messenger.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
socketio = SocketIO(app)

def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            text TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            message_id TEXT UNIQUE NOT NULL,
            reply_to TEXT,
            FOREIGN KEY(reply_to) REFERENCES messages(message_id)
        )''')
        conn.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            username TEXT PRIMARY KEY,
            avatar TEXT,
            status TEXT,
            bio TEXT,
            FOREIGN KEY(username) REFERENCES users(username)
        )''')
        conn.commit()

if not os.path.exists(app.config['DATABASE']):
    init_db()

def generate_message_id():
    return f"{int(time.time()*1000)}-{os.urandom(4).hex()}"

def save_message(username, text, message_id, reply_to=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.execute('''
                INSERT INTO messages (username, text, timestamp, message_id, reply_to)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, text, timestamp, message_id, reply_to))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_message_history(limit=100):
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.row_factory = sqlite3.Row
            messages = conn.execute('''
                SELECT m1.username, m1.text, m1.timestamp, m1.message_id, 
                       m1.reply_to, m2.username as reply_username, m2.text as reply_text
                FROM messages m1
                LEFT JOIN messages m2 ON m1.reply_to = m2.message_id
                ORDER BY m1.timestamp DESC 
                LIMIT ?
            ''', (limit,)).fetchall()
            
            return [{
                'username': m['username'],
                'text': m['text'],
                'timestamp': datetime.strptime(m['timestamp'], '%Y-%m-%d %H:%M:%S').strftime('%H:%M'),
                'fulldate': m['timestamp'],
                'id': m['message_id'],
                'replyTo': m['reply_to'],
                'replyUsername': m['reply_username'],
                'replyText': m['reply_text']
            } for m in messages]
    except Exception as e:
        print(f"Error fetching messages: {e}")
        return []

def get_profile(username):
    try:
        with sqlite3.connect(app.config['DATABASE']) as conn:
            profile = conn.execute('''
                SELECT avatar, status, bio 
                FROM profiles 
                WHERE username = ?
            ''', (username,)).fetchone()
            
            avatar_url = '/static/default_avatar.png'
            if profile and profile[0]:
                if profile[0].startswith('http'):
                    avatar_url = profile[0]
                elif os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], profile[0])):
                    avatar_url = f'/uploads/{profile[0]}'
            
            return {
                'username': username,
                'avatar': avatar_url,
                'status': profile[1] if profile else 'Online',
                'bio': profile[2] if profile else 'Пользователь DUMB'
            }
    except Exception as e:
        print(f"Error getting profile: {e}")
        return {
            'username': username,
            'avatar': '/static/default_avatar.png',
            'status': 'Online',
            'bio': 'Пользователь DUMB'
        }

def update_avatar(username, avatar_data):
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        with sqlite3.connect(app.config['DATABASE']) as conn:
            old_avatar = conn.execute(
                'SELECT avatar FROM profiles WHERE username = ?', 
                (username,)
            ).fetchone()
            
            if old_avatar and old_avatar[0]:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_avatar[0])
                if os.path.exists(old_path):
                    os.remove(old_path)
        
        filename = f"{username}_{uuid.uuid4().hex}.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(filepath, 'wb') as f:
            f.write(base64.b64decode(avatar_data.split(',')[1]))
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO profiles (username, avatar, status, bio)
                VALUES (?, ?, ?, ?)
            ''', (username, filename, 'Online', 'Пользователь DUMB'))
            conn.commit()
        
        return f'/uploads/{filename}'
    except Exception as e:
        print(f"Error updating avatar: {e}")
        return None

def authenticate(username, password):
    with sqlite3.connect(app.config['DATABASE']) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        return user and check_password_hash(user[0], password)

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    return render_template('chat.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            response = redirect(url_for('index'))
            response.set_cookie('username', username)
            return response
        flash('Неверные данные')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            with sqlite3.connect(app.config['DATABASE']) as conn:
                conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password))
                conn.commit()
            response = redirect(url_for('login'))
            return response
        except sqlite3.IntegrityError:
            flash('Имя занято')
    return render_template('register.html')

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.set_cookie('username', '', expires=0)
    return response

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('send_message')
def handle_message(data):
    username = request.cookies.get('username')
    if not username:
        return
    
    message_id = generate_message_id()
    message = {
        'username': username,
        'text': data['text'],
        'timestamp': datetime.now().strftime('%H:%M'),
        'fulldate': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'id': message_id,
        'replyTo': data.get('replyTo')
    }
    
    if save_message(username, data['text'], message_id, data.get('replyTo')):
        socketio.emit('new_message', message)

@socketio.on('get_history')
def handle_history():
    messages = get_message_history()
    emit('message_history', messages)

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
        emit('avatar_updated', {
            'username': username,
            'avatar': new_avatar
        }, broadcast=True)
        return True
    return False

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

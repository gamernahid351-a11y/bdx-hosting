import os
import sqlite3
import zipfile
import subprocess
import secrets
import json
import shutil
from datetime import datetime
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'bdx-hosting-secret-2025')

DATABASE = os.path.join(os.path.dirname(__file__), 'bdx_hosting.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'user_files')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ADMIN_EMAIL = 'mehedi23145545@gmail.com'
ADMIN_PASS = '8gcmic44'
TELEGRAM = '@proxaura'
BASE_DOMAIN = os.environ.get('BASE_DOMAIN', 'bdxhosting.up.railway.app')

PACKAGES = [
    {
        'id': 1, 'name': 'Starter', 'price': 'Free',
        'storage': '512 MB', 'bandwidth': '5 GB', 'ram': '256 MB',
        'features': ['1 Server', 'Python/HTML Support', 'Community Support']
    },
    {
        'id': 2, 'name': 'Basic', 'price': '$3/mo',
        'storage': '2 GB', 'bandwidth': '20 GB', 'ram': '512 MB',
        'features': ['3 Servers', 'Python/HTML/Node.js', 'Telegram Support', 'Custom Domain']
    },
    {
        'id': 3, 'name': 'Pro', 'price': '$8/mo',
        'storage': '10 GB', 'bandwidth': '100 GB', 'ram': '2 GB',
        'features': ['10 Servers', 'All Languages', '24/7 Support', 'API Access', 'Custom Domain']
    },
    {
        'id': 4, 'name': 'Business', 'price': '$20/mo',
        'storage': '50 GB', 'bandwidth': 'Unlimited', 'ram': '8 GB',
        'features': ['Unlimited Servers', 'Dedicated IP', 'Priority Support', 'API Access', 'SLA 99.9%']
    },
]


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        package_id INTEGER DEFAULT 0,
        api_key TEXT UNIQUE,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_name TEXT NOT NULL,
        domain TEXT,
        main_file TEXT,
        status TEXT DEFAULT 'pending',
        run_command TEXT,
        port INTEGER DEFAULT 8080,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        server_id INTEGER,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        filetype TEXT,
        uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        server_id INTEGER,
        action TEXT,
        output TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    # Seed admin
    existing = c.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,)).fetchone()
    if not existing:
        api_key = secrets.token_hex(24)
        c.execute('''INSERT INTO users (username, email, password, role, package_id, api_key)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  ('admin', ADMIN_EMAIL, generate_password_hash(ADMIN_PASS), 'admin', 4, api_key))
    conn.commit()
    conn.close()


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def user_dir(user_id, server_id=None):
    path = os.path.join(UPLOAD_FOLDER, str(user_id))
    if server_id:
        path = os.path.join(path, str(server_id))
    os.makedirs(path, exist_ok=True)
    return path


# ─── Routes ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', packages=PACKAGES, telegram=TELEGRAM)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['email'] = user['email']
            if user['role'] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE email=? OR username=?', (email, username)).fetchone()
        if existing:
            conn.close()
            flash('Email or username already exists.', 'error')
            return render_template('register.html')
        api_key = secrets.token_hex(24)
        conn.execute('''INSERT INTO users (username, email, password, api_key)
                        VALUES (?, ?, ?, ?)''',
                     (username, email, generate_password_hash(password), api_key))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        conn.close()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['email'] = user['email']
        flash('Account created! Welcome to BDX Hosting.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    servers = conn.execute('SELECT * FROM servers WHERE user_id=? ORDER BY created_at DESC',
                           (session['user_id'],)).fetchall()
    conn.close()
    pkg = next((p for p in PACKAGES if p['id'] == (user['package_id'] or 0)), None)
    return render_template('dashboard.html', user=user, servers=servers,
                           package=pkg, packages=PACKAGES, telegram=TELEGRAM,
                           base_domain=BASE_DOMAIN)


@app.route('/server/create', methods=['POST'])
@login_required
def create_server():
    server_name = request.form.get('server_name', '').strip()
    if not server_name:
        flash('Server name required.', 'error')
        return redirect(url_for('dashboard'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    count = conn.execute('SELECT COUNT(*) FROM servers WHERE user_id=?',
                         (session['user_id'],)).fetchone()[0]
    pkg = next((p for p in PACKAGES if p['id'] == (user['package_id'] or 0)), None)
    max_servers = {'Starter': 1, 'Basic': 3, 'Pro': 10, 'Business': 9999}.get(pkg['name'] if pkg else 'none', 0)
    if count >= max_servers:
        conn.close()
        flash(f'Server limit reached for your plan. Upgrade to add more servers.', 'error')
        return redirect(url_for('dashboard'))
    slug = server_name.lower().replace(' ', '-')
    domain = f"{session['username']}-{slug}.{BASE_DOMAIN}"
    conn.execute('''INSERT INTO servers (user_id, server_name, domain, status)
                    VALUES (?, ?, ?, ?)''',
                 (session['user_id'], server_name, domain, 'pending'))
    conn.commit()
    conn.close()
    flash(f'Server "{server_name}" created! Upload your files to get started.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/server/<int:server_id>')
@login_required
def server_detail(server_id):
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if not server:
        conn.close()
        flash('Server not found.', 'error')
        return redirect(url_for('dashboard'))
    files = conn.execute('SELECT * FROM files WHERE server_id=? ORDER BY uploaded_at DESC',
                         (server_id,)).fetchall()
    logs = conn.execute('SELECT * FROM logs WHERE server_id=? ORDER BY created_at DESC LIMIT 20',
                        (server_id,)).fetchall()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('server.html', server=server, files=files,
                           logs=logs, user=user, telegram=TELEGRAM)


@app.route('/server/<int:server_id>/upload', methods=['POST'])
@login_required
def upload_file(server_id):
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if not server:
        conn.close()
        flash('Server not found.', 'error')
        return redirect(url_for('dashboard'))

    if 'zipfile' not in request.files:
        conn.close()
        flash('No file selected.', 'error')
        return redirect(url_for('server_detail', server_id=server_id))

    f = request.files['zipfile']
    if f.filename == '' or not f.filename.endswith('.zip'):
        conn.close()
        flash('Please upload a .zip file.', 'error')
        return redirect(url_for('server_detail', server_id=server_id))

    sdir = user_dir(session['user_id'], server_id)
    zip_path = os.path.join(sdir, secure_filename(f.filename))
    f.save(zip_path)

    # Extract zip
    extracted = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(sdir)
            extracted = zf.namelist()
        os.remove(zip_path)

        # Check for requirements.txt and auto install
        req_file = os.path.join(sdir, 'requirements.txt')
        install_log = ''
        if os.path.exists(req_file):
            try:
                result = subprocess.run(
                    ['pip', 'install', '-r', req_file],
                    capture_output=True, text=True, timeout=120
                )
                install_log = result.stdout + result.stderr
                conn.execute('''INSERT INTO logs (user_id, server_id, action, output)
                                VALUES (?, ?, ?, ?)''',
                             (session['user_id'], server_id,
                              'Auto-install requirements.txt', install_log[:2000]))
            except Exception as e:
                install_log = str(e)

        # Register files in DB
        conn.execute('DELETE FROM files WHERE server_id=?', (server_id,))
        for fname in extracted:
            full = os.path.join(sdir, fname)
            if os.path.isfile(full):
                ext = os.path.splitext(fname)[1]
                conn.execute('''INSERT INTO files (user_id, server_id, filename, filepath, filetype)
                                VALUES (?, ?, ?, ?, ?)''',
                             (session['user_id'], server_id, fname, full, ext))
        conn.commit()
        msg = f'Extracted {len(extracted)} files.'
        if install_log:
            msg += ' requirements.txt auto-installed!'
        flash(msg, 'success')
    except zipfile.BadZipFile:
        flash('Invalid zip file.', 'error')
    finally:
        conn.close()

    return redirect(url_for('server_detail', server_id=server_id))


@app.route('/server/<int:server_id>/setmain', methods=['POST'])
@login_required
def set_main_file(server_id):
    main_file = request.form.get('main_file', '').strip()
    run_cmd = request.form.get('run_command', '').strip()
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if not server:
        conn.close()
        flash('Server not found.', 'error')
        return redirect(url_for('dashboard'))
    conn.execute('UPDATE servers SET main_file=?, run_command=? WHERE id=?',
                 (main_file, run_cmd, server_id))
    conn.commit()
    conn.close()
    flash(f'Main file set to "{main_file}".', 'success')
    return redirect(url_for('server_detail', server_id=server_id))


@app.route('/server/<int:server_id>/run', methods=['POST'])
@login_required
def run_command(server_id):
    command = request.form.get('command', '').strip()
    if not command:
        flash('No command provided.', 'error')
        return redirect(url_for('server_detail', server_id=server_id))

    # Safety: block dangerous commands
    blocked = ['rm -rf', 'shutdown', 'reboot', 'mkfs', 'dd if=', 'format']
    if any(b in command.lower() for b in blocked):
        flash('Command not allowed for security reasons.', 'error')
        return redirect(url_for('server_detail', server_id=server_id))

    sdir = user_dir(session['user_id'], server_id)
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if not server:
        conn.close()
        flash('Server not found.', 'error')
        return redirect(url_for('dashboard'))

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=60, cwd=sdir
        )
        output = result.stdout + result.stderr
        if not output:
            output = '(no output)'
        conn.execute('''INSERT INTO logs (user_id, server_id, action, output)
                        VALUES (?, ?, ?, ?)''',
                     (session['user_id'], server_id, f'Run: {command}', output[:3000]))
        conn.execute('UPDATE servers SET status=? WHERE id=?', ('running', server_id))
        conn.commit()
        flash('Command executed successfully!', 'success')
    except subprocess.TimeoutExpired:
        conn.execute('''INSERT INTO logs (user_id, server_id, action, output)
                        VALUES (?, ?, ?, ?)''',
                     (session['user_id'], server_id, f'Run: {command}', 'Timeout after 60 seconds'))
        conn.commit()
        flash('Command timed out after 60 seconds.', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('server_detail', server_id=server_id))


@app.route('/server/<int:server_id>/install', methods=['POST'])
@login_required
def install_packages(server_id):
    packages_input = request.form.get('packages', '').strip()
    if not packages_input:
        flash('No packages specified.', 'error')
        return redirect(url_for('server_detail', server_id=server_id))

    sdir = user_dir(session['user_id'], server_id)
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if not server:
        conn.close()
        flash('Server not found.', 'error')
        return redirect(url_for('dashboard'))

    try:
        cmd = ['pip', 'install'] + packages_input.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=sdir)
        output = result.stdout + result.stderr
        conn.execute('''INSERT INTO logs (user_id, server_id, action, output)
                        VALUES (?, ?, ?, ?)''',
                     (session['user_id'], server_id, f'Install: {packages_input}', output[:3000]))
        conn.commit()
        flash(f'Package(s) "{packages_input}" installed!', 'success')
    except Exception as e:
        flash(f'Install error: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('server_detail', server_id=server_id))


@app.route('/server/<int:server_id>/delete', methods=['POST'])
@login_required
def delete_server(server_id):
    conn = get_db()
    server = conn.execute('SELECT * FROM servers WHERE id=? AND user_id=?',
                          (server_id, session['user_id'])).fetchone()
    if server:
        sdir = user_dir(session['user_id'], server_id)
        if os.path.exists(sdir):
            shutil.rmtree(sdir)
        conn.execute('DELETE FROM files WHERE server_id=?', (server_id,))
        conn.execute('DELETE FROM logs WHERE server_id=?', (server_id,))
        conn.execute('DELETE FROM servers WHERE id=?', (server_id,))
        conn.commit()
        flash('Server deleted.', 'success')
    conn.close()
    return redirect(url_for('dashboard'))


# ─── Admin ─────────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    users = conn.execute('SELECT * FROM users WHERE role != "admin" ORDER BY created_at DESC').fetchall()
    servers = conn.execute('SELECT s.*, u.username, u.email FROM servers s JOIN users u ON s.user_id=u.id ORDER BY s.created_at DESC').fetchall()
    stats = {
        'total_users': conn.execute('SELECT COUNT(*) FROM users WHERE role!="admin"').fetchone()[0],
        'total_servers': conn.execute('SELECT COUNT(*) FROM servers').fetchone()[0],
        'running_servers': conn.execute('SELECT COUNT(*) FROM servers WHERE status="running"').fetchone()[0],
    }
    conn.close()
    return render_template('admin.html', users=users, servers=servers,
                           stats=stats, packages=PACKAGES, telegram=TELEGRAM)


@app.route('/admin/user/<int:user_id>/package', methods=['POST'])
@admin_required
def admin_set_package(user_id):
    package_id = int(request.form.get('package_id', 0))
    conn = get_db()
    conn.execute('UPDATE users SET package_id=? WHERE id=?', (package_id, user_id))
    conn.commit()
    conn.close()
    flash('Package updated.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/server/<int:server_id>/status', methods=['POST'])
@admin_required
def admin_set_status(server_id):
    status = request.form.get('status', 'pending')
    domain = request.form.get('domain', '').strip()
    conn = get_db()
    if domain:
        conn.execute('UPDATE servers SET status=?, domain=? WHERE id=?', (status, domain, server_id))
    else:
        conn.execute('UPDATE servers SET status=? WHERE id=?', (status, server_id))
    conn.commit()
    conn.close()
    flash('Server status updated.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM files WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM logs WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM servers WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    udir = os.path.join(UPLOAD_FOLDER, str(user_id))
    if os.path.exists(udir):
        shutil.rmtree(udir)
    flash('User deleted.', 'success')
    return redirect(url_for('admin'))


# ─── API ───────────────────────────────────────────────────────────────────

@app.route('/api/server/<api_key>')
def api_server_info(api_key):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE api_key=?', (api_key,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid API key'}), 401
    servers = conn.execute('SELECT * FROM servers WHERE user_id=?', (user['id'],)).fetchall()
    conn.close()
    return jsonify({
        'user': user['username'],
        'email': user['email'],
        'package_id': user['package_id'],
        'servers': [dict(s) for s in servers]
    })


@app.route('/api/status')
def api_status():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM servers').fetchone()[0]
    running = conn.execute('SELECT COUNT(*) FROM servers WHERE status="running"').fetchone()[0]
    conn.close()
    return jsonify({
        'status': 'online',
        'name': 'BDX Hosting Server',
        'total_servers': total,
        'running_servers': running,
        'timestamp': datetime.utcnow().isoformat()
    })


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

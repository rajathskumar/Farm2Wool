#!/usr/bin/env python3
"""Farm2Wool local authentication server. Python standard library only."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parent
ROLES = {'farmer': 'farmer.html', 'manufacturer': 'manufacture.html', 'customer': 'customer.html'}
PORTALS = {page: role for role, page in ROLES.items()}
PUBLIC = {'index.html', 'login.html', 'style.css', 'auth.css', 'auth.js', 'batch-details.js', 'video.mp4',
          'farmer.jpeg', 'manufacturer.jpeg', 'customer.jpeg'}
ITERATIONS = 600_000
TTL = 12 * 60 * 60
DUMMY_SALT = '00' * 16


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS).hex()


def normalize_mobile(value):
    value = str(value).strip()
    if not re.fullmatch(r'\+?[0-9 ()-]{8,24}', value):
        raise ValueError('Enter a valid mobile number, including country code if outside India.')
    digits = re.sub(r'\D', '', value)
    if len(digits) == 10:
        digits = '91' + digits
    if not 8 <= len(digits) <= 15 or digits.startswith('0'):
        raise ValueError('Enter a valid mobile number. Indian numbers can use 10 digits or +91.')
    return '+' + digits


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, database, secure_cookie=False):
        self.database = str(database)
        descriptor = os.open(self.database, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        self.secure_cookie = secure_cookie
        self.attempts = {}
        self.rate_lock = threading.Lock()
        with sqlite3.connect(self.database) as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, role TEXT NOT NULL, name TEXT NOT NULL,
                    region TEXT NOT NULL, mobile TEXT NOT NULL, business TEXT NOT NULL DEFAULT '',
                    salt TEXT NOT NULL, password_hash TEXT NOT NULL, created REAL NOT NULL,
                    UNIQUE(role, mobile));
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                    expires REAL NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
            ''')
        os.chmod(self.database, 0o600)
        super().__init__(address, Handler)

    def connect(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def limited(self, key):
        now = time.monotonic()
        with self.rate_lock:
            # Bound memory and remove expired attempts for this local server.
            self.attempts = {k: [t for t in ts if now - t < 900]
                             for k, ts in self.attempts.items() if ts and now - ts[-1] < 900}
            times = self.attempts.setdefault(key, [])
            if len(times) >= 10:
                return True
            times.append(now)
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = 'Farm2Wool'

    def log_message(self, fmt, *args):
        # Avoid recording phone numbers or submitted credentials in request logs.
        pass

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def respond(self, status, data, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        if cookie:
            self.send_header('Set-Cookie', cookie)
        if status == 429:
            self.send_header('Retry-After', '900')
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
            return cookie['f2w_session'].value if 'f2w_session' in cookie else ''
        except Exception:
            return ''

    def user(self):
        token = self.token()
        if not token:
            return None
        with self.server.connect() as db:
            user = db.execute('''SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
                                 WHERE s.token_hash=? AND s.expires>?''',
                              (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        return user

    def public_user(self, user):
        return {key: user[key] for key in ('id', 'role', 'name', 'region', 'mobile', 'business')}

    def cookie(self, token='', max_age=0):
        return ('f2w_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + str(max_age)
                + ('; Secure' if self.server.secure_cookie else ''))

    def issue_session(self, user_id):
        token = secrets.token_urlsafe(32)
        with self.server.connect() as db:
            db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
            old = self.token()
            if old:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(old.encode()).hexdigest(),))
            db.execute('INSERT INTO sessions VALUES (?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), user_id, time.time() + TTL))
        return self.cookie(token, TTL)

    def redirect(self, location):
        self.send_response(303)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path == '/api/me':
            user = self.user()
            return self.respond(200 if user else 401, {'user': self.public_user(user) if user else None})
        filename = path.lstrip('/') or 'index.html'
        # Serve only explicitly listed project assets. Never expose database, source, or backups.
        if filename not in PUBLIC and filename not in PORTALS:
            return self.respond(404, {'error': 'Page not found.'})
        if filename in PORTALS:
            user = self.user()
            role = PORTALS[filename]
            if not user:
                return self.redirect('/login.html?role=' + role)
            if user['role'] != role:
                return self.redirect('/login.html?role=' + role + '&switch=1')
        file = ROOT / filename
        if not file.is_file():
            return self.respond(404, {'error': 'File not found.'})
        types = {'.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8',
                 '.js':'text/javascript; charset=utf-8', '.jpeg':'image/jpeg', '.mp4':'video/mp4'}
        # Stream video with byte ranges so Safari and mobile browsers can play it.
        size = file.stat().st_size
        start, end, status = 0, size - 1, 200
        byte_range = self.headers.get('Range', '')
        if file.suffix == '.mp4' and byte_range:
            match = re.fullmatch(r'bytes=(\d+)-(\d*)', byte_range)
            if not match:
                return self.respond(416, {'error':'Unsupported byte range.'})
            start = int(match[1]); end = min(int(match[2]) if match[2] else end, end)
            if start > end:
                return self.respond(416, {'error':'Invalid byte range.'})
            status = 206
        self.send_response(status)
        self.send_header('Content-Type', types[file.suffix])
        self.send_header('Content-Length', str(end - start + 1))
        if file.suffix == '.mp4':
            self.send_header('Accept-Ranges', 'bytes')
        if status == 206:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.end_headers()
        try:
            with file.open('rb') as stream:
                stream.seek(start)
                remaining = end - start + 1
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ('/api/signup', '/api/login', '/api/logout'):
            return self.respond(404, {'error': 'Endpoint not found.'})
        # JSON + custom header + same-origin checks prevent cross-site form submissions.
        origin = self.headers.get('Origin')
        expected = ('https' if self.server.secure_cookie else 'http') + '://' + self.headers.get('Host', '')
        if (self.headers.get('X-F2W-Request') != '1'
                or (origin and origin != expected)
                or self.headers.get('Sec-Fetch-Site') == 'cross-site'):
            return self.respond(403, {'error': 'Please submit from this website.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.respond(415, {'error': 'JSON request required.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192:
                raise ValueError()
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.respond(400, {'error': 'Invalid request.'})
        if path == '/api/logout':
            token = self.token()
            with self.server.connect() as db:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))
            return self.respond(200, {'ok':True}, self.cookie())
        if self.server.limited(self.client_address[0]):
            return self.respond(429, {'error':'Too many attempts. Please try again in 15 minutes.'})
        role = data.get('role')
        if not isinstance(role, str) or role not in ROLES:
            return self.respond(400, {'error':'Choose Farmer, Manufacturer, or Customer.'})
        try:
            mobile = normalize_mobile(data.get('mobile', ''))
        except ValueError as error:
            return self.respond(400, {'error':str(error)})
        password = data.get('password', '')
        if not isinstance(password, str) or not 1 <= len(password) <= 128:
            return self.respond(400, {'error':'Password must be at most 128 characters.'})
        if path == '/api/signup':
            name = data.get('name', '')
            region = data.get('region', '')
            business = data.get('business', '')
            if (not all(isinstance(v, str) for v in (name, region, business))
                    or not 2 <= len(name.strip()) <= 100 or not 2 <= len(region.strip()) <= 160
                    or len(business) > 160):
                return self.respond(400, {'error':'Enter your name and region (2–100 and 2–160 characters). Business name can be at most 160 characters.'})
            if len(password) < 10:
                return self.respond(400, {'error':'Choose a password with at least 10 characters.'})
            if password != data.get('confirmPassword'):
                return self.respond(400, {'error':'Passwords do not match.'})
            salt = secrets.token_hex(16)
            encoded = password_hash(password, salt)
            try:
                with self.server.connect() as db:
                    cursor = db.execute('''INSERT INTO users
                      (role,name,region,mobile,business,salt,password_hash,created) VALUES (?,?,?,?,?,?,?,?)''',
                      (role, name.strip(), region.strip(), mobile, business.strip() if role == 'manufacturer' else '', salt, encoded, time.time()))
                    user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return self.respond(409, {'error':'An account already exists for this mobile number in this portal. Please log in.'})
        else:
            with self.server.connect() as db:
                user = db.execute('SELECT * FROM users WHERE role=? AND mobile=?', (role, mobile)).fetchone()
            encoded = password_hash(password, user['salt'] if user else DUMMY_SALT)
            if not user or not hmac.compare_digest(encoded, user['password_hash']):
                return self.respond(401, {'error':'Mobile number or password is incorrect for this portal.'})
            user_id = user['id']
        cookie = self.issue_session(user_id)
        return self.respond(201 if path == '/api/signup' else 200,
                            {'ok':True, 'redirect':'/' + ROLES[role]}, cookie)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--database', type=Path, default=ROOT / 'accounts.sqlite3')
    args = parser.parse_args()
    server = AppServer(('127.0.0.1', args.port), args.database)
    print(f'Farm2Wool: http://localhost:{server.server_port}', flush=True)
    print('Keep this terminal open. Press Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()

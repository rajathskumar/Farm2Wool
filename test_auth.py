"""Run: python3 -m unittest -v test_auth.py (uses temporary accounts only)."""
import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from server import AppServer, ROLES, normalize_mobile


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'test.sqlite3'
        self.app = AppServer(('127.0.0.1', 0), self.path)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.app.server_port

    def tearDown(self):
        self.app.shutdown(); self.app.server_close(); self.thread.join()
        self.tmp.cleanup()

    def call(self, path, data=None, cookie=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        request_headers = {'Content-Type':'application/json', 'X-F2W-Request':'1'}
        if cookie:
            request_headers['Cookie'] = cookie.split(';')[0]
        if headers:
            request_headers.update(headers)
        conn.request('POST' if data is not None else 'GET', path,
                     json.dumps(data) if data is not None else None, request_headers)
        res = conn.getresponse(); body = res.read(); result = (res.status, dict(res.getheaders()), body)
        conn.close(); return result

    def signup(self, role='farmer', **overrides):
        data = dict(role=role, name='Test Farmer', region='Hassan, Karnataka', mobile='9876543210',
                    password='a long test passphrase', confirmPassword='a long test passphrase')
        data.update(overrides)
        return self.call('/api/signup', data)

    def test_all_roles_signup_and_access_control(self):
        for role, page in ROLES.items():
            status, headers, _ = self.signup(role)
            self.assertEqual(status, 201)
            cookie = headers['Set-Cookie']
            self.assertIn('HttpOnly', cookie); self.assertIn('SameSite=Strict', cookie)
            self.assertEqual(self.call('/'+page, cookie=cookie)[0], 200)
            status, _, body = self.call('/api/me', cookie=cookie)
            self.assertEqual(json.loads(body)['user']['role'], role)
            other = next(file for key, file in ROLES.items() if key != role)
            self.assertEqual(self.call('/'+other, cookie=cookie)[0], 303)
            self.assertEqual(self.call('/'+page)[0], 303)

    def test_normalization_duplicates_and_password_hashing(self):
        self.assertEqual(normalize_mobile('98765 43210'), '+919876543210')
        status, _, _ = self.signup(); self.assertEqual(status, 201)
        self.assertEqual(self.signup(mobile='+91 9876543210')[0], 409)
        with sqlite3.connect(self.path) as db:
            salt, stored = db.execute('SELECT salt,password_hash FROM users').fetchone()
            token_hash, = db.execute('SELECT token_hash FROM sessions').fetchone()
        self.assertNotEqual(stored, 'a long test passphrase')
        self.assertEqual(len(salt), 32); self.assertEqual(len(stored), 64); self.assertEqual(len(token_hash), 64)

    def test_login_wrong_password_logout_and_session_rotation(self):
        _, headers, _ = self.signup(); old = headers['Set-Cookie']
        credentials = dict(role='farmer', mobile='+919876543210', password='wrong')
        self.assertEqual(self.call('/api/login', credentials)[0], 401)
        credentials['password'] = 'a long test passphrase'
        status, headers, _ = self.call('/api/login', credentials, cookie=old)
        self.assertEqual(status, 200); new = headers['Set-Cookie']
        self.assertNotEqual(new, old); self.assertEqual(self.call('/api/me', cookie=old)[0], 401)
        self.assertEqual(self.call('/api/me', cookie=new)[0], 200)
        self.assertEqual(self.call('/api/logout', {}, cookie=new)[0], 200)
        self.assertEqual(self.call('/api/me', cookie=new)[0], 401)
        self.assertEqual(self.call('/farmer.html', cookie=new)[0], 303)

    def test_validation(self):
        for changes in [dict(password='short', confirmPassword='short'), dict(confirmPassword='mismatch'),
                        dict(name=''), dict(region=''), dict(mobile='123'), dict(role='admin'), dict(role=[])]:
            self.assertEqual(self.signup(**changes)[0], 400, changes)

    def test_expired_session(self):
        _, headers, _ = self.signup(); cookie = headers['Set-Cookie']
        with self.app.connect() as db:
            db.execute('UPDATE sessions SET expires=0')
        self.assertEqual(self.call('/api/me', cookie=cookie)[0], 401)

    def test_cross_site_requests_rejected(self):
        self.assertEqual(self.call('/api/signup', {}, headers={'Origin':'https://other.example'})[0], 403)
        self.assertEqual(self.call('/api/signup', {}, headers={'X-F2W-Request':''})[0], 403)
        self.assertEqual(self.call('/api/logout', {}, headers={'Sec-Fetch-Site':'cross-site'})[0], 403)

    def test_private_files_not_served(self):
        for path in ['/accounts.sqlite3', '/server.py', '/test_auth.py', '/../server.py', '/%2e%2e/server.py', '/']:
            status, _, body = self.call(path)
            self.assertEqual(status, 200 if path == '/' else 404)

    def test_rate_limiting(self):
        bad = dict(role='farmer', mobile='invalid', password='wrong')
        for _ in range(10):
            self.assertEqual(self.call('/api/login', bad)[0], 400)
        self.assertEqual(self.call('/api/login', bad)[0], 429)

    def test_sessions_survive_server_restart(self):
        _, headers, _ = self.signup(); cookie = headers['Set-Cookie']
        self.app.shutdown(); self.app.server_close(); self.thread.join()
        self.app = AppServer(('127.0.0.1', 0), self.path)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True); self.thread.start()
        self.port = self.app.server_port
        self.assertEqual(self.call('/api/me', cookie=cookie)[0], 200)

    def test_video_byte_ranges(self):
        status, headers, body = self.call('/video.mp4', headers={'Range':'bytes=0-99'})
        self.assertEqual(status, 206); self.assertEqual(len(body), 100)
        self.assertTrue(headers['Content-Range'].startswith('bytes 0-99/'))

if __name__ == '__main__':
    unittest.main()

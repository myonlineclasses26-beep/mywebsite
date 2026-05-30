import http.server
import socketserver
import os, json, sqlite3, hashlib, secrets, time, re, random

PORT = 5000
DB_PATH = "data/users.db"
ONLINE_USERS = {}   # sid -> last_seen timestamp
ONLINE_ANON = {}    # ip -> last_seen timestamp

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migrate: add email column if missing
    try:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        conn.execute("UPDATE users SET email = username WHERE email IS NULL")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migrate: add is_admin column if missing
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migrate: add is_blocked column if missing
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    # Promote the owner to admin if they exist
    conn.execute("UPDATE users SET is_admin = 1 WHERE email = 'jonathanglenn92@gmail.com'")
    conn.commit()
    # Track page visits
    conn.execute("""
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            path TEXT,
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            expires REAL NOT NULL
        )
    """)
    conn.commit()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            section TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, section, key)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vocab_words (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            word TEXT NOT NULL,
            meaning TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, word)
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"

def verify_password(password, stored):
    salt, h = stored.split('$', 1)
    computed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return computed.hex() == h

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        print(format % args)

    def end_headers(self):
        if self.path.endswith(('.js', '.css', '.html')):
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data).encode()
        self.send_response(status)
        if extra_headers:
            for key, val in extra_headers:
                self.send_header(key, val)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def require_admin(self):
        session = self.get_session()
        if not session:
            self.send_json(401, {'error': 'Not logged in'})
            return None
        if not session.get('is_admin', False):
            self.send_json(403, {'error': 'Admin access required'})
            return None
        return session

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode())

    def get_session(self):
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                if k == 'session_id':
                    conn = sqlite3.connect(DB_PATH)
                    row = conn.execute("SELECT user_id, username, is_admin, expires FROM sessions WHERE session_id = ?", (v,)).fetchone()
                    conn.close()
                    if row:
                        if row[3] > time.time():
                            ONLINE_USERS[v] = time.time()
                            return {'user_id': row[0], 'username': row[1], 'is_admin': bool(row[2]), 'expires': row[3]}
                        conn = sqlite3.connect(DB_PATH)
                        conn.execute("DELETE FROM sessions WHERE session_id = ?", (v,))
                        conn.commit()
                        conn.close()
        return None

    def set_session(self, user_id, username, is_admin=0):
        sid = secrets.token_hex(32)
        expires = time.time() + 86400
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("INSERT INTO sessions (session_id, user_id, username, is_admin, expires) VALUES (?, ?, ?, ?, ?)", (sid, user_id, username, int(is_admin), expires))
        conn.commit()
        conn.close()
        self.send_header('Set-Cookie', f'session_id={sid}; Path=/; HttpOnly; SameSite=Lax')

    def clear_session(self):
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                if k == 'session_id':
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM sessions WHERE session_id = ?", (v,))
                    conn.commit()
                    conn.close()


    def do_GET(self):
        # Track page visits (skip static files and API)
        if self.path in ('/', '/index.html', '') or self.path.startswith('/#'):
            ip = self.headers.get('X-Forwarded-For', self.client_address[0]).split(',')[0].strip()
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO visits (ip, path) VALUES (?, ?)", (ip, self.path))
            ONLINE_ANON[ip] = time.time()
            conn.commit()
            conn.close()
        if self.path == '/api/me':
            session = self.get_session()
            if session:
                self.send_json(200, {'username': session['username'], 'isAdmin': session.get('is_admin', False)})
            else:
                self.send_json(401, {'error': 'Not logged in'})

        elif self.path == '/api/stats':
            session = self.get_session()
            if not session:
                self.send_json(401, {'error': 'Not logged in'})
                return
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("SELECT key, value FROM user_stats WHERE user_id = ?", (session['user_id'],)).fetchall()
            conn.close()
            self.send_json(200, {k: v for k, v in rows})

        elif self.path == '/api/vocab/stats':
            session = self.get_session()
            if not session:
                self.send_json(401, {'error': 'Not logged in'})
                return
            conn = sqlite3.connect(DB_PATH)
            total = conn.execute("SELECT COUNT(*) FROM vocab_words WHERE user_id = ?", (session['user_id'],)).fetchone()[0]
            weekly = conn.execute("""
                SELECT COUNT(*) FROM vocab_words
                WHERE user_id = ? AND created_at >= datetime('now', '-7 days')
            """, (session['user_id'],)).fetchone()[0]
            rows = conn.execute("""
                SELECT word, meaning FROM vocab_words WHERE user_id = ? ORDER BY created_at DESC LIMIT 10
            """, (session['user_id'],)).fetchall()
            conn.close()
            self.send_json(200, {'total': total, 'weekly': weekly, 'recent': [{'word': w, 'meaning': m} for w, m in rows]})

        elif self.path == '/api/vocab/leaderboard/lifetime':
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("""
                SELECT u.username, COUNT(v.id) as cnt
                FROM users u
                JOIN vocab_words v ON u.id = v.user_id
                GROUP BY u.id
                ORDER BY cnt DESC
                LIMIT 20
            """).fetchall()
            conn.close()
            self.send_json(200, {'leaderboard': [{'username': u, 'words': c} for u, c in rows]})

        elif self.path == '/api/vocab/leaderboard/weekly':
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("""
                SELECT u.username, COUNT(v.id) as cnt
                FROM users u
                JOIN vocab_words v ON u.id = v.user_id
                WHERE v.created_at >= datetime('now', '-7 days')
                GROUP BY u.id
                ORDER BY cnt DESC
                LIMIT 20
            """).fetchall()
            conn.close()
            self.send_json(200, {'leaderboard': [{'username': u, 'words': c} for u, c in rows]})

        elif self.path == '/api/admin/users':
            session = self.require_admin()
            if not session:
                return
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute("""
                SELECT u.id, u.username, u.email, u.created_at, u.is_blocked,
                       COUNT(v.id) as word_count
                FROM users u
                LEFT JOIN vocab_words v ON u.id = v.user_id
                GROUP BY u.id
                ORDER BY u.id
            """).fetchall()
            conn.close()
            self.send_json(200, {'users': [
                {'id': r[0], 'username': r[1], 'email': r[2], 'createdAt': r[3], 'isBlocked': bool(r[4]), 'wordCount': r[5]}
                for r in rows
            ]})

        elif self.path == '/api/admin/stats':
            session = self.require_admin()
            if not session:
                return
            conn = sqlite3.connect(DB_PATH)
            total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_words = conn.execute("SELECT COUNT(*) FROM vocab_words").fetchone()[0]
            active_weekly = conn.execute("""
                SELECT COUNT(DISTINCT user_id) FROM vocab_words
                WHERE created_at >= datetime('now', '-7 days')
            """).fetchone()[0]
            total_visits = conn.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
            unique_visitors = conn.execute("SELECT COUNT(DISTINCT ip) FROM visits").fetchone()[0]
            conn.close()
            now = time.time()
            cutoff = now - 300
            logged_in_online = sum(1 for t in ONLINE_USERS.values() if t > cutoff)
            anon_online = sum(1 for t in ONLINE_ANON.values() if t > cutoff)
            self.send_json(200, {'totalUsers': total_users, 'totalWords': total_words, 'activeWeekly': active_weekly, 'totalVisits': total_visits, 'uniqueVisitors': unique_visitors, 'onlineNow': logged_in_online + anon_online, 'onlineLoggedIn': logged_in_online, 'onlineAnonymous': anon_online})

        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/api/register':
            body = self.read_body()
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')
            if not email or not password:
                self.send_json(400, {'error': 'Email and password required'})
                return
            if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
                self.send_json(400, {'error': 'Please enter a valid email address'})
                return
            if len(password) < 4:
                self.send_json(400, {'error': 'Password must be at least 4 characters'})
                return
            conn = sqlite3.connect(DB_PATH)
            try:
                existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
                if existing:
                    self.send_json(409, {'error': 'An account with this email already exists'})
                    return
                count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                username = f"coder{count + 1:04d}"
                while conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
                    count += 1
                    username = f"coder{count + 1:04d}"
                conn.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                             (username, hash_password(password), email))
                conn.commit()
                user_id = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
                body = json.dumps({'success': True, 'username': username}).encode()
                self.send_response(200)
                self.set_session(user_id, username)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            finally:
                conn.close()

        elif self.path == '/api/login':
            body = self.read_body()
            email = body.get('email', '').strip().lower()
            password = body.get('password', '')
            if not email:
                self.send_json(400, {'error': 'Email is required'})
                return
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute("SELECT id, username, password_hash, is_admin, is_blocked FROM users WHERE email = ?", (email,)).fetchone()
            conn.close()
            if row and verify_password(password, row[2]):
                if row[4]:
                    self.send_json(403, {'error': 'Your account has been blocked. Contact the admin.'})
                    return
                username = row[1]
                is_admin = row[3] if row[3] is not None else 0
                body = json.dumps({'success': True, 'username': username, 'isAdmin': bool(is_admin)}).encode()
                self.send_response(200)
                self.set_session(row[0], username, is_admin)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_json(401, {'error': 'Invalid email or password'})

        elif self.path == '/api/logout':
            self.clear_session()
            self.send_json(200, {'success': True}, extra_headers=[('Set-Cookie', 'session_id=; Path=/; Max-Age=0; SameSite=Lax')])

        elif self.path == '/api/stats':
            session = self.get_session()
            if not session:
                self.send_json(401, {'error': 'Not logged in'})
                return
            body = self.read_body()
            conn = sqlite3.connect(DB_PATH)
            for key, val in body.items():
                conn.execute("""
                    INSERT INTO user_stats (user_id, section, key, value)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, section, key)
                    DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
                """, (session['user_id'], 'general', key, str(val)))
            conn.commit()
            conn.close()
            self.send_json(200, {'success': True})

        elif self.path == '/api/vocab/word':
            session = self.get_session()
            if not session:
                self.send_json(401, {'error': 'Not logged in'})
                return
            body = self.read_body()
            word = body.get('word', '').strip().lower()
            meaning = body.get('meaning', '').strip()
            if not word:
                self.send_json(400, {'error': 'Word is required'})
                return
            conn = sqlite3.connect(DB_PATH)
            try:
                conn.execute("""
                    INSERT INTO vocab_words (user_id, word, meaning)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id, word)
                    DO UPDATE SET meaning = excluded.meaning, created_at = CURRENT_TIMESTAMP
                """, (session['user_id'], word, meaning))
                conn.commit()
                total = conn.execute("SELECT COUNT(*) FROM vocab_words WHERE user_id = ?", (session['user_id'],)).fetchone()[0]
                weekly = conn.execute("""
                    SELECT COUNT(*) FROM vocab_words
                    WHERE user_id = ? AND created_at >= datetime('now', '-7 days')
                """, (session['user_id'],)).fetchone()[0]
                self.send_json(200, {'success': True, 'total': total, 'weekly': weekly})
            finally:
                conn.close()

        elif self.path == '/api/vocab/chat':
            session = self.get_session()
            if not session:
                self.send_json(401, {'error': 'Log in to chat with the bot'})
                return
            body = self.read_body()
            msg = body.get('message', '').strip().lower()
            if not msg:
                self.send_json(200, {'reply': 'Hey there! Type something like "what does recursion mean?" or "teach me a word".'})
                return
            conn = sqlite3.connect(DB_PATH)
            words = conn.execute("SELECT word, meaning FROM vocab_words WHERE user_id = ?", (session['user_id'],)).fetchall()
            vocab = {w: m for w, m in words}
            conn.close()

            reply = ""

            m = re.search(r"(?:what does|define|explain|what is|meaning of)\s+['\"]?([a-z]+)['\"]?", msg)
            if m:
                w = m.group(1)
                if w in vocab:
                    reply = f"'{w}' means: {vocab[w]}"
                else:
                    reply = f"I don't know '{w}' yet! Teach it to me and I'll remember it."
            elif any(p in msg for p in ['teach me', 'show me a word', 'random word', 'tell me a word']):
                if vocab:
                    w, m = random.choice(list(vocab.items()))
                    reply = f"Here's one of your words: '{w}' means {m}. Want to learn another?"
                else:
                    reply = "You haven't taught me any words yet! Add some above and I'll quiz you on them."
            elif any(p in msg for p in ['list words', 'words do you know', 'my words', 'all words']):
                if vocab:
                    word_list = ", ".join([f"'{w}'" for w in sorted(vocab)[:20]])
                    reply = f"I know {len(vocab)} words: {word_list}"
                    if len(vocab) > 20:
                        reply += " and more!"
                else:
                    reply = "I don't know any words yet. Teach me some!"
            elif any(p in msg for p in ['quiz me', 'test me', 'question']):
                if vocab:
                    w, m = random.choice(list(vocab.items()))
                    reply = f"QUIZ: What does '{w}' mean?"
                else:
                    reply = "Add some words first, then I'll quiz you!"
            elif any(p in msg for p in ['hello', 'hi', 'hey', 'sup']):
                reply = f"Hey {session['username']}! I know {len(vocab)} words. Ask me to define one, teach you a word, or quiz you!"
            elif any(p in msg for p in ['help', 'how', 'what can you do']):
                reply = "I can: define words you taught me, teach you a random word, list your words, or quiz you! Just ask."
            else:
                reply = "Hmm, I didn't catch that. Try: 'what does recursion mean?', 'teach me a word', 'quiz me', or 'list my words'."

            self.send_json(200, {'reply': reply, 'wordCount': len(vocab)})

        elif self.path == '/api/admin/reset-leaderboard':
            session = self.require_admin()
            if not session:
                return
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM vocab_words")
            conn.commit()
            conn.close()
            self.send_json(200, {'success': True, 'message': 'All word data has been reset'})

        elif self.path == '/api/admin/block-user':
            session = self.require_admin()
            if not session:
                return
            body = self.read_body()
            user_id = body.get('userId')
            if not user_id:
                self.send_json(400, {'error': 'userId is required'})
                return
            conn = sqlite3.connect(DB_PATH)
            conn.execute("UPDATE users SET is_blocked = 1 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            self.send_json(200, {'success': True, 'message': f'User {user_id} blocked'})

        elif self.path == '/api/admin/unblock-user':
            session = self.require_admin()
            if not session:
                return
            body = self.read_body()
            user_id = body.get('userId')
            if not user_id:
                self.send_json(400, {'error': 'userId is required'})
                return
            conn = sqlite3.connect(DB_PATH)
            conn.execute("UPDATE users SET is_blocked = 0 WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            self.send_json(200, {'success': True, 'message': f'User {user_id} unblocked'})

        else:
            self.send_json(404, {'error': 'Not found'})

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

os.chdir(os.path.dirname(os.path.abspath(__file__)))
init_db()

with ReusableTCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()

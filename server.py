import csv, os, json, sqlite3, secrets, hashlib, hmac, time, threading, io
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_SQLITE = BASE / 'votes.db'
ENV_PATH = BASE / '.env'

# Load .env file if present
if ENV_PATH.exists():
    for line in ENV_PATH.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"\''))

ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
HOURS = float(os.getenv('VOTING_HOURS', '3'))
PORT = int(os.getenv('PORT', '8000'))
MONGO_URI = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI')

if len(ADMIN_PASSWORD) < 12:
    raise SystemExit("Set ADMIN_PASSWORD to a strong password (12+ characters).")

LOCK = threading.Lock()
SESSIONS = {}
ATTEMPTS = {}

def digest(value, salt_bytes):
    return hashlib.pbkdf2_hmac('sha256', value.encode(), salt_bytes, 180000).hex()

# MongoDB setup (with SQLite fallback)
MONGO_CLIENT = None
MONGO_DB = None
if MONGO_URI:
    try:
        import pymongo
        MONGO_CLIENT = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        try:
            MONGO_DB = MONGO_CLIENT.get_default_database()
        except Exception:
            MONGO_DB = None
        if MONGO_DB is None:
            MONGO_DB = MONGO_CLIENT['college_trip_voting']
        MONGO_CLIENT.admin.command('ping')
        print(f"Connected to MongoDB Atlas: {MONGO_DB.name}")
    except Exception as e:
        print(f"MongoDB connection notice ({e}). Falling back to SQLite.")
        MONGO_DB = None

def get_sqlite():
    c = sqlite3.connect(DB_SQLITE, timeout=20)
    c.row_factory = sqlite3.Row
    return c

def db_init():
    if MONGO_DB is not None:
        students = MONGO_DB['students']
        votes = MONGO_DB['votes']
        settings = MONGO_DB['settings']
        students.create_index('roll', unique=True)
        votes.create_index('roll', unique=True)
        settings.create_index('key', unique=True)
        cur_deadline = settings.find_one({'key': 'deadline'})
        target_deadline = time.time() + HOURS * 3600
        if not cur_deadline or target_deadline > float(cur_deadline.get('value', 0)):
            settings.update_one({'key': 'deadline'}, {'$set': {'value': str(target_deadline)}}, upsert=True)
        if not settings.find_one({'key': 'closed'}):
            settings.insert_one({'key': 'closed', 'value': '0'})
        if students.count_documents({}) == 0:
            with open(BASE / 'voters_private.csv', encoding='utf-8-sig', newline='') as f:
                docs = []
                for row in csv.DictReader(f):
                    salt = os.urandom(16)
                    docs.append({
                        'roll': row['Roll Number'].strip(),
                        'name': row['Name'].strip(),
                        'phone': row['Phone Number'].strip(),
                        'salt': salt.hex(),
                        'pin_hash': digest(row['Secret Code'].strip(), salt)
                    })
                if docs:
                    students.insert_many(docs)
    else:
        with get_sqlite() as c:
            c.execute('CREATE TABLE IF NOT EXISTS students (roll TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, salt BLOB NOT NULL, pin_hash TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS votes (roll TEXT PRIMARY KEY REFERENCES students(roll), agency TEXT NOT NULL, voted_at TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            c.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('deadline', str(time.time() + HOURS * 3600)))
            c.execute('INSERT OR IGNORE INTO settings VALUES (?,?)', ('closed', '0'))
            if c.execute('SELECT count(*) FROM students').fetchone()[0] == 0:
                with open(BASE / 'voters_private.csv', encoding='utf-8-sig', newline='') as f:
                    for row in csv.DictReader(f):
                        salt = os.urandom(16)
                        c.execute('INSERT INTO students VALUES (?,?,?,?,?)', (row['Roll Number'].strip(), row['Name'].strip(), row['Phone Number'].strip(), salt, digest(row['Secret Code'].strip(), salt)))

def db_is_open():
    if MONGO_DB is not None:
        st = {doc['key']: doc['value'] for doc in MONGO_DB['settings'].find({})}
        return st.get('closed', '0') == '0' and time.time() < float(st.get('deadline', 0))
    else:
        with get_sqlite() as c:
            st = dict(c.execute('SELECT key,value FROM settings').fetchall())
            return st.get('closed', '0') == '0' and time.time() < float(st.get('deadline', 0))

def db_close_voting():
    if MONGO_DB is not None:
        MONGO_DB['settings'].update_one({'key': 'closed'}, {'$set': {'value': '1'}}, upsert=True)
    else:
        with get_sqlite() as c:
            c.execute("UPDATE settings SET value='1' WHERE key='closed'")

def db_get_admin_data():
    if MONGO_DB is not None:
        raw_students = list(MONGO_DB['students'].find({}, {'_id': 0}))
        raw_votes = {v['roll']: v for v in MONGO_DB['votes'].find({}, {'_id': 0})}
        def roll_key(s):
            try: return int(s.get('roll', 0))
            except: return 0
        raw_students.sort(key=roll_key)
        out = []
        for s in raw_students:
            v = raw_votes.get(s['roll'], {})
            out.append({
                'roll': s['roll'],
                'name': s['name'],
                'phone': s['phone'],
                'agency': v.get('agency'),
                'voted_at': v.get('voted_at')
            })
        return out
    else:
        with get_sqlite() as c:
            rows = c.execute('SELECT s.roll,s.name,s.phone,v.agency,v.voted_at FROM students s LEFT JOIN votes v ON s.roll=v.roll ORDER BY CAST(s.roll AS INTEGER)').fetchall()
            return [{'roll': r['roll'], 'name': r['name'], 'phone': r['phone'], 'agency': r['agency'], 'voted_at': r['voted_at']} for r in rows]

def db_login(roll, phone, pin):
    if not db_is_open():
        return False, 'Voting is closed', None
    if MONGO_DB is not None:
        s = MONGO_DB['students'].find_one({'roll': roll})
        if not s:
            return False, 'Invalid login details', None
        salt_bytes = bytes.fromhex(s['salt']) if isinstance(s['salt'], str) else s['salt']
        if not hmac.compare_digest(phone, s['phone']) or not hmac.compare_digest(digest(pin, salt_bytes), s['pin_hash']):
            return False, 'Invalid login details', None
        if MONGO_DB['votes'].find_one({'roll': roll}):
            return False, 'You have already voted', None
        return True, None, {'name': s['name'], 'roll': roll}
    else:
        with get_sqlite() as c:
            r = c.execute('SELECT * FROM students WHERE roll=?', (roll,)).fetchone()
            if not r:
                return False, 'Invalid login details', None
            salt_bytes = r['salt']
            if not hmac.compare_digest(phone, r['phone']) or not hmac.compare_digest(digest(pin, salt_bytes), r['pin_hash']):
                return False, 'Invalid login details', None
            if c.execute('SELECT 1 FROM votes WHERE roll=?', (roll,)).fetchone():
                return False, 'You have already voted', None
            return True, None, {'name': r['name'], 'roll': roll}

def db_vote(roll, agency):
    if not db_is_open():
        return False, 'Voting is closed'
    if MONGO_DB is not None:
        import pymongo
        try:
            MONGO_DB['votes'].insert_one({
                'roll': roll,
                'agency': agency,
                'voted_at': datetime.now(timezone.utc).isoformat()
            })
            return True, None
        except pymongo.errors.DuplicateKeyError:
            return False, 'Already voted'
    else:
        with get_sqlite() as c:
            try:
                c.execute('INSERT INTO votes VALUES (?,?,?)', (roll, agency, datetime.now(timezone.utc).isoformat()))
                return True, None
            except sqlite3.IntegrityError:
                return False, 'Already voted'

def ist(s):
    if not s: return ''
    return datetime.fromisoformat(s).astimezone(timezone(timedelta(hours=5, minutes=30))).strftime('%d %b %Y %I:%M:%S %p')

class Handler(BaseHTTPRequestHandler):
    def send(self, code, data, ctype='application/json', cookie=None):
        raw = (json.dumps(data).encode() if ctype == 'application/json' else data)
        self.send_response(code)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if cookie: self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(raw)

    def error(self, code, msg):
        self.send(code, {'error': msg})

    def session(self):
        cookie = SimpleCookie()
        try: cookie.load(self.headers.get('Cookie', ''))
        except: return None
        token = cookie.get('session')
        return SESSIONS.get(token.value) if token else None

    def readjson(self):
        n = int(self.headers.get('Content-Length', '0'))
        if n > 4096: raise ValueError('Request too large')
        return json.loads(self.rfile.read(n))

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/admin'):
            name = 'admin.html' if path == '/admin' else 'index.html'
            return self.send(200, (BASE / name).read_bytes(), 'text/html')
        if path in ('/api/admin/data', '/api/export'):
            if not self.session() or self.session()['role'] != 'admin':
                return self.error(403, 'Admin login required')
            data = db_get_admin_data()
            counts = {x: sum(r['agency'] == x for r in data) for x in ('travlog', 'thilal', 'stories')}
            if path == '/api/export':
                f = io.StringIO()
                w = csv.writer(f)
                w.writerow(['Roll', 'Name', 'Phone', 'Status', 'Agency', 'Time IST'])
                for r in data:
                    w.writerow([r['roll'], r['name'], r['phone'], 'Voted' if r['agency'] else 'Pending', r['agency'] or '', ist(r['voted_at'])])
                return self.send(200, f.getvalue().encode('utf-8-sig'), 'text/csv')
            return self.send(200, {
                'total': len(data),
                'voted': sum(bool(r['agency']) for r in data),
                'counts': counts,
                'open': db_is_open(),
                'students': [{'roll': r['roll'], 'name': r['name'], 'phone': '******' + r['phone'][-4:], 'agency': r['agency'], 'time': ist(r['voted_at'])} for r in data]
            })
        self.error(404, 'Not found')

    def do_POST(self):
        path = urlparse(self.path).path
        origin = self.headers.get('Origin')
        host = self.headers.get('Host', '')
        fwd_host = self.headers.get('X-Forwarded-Host', '')
        if origin:
            allowed = {f"http://{host}", f"https://{host}"}
            if fwd_host:
                allowed.update({f"http://{fwd_host}", f"https://{fwd_host}"})
            if origin not in allowed and urlparse(origin).netloc not in (host, fwd_host):
                return self.error(403, 'Origin rejected')
        try:
            data = self.readjson()
        except:
            return self.error(400, 'Invalid request')

        ip = self.client_address[0]
        if path in ('/api/login', '/api/admin/login'):
            with LOCK:
                recent = [t for t in ATTEMPTS.get(ip, []) if time.time() - t < 900]
                if len(recent) >= 12:
                    return self.error(429, 'Too many attempts. Try later.')
                recent.append(time.time())
                ATTEMPTS[ip] = recent

        if path == '/api/admin/login':
            if not hmac.compare_digest(str(data.get('password', '')), ADMIN_PASSWORD):
                return self.error(401, 'Invalid admin password')
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {'role': 'admin'}
            return self.send(200, {'ok': True}, cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=14400' + ('; Secure' if self.headers.get('X-Forwarded-Proto') == 'https' else ''))

        if path == '/api/login':
            roll = str(data.get('roll', '')).strip()
            phone = str(data.get('phone', '')).strip()
            pin = str(data.get('pin', '')).strip()
            ok, err, student = db_login(roll, phone, pin)
            if not ok:
                code = 403 if err in ('Voting is closed', 'You have already voted') else 401
                return self.error(code, err)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {'role': 'student', 'roll': roll}
            return self.send(200, student, cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600' + ('; Secure' if self.headers.get('X-Forwarded-Proto') == 'https' else ''))

        if path == '/api/vote':
            session = self.session()
            if not session or session['role'] != 'student':
                return self.error(401, 'Login first')
            agency = data.get('agency')
            if agency not in ('travlog', 'thilal', 'stories'):
                return self.error(400, 'Invalid agency')
            with LOCK:
                ok, err = db_vote(session['roll'], agency)
                if not ok:
                    code = 403 if err == 'Voting is closed' else 409
                    return self.error(code, err)
            return self.send(200, {'ok': True})

        if path == '/api/admin/close':
            if not self.session() or self.session()['role'] != 'admin':
                return self.error(403, 'Admin login required')
            db_close_voting()
            return self.send(200, {'ok': True})

        self.error(404, 'Not found')

db_init()
print(f'Open http://localhost:{PORT} (admin: /admin)')
ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

#!/usr/bin/env python3
"""أثر — تتبّع الموقع المباشر بموافقة صريحة.

يرسل الأدمن رابطاً فريداً للشخص عبر واتساب. الشخص يفتح الرابط، يشوف شاشة
موافقة واضحة، ويضغط "موافق" ليبدأ مشاركة موقعه. الأدمن يشوف خريطة حية
بأسماء كل من وافق. من يقفل الصفحة أو يسحب الموافقة تتوقف مشاركته فوراً.

يحتاج استضافة بعنوان HTTPS عام (الجوال يفتح الرابط من أي مكان، ومتصفحات
الجوال ما تسمح بمشاركة الموقع إلا على HTTPS). شوف README.md للنشر على
استضافة مجانية (Render).

تشغيل محلي للتجربة:  ADMIN_PASSWORD='كلمتك' python3 server.py
"""
import hmac, json, os, re, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("PORT", "8080"))
HOST = os.environ.get("HOST", "0.0.0.0")
DATA_FILE = os.environ.get("DATA_FILE", os.path.join(HERE, "people.json"))
SESSION_TTL = 8 * 3600
STALE_AFTER = 90          # ثانية بدون تحديث = "غير متصل"


def load_password():
    p = os.environ.get("ADMIN_PASSWORD")
    if p:
        return p
    try:
        with open(os.path.join(HERE, "password.txt"), encoding="utf-8-sig") as f:
            p = f.read().strip()
        if p:
            return p
    except OSError:
        pass
    return "135790123"


PASSWORD = load_password()
lock = threading.Lock()
sessions, fails = {}, {}


def load_people():
    try:
        with open(DATA_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_people(d):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, DATA_FILE)


NAME_RE = re.compile(r"^[^\x00-\x1f]{1,60}$")


def page(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        body = f.read()
    return ('<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            '<style>body{margin:0}</style></head><body>' + body + '</body></html>').encode()


class H(BaseHTTPRequestHandler):
    server_version = "Athar"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json", extra=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body_json(self, limit=8192):
        try:
            n = min(int(self.headers.get("Content-Length", "0")), limit)
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def sid(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return ""

    def authed(self):
        s = self.sid()
        with lock:
            exp = sessions.get(s)
            if exp and exp > time.time():
                return True
            sessions.pop(s, None)
        return False

    # ---------------- GET ----------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self.send(200, page("admin.html"), "text/html")
        m = re.fullmatch(r"/t/([A-Za-z0-9_-]{8,64})", u.path)
        if m:
            return self.send(200, page("child.html"), "text/html")

        if u.path.startswith("/api/person/"):
            token = u.path.rsplit("/", 1)[-1]
            people = load_people()
            p = people.get(token)
            if not p:
                return self.send(404, {"error": "not found"})
            return self.send(200, {"name": p["name"]})

        if not self.authed():
            return self.send(401, {"error": "auth"})
        if u.path == "/api/people":
            now = time.time()
            out = []
            for token, p in load_people().items():
                loc = p.get("loc")
                out.append({
                    "token": token, "name": p["name"], "createdAt": p["createdAt"],
                    "lat": loc["lat"] if loc else None, "lng": loc["lng"] if loc else None,
                    "acc": loc.get("acc") if loc else None,
                    "updatedAt": loc["t"] if loc else None,
                    "online": bool(loc) and (now - loc["t"]) < STALE_AFTER,
                    "sharing": p.get("sharing", False),
                })
            out.sort(key=lambda p: p["createdAt"], reverse=True)
            return self.send(200, {"people": out})
        self.send(404, {"error": "not found"})

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)

        if u.path == "/api/login":
            return self.login()
        if u.path == "/api/logout":
            with lock:
                sessions.pop(self.sid(), None)
            return self.send(200, {"ok": True}, extra=[("Set-Cookie", "sid=; Max-Age=0; Path=/")])

        m = re.fullmatch(r"/api/report/([A-Za-z0-9_-]{8,64})", u.path)
        if m:
            return self.report(m.group(1))
        m = re.fullmatch(r"/api/consent/([A-Za-z0-9_-]{8,64})", u.path)
        if m:
            return self.consent(m.group(1))

        if not self.authed():
            return self.send(401, {"error": "auth"})
        if u.path == "/api/people":
            return self.add_person()
        self.send(404, {"error": "not found"})

    def do_DELETE(self):
        u = urlparse(self.path)
        if not self.authed():
            return self.send(401, {"error": "auth"})
        m = re.fullmatch(r"/api/people/([A-Za-z0-9_-]{8,64})", u.path)
        if m:
            with lock:
                people = load_people()
                people.pop(m.group(1), None)
                save_people(people)
            return self.send(200, {"ok": True})
        self.send(404, {"error": "not found"})

    # ---------------- actions ----------------
    def login(self):
        ip, now = self.client_address[0], time.time()
        with lock:
            cnt, first = fails.get(ip, (0, now))
            if now - first > 60:
                cnt, first = 0, now
            if cnt >= 5:
                return self.send(429, {"error": "locked"})
        pw = str(self.body_json(4096).get("password", ""))
        if hmac.compare_digest(pw.encode(), PASSWORD.encode()):
            sid = secrets.token_urlsafe(24)
            with lock:
                sessions[sid] = now + SESSION_TTL
                fails.pop(ip, None)
            return self.send(200, {"ok": True},
                             extra=[("Set-Cookie", f"sid={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}")])
        with lock:
            fails[ip] = (cnt + 1, first)
        time.sleep(0.6)
        self.send(401, {"error": "bad password"})

    def add_person(self):
        name = str(self.body_json().get("name", "")).strip()
        if not name or not NAME_RE.match(name):
            return self.send(400, {"error": "bad name"})
        token = secrets.token_urlsafe(16)
        with lock:
            people = load_people()
            people[token] = {"name": name, "createdAt": time.time(), "sharing": False, "loc": None}
            save_people(people)
        self.send(200, {"token": token})

    def consent(self, token):
        body = self.body_json()
        with lock:
            people = load_people()
            p = people.get(token)
            if not p:
                return self.send(404, {"error": "not found"})
            p["sharing"] = bool(body.get("sharing"))
            if not p["sharing"]:
                p["loc"] = None
            save_people(people)
        self.send(200, {"ok": True})

    def report(self, token):
        body = self.body_json()
        try:
            lat, lng = float(body["lat"]), float(body["lng"])
        except (KeyError, TypeError, ValueError):
            return self.send(400, {"error": "bad location"})
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            return self.send(400, {"error": "bad location"})
        acc = body.get("acc")
        with lock:
            people = load_people()
            p = people.get(token)
            if not p or not p.get("sharing"):
                return self.send(403, {"error": "no consent"})
            p["loc"] = {"lat": lat, "lng": lng, "acc": acc, "t": time.time()}
            save_people(people)
        self.send(200, {"ok": True})


def main():
    print("افتح لوحة الأدمن من:")
    print(f"  http://localhost:{PORT}/   (للتجربة المحلية فقط)")
    print("للجوالات يجب نشره على استضافة بعنوان https:// — راجع README.md")
    try:
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    import sys, time, traceback
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.stdout.flush()
        time.sleep(120)
        raise

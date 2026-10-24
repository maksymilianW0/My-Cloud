"""SelfCloud – self-hosted storage for files and notes (FastAPI + SQLite, opcjonalnie Google Drive)."""
import hashlib, hmac, mimetypes, os, secrets, shutil, sqlite3, threading, time, uuid
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode

import httpx
import jwt
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

import uvicorn


from dotenv import load_dotenv

load_dotenv()


DATA = Path(os.getenv("DATA_DIR") or "data")  # `or` – pusty DATA_DIR w .env nie oznacza katalogu bieżącego
FILES = DATA / "files"
FILES.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "selfcloud.db"
KEY_PATH = DATA / "secret.key"
if not KEY_PATH.exists():
    KEY_PATH.write_text(secrets.token_hex(32))
SECRET = KEY_PATH.read_text()

# ---------- Google OAuth / Drive ----------
G_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
G_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
G_AUTH_URI = os.getenv("GOOGLE_OAUTH_URI") or "https://accounts.google.com/o/oauth2/auth"
G_TOKEN_URI = os.getenv("GOOGLE_OAUTH_TOKEN_URI") or "https://oauth2.googleapis.com/token"
G_REDIRECT = os.getenv("GOOGLE_OAUTH_REDIRECT_URI", "").strip()  # np. http://localhost:8080/auth/google/callback
# GOOGLE_OAUTH_CERT_PROVIDER (auth_provider_x509_cert_url) nie jest potrzebne do tego przepływu.
G_REVOKE_URI = "https://oauth2.googleapis.com/revoke"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata"
G_SCOPES = f"openid email {DRIVE_SCOPE}"
DRIVE_API = "https://www.googleapis.com/drive/v3/files"
DRIVE_UPLOAD = "https://www.googleapis.com/upload/drive/v3/files"
DRIVE_CHUNK = 8 * 1024 * 1024  # musi być wielokrotnością 256 KiB
# Osobny klucz dla parametru `state`, żeby nie dało się go użyć jako tokena sesji.
STATE_KEY = hashlib.sha256(b"google-state:" + SECRET.encode()).hexdigest()

# Domyślna konfiguracja – admin może ją zmieniać w panelu (zapis w bazie).
DEFAULT_SETTINGS = {
    "site_name": "SelfCloud",
    "registration_enabled": True,     # czy każdy może założyć konto
    "default_quota_mb": 1024,         # limit miejsca dla nowych kont (0 = bez limitu)
    "max_upload_mb": 100,             # maks. rozmiar jednego pliku
    "allowed_extensions": "",         # np. "pdf,png,txt" – puste = wszystkie
    "blocked_extensions": "exe,bat,sh",
    "token_ttl_minutes": 720,         # ważność sesji
    "min_password_length": 8,
    "max_notes_per_user": 0,          # 0 = bez limitu
    "google_drive_enabled": True,     # czy użytkownicy mogą łączyć konto Google (wymaga danych w .env)
}

class Res:
    def __init__(s, cur):
        s.rows, s.rowcount, s.lastrowid = cur.fetchall(), cur.rowcount, cur.lastrowid

    def fetchone(s):
        return s.rows[0] if s.rows else None

    def __iter__(s):
        return iter(s.rows)


class DB:
    """Połączenie SQLite bezpieczne dla wątków (FastAPI uruchamia endpointy w puli wątków)."""
    def __init__(s, path):
        s.c = sqlite3.connect(path, check_same_thread=False)
        s.c.row_factory = sqlite3.Row
        s.c.execute("PRAGMA journal_mode=WAL")
        s.l = threading.RLock()

    def execute(s, *a):
        with s.l:
            return Res(s.c.execute(*a))

    def executescript(s, q):
        with s.l:
            s.c.executescript(q)

    def commit(s):
        with s.l:
            s.c.commit()


db = DB(DB_PATH)
db.executescript("""
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT,
  is_admin INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1, quota_mb INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, owner INTEGER, name TEXT, size INTEGER, created REAL);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner INTEGER, title TEXT, body TEXT, updated REAL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS google_links(user_id INTEGER PRIMARY KEY, google_sub TEXT UNIQUE, email TEXT,
  refresh_token TEXT, access_token TEXT, expires REAL DEFAULT 0, upload_to_drive INTEGER DEFAULT 1, created REAL);
""")
# Migracja istniejących baz: skąd pochodzi plik (dysk serwera czy Google Drive).
_cols = {r["name"] for r in db.execute("PRAGMA table_info(files)")}
if "backend" not in _cols:
    db.execute("ALTER TABLE files ADD COLUMN backend TEXT DEFAULT 'local'")
if "drive_id" not in _cols:
    db.execute("ALTER TABLE files ADD COLUMN drive_id TEXT")
db.commit()


# ---------- helpers ----------
def hash_pw(p: str) -> str:
    salt = os.urandom(16)
    return salt.hex() + ":" + hashlib.scrypt(p.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def check_pw(p: str, stored: str) -> bool:
    salt, h = stored.split(":")
    return hmac.compare_digest(hashlib.scrypt(p.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex(), h)


def cfg() -> dict:
    out = dict(DEFAULT_SETTINGS)
    for r in db.execute("SELECT key, value FROM settings"):
        if r["key"] in out:
            t = type(DEFAULT_SETTINGS[r["key"]])
            out[r["key"]] = (r["value"] == "1") if t is bool else t(r["value"])
    return out


def ext_list(s: str):
    return {e.strip().lower().lstrip(".") for e in s.split(",") if e.strip()}


def used_bytes(uid: int) -> int:
    """Miejsce zajęte na serwerze (pliki na Google Drive nie liczą się do limitu)."""
    return db.execute("SELECT COALESCE(SUM(size),0) FROM files WHERE owner=? AND backend!='drive'", (uid,)).fetchone()[0]


def bootstrap_admin():
    if db.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
        return
    user = os.getenv("ADMIN_USER", "admin")
    pw = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    db.execute("INSERT INTO users(username,pw,is_admin,quota_mb,created) VALUES(?,?,1,0,?)",
               (user, hash_pw(pw), time.time()))
    db.commit()
    print(f"\n=== Utworzono konto admina: {user} / {pw}  (zmień hasło po zalogowaniu) ===\n")


bootstrap_admin()
bearer = HTTPBearer(auto_error=False)


def current_user(request: Request, c: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    tok = c.credentials if c else request.query_params.get("token")  # ?token= pozwala pobierać pliki zwykłym linkiem
    if not tok:
        raise HTTPException(401, "Wymagane logowanie")
    try:
        uid = jwt.decode(tok, SECRET, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        raise HTTPException(401, "Sesja wygasła – zaloguj się ponownie")
    u = db.execute("SELECT * FROM users WHERE id=?", (int(uid),)).fetchone()
    if not u or not u["is_active"]:
        raise HTTPException(403, "Konto nieaktywne")
    return u


def admin_user(u=Depends(current_user)):
    if not u["is_admin"]:
        raise HTTPException(403, "Tylko dla administratora")
    return u


def public(u) -> dict:
    return {"id": u["id"], "username": u["username"], "is_admin": bool(u["is_admin"]),
            "is_active": bool(u["is_active"]), "quota_mb": u["quota_mb"], "used": used_bytes(u["id"])}


# ---------- Google Drive (appDataFolder) ----------
def google_ready() -> bool:
    return bool(G_ID and G_SECRET and G_REDIRECT and cfg()["google_drive_enabled"])


def get_link(uid: int):
    return db.execute("SELECT * FROM google_links WHERE user_id=?", (uid,)).fetchone()


def drive_token(uid: int) -> str:
    """Zwraca ważny access token użytkownika (odświeża go w razie potrzeby)."""
    l = get_link(uid)
    if not l:
        raise HTTPException(409, "Konto Google nie jest połączone")
    if l["access_token"] and l["expires"] > time.time() + 60:
        return l["access_token"]
    r = httpx.post(G_TOKEN_URI, timeout=20, data={
        "client_id": G_ID, "client_secret": G_SECRET,
        "refresh_token": l["refresh_token"], "grant_type": "refresh_token"})
    if r.status_code in (400, 401):
        raise HTTPException(409, "Połączenie z Google wygasło – połącz konto ponownie w zakładce Konto")
    if r.status_code != 200:
        raise HTTPException(502, "Nie można odświeżyć dostępu do Google")
    t = r.json()
    db.execute("UPDATE google_links SET access_token=?, expires=? WHERE user_id=?",
               (t["access_token"], time.time() + int(t.get("expires_in", 3600)), uid))
    db.commit()
    return t["access_token"]


def gerr(r: httpx.Response):
    try:
        reason = r.json()["error"]["errors"][0]["reason"]
    except Exception:
        reason = ""
    if reason == "storageQuotaExceeded":
        raise HTTPException(507, "Brak wolnego miejsca na Dysku Google")
    raise HTTPException(502, f"Google Drive zwrócił błąd ({r.status_code})")


def drive_put(uid: int, name: str, src, size: int) -> str:
    """Wysyła plik do ukrytego folderu appDataFolder (wznawialnie, porcjami). Zwraca id pliku na Drive."""
    h = {"Authorization": "Bearer " + drive_token(uid)}
    meta = {"name": name, "parents": ["appDataFolder"]}
    with httpx.Client(timeout=120) as c:
        if size == 0:  # pusty plik – wystarczą same metadane
            r = c.post(DRIVE_API, headers=h, json=meta, params={"fields": "id"})
            if r.status_code != 200:
                gerr(r)
            return r.json()["id"]
        r = c.post(DRIVE_UPLOAD, params={"uploadType": "resumable", "fields": "id"}, json=meta,
                   headers={**h, "X-Upload-Content-Length": str(size)})
        if r.status_code != 200:
            gerr(r)
        session = r.headers["Location"]
        pos = 0
        while pos < size:
            data = src.read(DRIVE_CHUNK)
            if not data:
                break
            r = c.put(session, content=data, headers={"Content-Range": f"bytes {pos}-{pos + len(data) - 1}/{size}"})
            pos += len(data)
            if r.status_code in (200, 201):
                return r.json()["id"]
            if r.status_code != 308:  # 308 = „wyślij kolejną porcję”
                gerr(r)
    raise HTTPException(502, "Nie udało się wysłać całego pliku do Google Drive")


def drive_delete(uid: int, drive_id: str):
    r = httpx.delete(f"{DRIVE_API}/{drive_id}", headers={"Authorization": "Bearer " + drive_token(uid)}, timeout=30)
    if r.status_code not in (200, 204, 404):
        gerr(r)


def drive_stream(uid: int, f) -> StreamingResponse:
    """Przesyła plik z Google Drive do przeglądarki bez zapisywania go na serwerze."""
    client = httpx.Client(timeout=httpx.Timeout(30, read=300))
    try:
        req = client.build_request("GET", f"{DRIVE_API}/{f['drive_id']}", params={"alt": "media"},
                                   headers={"Authorization": "Bearer " + drive_token(uid), "Accept-Encoding": "identity"})
        resp = client.send(req, stream=True)
    except BaseException:
        client.close()
        raise
    if resp.status_code != 200:
        resp.close(); client.close()
        raise HTTPException(404 if resp.status_code == 404 else 502, "Nie można pobrać pliku z Dysku Google")
    return StreamingResponse(
        resp.iter_bytes(1024 * 1024),
        media_type=mimetypes.guess_type(f["name"])[0] or "application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(f['name'])}", "Content-Length": str(f["size"])},
        background=BackgroundTask(lambda: (resp.close(), client.close())))


# ---------- schemas ----------
class Creds(BaseModel):
    username: str
    password: str


class NoteIn(BaseModel):
    title: str = ""
    body: str = ""


class UserPatch(BaseModel):
    password: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None
    quota_mb: Optional[int] = None


class PwChange(BaseModel):
    old_password: str
    new_password: str


class GooglePatch(BaseModel):
    upload_to_drive: bool


app = FastAPI(title="SelfCloud")


@app.exception_handler(httpx.HTTPError)
async def google_unreachable(_, e):
    return JSONResponse({"detail": "Nie można połączyć się z Google"}, status_code=502)


# ---------- auth ----------
def make_user(username: str, password: str, admin=False):
    c = cfg()
    username = username.strip()
    if not (3 <= len(username) <= 32) or not username.replace("_", "").replace(".", "").isalnum():
        raise HTTPException(400, "Nazwa: 3–32 znaków, litery, cyfry, _ lub .")
    if len(password) < c["min_password_length"]:
        raise HTTPException(400, f"Hasło musi mieć min. {c['min_password_length']} znaków")
    try:
        cur = db.execute("INSERT INTO users(username,pw,is_admin,quota_mb,created) VALUES(?,?,?,?,?)",
                         (username, hash_pw(password), int(admin), c["default_quota_mb"], time.time()))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Taka nazwa użytkownika już istnieje")
    return cur.lastrowid


@app.get("/api/public")
def public_info():
    c = cfg()
    return {"site_name": c["site_name"], "registration_enabled": c["registration_enabled"]}


@app.post("/api/register")
def register(b: Creds):
    if not cfg()["registration_enabled"]:
        raise HTTPException(403, "Rejestracja jest wyłączona")
    make_user(b.username, b.password)
    return login(b)


@app.post("/api/login")
def login(b: Creds):
    u = db.execute("SELECT * FROM users WHERE username=?", (b.username.strip(),)).fetchone()
    if not u or not check_pw(b.password, u["pw"]):
        raise HTTPException(401, "Błędna nazwa użytkownika lub hasło")
    if not u["is_active"]:
        raise HTTPException(403, "Konto zostało zablokowane")
    exp = time.time() + cfg()["token_ttl_minutes"] * 60
    return {"token": jwt.encode({"sub": str(u["id"]), "exp": exp}, SECRET, algorithm="HS256")}


@app.get("/api/me")
def me(u=Depends(current_user)):
    return public(u)


@app.post("/api/me/password")
def change_pw(b: PwChange, u=Depends(current_user)):
    if not check_pw(b.old_password, u["pw"]):
        raise HTTPException(400, "Stare hasło jest nieprawidłowe")
    if len(b.new_password) < cfg()["min_password_length"]:
        raise HTTPException(400, "Nowe hasło jest za krótkie")
    db.execute("UPDATE users SET pw=? WHERE id=?", (hash_pw(b.new_password), u["id"]))
    db.commit()
    return {"ok": True}


# ---------- konto Google ----------
@app.get("/api/google")
def google_status(u=Depends(current_user)):
    l = get_link(u["id"])
    n, b = db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM files WHERE owner=? AND backend='drive'",
                      (u["id"],)).fetchone()
    return {"available": google_ready(), "linked": bool(l), "email": l["email"] if l else None,
            "upload_to_drive": bool(l and l["upload_to_drive"]), "drive_files": n, "drive_bytes": b}


@app.post("/api/google/connect")
def google_connect(u=Depends(current_user)):
    """Zwraca adres, na który frontend przekierowuje użytkownika (przeglądarka nie może tu wysłać nagłówka Authorization)."""
    if not google_ready():
        raise HTTPException(503, "Integracja z Google jest wyłączona lub nieskonfigurowana")
    state = jwt.encode({"uid": u["id"], "purpose": "google_link", "exp": time.time() + 600}, STATE_KEY, algorithm="HS256")
    q = urlencode({"client_id": G_ID, "redirect_uri": G_REDIRECT, "response_type": "code", "scope": G_SCOPES,
                   "access_type": "offline", "prompt": "consent", "state": state})
    return {"url": f"{G_AUTH_URI}?{q}"}


@app.get("/auth/google/callback")
def google_callback(code: str = "", state: str = "", error: str = ""):
    def back(status):
        return RedirectResponse(f"/?google={status}", status_code=303)

    try:
        s = jwt.decode(state, STATE_KEY, algorithms=["HS256"])
        assert s["purpose"] == "google_link"
        uid = int(s["uid"])
    except (jwt.PyJWTError, KeyError, ValueError, AssertionError):
        return back("invalid")
    u = db.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
    if not u or not u["is_active"]:
        return back("invalid")
    if error or not code:
        return back("denied")
    try:
        r = httpx.post(G_TOKEN_URI, timeout=20, data={
            "code": code, "client_id": G_ID, "client_secret": G_SECRET,
            "redirect_uri": G_REDIRECT, "grant_type": "authorization_code"})
    except httpx.HTTPError:
        return back("error")
    if r.status_code != 200:
        return back("error")
    t = r.json()
    if DRIVE_SCOPE not in t.get("scope", "").split():  # użytkownik mógł odznaczyć zgodę na Drive
        return back("scope")
    try:  # id_token pochodzi bezpośrednio od Google (TLS), więc podpisu nie trzeba tu weryfikować
        idt = jwt.decode(t["id_token"], options={"verify_signature": False})
    except (KeyError, jwt.PyJWTError):
        idt = {}
    sub, email = idt.get("sub"), idt.get("email")
    if sub and db.execute("SELECT 1 FROM google_links WHERE google_sub=? AND user_id!=?", (sub, uid)).fetchone():
        return back("taken")
    old = get_link(uid)
    refresh = t.get("refresh_token") or (old["refresh_token"] if old else None)
    if not refresh:
        return back("error")
    db.execute("INSERT OR REPLACE INTO google_links(user_id,google_sub,email,refresh_token,access_token,expires,"
               "upload_to_drive,created) VALUES(?,?,?,?,?,?,?,?)",
               (uid, sub, email, refresh, t["access_token"], time.time() + int(t.get("expires_in", 3600)),
                old["upload_to_drive"] if old else 1, time.time()))
    db.commit()
    return back("ok")


@app.patch("/api/google")
def google_patch(b: GooglePatch, u=Depends(current_user)):
    if not get_link(u["id"]):
        raise HTTPException(404, "Konto Google nie jest połączone")
    db.execute("UPDATE google_links SET upload_to_drive=? WHERE user_id=?", (int(b.upload_to_drive), u["id"]))
    db.commit()
    return {"ok": True}


@app.delete("/api/google")
def google_disconnect(force: bool = False, u=Depends(current_user)):
    l = get_link(u["id"])
    if not l:
        return {"ok": True}
    n = db.execute("SELECT COUNT(*) FROM files WHERE owner=? AND backend='drive'", (u["id"],)).fetchone()[0]
    if n and not force:
        raise HTTPException(409, f"Masz {n} plików na Dysku Google – najpierw je pobierz lub usuń")
    try:
        httpx.post(G_REVOKE_URI, data={"token": l["refresh_token"]}, timeout=10)
    except httpx.HTTPError:
        pass  # odłączamy lokalnie nawet jeśli Google jest niedostępne
    db.execute("DELETE FROM files WHERE owner=? AND backend='drive'", (u["id"],))
    db.execute("DELETE FROM google_links WHERE user_id=?", (u["id"],))
    db.commit()
    return {"ok": True}


# ---------- files ----------
@app.get("/api/files")
def list_files(u=Depends(current_user)):
    rows = db.execute("SELECT id,name,size,created,backend FROM files WHERE owner=? ORDER BY created DESC", (u["id"],))
    return [dict(r) for r in rows]


def save_local(src, path: Path):
    with open(path, "wb") as out:
        shutil.copyfileobj(src, out, 1024 * 1024)


@app.post("/api/files")
async def upload(f: UploadFile = File(...), u=Depends(current_user)):
    c = cfg()
    name = Path(f.filename or "plik").name
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    allowed, blocked = ext_list(c["allowed_extensions"]), ext_list(c["blocked_extensions"])
    if ext in blocked or (allowed and ext not in allowed):
        raise HTTPException(400, f"Typ pliku „.{ext}” jest niedozwolony")
    f.file.seek(0, os.SEEK_END)
    size = f.file.tell()
    f.file.seek(0)
    limit = c["max_upload_mb"] * 1024 * 1024
    if limit and size > limit:
        raise HTTPException(413, "Plik jest za duży lub przekroczono limit miejsca")
    fid = uuid.uuid4().hex
    link = get_link(u["id"])
    if link and link["upload_to_drive"] and google_ready():
        # Na Drive plik dostaje neutralną nazwę (id); prawdziwa nazwa żyje w bazie SelfCloud.
        backend, drive_id = "drive", await run_in_threadpool(drive_put, u["id"], fid, f.file, size)
    else:
        quota = (u["quota_mb"] or 0) * 1024 * 1024
        if quota and used_bytes(u["id"]) + size > quota:
            raise HTTPException(413, "Plik jest za duży lub przekroczono limit miejsca")
        folder = FILES / str(u["id"])
        folder.mkdir(exist_ok=True)
        await run_in_threadpool(save_local, f.file, folder / fid)
        backend, drive_id = "local", None
    db.execute("INSERT INTO files(id,owner,name,size,created,backend,drive_id) VALUES(?,?,?,?,?,?,?)",
               (fid, u["id"], name, size, time.time(), backend, drive_id))
    db.commit()
    return {"id": fid, "name": name, "size": size}


def own_file(fid: str, u):
    r = db.execute("SELECT * FROM files WHERE id=? AND owner=?", (fid, u["id"])).fetchone()
    if not r:
        raise HTTPException(404, "Nie znaleziono pliku")
    return r


@app.get("/api/files/{fid}")
def download(fid: str, u=Depends(current_user)):
    r = own_file(fid, u)
    if r["backend"] == "drive":
        return drive_stream(u["id"], r)
    return FileResponse(FILES / str(u["id"]) / fid, filename=r["name"])


class Rename(BaseModel):
    name: str


@app.patch("/api/files/{fid}")
def rename_file(fid: str, b: Rename, u=Depends(current_user)):
    own_file(fid, u)
    name = Path(b.name.strip()).name
    if not name:
        raise HTTPException(400, "Nazwa nie może być pusta")
    db.execute("UPDATE files SET name=? WHERE id=?", (name, fid))
    db.commit()
    return {"ok": True}


@app.delete("/api/files/{fid}")
def delete_file(fid: str, u=Depends(current_user)):
    r = own_file(fid, u)
    if r["backend"] == "drive":
        drive_delete(u["id"], r["drive_id"])
    else:
        (FILES / str(u["id"]) / fid).unlink(missing_ok=True)
    db.execute("DELETE FROM files WHERE id=?", (fid,))
    db.commit()
    return {"ok": True}


# ---------- notes ----------
@app.get("/api/notes")
def list_notes(u=Depends(current_user)):
    rows = db.execute("SELECT * FROM notes WHERE owner=? ORDER BY updated DESC", (u["id"],))
    return [dict(r) for r in rows]


@app.post("/api/notes")
def create_note(n: NoteIn, u=Depends(current_user)):
    m = cfg()["max_notes_per_user"]
    if m and db.execute("SELECT COUNT(*) FROM notes WHERE owner=?", (u["id"],)).fetchone()[0] >= m:
        raise HTTPException(400, "Osiągnięto limit notatek")
    cur = db.execute("INSERT INTO notes(owner,title,body,updated) VALUES(?,?,?,?)",
                     (u["id"], n.title, n.body, time.time()))
    db.commit()
    return {"id": cur.lastrowid}


@app.put("/api/notes/{nid}")
def update_note(nid: int, n: NoteIn, u=Depends(current_user)):
    cur = db.execute("UPDATE notes SET title=?,body=?,updated=? WHERE id=? AND owner=?",
                     (n.title, n.body, time.time(), nid, u["id"]))
    db.commit()
    if not cur.rowcount:
        raise HTTPException(404, "Nie znaleziono notatki")
    return {"ok": True}


@app.delete("/api/notes/{nid}")
def delete_note(nid: int, u=Depends(current_user)):
    db.execute("DELETE FROM notes WHERE id=? AND owner=?", (nid, u["id"]))
    db.commit()
    return {"ok": True}


# ---------- admin ----------
@app.get("/api/admin/stats")
def stats(_=Depends(admin_user)):
    q = lambda s: db.execute(s).fetchone()[0]
    return {"users": q("SELECT COUNT(*) FROM users"), "files": q("SELECT COUNT(*) FROM files"),
            "notes": q("SELECT COUNT(*) FROM notes"),
            "bytes": q("SELECT COALESCE(SUM(size),0) FROM files WHERE backend!='drive'"),
            "disk_free": shutil.disk_usage(DATA).free}


@app.get("/api/admin/users")
def users(_=Depends(admin_user)):
    return [public(u) for u in db.execute("SELECT * FROM users ORDER BY id")]


@app.post("/api/admin/users")
def admin_create(b: Creds, _=Depends(admin_user)):
    return {"id": make_user(b.username, b.password)}


@app.patch("/api/admin/users/{uid}")
def admin_patch(uid: int, p: UserPatch, a=Depends(admin_user)):
    if uid == a["id"] and (p.is_admin is False or p.is_active is False):
        raise HTTPException(400, "Nie możesz odebrać sobie uprawnień ani zablokować własnego konta")
    for col, val in (("is_admin", p.is_admin), ("is_active", p.is_active), ("quota_mb", p.quota_mb)):
        if val is not None:
            db.execute(f"UPDATE users SET {col}=? WHERE id=?", (int(val), uid))
    if p.password:
        if len(p.password) < cfg()["min_password_length"]:
            raise HTTPException(400, "Hasło jest za krótkie")
        db.execute("UPDATE users SET pw=? WHERE id=?", (hash_pw(p.password), uid))
    db.commit()
    return {"ok": True}


@app.delete("/api/admin/users/{uid}")
def admin_delete(uid: int, a=Depends(admin_user)):
    if uid == a["id"]:
        raise HTTPException(400, "Nie możesz usunąć własnego konta")
    for r in db.execute("SELECT drive_id FROM files WHERE owner=? AND backend='drive'", (uid,)):
        try:
            drive_delete(uid, r["drive_id"])  # best effort – nie blokuj usuwania konta, gdy Google nie odpowiada
        except Exception:
            pass
    shutil.rmtree(FILES / str(uid), ignore_errors=True)
    for t, col in (("files", "owner"), ("notes", "owner"), ("google_links", "user_id"), ("users", "id")):
        db.execute(f"DELETE FROM {t} WHERE {col}=?", (uid,))
    db.commit()
    return {"ok": True}


@app.get("/api/admin/settings")
def get_settings(_=Depends(admin_user)):
    return cfg()


@app.put("/api/admin/settings")
def put_settings(new: dict, _=Depends(admin_user)):
    for k, v in new.items():
        if k not in DEFAULT_SETTINGS:
            raise HTTPException(400, f"Nieznane ustawienie: {k}")
        t = type(DEFAULT_SETTINGS[k])
        try:
            v = bool(v) if t is bool else t(v)
        except (TypeError, ValueError):
            raise HTTPException(400, f"Nieprawidłowa wartość: {k}")
        db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (k, "1" if v is True else "0" if v is False else str(v)))
    db.commit()
    return cfg()


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
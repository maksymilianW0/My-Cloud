"""SelfCloud – self-hosted storage for files and notes (FastAPI + SQLite)."""
import hashlib, hmac, os, secrets, shutil, sqlite3, threading, time, uuid
from pathlib import Path
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import uvicorn


from dotenv import load_dotenv

load_dotenv()


DATA = Path(os.getenv("DATA_DIR", "data"))
FILES = DATA / "files"
FILES.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "selfcloud.db"
KEY_PATH = DATA / "secret.key"
if not KEY_PATH.exists():
    KEY_PATH.write_text(secrets.token_hex(32))
SECRET = KEY_PATH.read_text()

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
""")


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
    return db.execute("SELECT COALESCE(SUM(size),0) FROM files WHERE owner=?", (uid,)).fetchone()[0]


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


app = FastAPI(title="SelfCloud")


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


# ---------- files ----------
@app.get("/api/files")
def list_files(u=Depends(current_user)):
    rows = db.execute("SELECT id,name,size,created FROM files WHERE owner=? ORDER BY created DESC", (u["id"],))
    return [dict(r) for r in rows]


@app.post("/api/files")
async def upload(f: UploadFile = File(...), u=Depends(current_user)):
    c = cfg()
    name = Path(f.filename or "plik").name
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    allowed, blocked = ext_list(c["allowed_extensions"]), ext_list(c["blocked_extensions"])
    if ext in blocked or (allowed and ext not in allowed):
        raise HTTPException(400, f"Typ pliku „.{ext}” jest niedozwolony")
    fid = uuid.uuid4().hex
    folder = FILES / str(u["id"])
    folder.mkdir(exist_ok=True)
    path, size = folder / fid, 0
    limit = c["max_upload_mb"] * 1024 * 1024
    quota = (u["quota_mb"] or 0) * 1024 * 1024
    before = used_bytes(u["id"])
    with open(path, "wb") as out:
        while chunk := await f.read(1024 * 1024):
            size += len(chunk)
            if limit and size > limit or quota and before + size > quota:
                out.close(); path.unlink(missing_ok=True)
                raise HTTPException(413, "Plik jest za duży lub przekroczono limit miejsca")
            out.write(chunk)
    db.execute("INSERT INTO files VALUES(?,?,?,?,?)", (fid, u["id"], name, size, time.time()))
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
    own_file(fid, u)
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
            "notes": q("SELECT COUNT(*) FROM notes"), "bytes": q("SELECT COALESCE(SUM(size),0) FROM files"),
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
    shutil.rmtree(FILES / str(uid), ignore_errors=True)
    for t, col in (("files", "owner"), ("notes", "owner"), ("users", "id")):
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

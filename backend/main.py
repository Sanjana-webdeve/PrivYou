"""PrivYou API. The server only ever stores ciphertext + wrapped keys; plaintext never reaches it."""
import os, hmac, hashlib, secrets, smtplib, uuid, datetime as dt
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, String, Text, ForeignKey, DateTime, Boolean, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, defer
from dotenv import load_dotenv
load_dotenv()

DB_URL = os.getenv("DATABASE_URL", "sqlite:///privyou.db")
SECRET = os.getenv("SERVER_SECRET", "change-me").encode()
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
now = lambda: dt.datetime.utcnow()
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    nick: Mapped[str] = mapped_column(String(40))
    nick_key: Mapped[str] = mapped_column(String(40), unique=True)  # lowercase -> case-insensitive uniqueness
    email: Mapped[str] = mapped_column(String(254), index=True)
    auth_salt: Mapped[str] = mapped_column(String(64))
    auth_hash: Mapped[str] = mapped_column(String(128))   # scrypt of a client-derived secret, never the password
    kek_salt: Mapped[str] = mapped_column(String(64))
    wrapped_pw: Mapped[str] = mapped_column(Text)         # master key encrypted by password-derived key
    wrapped_rk: Mapped[str] = mapped_column(Text)         # master key encrypted by recovery key
class Token(Base):  # sessions and reset links
    __tablename__ = "tokens"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires: Mapped[dt.datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
class Notebook(Base):
    __tablename__ = "notebooks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    enc_title: Mapped[str] = mapped_column(Text)
    enc_content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class Recording(Base):  # voice note: audio, transcript and metadata are all client-side encrypted
    __tablename__ = "recordings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    notebook_id: Mapped[str] = mapped_column(ForeignKey("notebooks.id", ondelete="CASCADE"), index=True)
    enc_audio: Mapped[str] = mapped_column(Text)
    enc_meta: Mapped[str] = mapped_column(Text)        # mime type + duration
    enc_transcript: Mapped[str] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class VaultMeta(Base):  # one encrypted blob per user: moods, tags, pins
    __tablename__ = "vault_meta"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enc_data: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
Base.metadata.create_all(engine)

app = FastAPI(title="PrivYou")
def db():
    with SessionLocal() as s: yield s

def scrypt(secret: str, salt: str) -> str:
    return hashlib.scrypt(secret.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
def issue(s: Session, uid: int, kind: str, minutes: int) -> str:
    raw = secrets.token_urlsafe(32)
    s.add(Token(hash=sha(raw), kind=kind, user_id=uid, expires=now() + dt.timedelta(minutes=minutes)))
    s.commit(); return raw
def me(authorization: str = Header(""), s: Session = Depends(db)) -> User:
    t = s.get(Token, sha(authorization.removeprefix("Bearer ")))
    if not t or t.kind != "session" or t.expires < now(): raise HTTPException(401, "Please log in again.")
    return s.get(User, t.user_id)

class Keys(BaseModel):
    auth_salt: str; auth_secret: str; kek_salt: str; wrapped_pw: str; wrapped_rk: str
class Register(Keys):
    nick: str; email: EmailStr
class Login(BaseModel):
    nick: str; auth_secret: str
class NB(BaseModel):
    enc_title: str; enc_content: str
class Rec(BaseModel):
    enc_audio: str; enc_meta: str; enc_transcript: str
class Meta(BaseModel):
    enc_data: str
class Reset(Keys):
    token: str; wipe: bool = False

def session_payload(s, u):
    return {"token": issue(s, u.id, "session", 60 * 8), "nick": u.nick, "kek_salt": u.kek_salt, "wrapped_pw": u.wrapped_pw}

@app.get("/api/salt/{nick}")
def salt(nick: str, s: Session = Depends(db)):
    u = s.scalar(select(User).where(User.nick_key == nick.strip().lower()))
    # Unknown nicknames get a stable fake salt so login can't be used to probe accounts.
    return {"auth_salt": u.auth_salt if u else hmac.new(SECRET, nick.lower().encode(), "sha256").hexdigest()[:32]}

@app.post("/api/register")
def register(b: Register, s: Session = Depends(db)):
    key = b.nick.strip().lower()
    if not (2 <= len(key) <= 40): raise HTTPException(422, "Nickname must be 2-40 characters.")
    if s.scalar(select(User).where(User.nick_key == key)):
        raise HTTPException(409, "This nickname is taken. Please register with a different nickname.")
    u = User(nick=b.nick.strip(), nick_key=key, email=b.email.lower(), auth_salt=b.auth_salt,
             auth_hash=scrypt(b.auth_secret, b.auth_salt), kek_salt=b.kek_salt, wrapped_pw=b.wrapped_pw, wrapped_rk=b.wrapped_rk)
    s.add(u); s.commit()
    return session_payload(s, u)

@app.post("/api/login")
def login(b: Login, s: Session = Depends(db)):
    u = s.scalar(select(User).where(User.nick_key == b.nick.strip().lower()))
    if not u or not hmac.compare_digest(u.auth_hash, scrypt(b.auth_secret, u.auth_salt)):
        raise HTTPException(401, "Nickname or password is incorrect.")
    return session_payload(s, u)

def send_mail(to: str, link: str):
    msg = EmailMessage(); msg["Subject"] = "Reset your PrivYou password"
    msg["From"] = os.getenv("SMTP_FROM", "PrivYou <no-reply@privyou.local>"); msg["To"] = to
    msg.set_content(f"Open this link to choose a new password (valid 15 minutes):\n{link}\n\nIf you didn't ask for this, ignore this email.")
    host = os.getenv("SMTP_HOST")
    if not host: print(f"[DEV] reset link for {to}: {link}", flush=True); return
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", 587))) as c:
        c.starttls(); c.login(os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASS", "")); c.send_message(msg)

@app.post("/api/forgot")
def forgot(body: dict, s: Session = Depends(db)):
    for u in s.scalars(select(User).where(User.email == str(body.get("email", "")).lower())):
        send_mail(u.email, f"{BASE_URL}/#reset={issue(s, u.id, 'reset', 15)}")
    return {"ok": True}  # same answer whether or not the email exists

def reset_token(s, raw):
    t = s.get(Token, sha(raw))
    if not t or t.kind != "reset" or t.used or t.expires < now(): raise HTTPException(410, "This reset link has expired. Request a new one.")
    return t
@app.get("/api/reset/{raw}")
def reset_info(raw: str, s: Session = Depends(db)):
    u = s.get(User, reset_token(s, raw).user_id)
    return {"nick": u.nick, "wrapped_rk": u.wrapped_rk}
@app.post("/api/reset")
def do_reset(b: Reset, s: Session = Depends(db)):
    t = reset_token(s, b.token); u = s.get(User, t.user_id)
    u.auth_salt, u.auth_hash = b.auth_salt, scrypt(b.auth_secret, b.auth_salt)
    u.kek_salt, u.wrapped_pw, u.wrapped_rk = b.kek_salt, b.wrapped_pw, b.wrapped_rk
    if b.wipe:  # no recovery key: old ciphertext is unreadable, so remove it
        m = s.get(VaultMeta, u.id)
        if m: s.delete(m)
        for r in s.scalars(select(Recording).where(Recording.user_id == u.id)): s.delete(r)
        for n in s.scalars(select(Notebook).where(Notebook.user_id == u.id)): s.delete(n)
    t.used = True
    for o in s.scalars(select(Token).where(Token.user_id == u.id, Token.kind == "session")): s.delete(o)
    s.commit(); return {"ok": True}

def out(n): return {"id": n.id, "enc_title": n.enc_title, "enc_content": n.enc_content,
                    "created_at": n.created_at.isoformat() + "Z", "updated_at": n.updated_at.isoformat() + "Z"}
def own(s, u, nid):
    n = s.get(Notebook, nid)
    if not n or n.user_id != u.id: raise HTTPException(404, "Notebook not found.")
    return n
@app.get("/api/notebooks")
def list_nb(u: User = Depends(me), s: Session = Depends(db)):
    return [out(n) for n in s.scalars(select(Notebook).where(Notebook.user_id == u.id).order_by(Notebook.created_at))]
@app.post("/api/notebooks")
def create_nb(b: NB, u: User = Depends(me), s: Session = Depends(db)):
    n = Notebook(user_id=u.id, enc_title=b.enc_title, enc_content=b.enc_content); s.add(n); s.commit(); return out(n)
@app.put("/api/notebooks/{nid}")
def update_nb(nid: str, b: NB, u: User = Depends(me), s: Session = Depends(db)):
    n = own(s, u, nid); n.enc_title, n.enc_content, n.updated_at = b.enc_title, b.enc_content, now(); s.commit(); return out(n)
@app.delete("/api/notebooks/{nid}")
def delete_nb(nid: str, u: User = Depends(me), s: Session = Depends(db)):
    n = own(s, u, nid)
    for r in s.scalars(select(Recording).where(Recording.notebook_id == nid)): s.delete(r)
    s.delete(n); s.commit(); return {"ok": True}

def rec_out(r): return {"id": r.id, "enc_meta": r.enc_meta, "enc_transcript": r.enc_transcript, "created_at": r.created_at.isoformat() + "Z"}
@app.get("/api/notebooks/{nid}/recordings")
def list_rec(nid: str, u: User = Depends(me), s: Session = Depends(db)):
    own(s, u, nid)
    q = select(Recording).where(Recording.notebook_id == nid).options(defer(Recording.enc_audio)).order_by(Recording.created_at)
    return [rec_out(r) for r in s.scalars(q)]
@app.post("/api/notebooks/{nid}/recordings")
def create_rec(nid: str, b: Rec, u: User = Depends(me), s: Session = Depends(db)):
    own(s, u, nid)
    if len(b.enc_audio) > 20_000_000: raise HTTPException(413, "This recording is too long. Keep voice notes under about 10 minutes.")
    r = Recording(user_id=u.id, notebook_id=nid, enc_audio=b.enc_audio, enc_meta=b.enc_meta, enc_transcript=b.enc_transcript)
    s.add(r); s.commit(); return rec_out(r)
def own_rec(s, u, rid):
    r = s.get(Recording, rid)
    if not r or r.user_id != u.id: raise HTTPException(404, "Recording not found.")
    return r
@app.get("/api/recordings/{rid}")
def get_rec(rid: str, u: User = Depends(me), s: Session = Depends(db)):
    return {"enc_audio": own_rec(s, u, rid).enc_audio}
@app.delete("/api/recordings/{rid}")
def delete_rec(rid: str, u: User = Depends(me), s: Session = Depends(db)):
    s.delete(own_rec(s, u, rid)); s.commit(); return {"ok": True}

@app.get("/api/meta")
def get_meta(u: User = Depends(me), s: Session = Depends(db)):
    m = s.get(VaultMeta, u.id)
    return {"enc_data": m.enc_data if m else None}
@app.put("/api/meta")
def put_meta(b: Meta, u: User = Depends(me), s: Session = Depends(db)):
    if len(b.enc_data) > 2_000_000: raise HTTPException(413, "Too much data.")
    m = s.get(VaultMeta, u.id)
    if m: m.enc_data, m.updated_at = b.enc_data, now()
    else: s.add(VaultMeta(user_id=u.id, enc_data=b.enc_data))
    s.commit(); return {"ok": True}

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True))
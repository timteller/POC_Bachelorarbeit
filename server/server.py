"""
FastAPI-API
• Challenge-Response-Auth (Ed25519 + JWT)
• Dynamische Schlüssel-Synchronisation (Verzeichnis-Scan)
• Artefakt-Speicherung (Hash + Signatur)
• Client-Metadaten (name, fingerprint, revoked)
"""

import os, secrets, base64, datetime as dt, jwt
from typing import Set
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import (create_engine, Column, Integer, String, LargeBinary,
                        Boolean, DateTime, ForeignKey, UniqueConstraint)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------- Konfiguration ----------
DATABASE_URL = "sqlite:///./app.db"
KEY_DIR = "trusted_keys"                            # *.pem
JWT_SECRET = os.getenv("JWT_SECRET", "change_me")   # sofort setzen!
JWT_TTL = 3600                              # Sekunden
CHALLENGE_TTL = 300                         # Sekunden

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()
security = HTTPBearer()
app = FastAPI()
KEY_MTIME: float = 0.0                      # globale letzte Schlüssel-Änderung

# ---------- Datenbankmodelle ----------
class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    fingerprint = Column(String(64), unique=True, index=True)
    pubkey_pem = Column(LargeBinary, nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

class Challenge(Base):
    __tablename__ = "challenges"
    nonce = Column(String(64), primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"))
    expires_at = Column(DateTime)

class Artifact(Base):
    __tablename__ = "artifacts"
    id = Column(Integer, primary_key=True)
    file_hash = Column(String(64))
    signature = Column(LargeBinary)
    client_id = Column(Integer, ForeignKey("clients.id"))
    uploaded_at = Column(DateTime, default=dt.datetime.utcnow)
    __table_args__ = (
        UniqueConstraint("file_hash", "client_id", name="uniq_artifact"),
    )

Base.metadata.create_all(bind=engine)

# ---------- Utility ----------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _dir_mtime() -> float:
    try:
        return max(os.path.getmtime(os.path.join(KEY_DIR, f))
                   for f in os.listdir(KEY_DIR) if f.endswith(".pem"))
    except ValueError:
        return 0.0

def _fingerprint(pem: bytes) -> str:
    h = hashes.Hash(hashes.SHA256()); h.update(pem)
    return h.finalize().hex()

def sync_keys(db: Session) -> None:
    global KEY_MTIME
    current_files = [f for f in os.listdir(KEY_DIR) if f.endswith(".pem")]
    current_fp: Set[str] = set()
    for fn in current_files:
        pem = open(os.path.join(KEY_DIR, fn), "rb").read()
        fp = _fingerprint(pem); current_fp.add(fp)
        client = db.query(Client).filter_by(fingerprint=fp).first()
        name = os.path.splitext(fn)[0]
        if client:
            if client.revoked or client.name != name:
                client.revoked = False; client.name = name; client.pubkey_pem = pem
        else:
            db.add(Client(name=name, fingerprint=fp, pubkey_pem=pem))
    # mark entfernte Schlüssel als revoked
    for client in db.query(Client).filter_by(revoked=False).all():
        if client.fingerprint not in current_fp:
            client.revoked = True
    db.commit()
    KEY_MTIME = _dir_mtime()

def ensure_keys_fresh(db: Session) -> None:
    if _dir_mtime() > KEY_MTIME:
        sync_keys(db)

def get_pubkey(client: Client) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(client.pubkey_pem)

def issue_token(fingerprint: str) -> str:
    payload = {"sub": fingerprint,
               "exp": dt.datetime.utcnow() + dt.timedelta(seconds=JWT_TTL)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> str:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# ---------- Schemas ----------
class ChallengeRequest(BaseModel):
    fingerprint: str

class VerifyRequest(BaseModel):
    fingerprint: str
    challenge: str
    signature: str               # Base64

class ArtifactCreate(BaseModel):
    file_hash: str               # SHA-256 hex
    signature: str               # Base64

# ---------- Startup ----------
@app.on_event("startup")
def _startup() -> None:
    os.makedirs(KEY_DIR, exist_ok=True)
    with SessionLocal() as db:
        sync_keys(db)

# ---------- Auth ----------
@app.post("/auth/challenge")
def create_challenge(body: ChallengeRequest, db: Session = Depends(get_db)):
    ensure_keys_fresh(db)
    client = db.query(Client).filter_by(fingerprint=body.fingerprint, revoked=False).first()
    if not client:
        raise HTTPException(404, "Fingerprint unknown or revoked")
    nonce = secrets.token_hex(32)
    expires = dt.datetime.utcnow() + dt.timedelta(seconds=CHALLENGE_TTL)
    db.add(Challenge(nonce=nonce, client_id=client.id, expires_at=expires))
    db.commit()
    return {"nonce": nonce, "expires_at": expires.isoformat() + "Z"}

@app.post("/auth/verify")
def verify_challenge(body: VerifyRequest, db: Session = Depends(get_db)):
    ensure_keys_fresh(db)
    chal = db.get(Challenge, body.challenge)
    if not chal or chal.expires_at < dt.datetime.utcnow():
        raise HTTPException(400, "Challenge expired/invalid")
    client = db.get(Client, chal.client_id)
    if client.fingerprint != body.fingerprint or client.revoked:
        raise HTTPException(400, "Client mismatch")
    try:
        get_pubkey(client).verify(base64.b64decode(body.signature),
                                   bytes.fromhex(body.challenge))
    except Exception:
        raise HTTPException(401, "Signature verification failed")
    db.delete(chal); db.commit()
    return {"token": issue_token(client.fingerprint)}

# ---------- Abhängigkeit ----------
def current_client(
    cred: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> Client:
    fp = verify_token(cred.credentials)
    ensure_keys_fresh(db)
    client = db.query(Client).filter_by(fingerprint=fp, revoked=False).first()
    if not client:
        raise HTTPException(401, "Client revoked")
    return client

# ---------- Artefakte ----------
@app.post("/artifacts")
def upload_artifact(
    art: ArtifactCreate,
    client: Client = Depends(current_client),
    db: Session = Depends(get_db)
):
    db.add(
        Artifact(file_hash=art.file_hash.lower(),
                 signature=base64.b64decode(art.signature),
                 client_id=client.id)
    )
    db.commit()
    return {"status": "stored"}

@app.get("/artifacts/{file_hash}")
def list_signatures(file_hash: str, db: Session = Depends(get_db)):
    ensure_keys_fresh(db)
    rows = db.query(Artifact).filter_by(file_hash=file_hash.lower()).all()
    return [
        {
            "signature": base64.b64encode(r.signature).decode(),
            "client_fingerprint": db.get(Client, r.client_id).fingerprint,
            "client_name": db.get(Client, r.client_id).name,
            "uploaded_at": r.uploaded_at.isoformat() + "Z",
        } for r in rows
    ]

# ---------- Schlüssel-API ----------
@app.get("/keys/{fingerprint}")
def get_key(fingerprint: str, db: Session = Depends(get_db)):
    ensure_keys_fresh(db)
    client = db.query(Client).filter_by(fingerprint=fingerprint, revoked=False).first()
    if not client:
        raise HTTPException(404, "Key not found")
    return {"name": client.name, "public_key_pem": client.pubkey_pem.decode()}

@app.post("/keys/refresh")
def manual_refresh(db: Session = Depends(get_db)):
    """Manuelles Directory-Sync-Triggern (kein App-Restart nötig)."""
    sync_keys(db)
    return {"status": "refreshed", "mtime": KEY_MTIME}

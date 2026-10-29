import base64
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .config import DEMO_MODE, JWT_SECRET
from .db import AuditLog, SessionLocal, User, VaultItem, init_db
from .kms_fake import kms

app = FastAPI(title="Lockbox demo")
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
IP_FAILS: dict[str, tuple[int, datetime | None]] = {}
LOCK_MINUTES = 5

class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    salt_b64: str = Field(min_length=16, max_length=128)
    auth_key_b64: str = Field(min_length=40, max_length=128)
class LoginIn(BaseModel):
    email: str
    auth_key_b64: str
class ItemIn(BaseModel):
    ciphertext: str = Field(min_length=1)
    iv_b64: str = Field(min_length=16, max_length=64)
    label: str = Field(default="Mục đã mã hóa", max_length=120)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()
def client_ip(request: Request): return request.client.host if request.client else "unknown"
def audit(db, event, request, user_id=None, detail=""):
    # Không truyền password, master key, encryption key hay plaintext vault vào đây.
    db.add(AuditLog(user_id=user_id, event=event, detail=detail[:255], ip=client_ip(request)))
def token_for(user):
    return jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=15)}, JWT_SECRET, algorithm="HS256")
def current_user(request: Request, db: Session = Depends(get_db)):
    raw = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try: payload = jwt.decode(raw, JWT_SECRET, algorithms=["HS256"]); user_id = int(payload["sub"])
    except Exception: raise HTTPException(401, "Token không hợp lệ hoặc đã hết hạn")
    user = db.get(User, user_id)
    if not user: raise HTTPException(401, "Không tìm thấy người dùng")
    return user
def locked(ip: str):
    count, until = IP_FAILS.get(ip, (0, None))
    return until and until > datetime.utcnow()
def record_ip_failure(ip: str):
    count, until = IP_FAILS.get(ip, (0, None)); count += 1
    IP_FAILS[ip] = (count, datetime.utcnow() + timedelta(minutes=LOCK_MINUTES) if count >= 5 else until)
def clear_ip(ip: str): IP_FAILS.pop(ip, None)
def hash_auth_key(auth_key_b64: str) -> str:
    """Bcrypt hóa auth key đã dẫn xuất; server vẫn không hề nhận master password."""
    return bcrypt.hashpw(auth_key_b64.encode("ascii"), bcrypt.gensalt()).decode("ascii")
def verify_auth_key(auth_key_b64: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(auth_key_b64.encode("ascii"), stored_hash.encode("ascii"))

@app.on_event("startup")
def startup():
    init_db()
    # Migration tối thiểu cho DB demo cũ; production dùng Alembic migration.
    from .db import engine
    with engine.begin() as conn:
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(users)"))}
        if "kms_key_version" not in columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN kms_key_version INTEGER NOT NULL DEFAULT 1"))

@app.post("/api/register")
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(409, "Email đã tồn tại")
    try:
        base64.b64decode(body.salt_b64, validate=True); base64.b64decode(body.auth_key_b64, validate=True)
    except Exception: raise HTTPException(400, "Dữ liệu Base64 không hợp lệ")
    # Data key này chỉ phục vụ minh họa KMS; không phải khóa mã hóa vault zero-knowledge.
    wrapped, iv = kms.wrap(os.urandom(32))
    user = User(email=email, salt_b64=body.salt_b64, auth_key_hash=hash_auth_key(body.auth_key_b64), wrapped_data_key=wrapped, data_key_iv=iv)
    db.add(user); db.flush(); audit(db, "REGISTER", request, user.id, "Đăng ký tài khoản"); db.commit()
    return {"token": token_for(user), "expires_in": 900}

@app.get("/api/auth/salt")
def salt(email: str, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if not user: raise HTTPException(404, "Tài khoản không tồn tại")
    return {"salt_b64": user.salt_b64}

@app.post("/api/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip, now = client_ip(request), datetime.utcnow()
    user = db.scalar(select(User).where(User.email == body.email.lower().strip()))
    if locked(ip) or (user and user.locked_until and user.locked_until > now):
        audit(db, "LOGIN_BLOCKED", request, user.id if user else None, "Rate limit/account lock"); db.commit()
        raise HTTPException(429, f"Tạm khóa {LOCK_MINUTES} phút do quá nhiều lần đăng nhập sai")
    if not user or not verify_auth_key(body.auth_key_b64, user.auth_key_hash):
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= 5: user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
        record_ip_failure(ip); audit(db, "LOGIN_FAILED", request, user.id if user else None, "Sai auth key")
        db.commit(); raise HTTPException(401, "Thông tin đăng nhập không đúng")
    user.failed_attempts, user.locked_until = 0, None; clear_ip(ip)
    audit(db, "LOGIN_SUCCESS", request, user.id, "Đăng nhập thành công"); db.commit()
    return {"token": token_for(user), "expires_in": 900}

@app.get("/api/items")
def list_items(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    items = db.scalars(select(VaultItem).where(VaultItem.user_id == user.id).order_by(VaultItem.updated_at.desc())).all()
    audit(db, "VAULT_VIEW", request, user.id, f"Xem {len(items)} metadata mục"); db.commit()
    return [{"id": x.id, "ciphertext": x.ciphertext, "iv_b64": x.iv_b64, "label": x.label, "updated_at": x.updated_at.isoformat()} for x in items]
@app.post("/api/items")
def create_item(body: ItemIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = VaultItem(user_id=user.id, **body.model_dump()); db.add(item); db.flush(); audit(db, "VAULT_CREATE", request, user.id, f"Tạo item id={item.id}"); db.commit()
    return {"id": item.id}
@app.put("/api/items/{item_id}")
def update_item(item_id: int, body: ItemIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(VaultItem, item_id)
    if not item or item.user_id != user.id: raise HTTPException(404, "Không tìm thấy mục")
    item.ciphertext, item.iv_b64, item.label = body.ciphertext, body.iv_b64, body.label
    audit(db, "VAULT_UPDATE", request, user.id, f"Sửa item id={item_id}"); db.commit(); return {"ok": True}
@app.delete("/api/items/{item_id}")
def delete_item(item_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    item = db.get(VaultItem, item_id)
    if not item or item.user_id != user.id: raise HTTPException(404, "Không tìm thấy mục")
    db.delete(item); audit(db, "VAULT_DELETE", request, user.id, f"Xóa item id={item_id}"); db.commit(); return {"ok": True}

@app.get("/api/audit")
def audit_log(user: User = Depends(current_user), db: Session = Depends(get_db)):
    logs = db.scalars(select(AuditLog).where((AuditLog.user_id == user.id) | (AuditLog.user_id.is_(None))).order_by(AuditLog.created_at.desc()).limit(100)).all()
    return [{"time": x.created_at.isoformat(timespec="seconds"), "event": x.event, "detail": x.detail, "ip": x.ip} for x in logs]
@app.post("/api/kms/rotate")
def rotate_kms(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    version = kms.rotate_and_rewrap(db.scalars(select(User)).all())
    audit(db, "KMS_ROTATE", request, user.id, f"Re-wrap data keys, version={version}"); db.commit()
    return {"ok": True, "version": version, "note": "KMS demo data key đã được re-wrap; vault client-side không bị ảnh hưởng."}
@app.get("/api/demo/db-leak")
def db_leak(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not DEMO_MODE: raise HTTPException(404, "Chỉ bật khi DEMO_MODE=true")
    rows = db.scalars(select(VaultItem).where(VaultItem.user_id == user.id)).all()
    return {"warning": "DEMO MODE — dữ liệu thô mô phỏng DB bị lộ", "rows": [{"id": x.id, "user_id": x.user_id, "ciphertext": x.ciphertext, "iv_b64": x.iv_b64, "label": x.label} for x in rows]}

app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
@app.get("/")
def home(): return FileResponse(FRONTEND / "index.html")

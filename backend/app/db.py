from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from .config import DATABASE_URL

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    auth_key_hash: Mapped[str] = mapped_column(String(255))  # bcrypt(auth key), không phải master password
    salt_b64: Mapped[str] = mapped_column(String(128))       # salt công khai cho Argon2id phía client
    wrapped_data_key: Mapped[bytes] = mapped_column(LargeBinary)
    data_key_iv: Mapped[bytes] = mapped_column(LargeBinary)
    kms_key_version: Mapped[int] = mapped_column(Integer, default=1)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    items: Mapped[list["VaultItem"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class VaultItem(Base):
    __tablename__ = "vault_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    ciphertext: Mapped[str] = mapped_column(Text)  # AES-GCM ciphertext từ browser; server không thể đọc
    iv_b64: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(120), default="Mục đã mã hóa")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user: Mapped[User] = relationship(back_populates="items")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    event: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(String(255), default="")  # tuyệt đối không ghi plaintext vault/password
    ip: Mapped[str] = mapped_column(String(64), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
def init_db(): Base.metadata.create_all(engine)


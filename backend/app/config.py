import base64
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./lockbox.db")
JWT_SECRET = os.getenv("JWT_SECRET", "")
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
try:
    KMS_MASTER_KEY = base64.b64decode(os.getenv("KMS_MASTER_KEY_B64", ""), validate=True)
except Exception as exc:
    raise RuntimeError("KMS_MASTER_KEY_B64 phải là Base64 hợp lệ") from exc
if not JWT_SECRET or len(KMS_MASTER_KEY) != 32:
    raise RuntimeError("Hãy tạo .env từ .env.example; JWT_SECRET và KMS_MASTER_KEY_B64 là bắt buộc.")


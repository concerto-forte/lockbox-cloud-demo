"""Mô phỏng envelope encryption: thay bằng AWS KMS/Google Cloud KMS ở production."""
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import KMS_MASTER_KEY

class FakeKMS:
    def __init__(self):
        self.root_key, self.version = KMS_MASTER_KEY, 1

    def key_for_version(self, version: int) -> bytes:
        # Root key luôn từ biến môi trường. Version > 1 mô phỏng các CMK version của KMS cloud.
        # Nhờ vậy demo vẫn có thể mở data key sau khi restart process.
        if version == 1:
            return self.root_key
        return hmac.new(self.root_key, f"lockbox-fake-kms-v{version}".encode(), hashlib.sha256).digest()

    def wrap(self, data_key: bytes, version: int = 1) -> tuple[bytes, bytes]:
        iv = os.urandom(12)  # IV AES-GCM mới cho mỗi lần bọc
        return AESGCM(self.key_for_version(version)).encrypt(iv, data_key, None), iv
    def rotate_and_rewrap(self, users) -> int:
        """Mô phỏng RotateKey + ReEncrypt; production giao việc này cho KMS cloud."""
        # DB là nguồn sự thật của version: restart process không làm lặp lại version cũ.
        users = list(users)
        new_version = max([self.version, *(user.kms_key_version for user in users)]) + 1
        updated = 0
        for user in users:
            # KMS thật giữ key version cũ; Fake KMS dẫn xuất lại chúng từ root key trong .env.
            data_key = AESGCM(self.key_for_version(user.kms_key_version)).decrypt(user.data_key_iv, user.wrapped_data_key, None)
            iv = os.urandom(12)
            user.wrapped_data_key = AESGCM(self.key_for_version(new_version)).encrypt(iv, data_key, None)
            user.data_key_iv, user.kms_key_version = iv, new_version
            updated += 1
        self.version = new_version
        return self.version

kms = FakeKMS()

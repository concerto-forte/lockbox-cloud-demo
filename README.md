# Lockbox — zero-knowledge password manager demo

Demo học tập cho môn Điện toán đám mây. Note to self: CẤM ÁP DỤNG THỰC TIỄN, ĐÃ XONG ĐÂU...

## Kiến trúc ngắn gọn

```text
Browser: Argon2id → HKDF(auth key, encryption key) → AES-256-GCM ciphertext
                  │ auth key (không phải master password)
                  ▼
FastAPI: bcrypt(auth key) + JWT + SQLite(ciphertext, IV, metadata chung chung)
                  │
                  ▼
Fake KMS: master key từ biến môi trường → bọc data key mô phỏng của mỗi user
```

`encryption key` không rời trình duyệt và không được lưu. Data key của Fake KMS được **tách riêng** khỏi khóa mã hóa vault: nó minh họa envelope encryption và thao tác re-wrap mà không làm mất tính zero-knowledge. Trong cloud thật, module này sẽ gọi AWS KMS hoặc Google Cloud KMS.

## Cài và chạy

Yêu cầu Python 3.10+ và trình duyệt hiện đại. Trong PowerShell tại thư mục `lockbox`:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
py -3.12 -m pip install -r backend\requirements.txt
Copy-Item .env.example .env
```

Mở `.env`, thay hai giá trị placeholder bằng secret thực:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```

Gán kết quả thứ nhất cho `JWT_SECRET`, thứ hai cho `KMS_MASTER_KEY_B64`. Giữ `DEMO_MODE=true`, sau đó chạy:

```powershell
uvicorn app.main:app --app-dir backend --reload --port 8080
```

Mở `http://127.0.0.1:8080`. Lần đầu tải trang cần Internet để CDN tải `hash-wasm`; có thể vendoring thư viện này nếu cần demo offline.



1. Đăng ký một tài khoản mới. Nhấn mạnh master password không gửi lên server: browser chạy Argon2id (64 MiB, 3 iterations), rồi HKDF tách auth/encryption key.
2. Thêm hai mục vào Vault. Giải thích mỗi mục được mã hóa AES-256-GCM phía client với IV 12-byte mới.
3. Nhấn **DB leak view**. Chỉ thấy Base64 ciphertext, IV và nhãn chung chung `Mục đã mã hóa`, không có site/username/password/note. Endpoint này chỉ tồn tại khi `DEMO_MODE=true`.
4. (Giữ nguyên tab đang đăng nhập để còn xem audit log.) Đăng nhập sai 5 lần từ một tab/phiên khác, hoặc refresh tab rồi nhập sai 5 lần. Lần thứ 6 hiển thị khóa tạm 5 phút; đây mô phỏng WAF/rate limit edge và account lock.
5. Trong tab đăng nhập ban đầu, nhấn **Audit log**. Chỉ ra `LOGIN_SUCCESS`, `LOGIN_FAILED`, các sự kiện Vault; audit log không ghi plaintext.
6. Nhấn **Rotate KMS master key**, rồi **Tải lại** Vault. Vault vẫn giải mã bình thường vì content encryption key ở client không đổi, còn Fake KMS đã re-wrap các data key mô phỏng.

## Lưu ý bảo mật và giới hạn demo

- Không commit `.env` hoặc `lockbox.db`.
- JWT có hạn 15 phút. Rate limit in-memory được chủ ý đơn giản; production cần Redis/WAF phân tán.
- Fake KMS dẫn xuất các version wrapping key từ root key trong `.env`, để mô phỏng key versioning qua restart. Production vẫn cần KMS thật, IAM, rotation và audit bền vững.
- HTTPS, CSP, secure cookie/token storage, CSRF/XSS hardening, MFA/TOTP, recovery flow và backup chưa thuộc phạm vi demo này.

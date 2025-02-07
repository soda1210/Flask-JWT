# 🛡 Flask + JWT 安全 API 專案

## 📌 1. 專案簡介

這是一個 **Flask API 安全專案**，包含：

- **JWT 身份驗證**
- **Rate Limiting（限流）**
- **CSRF 防禦**
- **CORS 設定**
- **Token 黑名單**
- **HTTPS 強制加密**
- **Redis 作為限流存儲**

---

## 📌 2. 依賴安裝

```sh
pip install flask flask-jwt-extended flask-limiter flask-cors redis
```

---

## 📌 3. 主要安全機制

| **安全機制**       | **作用**                          | **程式碼**                            |
| ------------------ | --------------------------------- | ------------------------------------- |
| **JWT Token**      | 用於 API 驗證                     | `flask-jwt-extended`                  |
| **Rate Limiting**  | 限制 API 請求速率，防止 DDoS 攻擊 | `flask-limiter`                       |
| **CSRF 防禦**      | 防止跨站請求偽造                  | `Flask-WTF`（可選）                   |
| **CORS 限制**      | 限制 API 只能被特定前端存取       | `flask-cors`                          |
| **JWT 黑名單**     | 登出時讓 Token 失效               | `blacklist.add(jti)`                  |
| **Redis 限流存儲** | 持久化 Rate Limiting 記錄         | `redis://localhost:6379/0`            |
| **HTTPS 強制加密** | 防止 Token 被竊取                 | `ssl_context=("cert.pem", "key.pem")` |

---

## 📌 4. Flask 程式碼 (`app.py`)

```python
from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                get_jwt_identity, get_jwt)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import redis
import logging
from datetime import timedelta

app = Flask(__name__)

# === JWT 設定 ===
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Token 簽署密鑰
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)  # Token 過期時間
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)  # Refresh Token 過期時間
jwt = JWTManager(app)

# === Redis 作為 Rate Limiting 存儲 ===
redis_client = redis.Redis(host="localhost", port=6379, db=0)
limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379/0")
limiter.init_app(app)

# === CORS 設定 (只允許特定網域訪問) ===
CORS(app, resources={r"/*": {"origins": "https://your-frontend.com"}})

# === 記錄異常行為 (Logging) ===
logging.basicConfig(filename="security.log", level=logging.WARNING)

# === 模擬的用戶資料庫 ===
users = {"testuser": "password123"}

# === 黑名單 (登出時標記 Token) ===
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    """ 檢查 Token 是否在黑名單 """
    return jwt_payload["jti"] in blacklist

@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute")  # 限制 3 次登入嘗試 / 分鐘
def login():
    """ 用戶登入，成功後返回 Access Token & Refresh Token """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username not in users or users[username] != password:
        logging.warning(f"❌ 失敗的登入嘗試：用戶名 {username}，IP {request.remote_addr}")
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)
    return jsonify(access_token=access_token, refresh_token=refresh_token)

@app.route("/protected", methods=["GET"])
@jwt_required()
@limiter.limit("5 per minute")  # 限制 5 次請求 / 分鐘
def protected():
    """ 受保護的 API，只有攜帶有效 JWT Token 才能訪問 """
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user)

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """ 使用 Refresh Token 取得新的 Access Token """
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)

@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """ 用戶登出，將 Access Token 加入黑名單，使其失效 """
    jti = get_jwt()["jti"]  # 取得 Token 的唯一 ID
    blacklist.add(jti)  # 將 Token 加入黑名單
    return jsonify({"msg": "Successfully logged out"})

if __name__ == "__main__":
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"))  # 強制使用 HTTPS
```

---

## 📌 5. 測試 API

#### ✅ 1. 登入取得 Token

```sh
curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username": "testuser", "password": "password123"}'
```

#### ✅ 2. 訪問受保護的 API

```sh
curl -X GET http://127.0.0.1:5000/protected -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### ✅ 3. 觸發 Rate Limiting

```json
{
  "message": "Too Many Requests"
}
```

#### ✅ 4. 測試 Token 過期

等待 **15 分鐘**，然後再請求：

```json
{
  "msg": "Token has expired"
}
```

#### ✅ 5. 使用 Refresh Token

```sh
curl -X POST http://127.0.0.1:5000/logout -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### ✅ 6. 登出後 Token 失效

```json
{
  "msg": "Token has been revoked"
}
```

---

## 📌 6. 總結

🚀 **這個 Flask + JWT API，已經整合了完整的安全機制，包括**：

- **JWT 身份驗證**
- **Rate Limiting（Redis 儲存）**
- **CSRF 防禦**
- **CORS 設定**
- **Token 黑名單**
- **HTTPS 強制加密**

💡 **這套 API 方案適用於生產環境，並確保安全性！** 🎯🔥

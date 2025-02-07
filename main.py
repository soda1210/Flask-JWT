from flask import Flask, jsonify, request
from flask_jwt_extended import (JWTManager, create_access_token,
                                create_refresh_token, jwt_required,
                                get_jwt_identity, get_jwt)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from datetime import timedelta
import logging

app = Flask(__name__)

# === JWT 設定 ===
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Token 簽署密鑰
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    minutes=15)  # Access Token 過期時間
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(
    days=7)  # Refresh Token 過期時間
app.config["JWT_BLACKLIST_ENABLED"] = True  # 啟用黑名單
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access", "refresh"]  # 檢查黑名單
app.config["SESSION_COOKIE_SECURE"] = False  # 只允許 HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True  # 防止 JavaScript 讀取 Cookie
jwt = JWTManager(app)

# === 限制請求次數 (Rate Limiting) ===
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# === CSRF 防禦 ===
# csrf = CSRFProtect(app)

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
    """
    每次請求時，檢查 Token 是否在黑名單中。
    """
    return jwt_payload["jti"] in blacklist


@app.route("/login", methods=["POST"])
@limiter.limit("3 per minute")  # 限制 3 次登入嘗試 / 分鐘
def login():
    """
    用戶登入，成功後返回 Access Token & Refresh Token。
    """
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
    """
    受保護的 API，只有攜帶有效 JWT Token 才能訪問。
    """
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user)


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    使用 Refresh Token 取得新的 Access Token。
    """
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)


@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    用戶登出，將 Access Token 加入黑名單，使其失效。
    """
    jti = get_jwt()["jti"]  # 取得 Token 的唯一 ID
    blacklist.add(jti)  # 將 Token 加入黑名單
    return jsonify({"msg": "Successfully logged out"})


if __name__ == "__main__":
    # app.run(debug=True, ssl_context=("cert.pem", "key.pem"))  # 強制使用 HTTPS
    app.run(debug=True)  # 強制使用 HTTPS

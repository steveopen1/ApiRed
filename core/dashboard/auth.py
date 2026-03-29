"""
Authentication Module
简单的用户认证系统

功能:
- Token 验证
- 简单的用户管理 (数据库存储)
- 登录/登出 API
- 认证中间件
"""

import hashlib
import secrets
import time
import logging
from typing import Optional, Dict
from dataclasses import dataclass
from aiohttp import web

logger = logging.getLogger(__name__)


@dataclass
class User:
    """用户"""
    user_id: str
    username: str
    password_hash: str
    role: str = "user"
    created_at: float = 0
    last_login: Optional[float] = None


class SimpleAuth:
    """
    简单认证系统
    
    支持:
    - 用户注册/登录
    - Token 验证
    - 角色权限 (admin/user)
    - 会话管理
    """

    def __init__(self, db_path: str = "./results/auth.db"):
        import sqlite3
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        
        # 创建默认管理员账户
        if not self.get_user("admin"):
            self.register("admin", "admin123", role="admin")
            logger.info("Created default admin user: admin/admin123")

    def _init_db(self):
        """初始化数据库"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at REAL,
                last_login REAL
            )
        ''')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL,
                expires_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        self.conn.commit()

    def _hash_password(self, password: str) -> str:
        """密码哈希"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', 
                                        password.encode(), 
                                        salt.encode(), 
                                        100000)
        return f"{salt}${hash_obj.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        try:
            salt, stored_hash = password_hash.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256',
                                            password.encode(),
                                            salt.encode(),
                                            100000)
            return secrets.compare_digest(hash_obj.hex(), stored_hash)
        except Exception:
            return False

    def register(self, username: str, password: str, role: str = "user") -> Optional[str]:
        """注册用户"""
        import uuid
        
        user_id = str(uuid.uuid4())
        password_hash = self._hash_password(password)
        
        try:
            self.conn.execute('''
                INSERT INTO users VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, password_hash, role, time.time()))
            self.conn.commit()
            logger.info(f"Registered new user: {username}")
            return user_id
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            return None

    def login(self, username: str, password: str) -> Optional[str]:
        """登录并返回 token"""
        cursor = self.conn.execute(
            'SELECT user_id, password_hash FROM users WHERE username = ?',
            (username,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        user_id, password_hash = row
        
        if not self._verify_password(password, password_hash):
            return None
        
        # 生成 token
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + 7 * 24 * 3600  # 7 天
        
        self.conn.execute('''
            INSERT INTO tokens VALUES (?, ?, ?, ?)
        ''', (token, user_id, time.time(), expires_at))
        
        self.conn.execute(
            'UPDATE users SET last_login=? WHERE user_id=?',
            (time.time(), user_id))
        self.conn.commit()
        
        logger.info(f"User logged in: {username}")
        return token

    def verify_token(self, token: str) -> Optional[Dict]:
        """验证 token"""
        if not token:
            return None
        
        cursor = self.conn.execute(
            'SELECT user_id, expires_at FROM tokens WHERE token = ?',
            (token,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        user_id, expires_at = row
        
        if time.time() > expires_at:
            self.logout(token)
            return None
        
        cursor = self.conn.execute(
            'SELECT user_id, username, role FROM users WHERE user_id = ?',
            (user_id,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return None
        
        return {
            'user_id': user_row[0],
            'username': user_row[1],
            'role': user_row[2]
        }

    def logout(self, token: str):
        """登出"""
        self.conn.execute('DELETE FROM tokens WHERE token = ?', (token,))
        self.conn.commit()

    def get_user(self, username: str) -> Optional[User]:
        """获取用户"""
        cursor = self.conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return User(
                user_id=row[0],
                username=row[1],
                password_hash=row[2],
                role=row[3],
                created_at=row[4],
                last_login=row[5]
            )
        return None

    def is_admin(self, token: str) -> bool:
        """检查是否是管理员"""
        user = self.verify_token(token)
        return user is not None and user.get('role') == 'admin'

    def close(self):
        """关闭数据库"""
        self.conn.close()


def auth_middleware(auth: SimpleAuth):
    """认证中间件工厂"""
    async def middleware(request, handler):
        # 公开路径不需要认证
        public_paths = ['/api/auth/login', '/api/auth/register', '/api/health', '/ws']
        if any(request.path.startswith(p) for p in public_paths):
            return await handler(request)
        
        if request.path == '/api/auth/login' or request.path == '/api/auth/register':
            return await handler(request)
        
        token = request.headers.get('Authorization', '')
        if token.startswith('Bearer '):
            token = token[7:]
        
        user = auth.verify_token(token)
        if not user:
            return web.json_response({
                'success': False,
                'error': 'Unauthorized'
            }, status=401)
        
        request['user'] = user
        return await handler(request)
    
    return middleware


if __name__ == "__main__":
    auth = SimpleAuth()
    print(f"Users: {auth.get_user('admin')}")
    
    token = auth.login("admin", "admin123")
    print(f"Token: {token}")
    
    user = auth.verify_token(token)
    print(f"Verified user: {user}")

"""
User Management
用户权限管理系统

功能:
- 多用户支持
- 角色权限管理 (admin/analyst/viewer)
- 用户CRUD操作
- 权限验证装饰器
"""

import hashlib
import secrets
import time
import logging
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass
from enum import Enum
import sqlite3

logger = logging.getLogger(__name__)


class UserRole(Enum):
    """用户角色"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    
    @classmethod
    def get_permissions(cls, role: 'UserRole') -> List[str]:
        """获取角色权限"""
        permissions = {
            cls.ADMIN: [
                'user:create', 'user:read', 'user:update', 'user:delete',
                'scan:create', 'scan:read', 'scan:update', 'scan:delete', 'scan:cancel',
                'schedule:create', 'schedule:read', 'schedule:update', 'schedule:delete',
                'report:create', 'report:read', 'report:delete', 'report:export',
                'import:create', 'import:read',
                'config:read', 'config:update',
                'plugin:load', 'plugin:unload'
            ],
            cls.ANALYST: [
                'scan:create', 'scan:read', 'scan:cancel',
                'schedule:create', 'schedule:read',
                'report:create', 'report:read', 'report:export',
                'import:create', 'import:read'
            ],
            cls.VIEWER: [
                'scan:read',
                'schedule:read',
                'report:read'
            ]
        }
        return permissions.get(role, [])


@dataclass
class User:
    """用户信息"""
    user_id: str
    username: str
    password_hash: str
    role: str
    email: Optional[str] = None
    is_active: bool = True
    created_at: float = 0
    last_login: Optional[float] = None


class UserManager:
    """
    用户权限管理系统
    
    支持:
    - 多用户CRUD
    - 角色权限管理
    - 权限验证
    """

    def __init__(self, db_path: str = "./results/users.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        
        if not self.get_user_by_username("admin"):
            self.create_user("admin", "admin123", role="admin")
            logger.info("Created default admin user")

    def _init_db(self):
        """初始化数据库"""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'viewer',
                email TEXT,
                is_active INTEGER DEFAULT 1,
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
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}${hash_obj.hex()}"

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """验证密码"""
        try:
            salt, stored_hash = password_hash.split('$')
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return secrets.compare_digest(hash_obj.hex(), stored_hash)
        except Exception:
            return False

    def create_user(
        self, 
        username: str, 
        password: str, 
        role: str = "viewer",
        email: Optional[str] = None
    ) -> Optional[str]:
        """创建用户"""
        import uuid
        
        user_id = str(uuid.uuid4())
        password_hash = self._hash_password(password)
        
        try:
            self.conn.execute('''
                INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, password_hash, role, email, 1, time.time(), None))
            self.conn.commit()
            logger.info(f"Created user: {username} with role {role}")
            return user_id
        except sqlite3.IntegrityError:
            logger.warning(f"User {username} already exists")
            return None

    def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        cursor = self.conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """通过用户名获取用户"""
        cursor = self.conn.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        return self._row_to_user(row) if row else None

    def _row_to_user(self, row: tuple) -> User:
        """行转用户对象"""
        return User(
            user_id=row[0],
            username=row[1],
            password_hash=row[2],
            role=row[3],
            email=row[4],
            is_active=bool(row[5]),
            created_at=row[6],
            last_login=row[7]
        )

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """用户认证"""
        user = self.get_user_by_username(username)
        if not user or not user.is_active:
            return None
        
        if not self._verify_password(password, user.password_hash):
            return None
        
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + 7 * 24 * 3600
        
        self.conn.execute('''
            INSERT INTO tokens VALUES (?, ?, ?, ?)
        ''', (token, user.user_id, time.time(), expires_at))
        
        self.conn.execute(
            'UPDATE users SET last_login=? WHERE user_id=?',
            (time.time(), user.user_id))
        self.conn.commit()
        
        logger.info(f"User authenticated: {username}")
        return token

    def verify_token(self, token: str) -> Optional[Dict]:
        """验证Token"""
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
            self.revoke_token(token)
            return None
        
        user = self.get_user(user_id)
        if not user or not user.is_active:
            return None
        
        return {
            'user_id': user.user_id,
            'username': user.username,
            'role': user.role,
            'permissions': UserRole.get_permissions(UserRole(user.role))
        }

    def revoke_token(self, token: str):
        """撤销Token"""
        self.conn.execute('DELETE FROM tokens WHERE token = ?', (token,))
        self.conn.commit()

    def has_permission(self, token: str, permission: str) -> bool:
        """检查权限"""
        user_data = self.verify_token(token)
        if not user_data:
            return False
        return permission in user_data.get('permissions', [])

    def update_user(self, user_id: str, **kwargs) -> bool:
        """更新用户"""
        allowed_fields = {'email', 'is_active', 'role'}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [user_id]
        
        self.conn.execute(
            f'UPDATE users SET {set_clause} WHERE user_id = ?',
            values)
        self.conn.commit()
        
        logger.info(f"Updated user: {user_id}")
        return True

    def update_password(self, user_id: str, new_password: str) -> bool:
        """更新密码"""
        password_hash = self._hash_password(new_password)
        self.conn.execute(
            'UPDATE users SET password_hash = ? WHERE user_id = ?',
            (password_hash, user_id))
        self.conn.commit()
        return True

    def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        self.conn.execute('DELETE FROM tokens WHERE user_id = ?', (user_id,))
        self.conn.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        self.conn.commit()
        logger.info(f"Deleted user: {user_id}")
        return True

    def list_users(self) -> List[User]:
        """列出所有用户"""
        cursor = self.conn.execute('SELECT * FROM users ORDER BY created_at DESC')
        return [self._row_to_user(row) for row in cursor.fetchall()]

    def close(self):
        """关闭数据库"""
        self.conn.close()


def require_permission(permission: str):
    """权限验证装饰器"""
    def decorator(func: Callable):
        def wrapper(self, *args, **kwargs):
            token = kwargs.get('token') or (args[0] if args else None)
            if not token:
                raise PermissionError("No authentication token provided")
            
            user_manager = getattr(self, 'user_manager', None)
            if not user_manager:
                raise AttributeError("UserManager not found")
            
            if not user_manager.has_permission(token, permission):
                raise PermissionError(f"Missing permission: {permission}")
            
            return func(self, *args, **kwargs)
        return wrapper
    return decorator


_global_user_manager: Optional[UserManager] = None


def get_user_manager() -> UserManager:
    """获取全局用户管理器"""
    global _global_user_manager
    if _global_user_manager is None:
        _global_user_manager = UserManager()
    return _global_user_manager


if __name__ == "__main__":
    um = UserManager()
    print(f"Users: {[u.username for u in um.list_users()]}")
    
    token = um.authenticate("admin", "admin123")
    print(f"Token: {token}")
    
    if token:
        user = um.verify_token(token)
        print(f"User: {user}")
        print(f"Permissions: {user.get('permissions', [])[:5] if user else []}")

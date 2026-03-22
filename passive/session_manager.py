"""
Session Manager Module
会话管理 - 多会话支持与数据持久化
"""

import json
import sqlite3
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class SessionStatus(Enum):
    """会话状态"""
    ACTIVE = 'active'
    PAUSED = 'paused'
    COMPLETED = 'completed'
    FAILED = 'failed'


@dataclass
class PassiveSession:
    """被动捕获会话"""
    session_id: str
    domain: str
    name: str
    started_at: float
    ended_at: Optional[float] = None
    status: SessionStatus = SessionStatus.ACTIVE
    capture_count: int = 0
    api_count: int = 0
    sensitive_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'domain': self.domain,
            'name': self.name,
            'started_at': self.started_at,
            'ended_at': self.ended_at,
            'status': self.status.value,
            'capture_count': self.capture_count,
            'api_count': self.api_count,
            'sensitive_count': self.sensitive_count,
            'metadata': self.metadata
        }


class PassiveSessionManager:
    """
    会话管理器
    支持多会话管理、会话合并、数据导入导出
    """
    
    def __init__(self, db_path: str = ':memory:'):
        """
        初始化会话管理器
        
        Args:
            db_path: SQLite数据库路径
        """
        self.db_path = db_path
        self.sessions: Dict[str, PassiveSession] = {}
        self.active_session: Optional[str] = None
        
        self._init_database()
    
    def _init_database(self):
        """初始化数据库"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS passive_sessions (
                session_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                name TEXT,
                started_at REAL,
                ended_at REAL,
                status TEXT,
                capture_count INTEGER DEFAULT 0,
                api_count INTEGER DEFAULT 0,
                sensitive_count INTEGER DEFAULT 0,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS passive_session_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                flow_id TEXT,
                flow_data TEXT,
                FOREIGN KEY(session_id) REFERENCES passive_sessions(session_id)
            )
        ''')
        self.conn.commit()
        
        self._load_sessions()
    
    def _load_sessions(self):
        """从数据库加载会话"""
        cursor = self.conn.execute(
            'SELECT session_id, domain, name, started_at, ended_at, status, '
            'capture_count, api_count, sensitive_count, metadata FROM passive_sessions'
        )
        for row in cursor.fetchall():
            session = PassiveSession(
                session_id=row[0],
                domain=row[1],
                name=row[2] or '',
                started_at=row[3],
                ended_at=row[4],
                status=SessionStatus(row[5]) if row[5] else SessionStatus.ACTIVE,
                capture_count=row[6] or 0,
                api_count=row[7] or 0,
                sensitive_count=row[8] or 0,
                metadata=json.loads(row[9]) if row[9] else {}
            )
            self.sessions[session.session_id] = session
    
    def create_session(self, domain: str, name: str = None) -> PassiveSession:
        """
        创建新会话
        
        Args:
            domain: 目标域名
            name: 会话名称
            
        Returns:
            PassiveSession: 新创建的会话
        """
        session_id = str(uuid.uuid4())
        session = PassiveSession(
            session_id=session_id,
            domain=domain,
            name=name or f'{domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            started_at=datetime.now().timestamp(),
            status=SessionStatus.ACTIVE
        )
        
        self.sessions[session_id] = session
        self.active_session = session_id
        
        self._save_session(session)
        
        return session
    
    def switch_session(self, session_id: str) -> bool:
        """
        切换活跃会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 是否成功
        """
        if session_id in self.sessions:
            self.active_session = session_id
            return True
        return False
    
    def end_session(self, session_id: str) -> bool:
        """
        结束会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 是否成功
        """
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session.status = SessionStatus.COMPLETED
            session.ended_at = datetime.now().timestamp()
            
            if self.active_session == session_id:
                self.active_session = None
            
            self._save_session(session)
            return True
        return False
    
    def update_stats(self, session_id: str, capture_count: int = None, 
                     api_count: int = None, sensitive_count: int = None):
        """
        更新会话统计
        
        Args:
            session_id: 会话ID
            capture_count: 捕获数
            api_count: API数
            sensitive_count: 敏感端点数
        """
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        if capture_count is not None:
            session.capture_count = capture_count
        if api_count is not None:
            session.api_count = api_count
        if sensitive_count is not None:
            session.sensitive_count = sensitive_count
        
        self._save_session(session)
    
    def _save_session(self, session: PassiveSession):
        """保存会话到数据库"""
        self.conn.execute('''
            INSERT OR REPLACE INTO passive_sessions
            (session_id, domain, name, started_at, ended_at, status,
             capture_count, api_count, sensitive_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id,
            session.domain,
            session.name,
            session.started_at,
            session.ended_at,
            session.status.value,
            session.capture_count,
            session.api_count,
            session.sensitive_count,
            json.dumps(session.metadata)
        ))
        self.conn.commit()
    
    def get_session(self, session_id: str) -> Optional[PassiveSession]:
        """获取会话"""
        return self.sessions.get(session_id)
    
    def get_active_session(self) -> Optional[PassiveSession]:
        """获取当前活跃会话"""
        if self.active_session:
            return self.sessions.get(self.active_session)
        return None
    
    def get_all_sessions(self) -> List[PassiveSession]:
        """获取所有会话"""
        return list(self.sessions.values())
    
    def get_sessions_by_domain(self, domain: str) -> List[PassiveSession]:
        """获取指定域名的所有会话"""
        return [s for s in self.sessions.values() if s.domain == domain]
    
    def delete_session(self, session_id: str) -> bool:
        """
        删除会话
        
        Args:
            session_id: 会话ID
            
        Returns:
            bool: 是否成功
        """
        if session_id not in self.sessions:
            return False
        
        del self.sessions[session_id]
        
        if self.active_session == session_id:
            self.active_session = None
        
        self.conn.execute('DELETE FROM passive_sessions WHERE session_id = ?', (session_id,))
        self.conn.execute('DELETE FROM passive_session_flows WHERE session_id = ?', (session_id,))
        self.conn.commit()
        
        return True
    
    def merge_sessions(self, target_session_id: str, source_session_ids: List[str]) -> bool:
        """
        合并会话
        
        Args:
            target_session_id: 目标会话ID
            source_session_ids: 源会话ID列表
            
        Returns:
            bool: 是否成功
        """
        if target_session_id not in self.sessions:
            return False
        
        target = self.sessions[target_session_id]
        
        for source_id in source_session_ids:
            if source_id in self.sessions and source_id != target_session_id:
                source = self.sessions[source_id]
                
                target.capture_count += source.capture_count
                target.api_count += source.api_count
                target.sensitive_count += source.sensitive_count
                
                target.metadata['merged_from'] = target.metadata.get('merged_from', [])
                target.metadata['merged_from'].append(source_id)
        
        self._save_session(target)
        
        for source_id in source_session_ids:
            if source_id in self.sessions and source_id != target_session_id:
                self.delete_session(source_id)
        
        return True
    
    def export_session(self, session_id: str, format: str = 'json') -> str:
        """
        导出会话
        
        Args:
            session_id: 会话ID
            format: 导出格式 (json/har)
            
        Returns:
            str: 导出的数据
        """
        if session_id not in self.sessions:
            return '{}'
        
        session = self.sessions[session_id]
        
        if format == 'json':
            return json.dumps(session.to_dict(), indent=2, ensure_ascii=False)
        else:
            return '{}'
    
    def import_session(self, data: str, format: str = 'json') -> Optional[PassiveSession]:
        """
        导入会话
        
        Args:
            data: 导入数据
            format: 数据格式
            
        Returns:
            PassiveSession: 导入的会话
        """
        try:
            if format == 'json':
                session_data = json.loads(data)
                
                session_id = str(uuid.uuid4())
                session = PassiveSession(
                    session_id=session_id,
                    domain=session_data.get('domain', ''),
                    name=session_data.get('name', ''),
                    started_at=session_data.get('started_at', datetime.now().timestamp()),
                    ended_at=session_data.get('ended_at'),
                    status=SessionStatus(session_data.get('status', 'active')),
                    capture_count=session_data.get('capture_count', 0),
                    api_count=session_data.get('api_count', 0),
                    sensitive_count=session_data.get('sensitive_count', 0),
                    metadata=session_data.get('metadata', {})
                )
                
                self.sessions[session_id] = session
                self._save_session(session)
                
                return session
        except Exception as e:
            print(f'Failed to import session: {e}')
        
        return None
    
    def close(self):
        """关闭连接"""
        if self.conn:
            self.conn.close()

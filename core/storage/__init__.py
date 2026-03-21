"""
Storage Module
存储层模块
"""

import sqlite3
import json
import os
import hashlib
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime
import threading


class DBStorage:
    """数据库存储封装"""
    
    def __init__(self, db_path: str, wal_mode: bool = True):
        self.db_path = db_path
        self.wal_mode = wal_mode
        self._ensure_dir()
        self.conn: Optional[sqlite3.Connection] = None
        self._local = threading.local()
        self._init_db()
    
    def _ensure_dir(self):
        """确保目录存在"""
        dir_path = os.path.dirname(self.db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
    
    def _get_connection(self) -> sqlite3.Connection:
        """获取线程本地连接"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                timeout=60,
                check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
            
            if self.wal_mode:
                self._local.conn.execute("PRAGMA journal_mode=WAL")
            
            self._local.conn.execute("PRAGMA synchronous=OFF")
            self._local.conn.execute("PRAGMA cache_size=-64000")
            self._local.conn.execute("PRAGMA temp_store=MEMORY")
        
        return self._local.conn
    
    @property
    def conn(self) -> sqlite3.Connection:
        """获取连接"""
        return self._get_connection()
    
    def _init_db(self):
        """初始化数据库表"""
        conn = self.conn
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS meta_info (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_endpoints (
                api_id TEXT PRIMARY KEY,
                path TEXT,
                method TEXT,
                base_url TEXT,
                full_url TEXT,
                status TEXT,
                score INTEGER DEFAULT 0,
                is_high_value INTEGER DEFAULT 0,
                service_key TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_sources (
                api_id TEXT,
                source_type TEXT,
                source_data TEXT,
                FOREIGN KEY(api_id) REFERENCES api_endpoints(api_id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS js_fingerprint_cache (
                content_hash TEXT PRIMARY KEY,
                js_url TEXT,
                ast_results TEXT,
                regex_results TEXT,
                file_size INTEGER,
                cached_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS api_evidence (
                api_id TEXT PRIMARY KEY,
                normalized_path TEXT,
                sources TEXT,
                score INTEGER DEFAULT 0,
                is_high_value INTEGER DEFAULT 0,
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(api_id) REFERENCES api_endpoints(api_id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stage_stats (
                stage_name TEXT,
                start_time REAL,
                end_time REAL,
                duration REAL,
                input_count INTEGER,
                output_count INTEGER,
                error_count INTEGER
            )
        """)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_path ON api_endpoints(path)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_score ON api_endpoints(score DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_js_fingerprint ON js_fingerprint_cache(content_hash)
        """)
        
        conn.commit()
    
    def insert_api(self, api: Dict[str, Any]) -> bool:
        """插入API"""
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO api_endpoints 
                (api_id, path, method, base_url, full_url, status, score, 
                 is_high_value, service_key, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                api.get('api_id'),
                api.get('path'),
                api.get('method'),
                api.get('base_url'),
                api.get('full_url'),
                api.get('status'),
                api.get('score', 0),
                api.get('is_high_value', 0),
                api.get('service_key'),
                api.get('created_at'),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Insert API error: {e}")
            return False
    
    def insert_js_cache(self, content_hash: str, js_url: str, 
                       ast_results: Dict, regex_results: Dict, file_size: int) -> bool:
        """插入JS缓存"""
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO js_fingerprint_cache
                (content_hash, js_url, ast_results, regex_results, file_size)
                VALUES (?, ?, ?, ?, ?)
            """, (
                content_hash,
                js_url,
                json.dumps(ast_results),
                json.dumps(regex_results),
                file_size
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Insert JS cache error: {e}")
            return False
    
    def get_js_cache(self, content_hash: str) -> Optional[Dict]:
        """获取JS缓存"""
        row = self.conn.execute("""
            SELECT ast_results, regex_results FROM js_fingerprint_cache
            WHERE content_hash = ?
        """, (content_hash,)).fetchone()
        
        if row:
            return {
                'ast': json.loads(row[0]) if row[0] else {},
                'regex': json.loads(row[1]) if row[1] else {}
            }
        return None
    
    def insert_evidence(self, api_id: str, normalized_path: str,
                       sources: Dict, score: int) -> bool:
        """插入API证据"""
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO api_evidence
                (api_id, normalized_path, sources, score, is_high_value, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                api_id,
                normalized_path,
                json.dumps(sources),
                score,
                1 if score >= 5 else 0,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Insert evidence error: {e}")
            return False
    
    def record_stage_stats(self, stats: Dict[str, Any]) -> bool:
        """记录阶段统计"""
        try:
            self.conn.execute("""
                INSERT INTO stage_stats
                (stage_name, start_time, end_time, duration, input_count, output_count, error_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                stats.get('stage_name'),
                stats.get('start_time'),
                stats.get('end_time'),
                stats.get('duration'),
                stats.get('input_count'),
                stats.get('output_count'),
                stats.get('error_count')
            ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Record stage stats error: {e}")
            return False
    
    def get_all_apis(self) -> List[Dict]:
        """获取所有API"""
        rows = self.conn.execute("""
            SELECT * FROM api_endpoints ORDER BY score DESC
        """).fetchall()
        
        return [dict(row) for row in rows]
    
    def get_high_value_apis(self, min_score: int = 5) -> List[Dict]:
        """获取高价值API"""
        rows = self.conn.execute("""
            SELECT * FROM api_endpoints 
            WHERE score >= ? ORDER BY score DESC
        """, (min_score,)).fetchall()
        
        return [dict(row) for row in rows]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        stats = {}
        
        row = self.conn.execute("""
            SELECT COUNT(*) as total FROM api_endpoints
        """).fetchone()
        stats['total_apis'] = row[0] if row else 0
        
        row = self.conn.execute("""
            SELECT COUNT(*) as alive FROM api_endpoints WHERE status = 'alive'
        """).fetchone()
        stats['alive_apis'] = row[0] if row else 0
        
        row = self.conn.execute("""
            SELECT COUNT(*) as high_value FROM api_endpoints WHERE is_high_value = 1
        """).fetchone()
        stats['high_value_apis'] = row[0] if row else 0
        
        row = self.conn.execute("""
            SELECT COUNT(*) as cached FROM js_fingerprint_cache
        """).fetchone()
        stats['cached_js'] = row[0] if row else 0
        
        return stats
    
    def close(self):
        """关闭连接"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


class FileStorage:
    """文件存储封装"""
    
    def __init__(self, base_dir: str = "./results"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def save_json(self, data: Any, file_path: str) -> bool:
        """保存JSON文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"Save JSON error: {e}")
            return False
    
    def load_json(self, file_path: str) -> Optional[Any]:
        """加载JSON文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            if not os.path.exists(full_path):
                return None
            
            with open(full_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Load JSON error: {e}")
            return None
    
    def save_text(self, content: str, file_path: str) -> bool:
        """保存文本文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Save text error: {e}")
            return False
    
    def append_text(self, content: str, file_path: str) -> bool:
        """追加文本文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            with open(full_path, 'a', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"Append text error: {e}")
            return False

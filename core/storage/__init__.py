"""
Storage Module
存储层模块
"""

import sqlite3
import json
import os
import hashlib
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime
import threading

logger = logging.getLogger(__name__)


class DBStorage:
    """数据库存储封装"""
    
    def __init__(self, db_path: str, wal_mode: bool = True, max_retries: int = 3):
        self.db_path = db_path
        self.wal_mode = wal_mode
        self.max_retries = max_retries
        self._ensure_dir()
        self._local = threading.local()
        self._init_db()
        self._connection_valid = True
    
    def _ensure_dir(self):
        """确保目录存在"""
        dir_path = os.path.dirname(self.db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
    
    def _is_connection_valid(self, conn: sqlite3.Connection) -> bool:
        """检查连接是否有效"""
        try:
            conn.execute("SELECT 1")
            return True
        except (sqlite3.ProgrammingError, sqlite3.OperationalError) as e:
            logger.debug(f"Connection validity check failed: {e}")
            return False
    
    def _reconnect(self):
        """重新建立数据库连接"""
        logger.info("Attempting to reconnect to database...")
        
        if hasattr(self._local, 'conn') and self._local.conn:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None
        
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
        
        self._connection_valid = True
        logger.info("Database reconnection successful")
    
    def _get_connection(self) -> sqlite3.Connection:
        """获取线程本地连接"""
        retry_count = 0
        
        while retry_count < self.max_retries:
            if not hasattr(self._local, 'conn') or self._local.conn is None:
                self._local.conn = self._create_connection()
            
            if self._is_connection_valid(self._local.conn):
                return self._local.conn
            else:
                self._connection_valid = False
                self._local.conn = None
                retry_count += 1
                logger.warning(f"Invalid connection, retrying ({retry_count}/{self.max_retries})...")
        
        self._reconnect()
        return self._local.conn
    
    def _create_connection(self) -> sqlite3.Connection:
        """创建新的数据库连接"""
        conn = sqlite3.connect(
            self.db_path,
            timeout=60,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        
        if self.wal_mode:
            conn.execute("PRAGMA journal_mode=WAL")
        
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA cache_size=-64000")
        conn.execute("PRAGMA temp_store=MEMORY")
        
        return conn
    
    def is_healthy(self) -> bool:
        """检查数据库健康状态"""
        try:
            conn = self._get_connection()
            return self._is_connection_valid(conn)
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
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
            logger.error(f"Insert API error: {e}")
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
            logger.error(f"Insert JS cache error: {e}")
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
            logger.error(f"Insert evidence error: {e}")
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
            logger.error(f"Record stage stats error: {e}")
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
            normalized = os.path.normpath(full_path)
            if not normalized.startswith(os.path.normpath(self.base_dir)):
                logger.warning("Save JSON error: path traversal attempt detected")
                return False
            os.makedirs(os.path.dirname(normalized), exist_ok=True)
            
            with open(normalized, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            logger.error(f"Save JSON error: {e}")
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
            logger.error(f"Load JSON error: {e}")
            return None
    
    def save_text(self, content: str, file_path: str) -> bool:
        """保存文本文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            normalized = os.path.normpath(full_path)
            if not normalized.startswith(os.path.normpath(self.base_dir)):
                logger.warning("Save text error: path traversal attempt detected")
                return False
            os.makedirs(os.path.dirname(normalized), exist_ok=True)
            
            with open(normalized, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Save text error: {e}")
            return False
    
    def append_text(self, content: str, file_path: str) -> bool:
        """追加文本文件"""
        try:
            full_path = os.path.join(self.base_dir, file_path)
            normalized = os.path.normpath(full_path)
            if not normalized.startswith(os.path.normpath(self.base_dir)):
                logger.warning("Append text error: path traversal attempt detected")
                return False
            os.makedirs(os.path.dirname(normalized), exist_ok=True)
            
            with open(normalized, 'a', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Append text error: {e}")
            return False


class MySQLStorage:
    """
    MySQL 存储封装
    提供完整的 MySQL 数据库存储功能
    参考 0x727/ChkApi 的数据存储设计
    """

    def __init__(self, host: str = "localhost", port: int = 3306,
                 user: str = "root", password: str = "",
                 database: str = "apired", charset: str = "utf8mb4"):
        self.config = {
            'host': host,
            'port': port,
            'user': user,
            'password': password,
            'database': database,
            'charset': charset
        }
        self._conn = None
        self._connect()

    def _connect(self):
        """连接 MySQL"""
        try:
            import pymysql
            self._conn = pymysql.connect(**self.config)
        except ImportError:
            logger.warning("pymysql not installed, MySQL storage unavailable")
            self._conn = None
        except Exception as e:
            logger.error(f"MySQL connection failed: {e}")
            self._conn = None

    def _ensure_database(self):
        """确保数据库存在"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']} "
                             f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Create database error: {e}")
            return False

    def init_tables(self):
        """初始化表结构"""
        if not self._conn:
            return False

        tables = [
            """
            CREATE TABLE IF NOT EXISTS load_urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL地址',
                load_url VARCHAR(2048) COMMENT '自动加载的URL地址',
                load_url_type VARCHAR(50) COMMENT 'js/static_url/no_js',
                referer VARCHAR(2048) COMMENT '来源URL',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_load_url (load_url(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS js_static_urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                js_static_url VARCHAR(2048) COMMENT 'JS地址或静态URL',
                url_type VARCHAR(50) COMMENT 'js_url/static_url',
                status_code INT COMMENT '响应状态码',
                res_length BIGINT COMMENT '响应长度',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_type (url_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS api_paths (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                api_path VARCHAR(2048) COMMENT '提取的API接口',
                method VARCHAR(10) DEFAULT 'GET' COMMENT '请求方法',
                source_type VARCHAR(50) COMMENT 'js_fingerprint/swagger/fuzz',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_api_path (api_path(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS base_urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                tree_url VARCHAR(2048) COMMENT 'Tree URL',
                base_url VARCHAR(255) COMMENT 'Base URL (微服务名)',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_base_url (base_url)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS parameters (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                api_path VARCHAR(2048) COMMENT 'API路径',
                parameter VARCHAR(255) COMMENT '参数名',
                param_source VARCHAR(50) COMMENT '来源: response_key/error_msg',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_param (parameter)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS api_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                api_url VARCHAR(2048) COMMENT 'API完整路径',
                method VARCHAR(10) DEFAULT 'GET' COMMENT '请求方法',
                parameter TEXT COMMENT '请求参数',
                res_type VARCHAR(50) COMMENT '响应格式: json/html/xml',
                status_code INT COMMENT '响应状态码',
                res_length BIGINT COMMENT '响应长度',
                response_content LONGTEXT COMMENT '响应内容(摘要)',
                content_hash VARCHAR(64) COMMENT '响应内容哈希',
                hash_count INT DEFAULT 1 COMMENT '相同哈希出现次数',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_api_url (api_url(255)),
                INDEX idx_content_hash (content_hash)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS sensitive_data (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                api_url VARCHAR(2048) COMMENT '来源API',
                sensitive_type VARCHAR(100) COMMENT '敏感信息类型',
                sensitive_content TEXT COMMENT '敏感内容(脱敏)',
                rule_name VARCHAR(100) COMMENT '匹配规则名',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_sensitive_type (sensitive_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """,
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(2048) NOT NULL COMMENT '被检测的URL',
                api_url VARCHAR(2048) COMMENT '漏洞API',
                vuln_type VARCHAR(100) COMMENT '漏洞类型',
                severity VARCHAR(20) COMMENT '严重程度',
                evidence TEXT COMMENT '证据',
                payload TEXT COMMENT 'payload',
                remediation TEXT COMMENT '修复建议',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_url (url(255)),
                INDEX idx_vuln_type (vuln_type)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """
        ]

        try:
            with self._conn.cursor() as cursor:
                for table_sql in tables:
                    cursor.execute(table_sql)
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Init tables error: {e}")
            return False

    def insert_load_url(self, url: str, load_url: str, load_url_type: str, referer: str = "") -> bool:
        """插入自动加载URL"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO load_urls (url, load_url, load_url_type, referer) VALUES (%s, %s, %s, %s)",
                    (url, load_url, load_url_type, referer)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert load_url error: {e}")
            return False

    def insert_js_url(self, url: str, js_url: str, url_type: str, status_code: int = 200,
                     res_length: int = 0) -> bool:
        """插入JS/静态URL"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO js_static_urls (url, js_static_url, url_type, status_code, res_length) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (url, js_url, url_type, status_code, res_length)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert js_url error: {e}")
            return False

    def insert_api_path(self, url: str, api_path: str, method: str = "GET",
                       source_type: str = "js_fingerprint") -> bool:
        """插入API路径"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO api_paths (url, api_path, method, source_type) VALUES (%s, %s, %s, %s)",
                    (url, api_path, method, source_type)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert api_path error: {e}")
            return False

    def insert_base_url(self, url: str, tree_url: str = "", base_url: str = "") -> bool:
        """插入Base URL"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO base_urls (url, tree_url, base_url) VALUES (%s, %s, %s)",
                    (url, tree_url, base_url)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert base_url error: {e}")
            return False

    def insert_parameter(self, url: str, api_path: str, parameter: str,
                        param_source: str = "response_key") -> bool:
        """插入参数"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO parameters (url, api_path, parameter, param_source) VALUES (%s, %s, %s, %s)",
                    (url, api_path, parameter, param_source)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert parameter error: {e}")
            return False

    def insert_api_result(self, url: str, api_url: str, method: str, parameter: str = "",
                         res_type: str = "json", status_code: int = 200, res_length: int = 0,
                         content_hash: str = "", hash_count: int = 1) -> bool:
        """插入API测试结果"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO api_results (url, api_url, method, parameter, res_type, status_code, "
                    "res_length, content_hash, hash_count) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (url, api_url, method, parameter, res_type, status_code, res_length, content_hash, hash_count)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert api_result error: {e}")
            return False

    def insert_sensitive_data(self, url: str, api_url: str, sensitive_type: str,
                              sensitive_content: str, rule_name: str = "") -> bool:
        """插入敏感数据"""
        if not self._conn:
            return False
        masked_content = sensitive_content[:50] + "***" if len(sensitive_content) > 50 else "***"
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO sensitive_data (url, api_url, sensitive_type, sensitive_content, rule_name) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (url, api_url, sensitive_type, masked_content, rule_name)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert sensitive_data error: {e}")
            return False

    def insert_vulnerability(self, url: str, api_url: str, vuln_type: str, severity: str,
                            evidence: str = "", payload: str = "", remediation: str = "") -> bool:
        """插入漏洞"""
        if not self._conn:
            return False
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO vulnerabilities (url, api_url, vuln_type, severity, evidence, payload, remediation) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (url, api_url, vuln_type, severity, evidence[:500], payload, remediation)
                )
            self._conn.commit()
            return True
        except Exception as e:
            logger.error(f"Insert vulnerability error: {e}")
            return False

    def query_sensitive_keywords(self, keywords: str) -> List[Dict]:
        """查询敏感信息（RCE相关关键词）"""
        if not self._conn:
            return []
        try:
            with self._conn.cursor() as cursor:
                pattern = f"%{keywords}%"
                cursor.execute(
                    "SELECT * FROM api_results WHERE api_url LIKE ? OR parameter LIKE ?",
                    (pattern, pattern)
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Query sensitive keywords error: {e}")
            return []

    def query_similar_responses(self, content_hash: str) -> List[Dict]:
        """查询相同响应的数量（响应差异化）"""
        if not self._conn:
            return []
        try:
            with self._conn.cursor() as cursor:
                cursor.execute(
                    "SELECT content_hash, COUNT(*) as count FROM api_results GROUP BY content_hash HAVING count > 1"
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Query similar responses error: {e}")
            return []

    def close(self):
        """关闭连接"""
        if self._conn:
            self._conn.close()
            self._conn = None


from .realtime_output import RealtimeOutput, get_realtime_output

__all__ = [
    'DBStorage',
    'FileStorage',
    'RealtimeOutput',
    'get_realtime_output',
]

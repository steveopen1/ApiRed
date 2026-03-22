"""
Dashboard Database Module
SQLite数据库集成
"""

import sqlite3
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
from contextlib import contextmanager

DATABASE_PATH = "apired_dashboard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    tags TEXT DEFAULT '[]',
    target_count INTEGER DEFAULT 0,
    api_count INTEGER DEFAULT 0,
    vuln_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT,
    status TEXT DEFAULT 'pending',
    last_scan_at TEXT,
    api_count INTEGER DEFAULT 0,
    vuln_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    total_apis INTEGER DEFAULT 0,
    alive_apis INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    result_json TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_results_target ON scan_results(target_id);
"""


class Database:
    """数据库管理类"""
    
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self.init_schema()
    
    def init_schema(self):
        """初始化数据库schema"""
        with self.get_conn() as conn:
            conn.executescript(SCHEMA)
            conn.commit()
    
    @contextmanager
    def get_conn(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_project(self, name: str, description: str = None, tags: List[str] = None) -> int:
        """创建项目"""
        with self.get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO projects (name, description, tags) VALUES (?, ?, ?)""",
                (name, description, json.dumps(tags or [])))
            conn.commit()
            return cursor.lastrowid
    
    def get_projects(self, skip: int = 0, limit: int = 20, tag: str = None) -> List[Dict]:
        """获取项目列表"""
        with self.get_conn() as conn:
            if tag:
                cursor = conn.execute(
                    """SELECT * FROM projects WHERE tags LIKE ? LIMIT ? OFFSET ?""",
                    (f'%{tag}%', limit, skip))
            else:
                cursor = conn.execute(
                    """SELECT * FROM projects LIMIT ? OFFSET ?""",
                    (limit, skip))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_project(self, project_id: int) -> Optional[Dict]:
        """获取单个项目"""
        with self.get_conn() as conn:
            cursor = conn.execute(
                """SELECT * FROM projects WHERE id = ?""", (project_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_project(self, project_id: int, **kwargs) -> bool:
        """更新项目"""
        if not kwargs:
            return False
        
        kwargs['updated_at'] = datetime.now().isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [project_id]
        
        with self.get_conn() as conn:
            conn.execute(
                f"""UPDATE projects SET {set_clause} WHERE id = ?""",
                values)
            conn.commit()
            return True
    
    def delete_project(self, project_id: int) -> bool:
        """删除项目"""
        with self.get_conn() as conn:
            conn.execute("""DELETE FROM projects WHERE id = ?""", (project_id,))
            conn.commit()
            return True
    
    def create_target(self, project_id: int, url: str, name: str = None) -> int:
        """创建目标"""
        with self.get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO targets (project_id, url, name) VALUES (?, ?, ?)""",
                (project_id, url, name))
            
            conn.execute(
                """UPDATE projects SET target_count = target_count + 1 WHERE id = ?""",
                (project_id,))
            conn.commit()
            return cursor.lastrowid
    
    def get_targets(self, project_id: int = None, status: str = None, 
                   skip: int = 0, limit: int = 50) -> List[Dict]:
        """获取目标列表"""
        conditions = []
        params = []
        
        if project_id is not None:
            conditions.append("project_id = ?")
            params.append(project_id)
        if status:
            conditions.append("status = ?")
            params.append(status)
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        with self.get_conn() as conn:
            cursor = conn.execute(
                f"""SELECT * FROM targets WHERE {where_clause} LIMIT ? OFFSET ?""",
                params + [limit, skip])
            return [dict(row) for row in cursor.fetchall()]
    
    def update_target(self, target_id: int, **kwargs) -> bool:
        """更新目标"""
        if not kwargs:
            return False
        
        set_clause = ", ".join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values())
        
        with self.get_conn() as conn:
            conn.execute(
                f"""UPDATE targets SET {set_clause} WHERE id = ?""",
                values + [target_id])
            conn.commit()
            return True
    
    def delete_target(self, target_id: int) -> bool:
        """删除目标"""
        with self.get_conn() as conn:
            target = conn.execute(
                """SELECT project_id FROM targets WHERE id = ?""", (target_id,)).fetchone()
            if target:
                conn.execute("""DELETE FROM targets WHERE id = ?""", (target_id,))
                conn.execute(
                    """UPDATE projects SET target_count = target_count - 1 WHERE id = ?""",
                    (target[0],))
                conn.commit()
                return True
            return False
    
    def create_scan_result(self, target_id: int, status: str = 'pending',
                          total_apis: int = 0, alive_apis: int = 0,
                          high_vulns: int = 0, medium_vulns: int = 0,
                          low_vulns: int = 0, result_json: str = None) -> int:
        """创建扫描结果"""
        with self.get_conn() as conn:
            cursor = conn.execute(
                """INSERT INTO scan_results (target_id, status, total_apis, alive_apis, high_vulns, medium_vulns, low_vulns, result_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (target_id, status, total_apis, alive_apis, high_vulns, medium_vulns, low_vulns, result_json))
            conn.commit()
            return cursor.lastrowid
    
    def get_scan_results(self, target_id: int = None, limit: int = 50) -> List[Dict]:
        """获取扫描结果"""
        if target_id:
            with self.get_conn() as conn:
                cursor = conn.execute(
                    """SELECT * FROM scan_results WHERE target_id = ? ORDER BY created_at DESC LIMIT ?""",
                    (target_id, limit))
                return [dict(row) for row in cursor.fetchall()]
        
        with self.get_conn() as conn:
            cursor = conn.execute(
                """SELECT * FROM scan_results ORDER BY created_at DESC LIMIT ?""", (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_overview_stats(self) -> Dict[str, int]:
        """获取概览统计"""
        with self.get_conn() as conn:
            projects = conn.execute("""SELECT COUNT(*) as count FROM projects""").fetchone()[0]
            active_targets = conn.execute(
                """SELECT COUNT(*) as count FROM targets WHERE status = 'scanning'""").fetchone()[0]
            total_apis = conn.execute(
                """SELECT SUM(api_count) FROM targets""").fetchone()[0] or 0
            critical = conn.execute(
                """SELECT SUM(high_vulns) FROM scan_results""").fetchone()[0] or 0
            high_vulns = conn.execute(
                """SELECT SUM(medium_vulns) FROM scan_results""").fetchone()[0] or 0
            
            return {
                "total_projects": projects,
                "active_targets": active_targets,
                "total_apis": total_apis,
                "critical_vulns": critical,
                "high_vulns": high_vulns
            }


db = Database()

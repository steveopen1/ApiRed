"""
Persistent Scheduled Testing Module
定时任务持久化模块

将 CronScheduler 的任务持久化到 SQLite 数据库
"""

import sqlite3
import json
import time
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class PersistentScheduler:
    """
    持久化定时任务管理器
    
    提供:
    - SQLite 数据库存储
    - 任务 CRUD 操作
    - 扫描历史记录
    - 增量对比
    """

    def __init__(self, db_path: str = './results/schedules.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                task_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                trigger_type TEXT DEFAULT 'cron',
                interval_seconds INTEGER DEFAULT 3600,
                enabled INTEGER DEFAULT 1,
                config TEXT DEFAULT '{}',
                created_at REAL,
                next_run REAL,
                status TEXT DEFAULT 'pending'
            )
        ''')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                task_id TEXT,
                target TEXT NOT NULL,
                start_time REAL,
                end_time REAL,
                status TEXT,
                result_summary TEXT,
                vulnerabilities_found INTEGER DEFAULT 0,
                errors TEXT
            )
        ''')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                task_id TEXT,
                target TEXT NOT NULL,
                result_data TEXT,
                created_at REAL
            )
        ''')
        self.conn.commit()
        logger.info(f"Initialized persistent scheduler with DB: {self.db_path}")

    def add_task(self, task_id: str, name: str, target: str, 
                 cron_expression: str, trigger_type: str = 'cron',
                 interval_seconds: int = 3600, config: Dict = None,
                 next_run: float = None) -> bool:
        """添加定时任务"""
        try:
            self.conn.execute('''
                INSERT OR REPLACE INTO scheduled_tasks 
                (task_id, name, target, cron_expression, trigger_type, 
                 interval_seconds, enabled, config, created_at, next_run, status)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 'pending')
            ''', (task_id, name, target, cron_expression, trigger_type,
                  interval_seconds, json.dumps(config or {}),
                  time.time(), next_run))
            self.conn.commit()
            logger.info(f"Added scheduled task: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add task: {e}")
            return False

    def get_task(self, task_id: str) -> Optional[Dict]:
        """获取任务"""
        cursor = self.conn.execute(
            'SELECT * FROM scheduled_tasks WHERE task_id = ?', (task_id,))
        row = cursor.fetchone()
        if row:
            return self._row_to_task(row)
        return None

    def get_all_tasks(self) -> List[Dict]:
        """获取所有任务"""
        cursor = self.conn.execute('SELECT * FROM scheduled_tasks ORDER BY created_at DESC')
        return [self._row_to_task(row) for row in cursor.fetchall()]

    def get_pending_tasks(self) -> List[Dict]:
        """获取待执行的任务"""
        current_time = time.time()
        cursor = self.conn.execute(
            'SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run <= ? ORDER BY next_run',
            (current_time,))
        return [self._row_to_task(row) for row in cursor.fetchall()]

    def update_task(self, task_id: str, **kwargs) -> bool:
        """更新任务"""
        allowed_fields = {'name', 'target', 'cron_expression', 'enabled', 'next_run', 'status'}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if 'enabled' in updates:
            updates['enabled'] = 1 if updates['enabled'] else 0
        
        if updates:
            set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
            values = list(updates.values()) + [task_id]
            self.conn.execute(
                f'UPDATE scheduled_tasks SET {set_clause} WHERE task_id = ?',
                values)
            self.conn.commit()
            logger.info(f"Updated task: {task_id}")
        return True

    def delete_task(self, task_id: str) -> bool:
        """删除任务"""
        self.conn.execute('DELETE FROM scheduled_tasks WHERE task_id = ?', (task_id,))
        self.conn.commit()
        logger.info(f"Deleted task: {task_id}")
        return True

    def record_scan(self, scan_id: str, task_id: str, target: str,
                    start_time: float, end_time: float, status: str,
                    result_summary: Dict = None, vulnerabilities_found: int = 0,
                    errors: List = None) -> bool:
        """记录扫描历史"""
        try:
            self.conn.execute('''
                INSERT INTO scan_history 
                (scan_id, task_id, target, start_time, end_time, status,
                 result_summary, vulnerabilities_found, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, task_id, target, start_time, end_time, status,
                   json.dumps(result_summary or {}), vulnerabilities_found,
                   json.dumps(errors or [])))
            
            self.conn.execute(
                'UPDATE scheduled_tasks SET last_run=?, status=? WHERE task_id=?',
                (end_time, status, task_id))
            
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to record scan: {e}")
            return False

    def save_result(self, scan_id: str, task_id: str, target: str,
                    result_data: Dict) -> bool:
        """保存扫描结果"""
        try:
            self.conn.execute('''
                INSERT OR REPLACE INTO scan_results VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, task_id, target, json.dumps(result_data), time.time()))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save result: {e}")
            return False

    def get_result(self, scan_id: str) -> Optional[Dict]:
        """获取扫描结果"""
        cursor = self.conn.execute(
            'SELECT result_data FROM scan_results WHERE scan_id = ?', (scan_id,))
        row = cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None

    def get_history(self, task_id: str = None, limit: int = 50) -> List[Dict]:
        """获取扫描历史"""
        if task_id:
            cursor = self.conn.execute(
                'SELECT * FROM scan_history WHERE task_id=? ORDER BY start_time DESC LIMIT ?',
                (task_id, limit))
        else:
            cursor = self.conn.execute(
                'SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?',
                (limit,))
        return [self._row_to_history(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        """获取统计信息"""
        cursor = self.conn.execute('''
            SELECT 
                COUNT(*) as total_tasks,
                SUM(enabled) as enabled_tasks,
                SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) as running_tasks
            FROM scheduled_tasks
        ''')
        task_row = cursor.fetchone()
        
        cursor = self.conn.execute('SELECT COUNT(*) FROM scan_history')
        history_count = cursor.fetchone()[0]
        
        cursor = self.conn.execute(
            'SELECT COUNT(*) FROM scan_history WHERE status="completed"')
        completed = cursor.fetchone()[0]
        
        return {
            'total_tasks': task_row[0] or 0,
            'enabled_tasks': task_row[1] or 0,
            'running_tasks': task_row[2] or 0,
            'total_scans': history_count,
            'completed_scans': completed
        }

    def _row_to_task(self, row: tuple) -> Dict:
        """行转任务字典"""
        return {
            'task_id': row[0],
            'name': row[1],
            'target': row[2],
            'cron_expression': row[3],
            'trigger_type': row[4],
            'interval_seconds': row[5],
            'enabled': bool(row[6]),
            'config': json.loads(row[7]) if row[7] else {},
            'created_at': row[8],
            'next_run': row[9],
            'status': row[10]
        }

    def _row_to_history(self, row: tuple) -> Dict:
        """行转历史字典"""
        return {
            'scan_id': row[0],
            'task_id': row[1],
            'target': row[2],
            'start_time': row[3],
            'end_time': row[4],
            'status': row[5],
            'result_summary': json.loads(row[6]) if row[6] else {},
            'vulnerabilities_found': row[7],
            'errors': json.loads(row[8]) if row[8] else []
        }

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()


def export_csv(scheduler: PersistentScheduler, output_path: str):
    """导出扫描历史为 CSV"""
    import csv
    
    history = scheduler.get_history(limit=1000)
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        if history:
            writer = csv.DictWriter(f, fieldnames=history[0].keys())
            writer.writeheader()
            writer.writerows(history)
    
    logger.info(f"Exported {len(history)} records to {output_path}")


def export_excel(scheduler: PersistentScheduler, output_path: str):
    """导出扫描历史为 Excel"""
    try:
        import pandas as pd
        
        history = scheduler.get_history(limit=1000)
        df = pd.DataFrame(history)
        df.to_excel(output_path, index=False)
        logger.info(f"Exported {len(history)} records to {output_path}")
    except ImportError:
        logger.error("pandas not installed. Use: pip install pandas openpyxl")


if __name__ == "__main__":
    scheduler = PersistentScheduler()
    print(f"Tasks: {scheduler.get_all_tasks()}")
    print(f"Stats: {scheduler.get_stats()}")

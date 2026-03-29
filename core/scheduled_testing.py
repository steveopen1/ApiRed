"""
Scheduled Testing Module
定时扫描调度模块

功能:
1. 基于 cron 表达式的定时任务
2. 周期性 API 安全扫描
3. 增量扫描支持
4. 扫描结果历史对比

参考: Akto Scheduled Testing
"""

import time
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from croniter import croniter

logger = logging.getLogger(__name__)


class ScheduleStatus(Enum):
    """调度状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TriggerType(Enum):
    """触发类型"""
    CRON = "cron"
    INTERVAL = "interval"
    DAILY = "daily"
    WEEKLY = "weekly"
    MANUAL = "manual"


@dataclass
class ScheduledTask:
    """定时任务"""
    task_id: str
    name: str
    target: str
    cron_expression: str
    trigger_type: TriggerType
    interval_seconds: int = 0
    enabled: bool = True
    last_run: Optional[float] = None
    next_run: Optional[float] = None
    status: ScheduleStatus = ScheduleStatus.PENDING
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSchedule:
    """扫描计划"""
    schedule_id: str
    name: str
    description: str = ""
    tasks: List[ScheduledTask] = field(default_factory=list)
    timezone: str = "UTC"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class ScanHistory:
    """扫描历史"""
    scan_id: str
    task_id: str
    target: str
    start_time: float
    end_time: float
    status: str
    result_summary: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities_found: int = 0
    errors: List[str] = field(default_factory=list)


class CronScheduler:
    """
    Cron 调度器
    
    支持:
    - 标准 cron 表达式 (5-6 字段)
    - 常用预设 (daily, weekly, hourly)
    - 时区支持
    """

    PRESETS = {
        'every_minute': '* * * * *',
        'every_5_minutes': '*/5 * * * *',
        'every_15_minutes': '*/15 * * * *',
        'every_30_minutes': '*/30 * * * *',
        'every_hour': '0 * * * *',
        'every_6_hours': '0 */6 * * *',
        'every_12_hours': '0 */12 * * *',
        'daily_midnight': '0 0 * * *',
        'daily_2am': '0 2 * * *',
        'daily_4am': '0 4 * * *',
        'weekly_monday': '0 0 * * 1',
        'weekly_sunday': '0 0 * * 0',
        'monthly': '0 0 1 * *',
    }

    def __init__(self, timezone: str = "UTC"):
        self.timezone = timezone
        self.tasks: Dict[str, ScheduledTask] = {}
        self.history: List[ScanHistory] = []

    def add_task(
        self,
        task_id: str,
        name: str,
        target: str,
        cron_expression: str,
        trigger_type: TriggerType = TriggerType.CRON,
        config: Dict[str, Any] = None
    ) -> ScheduledTask:
        """
        添加定时任务
        
        Args:
            task_id: 任务 ID
            name: 任务名称
            target: 扫描目标
            cron_expression: cron 表达式
            trigger_type: 触发类型
            config: 扫描配置
            
        Returns:
            ScheduledTask 对象
        """
        if trigger_type == TriggerType.CRON:
            next_run = self._get_next_cron_run(cron_expression)
        elif trigger_type == TriggerType.INTERVAL:
            next_run = time.time() + config.get('interval_seconds', 3600)
        else:
            next_run = None
        
        task = ScheduledTask(
            task_id=task_id,
            name=name,
            target=target,
            cron_expression=cron_expression,
            trigger_type=trigger_type,
            interval_seconds=config.get('interval_seconds', 3600) if config else 3600,
            enabled=True,
            next_run=next_run,
            config=config or {}
        )
        
        self.tasks[task_id] = task
        logger.info(f"Added scheduled task: {name} (ID: {task_id})")
        return task

    def remove_task(self, task_id: str) -> bool:
        """移除任务"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            logger.info(f"Removed scheduled task: {task_id}")
            return True
        return False

    def enable_task(self, task_id: str) -> bool:
        """启用任务"""
        if task_id in self.tasks:
            self.tasks[task_id].enabled = True
            self.tasks[task_id].status = ScheduleStatus.PENDING
            return True
        return False

    def disable_task(self, task_id: str) -> bool:
        """禁用任务"""
        if task_id in self.tasks:
            self.tasks[task_id].enabled = False
            self.tasks[task_id].status = ScheduleStatus.CANCELLED
            return True
        return False

    def get_pending_tasks(self) -> List[ScheduledTask]:
        """获取待执行的任务"""
        current_time = time.time()
        pending = []
        
        for task in self.tasks.values():
            if task.enabled and task.next_run and task.next_run <= current_time:
                pending.append(task)
        
        pending.sort(key=lambda t: t.next_run)
        return pending

    def update_task_status(self, task_id: str, status: ScheduleStatus):
        """更新任务状态"""
        if task_id in self.tasks:
            self.tasks[task_id].status = status

    def record_run(self, task_id: str, history: ScanHistory):
        """记录任务执行"""
        if task_id in self.tasks:
            self.tasks[task_id].last_run = history.end_time
            self.tasks[task_id].status = ScheduleStatus.PENDING
            
            if self.tasks[task_id].trigger_type == TriggerType.CRON:
                self.tasks[task_id].next_run = self._get_next_cron_run(
                    self.tasks[task_id].cron_expression
                )
            elif self.tasks[task_id].trigger_type == TriggerType.INTERVAL:
                self.tasks[task_id].next_run = time.time() + self.tasks[task_id].interval_seconds
        
        self.history.append(history)
        logger.info(f"Recorded scan history for task {task_id}: {history.status}")

    def _get_next_cron_run(self, cron_expression: str) -> Optional[float]:
        """计算下次 cron 执行时间"""
        try:
            now = datetime.now()
            cron = croniter(cron_expression, now)
            return cron.get_next_timestamp()
        except Exception as e:
            logger.error(f"Invalid cron expression: {cron_expression} - {e}")
            return None

    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """获取任务状态"""
        if task_id not in self.tasks:
            return None
        
        task = self.tasks[task_id]
        return {
            'task_id': task.task_id,
            'name': task.name,
            'target': task.target,
            'status': task.status.value,
            'enabled': task.enabled,
            'last_run': datetime.fromtimestamp(task.last_run).isoformat() if task.last_run else None,
            'next_run': datetime.fromtimestamp(task.next_run).isoformat() if task.next_run else None,
            'cron': task.cron_expression
        }

    def get_schedule_summary(self) -> Dict[str, Any]:
        """获取调度摘要"""
        total = len(self.tasks)
        enabled = sum(1 for t in self.tasks.values() if t.enabled)
        running = sum(1 for t in self.tasks.values() if t.status == ScheduleStatus.RUNNING)
        
        return {
            'total_tasks': total,
            'enabled_tasks': enabled,
            'running_tasks': running,
            'tasks': [self.get_task_status(t.task_id) for t in self.tasks.values()]
        }


class ScheduledScanner:
    """
    定时扫描器
    
    使用方式:
    1. 创建调度器
    2. 添加扫描任务
    3. 启动调度循环
    """

    def __init__(self, scheduler: CronScheduler = None):
        self.scheduler = scheduler or CronScheduler()
        self.running = False
        self.scan_callback: Optional[Callable] = None
        self.check_interval = 60

    def set_scan_callback(self, callback: Callable):
        """设置扫描回调函数"""
        self.scan_callback = callback

    async def run_task(self, task: ScheduledTask) -> ScanHistory:
        """执行单个任务"""
        logger.info(f"Starting scheduled scan: {task.name} (target: {task.target})")
        
        self.scheduler.update_task_status(task.task_id, ScheduleStatus.RUNNING)
        
        start_time = time.time()
        history = ScanHistory(
            scan_id=f"scan_{int(start_time)}_{task.task_id}",
            task_id=task.task_id,
            target=task.target,
            start_time=start_time,
            end_time=0,
            status="running"
        )
        
        try:
            if self.scan_callback:
                result = await self.scan_callback(task)
                history.result_summary = result.get('summary', {})
                history.vulnerabilities_found = result.get('vulnerability_count', 0)
            else:
                logger.warning("No scan callback configured")
                history.status = "skipped_no_callback"
            
            history.status = "completed"
            history.end_time = time.time()
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            history.status = "failed"
            history.errors = [str(e)]
            history.end_time = time.time()
        
        self.scheduler.record_run(task.task_id, history)
        
        return history

    async def run_scheduler_loop(self):
        """运行调度循环"""
        self.running = True
        logger.info("Scheduler loop started")
        
        while self.running:
            try:
                pending_tasks = self.scheduler.get_pending_tasks()
                
                for task in pending_tasks:
                    asyncio.create_task(self.run_task(task))
                
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(self.check_interval)
        
        logger.info("Scheduler loop stopped")

    def start(self):
        """启动调度器"""
        self.running = True
        asyncio.create_task(self.run_scheduler_loop())
        logger.info("Scheduled scanner started")

    def stop(self):
        """停止调度器"""
        self.running = False
        logger.info("Scheduled scanner stopped")

    def create_daily_scan(
        self,
        name: str,
        target: str,
        hour: int = 2,
        config: Dict[str, Any] = None
    ) -> ScheduledTask:
        """创建每日扫描任务"""
        task_id = f"daily_{name.replace(' ', '_').lower()}_{int(time.time())}"
        cron_expr = f"0 {hour} * * *"
        
        return self.scheduler.add_task(
            task_id=task_id,
            name=name,
            target=target,
            cron_expression=cron_expr,
            trigger_type=TriggerType.CRON,
            config=config
        )

    def create_weekly_scan(
        self,
        name: str,
        target: str,
        day_of_week: int = 0,
        hour: int = 2,
        config: Dict[str, Any] = None
    ) -> ScheduledTask:
        """创建每周扫描任务"""
        task_id = f"weekly_{name.replace(' ', '_').lower()}_{int(time.time())}"
        cron_expr = f"0 {hour} * * {day_of_week}"
        
        return self.scheduler.add_task(
            task_id=task_id,
            name=name,
            target=target,
            cron_expression=cron_expr,
            trigger_type=TriggerType.CRON,
            config=config
        )

    def create_interval_scan(
        self,
        name: str,
        target: str,
        interval_hours: int = 6,
        config: Dict[str, Any] = None
    ) -> ScheduledTask:
        """创建间隔扫描任务"""
        task_id = f"interval_{name.replace(' ', '_').lower()}_{int(time.time())}"
        
        if config is None:
            config = {}
        config['interval_seconds'] = interval_hours * 3600
        
        return self.scheduler.add_task(
            task_id=task_id,
            name=name,
            target=target,
            cron_expression="",
            trigger_type=TriggerType.INTERVAL,
            config=config
        )


class IncrementalScanner:
    """
    增量扫描器
    
    功能:
    1. 对比两次扫描结果
    2. 发现新增 API
    3. 检测 API 变更
    4. 生成差异报告
    """

    def __init__(self):
        self.previous_results: Dict[str, Any] = {}

    def save_snapshot(self, scan_id: str, results: Dict[str, Any]):
        """保存扫描快照"""
        snapshot = {
            'scan_id': scan_id,
            'timestamp': time.time(),
            'endpoints': self._extract_endpoints(results),
            'vulnerabilities': self._extract_vulnerabilities(results),
            'summary': results.get('summary', {})
        }
        
        self.previous_results[scan_id] = snapshot
        logger.info(f"Saved snapshot: {scan_id}")

    def compare(
        self,
        current_results: Dict[str, Any],
        baseline_scan_id: str = None
    ) -> Dict[str, Any]:
        """
        对比当前结果与基线
        
        Args:
            current_results: 当前扫描结果
            baseline_scan_id: 基线扫描 ID
            
        Returns:
            差异报告
        """
        baseline = None
        if baseline_scan_id and baseline_scan_id in self.previous_results:
            baseline = self.previous_results[baseline_scan_id]
        elif self.previous_results:
            baseline = list(self.previous_results.values())[-1]
        
        if not baseline:
            return {
                'is_incremental': False,
                'reason': 'No baseline available',
                'current_endpoints': self._extract_endpoints(current_results)
            }
        
        current_endpoints = set(self._extract_endpoints(current_results))
        baseline_endpoints = set(baseline['endpoints'])
        
        new_endpoints = current_endpoints - baseline_endpoints
        removed_endpoints = baseline_endpoints - current_endpoints
        unchanged_endpoints = current_endpoints & baseline_endpoints
        
        current_vulns = self._extract_vulnerabilities(current_results)
        baseline_vulns = set(baseline['vulnerabilities'])
        current_vuln_set = set(current_vulns)
        
        new_vulnerabilities = current_vuln_set - baseline_vulns
        fixed_vulnerabilities = baseline_vulns - current_vuln_set
        
        return {
            'is_incremental': True,
            'baseline_scan_id': baseline.get('scan_id'),
            'baseline_timestamp': baseline.get('timestamp'),
            'endpoints': {
                'total_current': len(current_endpoints),
                'new': list(new_endpoints),
                'removed': list(removed_endpoints),
                'unchanged': list(unchanged_endpoints)
            },
            'vulnerabilities': {
                'total_current': len(current_vulns),
                'new': list(new_vulnerabilities),
                'fixed': list(fixed_vulnerabilities)
            },
            'summary': {
                'new_endpoints_count': len(new_endpoints),
                'removed_endpoints_count': len(removed_endpoints),
                'new_vulnerabilities_count': len(new_vulnerabilities),
                'fixed_vulnerabilities_count': len(fixed_vulnerabilities)
            }
        }

    def _extract_endpoints(self, results: Dict[str, Any]) -> List[str]:
        """提取端点列表"""
        endpoints = []
        
        for ep in results.get('api_endpoints', []):
            path = ep.get('path', ep.get('url', ''))
            method = ep.get('method', 'GET')
            endpoints.append(f"{method}:{path}")
        
        return list(set(endpoints))

    def _extract_vulnerabilities(self, results: Dict[str, Any]) -> List[str]:
        """提取漏洞列表"""
        vulns = []
        
        for vuln in results.get('vulnerabilities', []):
            vuln_id = f"{vuln.get('type', 'unknown')}:{vuln.get('path', '')}:{vuln.get('method', '')}"
            vulns.append(vuln_id)
        
        return list(set(vulns))


def create_schedule_file(schedule: ScanSchedule, file_path: str):
    """创建调度配置文件"""
    data = {
        'schedule_id': schedule.schedule_id,
        'name': schedule.name,
        'description': schedule.description,
        'timezone': schedule.timezone,
        'tasks': [
            {
                'task_id': t.task_id,
                'name': t.name,
                'target': t.target,
                'cron_expression': t.cron_expression,
                'trigger_type': t.trigger_type.value,
                'enabled': t.enabled,
                'config': t.config
            }
            for t in schedule.tasks
        ]
    }
    
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Created schedule file: {file_path}")


def load_schedule_file(file_path: str) -> ScanSchedule:
    """加载调度配置文件"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    schedule = ScanSchedule(
        schedule_id=data['schedule_id'],
        name=data['name'],
        description=data.get('description', ''),
        timezone=data.get('timezone', 'UTC')
    )
    
    scheduler = CronScheduler(timezone=schedule.timezone)
    
    for task_data in data.get('tasks', []):
        task = scheduler.add_task(
            task_id=task_data['task_id'],
            name=task_data['name'],
            target=task_data['target'],
            cron_expression=task_data.get('cron_expression', ''),
            trigger_type=TriggerType(task_data.get('trigger_type', 'cron')),
            config=task_data.get('config', {})
        )
        task.enabled = task_data.get('enabled', True)
        schedule.tasks.append(task)
    
    return schedule


if __name__ == "__main__":
    print("Scheduled Testing Module")
    scheduler = CronScheduler()
    
    print("Available presets:")
    for name, expr in CronScheduler.PRESETS.items():
        print(f"  {name}: {expr}")

"""
Observability Module
可观测性模块 - 阶段埋点、运行画像、转化率追踪
性能监控：操作耗时记录与性能报告生成
"""

import time
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from collections import defaultdict
import threading


@dataclass
class StageMetrics:
    """阶段指标"""
    stage_name: str
    start_time: float
    end_time: float = 0.0
    duration: float = 0.0
    input_count: int = 0
    output_count: int = 0
    error_count: int = 0
    throughput: float = 0.0
    success_rate: float = 0.0
    
    def finish(self):
        """结束阶段"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        if self.input_count > 0:
            self.success_rate = (self.input_count - self.error_count) / self.input_count * 100
        if self.duration > 0:
            self.throughput = self.output_count / self.duration
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'stage_name': self.stage_name,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': round(self.duration, 3),
            'input_count': self.input_count,
            'output_count': self.output_count,
            'error_count': self.error_count,
            'success_rate': round(self.success_rate, 2),
            'throughput': round(self.throughput, 2)
        }


class StageTracker:
    """阶段追踪器"""
    
    STAGE_NAMES = [
        'initialization',
        'js_collection',
        'api_extraction',
        'base_url_discovery',
        'service_discovery',
        'api_testing',
        'unauthorized_detection',
        'sensitive_detection',
        'vuln_testing',
        'reporting'
    ]
    
    def __init__(self):
        self.stages: Dict[str, StageMetrics] = {}
        self.current_stage: Optional[str] = None
        self.start_time: float = time.time()
    
    def start_stage(self, stage_name: str, input_count: int = 0):
        """开始阶段"""
        if self.current_stage:
            self.finish_stage()
        
        self.current_stage = stage_name
        self.stages[stage_name] = StageMetrics(
            stage_name=stage_name,
            start_time=time.time(),
            input_count=input_count
        )
    
    def update_count(self, output_count: int = None, error_count: int = None):
        """更新计数"""
        if self.current_stage and self.current_stage in self.stages:
            stage = self.stages[self.current_stage]
            if output_count is not None:
                stage.output_count = output_count
            if error_count is not None:
                stage.error_count = error_count
    
    def increment_output(self):
        """增加输出计数"""
        if self.current_stage and self.current_stage in self.stages:
            self.stages[self.current_stage].output_count += 1
    
    def increment_error(self):
        """增加错误计数"""
        if self.current_stage and self.current_stage in self.stages:
            self.stages[self.current_stage].error_count += 1
    
    def finish_stage(self):
        """结束当前阶段"""
        if self.current_stage and self.current_stage in self.stages:
            self.stages[self.current_stage].finish()
            self.current_stage = None
    
    def get_stage(self, stage_name: str) -> Optional[StageMetrics]:
        """获取阶段指标"""
        return self.stages.get(stage_name)
    
    def get_all_stages(self) -> List[StageMetrics]:
        """获取所有阶段"""
        return list(self.stages.values())
    
    def get_total_duration(self) -> float:
        """获取总耗时"""
        if self.stages:
            return sum(s.duration for s in self.stages.values())
        return time.time() - self.start_time


class ConversionTracker:
    """转化率追踪器"""
    
    def __init__(self):
        self.funnel: Dict[str, int] = defaultdict(int)
        self.conversions: Dict[str, float] = {}
    
    def record(self, stage: str, count: int = 1):
        """记录阶段数据"""
        self.funnel[stage] += count
    
    def calculate_conversion(
        self,
        from_stage: str,
        to_stage: str
    ) -> float:
        """计算转化率"""
        from_count = self.funnel.get(from_stage, 0)
        to_count = self.funnel.get(to_stage, 0)
        
        if from_count == 0:
            return 0.0
        
        return to_count / from_count * 100
    
    def set_conversion(self, key: str, value: float):
        """设置转化率"""
        self.conversions[key] = value
    
    def get_funnel_stats(self) -> Dict[str, Any]:
        """获取漏斗统计"""
        stages = [
            'js_discovered',
            'js_alive',
            'api_extracted',
            'api_unique',
            'api_tested',
            'api_high_value',
            'unauth_candidates',
            'unauth_verified',
            'sensitive_found',
            'sensitive_verified'
        ]
        
        return {
            'stages': dict(self.funnel),
            'conversion_rates': self.conversions
        }


class RunProfiler:
    """运行画像生成器"""
    
    def __init__(self):
        self.tracker = StageTracker()
        self.conversion = ConversionTracker()
        self.start_time: float = time.time()
        self.end_time: float = 0.0
        self.metadata: Dict[str, Any] = {}
    
    def set_metadata(self, key: str, value: Any):
        """设置元数据"""
        self.metadata[key] = value
    
    def finish(self):
        """结束分析"""
        self.end_time = time.time()
        if self.tracker.current_stage:
            self.tracker.finish_stage()
    
    def generate_profile(self) -> Dict[str, Any]:
        """生成运行画像"""
        total_duration = self.end_time - self.start_time if self.end_time > 0 else time.time() - self.start_time
        
        stages = self.tracker.get_all_stages()
        slowest_stage = max(stages, key=lambda s: s.duration) if stages else None
        fastest_stage = min(stages, key=lambda s: s.duration) if stages else None
        
        total_input = sum(s.input_count for s in stages)
        total_output = sum(s.output_count for s in stages)
        total_errors = sum(s.error_count for s in stages)
        
        return {
            'metadata': self.metadata,
            'timing': {
                'total_duration': round(total_duration, 3),
                'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
                'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time > 0 else None
            },
            'stages': {
                'total': len(stages),
                'slowest': {
                    'name': slowest_stage.stage_name,
                    'duration': round(slowest_stage.duration, 3) if slowest_stage else 0
                } if slowest_stage else None,
                'fastest': {
                    'name': fastest_stage.stage_name,
                    'duration': round(fastest_stage.duration, 3) if fastest_stage else 0
                } if fastest_stage else None
            },
            'throughput': {
                'total_input': total_input,
                'total_output': total_output,
                'total_errors': total_errors,
                'overall_rate': round(total_output / total_duration * 100, 2) if total_duration > 0 else 0
            },
            'funnel': self.conversion.get_funnel_stats(),
            'recommendations': self._generate_recommendations(stages)
        }
    
    def _generate_recommendations(self, stages: List[StageMetrics]) -> List[str]:
        """生成优化建议"""
        recommendations = []
        
        for stage in stages:
            if stage.duration > 60 and stage.throughput < 1:
                recommendations.append(
                    f"阶段 '{stage.stage_name}' 耗时较长({round(stage.duration, 1)}s)，考虑优化"
                )
            
            if stage.success_rate < 80:
                recommendations.append(
                    f"阶段 '{stage.stage_name}' 成功率较低({round(stage.success_rate, 1)}%)，检查错误原因"
                )
            
            if stage.input_count > 0 and stage.output_count == 0:
                recommendations.append(
                    f"阶段 '{stage.stage_name}' 无有效输出，可能需要调整策略"
                )
        
        return recommendations
    
    def export_json(self) -> str:
        """导出JSON"""
        return json.dumps(self.generate_profile(), ensure_ascii=False, indent=2)
    
    def export_dict(self) -> Dict:
        """导出字典"""
        return self.generate_profile()


class MetricsCollector:
    """指标收集器"""
    
    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timestamps: Dict[str, float] = {}
    
    def increment(self, name: str, value: int = 1):
        """递增计数器"""
        self.counters[name] += value
    
    def set_gauge(self, name: str, value: float):
        """设置仪表值"""
        self.gauges[name] = value
        self.timestamps[name] = time.time()
    
    def record_histogram(self, name: str, value: float):
        """记录直方图值"""
        self.histograms[name].append(value)
    
    def get_snapshot(self) -> Dict[str, Any]:
        """获取快照"""
        return {
            'counters': dict(self.counters),
            'gauges': {
                k: {'value': v, 'timestamp': self.timestamps.get(k)}
                for k, v in self.gauges.items()
            },
            'histograms': {
                k: {
                    'count': len(v),
                    'min': min(v) if v else 0,
                    'max': max(v) if v else 0,
                    'avg': sum(v) / len(v) if v else 0
                }
                for k, v in self.histograms.items()
            }
        }


class PerformanceMonitor:
    """
    性能监控器
    
    记录操作耗时并生成性能报告。
    支持多线程安全操作。
    """
    
    def __init__(self):
        self._durations: Dict[str, List[float]] = defaultdict(list)
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._start_times: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._enabled = True
    
    def enable(self):
        """启用性能监控"""
        self._enabled = True
    
    def disable(self):
        """禁用性能监控"""
        self._enabled = False
    
    def record_duration(self, operation: str, duration: float):
        """
        记录操作耗时
        
        Args:
            operation: 操作名称
            duration: 耗时（秒）
        """
        if not self._enabled:
            return
        
        with self._lock:
            self._durations[operation].append(duration)
            self._operation_counts[operation] += 1
    
    def start_operation(self, operation: str) -> float:
        """
        开始记录操作
        
        Args:
            operation: 操作名称
            
        Returns:
            开始时间戳
        """
        start_time = time.time()
        with self._lock:
            self._start_times[operation] = start_time
        return start_time
    
    def end_operation(self, operation: str) -> Optional[float]:
        """
        结束记录操作
        
        Args:
            operation: 操作名称
            
        Returns:
            耗时，如果操作未开始返回 None
        """
        with self._lock:
            if operation not in self._start_times:
                return None
            start_time = self._start_times.pop(operation)
        
        duration = time.time() - start_time
        self.record_duration(operation, duration)
        return duration
    
    def get_operation_stats(self, operation: str) -> Dict[str, float]:
        """
        获取操作的统计信息
        
        Args:
            operation: 操作名称
            
        Returns:
            包含 count, total, avg, min, max 的字典
        """
        with self._lock:
            durations = self._durations.get(operation, [])
            count = len(durations)
            
            if count == 0:
                return {
                    'count': 0,
                    'total': 0.0,
                    'avg': 0.0,
                    'min': 0.0,
                    'max': 0.0
                }
            
            return {
                'count': count,
                'total': round(sum(durations), 3),
                'avg': round(sum(durations) / count, 3),
                'min': round(min(durations), 3),
                'max': round(max(durations), 3)
            }
    
    def get_report(self) -> Dict[str, Any]:
        """
        获取性能报告
        
        Returns:
            包含所有操作统计的字典
        """
        with self._lock:
            operations = list(self._durations.keys())
        
        report = {
            'total_operations': len(operations),
            'operations': {}
        }
        
        total_duration = 0.0
        slowest_operation = None
        slowest_duration = 0.0
        
        for operation in operations:
            stats = self.get_operation_stats(operation)
            report['operations'][operation] = stats
            total_duration += stats['total']
            
            if stats['total'] > slowest_duration:
                slowest_duration = stats['total']
                slowest_operation = operation
        
        report['total_duration'] = round(total_duration, 3)
        report['slowest_operation'] = slowest_operation
        report['slowest_duration'] = slowest_duration
        
        return report
    
    def get_top_slowest(self, n: int = 5) -> List[Dict[str, Any]]:
        """
        获取最慢的 N 个操作
        
        Args:
            n: 返回的操作数量
            
        Returns:
            按耗时排序的操作列表
        """
        report = self.get_report()
        operations = [
            {'operation': op, **stats}
            for op, stats in report['operations'].items()
        ]
        
        operations.sort(key=lambda x: x['total'], reverse=True)
        return operations[:n]
    
    def reset(self):
        """重置所有性能数据"""
        with self._lock:
            self._durations.clear()
            self._operation_counts.clear()
            self._start_times.clear()
    
    def export_json(self) -> str:
        """
        导出 JSON 格式的性能报告
        
        Returns:
            JSON 字符串
        """
        return json.dumps(self.get_report(), ensure_ascii=False, indent=2)


class OperationTimer:
    """
    操作计时器上下文管理器
    
    Usage:
        with OperationTimer(monitor, 'my_operation'):
            # do something
    """
    
    def __init__(self, monitor: PerformanceMonitor, operation: str):
        self.monitor = monitor
        self.operation = operation
        self.start_time: Optional[float] = None
    
    def __enter__(self):
        self.start_time = self.monitor.start_operation(self.operation)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            self.monitor.end_operation(self.operation)

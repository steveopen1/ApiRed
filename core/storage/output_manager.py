"""
Output Manager Module
统一输出目录管理模块

目录结构:
/result
-- http_xxx_xxx_xx
--- real_time
---- realtime_*.txt
--- results
---- scan_result.json
---- {target}/
----- attack_chain.html
----- flux_report.html
---- apired_report_*.html
---- apired_report_*.json
---- apired_report_*.xlsx
---- apired_report_*.csv
---- openapi.yaml
--- checkpoint
---- checkpoint_*.json
---- incremental.db
---- apired.log
"""

import os
import logging
from typing import Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class OutputManager:
    """
    统一输出目录管理器
    
    确保所有输出文件按照统一的目录结构组织:
    output_dir/
    ├── real_time/           # 实时输出文件
    │   ├── realtime_urls_*.txt
    │   ├── realtime_subdomains_*.txt
    │   ├── realtime_rootdomains_*.txt
    │   ├── realtime_apis_*.txt
    │   ├── realtime_ips_*.txt
    │   ├── realtime_sensitive_*.txt
    │   ├── realtime_js_*.txt
    │   └── realtime_vulns_*.txt
    ├── results/              # 扫描结果报告
    │   ├── scan_result.json
    │   ├── {target}/
    │   │   ├── attack_chain.html
    │   │   └── flux_report.html
    │   ├── apired_report_*.html
    │   ├── apired_report_*.json
    │   ├── apired_report_*.xlsx
    │   ├── apired_report_*.csv
    │   └── openapi.yaml
    ├── checkpoint/           # 检查点和数据库
    │   ├── checkpoint_*.json
    │   └── incremental.db
    └── apired.log           # 运行日志
    """
    
    def __init__(self, base_dir: str = "./results"):
        self.base_dir = base_dir
        self.target_name = ""
        self._timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self._real_time_dir = None
        self._results_dir = None
        self._checkpoint_dir = None
        
    def setup_for_target(self, target_url: str) -> 'OutputManager':
        """
        为特定目标设置目录结构
        
        Args:
            target_url: 目标 URL
            
        Returns:
            self
        """
        self.target_name = self._sanitize_filename(target_url)
        
        self._real_time_dir = os.path.join(
            self.base_dir, 
            self.target_name,
            'real_time'
        )
        self._results_dir = os.path.join(
            self.base_dir, 
            self.target_name,
            'results'
        )
        self._checkpoint_dir = os.path.join(
            self.base_dir,
            self.target_name,
            'checkpoint'
        )
        
        self._ensure_dirs()
        
        return self
    
    def _sanitize_filename(self, filename: str) -> str:
        """将 URL 或文件名转换为安全的目录名"""
        filename = filename.replace('://', '_')
        filename = filename.replace('https', '')
        filename = filename.replace('http', '')
        filename = filename.replace('/', '_')
        filename = filename.replace('.', '_')
        filename = filename.replace(':', '')
        filename = filename.replace('?', '_')
        filename = filename.replace('&', '_')
        filename = filename.replace('=', '_')
        
        if not filename.startswith('http'):
            filename = 'http_' + filename
        
        while '__' in filename:
            filename = filename.replace('__', '_')
        
        return filename.rstrip('_')
    
    def _ensure_dirs(self):
        """确保所有目录存在"""
        os.makedirs(self._real_time_dir, exist_ok=True)
        os.makedirs(self._results_dir, exist_ok=True)
        os.makedirs(self._checkpoint_dir, exist_ok=True)
    
    @property
    def real_time_dir(self) -> str:
        """实时输出目录"""
        if self._real_time_dir is None:
            self._real_time_dir = os.path.join(self.base_dir, 'real_time')
            os.makedirs(self._real_time_dir, exist_ok=True)
        return self._real_time_dir
    
    @property
    def results_dir(self) -> str:
        """结果输出目录"""
        if self._results_dir is None:
            self._results_dir = os.path.join(self.base_dir, 'results')
            os.makedirs(self._results_dir, exist_ok=True)
        return self._results_dir
    
    @property
    def checkpoint_dir(self) -> str:
        """检查点目录"""
        if self._checkpoint_dir is None:
            self._checkpoint_dir = os.path.join(self.base_dir, 'checkpoint')
            os.makedirs(self._checkpoint_dir, exist_ok=True)
        return self._checkpoint_dir
    
    @property
    def log_file(self) -> str:
        """日志文件路径"""
        return os.path.join(self.base_dir, 'apired.log')
    
    def get_realtime_output_path(self, filename: str) -> str:
        """获取实时输出文件的完整路径"""
        return os.path.join(self.real_time_dir, filename)
    
    def get_result_output_path(self, filename: str) -> str:
        """获取结果输出文件的完整路径"""
        return os.path.join(self.results_dir, filename)
    
    def get_checkpoint_path(self, filename: str) -> str:
        """获取检查点文件的完整路径"""
        return os.path.join(self.checkpoint_dir, filename)
    
    def get_target_result_dir(self) -> str:
        """获取目标专属的结果目录"""
        target_dir = os.path.join(self.results_dir, self.target_name)
        os.makedirs(target_dir, exist_ok=True)
        return target_dir
    
    def get_scan_result_path(self) -> str:
        """获取 scan_result.json 的完整路径"""
        return os.path.join(self.results_dir, 'scan_result.json')
    
    def get_attack_chain_path(self) -> str:
        """获取 attack_chain.html 的完整路径"""
        return os.path.join(self.get_target_result_dir(), 'attack_chain.html')
    
    def get_flux_report_path(self) -> str:
        """获取 flux_report.html 的完整路径"""
        return os.path.join(self.get_target_result_dir(), 'flux_report.html')
    
    def get_openapi_path(self) -> str:
        """获取 openapi.yaml 的完整路径"""
        return os.path.join(self.results_dir, 'openapi.yaml')
    
    def get_checkpoint_db_path(self) -> str:
        """获取 incremental.db 的完整路径"""
        return os.path.join(self.checkpoint_dir, 'incremental.db')
    
    def get_checkpoint_json_path(self) -> str:
        """获取带时间戳的 checkpoint json 路径"""
        return os.path.join(
            self.checkpoint_dir, 
            f"checkpoint_{self._timestamp}.json"
        )
    
    def get_report_prefix(self) -> str:
        """获取报告文件名前缀"""
        return os.path.join(self.results_dir, 'apired_report')
    
    def get_summary(self) -> dict:
        """获取目录结构摘要"""
        return {
            'base_dir': self.base_dir,
            'target': self.target_name,
            'real_time_dir': self._real_time_dir,
            'results_dir': self._results_dir,
            'checkpoint_dir': self._checkpoint_dir,
            'log_file': self.log_file,
            'structure': '''
{base_dir}/
├── {target}/
│   ├── real_time/
│   │   ├── realtime_urls_*.txt
│   │   ├── realtime_subdomains_*.txt
│   │   ├── realtime_rootdomains_*.txt
│   │   ├── realtime_apis_*.txt
│   │   ├── realtime_ips_*.txt
│   │   ├── realtime_sensitive_*.txt
│   │   ├── realtime_js_*.txt
│   │   └── realtime_vulns_*.txt
│   ├── results/
│   │   ├── scan_result.json
│   │   ├── {target}/
│   │   │   ├── attack_chain.html
│   │   │   └── flux_report.html
│   │   ├── apired_report_*.html
│   │   ├── apired_report_*.json
│   │   ├── apired_report_*.xlsx
│   │   ├── apired_report_*.csv
│   │   └── openapi.yaml
│   └── checkpoint/
│       ├── checkpoint_*.json
│       └── incremental.db
└── apired.log
'''.format(base_dir=self.base_dir, target=self.target_name)
        }


_output_manager_instance: Optional[OutputManager] = None


def get_output_manager(base_dir: str = "./results") -> OutputManager:
    """获取全局输出管理器实例"""
    global _output_manager_instance
    if _output_manager_instance is None:
        _output_manager_instance = OutputManager(base_dir)
    return _output_manager_instance


def setup_output_for_target(target_url: str, base_dir: str = "./results") -> OutputManager:
    """为特定目标设置输出目录"""
    manager = get_output_manager(base_dir)
    manager.setup_for_target(target_url)
    return manager

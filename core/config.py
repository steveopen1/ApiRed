"""
ScanConfig - 统一配置
合并 ScannerConfig 和 EngineConfig
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class ScanConfig:
    """统一扫描配置"""
    
    target: str
    
    collectors: Optional[List[str]] = None
    analyzers: Optional[List[str]] = None
    testers: Optional[List[str]] = None
    
    cookies: str = ""
    chrome: bool = True
    attack_mode: str = "all"
    no_api_scan: bool = False
    proxy: Optional[str] = None
    js_depth: int = 3
    
    ai_scan: bool = False
    concurrency: int = 50
    output_format: str = "json"
    
    resume: bool = False
    checkpoint_file: Optional[str] = None
    checkpoint_enabled: bool = True
    verify_ssl: bool = True
    
    targets: List[str] = field(default_factory=list)
    concurrent_targets: int = 5
    aggregate: bool = False
    
    dedupe: bool = True
    store: str = "all"
    
    output_dir: str = "./results"
    
    @classmethod
    def from_scanner_config(cls, config) -> 'ScanConfig':
        """从 ScannerConfig 转换"""
        return cls(
            target=config.target,
            cookies=config.cookies,
            chrome=config.chrome,
            attack_mode=config.attack_mode,
            no_api_scan=config.no_api_scan,
            proxy=config.proxy,
            js_depth=config.js_depth,
            ai_scan=config.ai_scan,
            concurrency=config.concurrency,
            output_format=config.output_format,
            resume=config.resume,
            checkpoint_file=config.checkpoint_file,
            verify_ssl=config.verify_ssl,
            targets=getattr(config, 'targets', []),
            concurrent_targets=getattr(config, 'concurrent_targets', 5),
            aggregate=getattr(config, 'aggregate', False)
        )
    
    @classmethod
    def from_engine_config(cls, config) -> 'ScanConfig':
        """从 EngineConfig 转换"""
        return cls(
            target=config.target,
            collectors=config.collectors,
            analyzers=config.analyzers,
            testers=config.testers,
            cookies=config.cookies,
            checkpoint_enabled=config.checkpoint_enabled,
            concurrency=config.concurrency,
            proxy=config.proxy,
            js_depth=config.js_depth,
            ai_scan=config.ai_enabled,
            output_dir=config.output_dir
        )
    
    def to_engine_config(self):
        """转换为 EngineConfig"""
        from .engine import EngineConfig
        return EngineConfig(
            target=self.target,
            collectors=self.collectors,
            analyzers=self.analyzers,
            testers=self.testers,
            ai_enabled=self.ai_scan,
            checkpoint_enabled=self.checkpoint_enabled,
            cookies=self.cookies,
            concurrency=self.concurrency,
            proxy=self.proxy,
            js_depth=self.js_depth,
            output_dir=self.output_dir
        )
    
    def to_scanner_config(self):
        """转换为 ScannerConfig"""
        from .scanner import ScannerConfig
        return ScannerConfig(
            target=self.target,
            cookies=self.cookies,
            chrome=self.chrome,
            attack_mode=self.attack_mode,
            no_api_scan=self.no_api_scan,
            proxy=self.proxy,
            js_depth=self.js_depth,
            ai_scan=self.ai_scan,
            concurrency=self.concurrency,
            output_format=self.output_format,
            resume=self.resume,
            checkpoint_file=self.checkpoint_file,
            verify_ssl=self.verify_ssl,
            targets=self.targets,
            concurrent_targets=self.concurrent_targets,
            aggregate=self.aggregate
        )

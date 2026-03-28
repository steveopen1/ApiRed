"""
ScanEngine 模块化拆分
====================

架构拆分：
- ScanEngineCore: 核心运行流程、初始化、事件机制，检查点、清理
- ScanCollector: 采集阶段所有方法
- ScanAnalyzer: 分析阶段所有方法  
- ScanTester: 测试阶段所有方法
- ScanReporter: 报告生成
- ScanFlux: FLUX 增强检测

迁移状态：
- [x] api_patterns 配置迁移
- [x] ScanEngineCore 核心模块
- [x] ScanCollector 采集模块
- [ ] ScanAnalyzer 分析模块
- [ ] ScanTester 测试模块
- [ ] ScanReporter 报告模块
- [ ] ScanFlux 模块
- [x] 向后兼容层
"""

from .core import ScanEngineCore
from .collector import ScanCollector
from .adapter import ScanEngineAdapter

__all__ = ['ScanEngineCore', 'ScanCollector', 'ScanEngineAdapter']

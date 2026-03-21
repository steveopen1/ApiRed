"""
Plugin System - 插件系统
支持 Collector、Tester、Exporter 插件的动态加载
"""

import importlib
import pkgutil
from typing import Dict, List, Type, Any, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass


class PluginRegistry:
    """插件注册表"""
    
    _collectors: Dict[str, Type] = {}
    _testers: Dict[str, Type] = {}
    _exporters: Dict[str, Type] = {}
    _analyzers: Dict[str, Type] = {}
    
    @classmethod
    def register_collector(cls, name: str, collector_class: Type):
        """注册采集器插件"""
        cls._collectors[name] = collector_class
    
    @classmethod
    def register_tester(cls, name: str, tester_class: Type):
        """注册测试器插件"""
        cls._testers[name] = tester_class
    
    @classmethod
    def register_exporter(cls, name: str, exporter_class: Type):
        """注册导出器插件"""
        cls._exporters[name] = exporter_class
    
    @classmethod
    def register_analyzer(cls, name: str, analyzer_class: Type):
        """注册分析器插件"""
        cls._analyzers[name] = analyzer_class
    
    @classmethod
    def get_collector(cls, name: str) -> Optional[Type]:
        return cls._collectors.get(name)
    
    @classmethod
    def get_tester(cls, name: str) -> Optional[Type]:
        return cls._testers.get(name)
    
    @classmethod
    def get_exporter(cls, name: str) -> Optional[Type]:
        return cls._exporters.get(name)
    
    @classmethod
    def get_analyzer(cls, name: str) -> Optional[Type]:
        return cls._analyzers.get(name)
    
    @classmethod
    def list_collectors(cls) -> List[str]:
        return list(cls._collectors.keys())
    
    @classmethod
    def list_testers(cls) -> List[str]:
        return list(cls._testers.keys())
    
    @classmethod
    def list_exporters(cls) -> List[str]:
        return list(cls._exporters.keys())
    
    @classmethod
    def list_analyzers(cls) -> List[str]:
        return list(cls._analyzers.keys())
    
    @classmethod
    def discover_plugins(cls, package_name: str):
        """自动发现插件"""
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return
        
        for importer, modname, ispkg in pkgutil.iter_modules(package.__path__, f"{package_name}."):
            if ispkg:
                continue
            try:
                module = importlib.import_module(modname)
            except ImportError:
                continue
            
            for attr_name in dir(module):
                try:
                    attr = getattr(module, attr_name)
                    if not isinstance(attr, type):
                        continue
                    if attr is BasePlugin:
                        continue
                    if not issubclass(attr, BasePlugin):
                        continue
                    
                    plugin_name = getattr(attr, 'name', None)
                    if plugin_name is None:
                        plugin_name = _snake_to_name(attr.__name__)
                    
                    if issubclass(attr, CollectorPlugin):
                        cls.register_collector(plugin_name, attr)
                    elif issubclass(attr, TesterPlugin):
                        cls.register_tester(plugin_name, attr)
                    elif issubclass(attr, ExporterPlugin):
                        cls.register_exporter(plugin_name, attr)
                    elif issubclass(attr, BasePlugin):
                        cls.register_analyzer(plugin_name, attr)
                except (TypeError, AttributeError):
                    continue


def _snake_to_name(snake_str: str) -> str:
    """将下划线命名转换为小写名称"""
    return snake_str.replace('_', '').lower()


class BasePlugin(ABC):
    """插件基类"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @abstractmethod
    def initialize(self, config: Dict):
        pass
    
    @abstractmethod
    async def execute(self, context: Dict) -> Dict:
        pass


class CollectorPlugin(BasePlugin):
    """采集器插件接口"""
    
    @abstractmethod
    async def collect(self, target: str) -> List[Any]:
        pass


class TesterPlugin(BasePlugin):
    """测试器插件接口"""
    
    @abstractmethod
    async def test(self, endpoint: Any) -> List[Any]:
        pass


class ExporterPlugin(BasePlugin):
    """导出器插件接口"""
    
    @abstractmethod
    async def export(self, data: Any, path: str):
        pass


class BypassTesterPlugin(TesterPlugin):
    """Bypass 技术测试插件"""
    
    @property
    def name(self) -> str:
        return "bypass"
    
    def __init__(self):
        self.techniques = [
            "header_injection",
            "method_tampering",
            "path_traversal",
            "case_sensitivity",
            "null_byte_injection"
        ]
    
    def initialize(self, config: Dict):
        if 'techniques' in config:
            self.techniques = config['techniques']
    
    async def execute(self, context: Dict) -> Dict:
        return {"tested": len(self.techniques), "techniques": self.techniques}
    
    async def test(self, endpoint: Any) -> List[Dict]:
        results = []
        for technique in self.techniques:
            result = await self._test_technique(endpoint, technique)
            results.append(result)
        return results
    
    async def _test_technique(self, endpoint: Any, technique: str) -> Dict:
        return {
            "technique": technique,
            "vulnerable": False,
            "endpoint": str(endpoint) if endpoint else None
        }


PluginRegistry.register_tester("bypass", BypassTesterPlugin)

"""
Plugin System
插件系统

功能:
- 动态加载测试用例插件
- 插件注册与管理
- 自定义测试用例加载
"""

import os
import sys
import importlib
import logging
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass, field
from pathlib import Path
import yaml

logger = logging.getLogger(__name__)


@dataclass
class PluginInfo:
    """插件信息"""
    name: str
    version: str
    author: str
    description: str
    test_cases: List[Dict[str, Any]] = field(default_factory=list)
    hooks: Dict[str, callable] = field(default_factory=dict)


class PluginRegistry:
    """
    插件注册表
    
    支持:
    - 插件发现与加载
    - 插件元数据解析
    - 测试用例注册
    - 生命周期钩子
    """

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self._plugins: Dict[str, PluginInfo] = {}
        self._test_cases: List[Dict[str, Any]] = []
        self._hooks: Dict[str, List[callable]] = {
            'on_scan_start': [],
            'on_scan_end': [],
            'on_vulnerability_found': [],
            'before_test': [],
            'after_test': [],
        }
        self._plugin_dirs = plugin_dirs or [
            './plugins',
            './testcases/custom',
            os.path.expanduser('~/.apired/plugins')
        ]

    def discover_plugins(self) -> List[str]:
        """发现并加载所有插件"""
        discovered = []
        
        for plugin_dir in self._plugin_dirs:
            if not os.path.exists(plugin_dir):
                continue
                
            for entry in os.listdir(plugin_dir):
                plugin_path = os.path.join(plugin_dir, entry)
                
                if os.path.isfile(plugin_path) and entry.endswith('.yaml'):
                    try:
                        self._load_yaml_plugin(entry[:-5], plugin_path)
                        discovered.append(entry[:-5])
                    except Exception as e:
                        logger.warning(f"Failed to load plugin {entry}: {e}")
                        
                elif os.path.isdir(plugin_path):
                    try:
                        self._load_directory_plugin(entry, plugin_path)
                        discovered.append(entry)
                    except Exception as e:
                        logger.warning(f"Failed to load plugin {entry}: {e}")
        
        logger.info(f"Discovered {len(discovered)} plugins: {discovered}")
        return discovered

    def _load_yaml_plugin(self, name: str, path: str):
        """加载YAML格式的插件"""
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data:
            return
            
        plugin_info = PluginInfo(
            name=data.get('name', name),
            version=data.get('version', '1.0.0'),
            author=data.get('author', 'Unknown'),
            description=data.get('description', ''),
            test_cases=data.get('test_cases', [])
        )
        
        self._plugins[name] = plugin_info
        self._test_cases.extend(plugin_info.test_cases)
        
        if 'hooks' in data:
            self._register_hooks(name, data['hooks'])
        
        logger.info(f"Loaded plugin: {name} v{plugin_info.version}")

    def _load_directory_plugin(self, name: str, path: str):
        """加载目录格式的插件"""
        manifest_path = os.path.join(path, 'plugin.yaml')
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        else:
            data = {'name': name, 'version': '1.0.0', 'test_cases': []}
        
        plugin_info = PluginInfo(
            name=data.get('name', name),
            version=data.get('version', '1.0.0'),
            author=data.get('author', 'Unknown'),
            description=data.get('description', ''),
            test_cases=data.get('test_cases', [])
        )
        
        testcase_dir = os.path.join(path, 'testcases')
        if os.path.exists(testcase_dir):
            for root, dirs, files in os.walk(testcase_dir):
                for file in files:
                    if file.endswith('.yaml') or file.endswith('.yml'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                testcase = yaml.safe_load(f)
                                if testcase:
                                    plugin_info.test_cases.append(testcase)
                        except Exception as e:
                            logger.warning(f"Failed to load testcase {file_path}: {e}")
        
        self._plugins[name] = plugin_info
        self._test_cases.extend(plugin_info.test_cases)
        
        if 'hooks' in data:
            self._register_hooks(name, data['hooks'])
        
        logger.info(f"Loaded plugin: {name} v{plugin_info.version}")

    def _register_hooks(self, plugin_name: str, hooks: Dict[str, Any]):
        """注册插件钩子"""
        for hook_name, hook_func in hooks.items():
            if hook_name in self._hooks:
                if callable(hook_func):
                    self._hooks[hook_name].append(hook_func)
                elif isinstance(hook_func, str):
                    try:
                        module_name, func_name = hook_func.rsplit('.', 1)
                        module = importlib.import_module(module_name)
                        func = getattr(module, func_name)
                        self._hooks[hook_name].append(func)
                    except Exception as e:
                        logger.warning(f"Failed to register hook {hook_name} from {plugin_name}: {e}")

    def register_hook(self, hook_name: str, func: callable):
        """手动注册钩子"""
        if hook_name in self._hooks:
            self._hooks[hook_name].append(func)

    def get_test_cases(self) -> List[Dict[str, Any]]:
        """获取所有测试用例"""
        return self._test_cases.copy()

    def get_test_cases_by_category(self, category: str) -> List[Dict[str, Any]]:
        """按分类获取测试用例"""
        return [
            tc for tc in self._test_cases 
            if tc.get('category', '').lower() == category.lower()
        ]

    def get_plugins(self) -> Dict[str, PluginInfo]:
        """获取所有插件信息"""
        return self._plugins.copy()

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        """获取指定插件信息"""
        return self._plugins.get(name)

    def trigger_hook(self, hook_name: str, *args, **kwargs):
        """触发钩子"""
        if hook_name in self._hooks:
            for func in self._hooks[hook_name]:
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    logger.error(f"Hook {hook_name} failed: {e}")

    def unload_plugin(self, name: str) -> bool:
        """卸载插件"""
        if name in self._plugins:
            plugin = self._plugins[name]
            self._test_cases = [
                tc for tc in self._test_cases 
                if tc not in plugin.test_cases
            ]
            del self._plugins[name]
            logger.info(f"Unloaded plugin: {name}")
            return True
        return False


_global_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    """获取全局插件注册表"""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
        _global_registry.discover_plugins()
    return _global_registry


def load_plugin(path: str) -> bool:
    """加载指定路径的插件"""
    registry = get_plugin_registry()
    try:
        if path.endswith('.yaml'):
            name = os.path.basename(path)[:-5]
            registry._load_yaml_plugin(name, path)
        else:
            name = os.path.basename(path)
            registry._load_directory_plugin(name, path)
        return True
    except Exception as e:
        logger.error(f"Failed to load plugin from {path}: {e}")
        return False


def register_test_case(test_case: Dict[str, Any]):
    """注册自定义测试用例"""
    registry = get_plugin_registry()
    registry._test_cases.append(test_case)


if __name__ == "__main__":
    registry = PluginRegistry()
    plugins = registry.discover_plugins()
    print(f"Found plugins: {plugins}")
    print(f"Total test cases: {len(registry.get_test_cases())}")

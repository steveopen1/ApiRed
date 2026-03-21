"""
Config Module
配置管理 - 线程安全的单例模式
"""

import threading
import yaml
from typing import Any, Optional, Dict
from pathlib import Path


class Config:
    """线程安全的配置管理"""
    
    _instance: Optional['Config'] = None
    _lock = threading.RLock()
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            
            self._config: Dict[str, Any] = {}
            self._lock_inner = threading.RLock()
            self._load_config()
            self._initialized = True
    
    def _load_config(self):
        """加载配置文件"""
        import os
        
        config_paths = [
            'config.yaml',
            os.path.expanduser('~/.chkapi/config.yaml'),
            '/etc/chkapi/config.yaml'
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    loaded = yaml.safe_load(f)
                    if loaded:
                        self._config = loaded
                return
        
        self._config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        return {
            'scanner': {
                'concurrency': {
                    'js_requests': 50,
                    'api_requests': 100,
                    'max_depth': 3,
                    'timeout': 30
                },
                'filters': {
                    'danger_api_filter': True,
                    'off_target_filter': True,
                    'dedupe_filter': True
                },
                'bypass': {
                    'enabled': True,
                    'techniques': [
                        'header_injection',
                        'method_tampering',
                        'path_traversal',
                        'encoding_bypass'
                    ]
                }
            },
            'storage': {
                'database': {
                    'path': './results/{target}/results.db',
                    'wal_mode': True,
                    'cache_size': 64
                },
                'cache': {
                    'js_fingerprint': True,
                    'api_results': True,
                    'ttl': 86400
                }
            },
            'ai': {
                'enabled': False,
                'provider': 'deepseek',
                'base_url': 'https://api.deepseek.com/v1',
                'model': 'deepseek-chat',
                'max_tokens': 2000,
                'thresholds': {
                    'high_value_api_score': 5,
                    'sensitive_confidence': 0.8
                }
            },
            'reporting': {
                'formats': ['json', 'html', 'excel'],
                'sections': [
                    'summary',
                    'api_inventory',
                    'vulnerabilities',
                    'sensitive_data',
                    'service_analysis'
                ]
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值，支持点号分隔的路径
        例如: get('ai.thresholds.high_value_api_score')
        """
        with self._lock_inner:
            keys = key.split('.')
            value = self._config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
    
    def set(self, key: str, value: Any):
        """
        设置配置值，支持点号分隔的路径
        例如: set('ai.enabled', True)
        """
        with self._lock_inner:
            keys = key.split('.')
            config = self._config
            
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            config[keys[-1]] = value
    
    def update(self, config_dict: Dict):
        """批量更新配置"""
        with self._lock_inner:
            self._deep_update(self._config, config_dict)
    
    def _deep_update(self, base: Dict, update: Dict):
        """深度更新字典"""
        for key, value in update.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value
    
    def load_from_file(self, path: str):
        """从 YAML 文件加载配置"""
        with self._lock_inner:
            file_path = Path(path)
            if file_path.exists():
                with open(file_path, 'r', encoding='utf-8') as f:
                    loaded = yaml.safe_load(f)
                    if loaded:
                        self._deep_update(self._config, loaded)
    
    def reload(self):
        """重新加载配置"""
        with self._lock_inner:
            self._load_config()
    
    def to_dict(self) -> Dict:
        """返回配置字典副本"""
        with self._lock_inner:
            import copy
            return copy.deepcopy(self._config)
    
    @property
    def all(self) -> Dict[str, Any]:
        """获取所有配置"""
        return self.to_dict()
    
    @classmethod
    def reset(cls):
        """重置单例（主要用于测试）"""
        with cls._lock:
            cls._instance = None
            cls._initialized = False


config = Config()

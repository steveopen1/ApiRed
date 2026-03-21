"""
Configuration Management Module
统一配置管理模块
"""

import os
import yaml
from typing import Any, Dict, Optional
from pathlib import Path


class Config:
    """配置管理类"""
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        """加载配置文件"""
        config_paths = [
            'config.yaml',
            os.path.expanduser('~/.chkapi/config.yaml'),
            '/etc/chkapi/config.yaml'
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    self._config = yaml.safe_load(f) or {}
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
        """获取配置项"""
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """设置配置项"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
    
    def reload(self):
        """重新加载配置"""
        self._load_config()
    
    @property
    def all(self) -> Dict[str, Any]:
        """获取所有配置"""
        return self._config.copy()


config = Config()

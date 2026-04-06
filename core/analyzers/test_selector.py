"""
Test Selector - 智能测试选择器
基于Akto风格的端点特征智能选择测试用例
"""

from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .endpoint_analyzer import EndpointFeatures, EndpointFeature


class TestCategory(Enum):
    """测试类别"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    IDOR = "idor"
    CORS = "cors_misconfig"
    CRLF = "crlf_injection"
    LFI = "lfi"
    SSTI = "ssti"
    VERBOSE_ERROR = "verbose_error"
    AUTH_BYPASS = "auth_bypass"
    JWT_SECURITY = "jwt_security"
    RATE_LIMIT = "rate_limit"
    INFORMATION_DISCLOSURE = "information_disclosure"
    BOLA = "bola"
    BFLA = "bfla"
    INJECTION_ATTACKS = "injection_attacks"
    INPUT_VALIDATION = "input_validation"
    HTTP_HEADERS = "http_headers"
    SECURITY_MISCONFIG = "security_misconfig"
    VERSION_DISCLOSURE = "version_disclosure"
    MASS_ASSIGNMENT = "mass_assignment"
    GRAPHQL = "graphql"
    SPRING_BOOT_ACTUATOR = "spring_boot_actuator"
    XSS_REFLECTED = "xss_reflected"
    CSRF = "csrf"
    SESSION_FIXATION = "session_fixation"
    CLOUD_CONFIG = "cloud_config"
    DEV_OPS_CONFIG = "devops_config"
    XXE = "xxe"
    XML_BOMB = "xml_bomb"
    GRPC_SECURITY = "grpc_security"
    DOM_XSS = "dom_xss"
    OAUTH2 = "oauth2"
    MFA_BRUTE_FORCE = "mfa_brute_force"
    MESSAGE_QUEUE = "message_queue"
    KAFKA_SECURITY = "kafka_security"
    RABBITMQ_SECURITY = "rabbitmq_security"
    REDIS_SECURITY = "redis_security"


@dataclass
class TestSelection:
    """测试选择结果"""
    test_name: str
    test_category: TestCategory
    priority: int
    reason: str
    param_name: Optional[str] = None
    payload: Optional[str] = None


@dataclass
class TestSelectionRule:
    """测试选择规则"""
    name: str
    category: TestCategory
    required_features: List[EndpointFeature]
    excluded_features: List[EndpointFeature] = field(default_factory=list)
    required_path_patterns: List[str] = field(default_factory=list)
    excluded_path_patterns: List[str] = field(default_factory=list)
    priority: int = 5
    param_name_hints: List[str] = field(default_factory=list)


class TestSelector:
    """智能测试选择器"""
    
    def __init__(self):
        self.rules: List[TestSelectionRule] = self._build_rules()
    
    def _build_rules(self) -> List[TestSelectionRule]:
        """构建测试选择规则"""
        return [
            TestSelectionRule(
                name="SSRF via URL parameter",
                category=TestCategory.SSRF,
                required_features=[EndpointFeature.HAS_URL_PARAM],
                excluded_features=[],
                priority=9,
                param_name_hints=['url', 'uri', 'link', 'redirect', 'callback']
            ),
            TestSelectionRule(
                name="LFI via file parameter",
                category=TestCategory.LFI,
                required_features=[EndpointFeature.HAS_FILE_PARAM],
                excluded_features=[],
                priority=8,
                param_name_hints=['file', 'path', 'doc', 'attachment']
            ),
            TestSelectionRule(
                name="SQL Injection via search parameter",
                category=TestCategory.SQL_INJECTION,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=9,
                param_name_hints=['q', 'query', 'search', 'keyword']
            ),
            TestSelectionRule(
                name="SQL Injection via ID parameter",
                category=TestCategory.SQL_INJECTION,
                required_features=[EndpointFeature.HAS_ID_PARAM],
                excluded_features=[],
                priority=8,
                param_name_hints=['id', 'uuid']
            ),
            TestSelectionRule(
                name="XSS via search parameter",
                category=TestCategory.XSS,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=8,
                param_name_hints=['q', 'query', 'search']
            ),
            TestSelectionRule(
                name="XSS via user input",
                category=TestCategory.XSS,
                required_features=[EndpointFeature.HAS_USER_PARAM],
                excluded_features=[],
                priority=7,
                param_name_hints=['username', 'user', 'name']
            ),
            TestSelectionRule(
                name="Command Injection via file parameter",
                category=TestCategory.COMMAND_INJECTION,
                required_features=[EndpointFeature.HAS_FILE_PARAM],
                excluded_features=[],
                priority=7,
                param_name_hints=['file', 'path', 'name']
            ),
            TestSelectionRule(
                name="IDOR via ID parameter",
                category=TestCategory.IDOR,
                required_features=[EndpointFeature.HAS_ID_PARAM],
                excluded_features=[],
                priority=9,
                param_name_hints=['id', 'user_id', 'order_id']
            ),
            TestSelectionRule(
                name="BOLA via object reference",
                category=TestCategory.BOLA,
                required_features=[EndpointFeature.HAS_ID_PARAM, EndpointFeature.IS_USER_ENDPOINT],
                excluded_features=[],
                priority=9
            ),
            TestSelectionRule(
                name="CRLF Injection via parameter",
                category=TestCategory.CRLF,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=6,
                param_name_hints=['q', 'query', 'search']
            ),
            TestSelectionRule(
                name="SSTI via template parameter",
                category=TestCategory.SSTI,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=7,
                param_name_hints=['template', 'view', 'render']
            ),
            TestSelectionRule(
                name="Verbose Error on sensitive endpoint",
                category=TestCategory.VERBOSE_ERROR,
                required_features=[EndpointFeature.IS_SENSITIVE_ENDPOINT],
                excluded_features=[],
                priority=5
            ),
            TestSelectionRule(
                name="CORS Misconfiguration on API endpoint",
                category=TestCategory.CORS,
                required_features=[EndpointFeature.IS_API_ENDPOINT],
                excluded_features=[],
                priority=6
            ),
            TestSelectionRule(
                name="Authentication Bypass on login endpoint",
                category=TestCategory.AUTH_BYPASS,
                required_features=[EndpointFeature.IS_LOGIN_ENDPOINT],
                excluded_features=[],
                priority=10
            ),
            TestSelectionRule(
                name="JWT Security on auth endpoint",
                category=TestCategory.JWT_SECURITY,
                required_features=[EndpointFeature.IS_LOGIN_ENDPOINT],
                excluded_features=[],
                priority=9
            ),
            TestSelectionRule(
                name="Rate Limiting on sensitive endpoint",
                category=TestCategory.RATE_LIMIT,
                required_features=[EndpointFeature.IS_SENSITIVE_ENDPOINT],
                excluded_features=[],
                priority=6
            ),
            TestSelectionRule(
                name="Information Disclosure on sensitive endpoint",
                category=TestCategory.INFORMATION_DISCLOSURE,
                required_features=[EndpointFeature.IS_SENSITIVE_ENDPOINT],
                excluded_features=[],
                priority=7
            ),
            TestSelectionRule(
                name="IDOR on user endpoint",
                category=TestCategory.IDOR,
                required_features=[EndpointFeature.IS_USER_ENDPOINT],
                excluded_features=[],
                priority=8
            ),
            TestSelectionRule(
                name="SQL Injection on search endpoint",
                category=TestCategory.SQL_INJECTION,
                required_features=[EndpointFeature.IS_SEARCH_ENDPOINT],
                excluded_features=[],
                priority=9
            ),
            TestSelectionRule(
                name="XSS on upload endpoint",
                category=TestCategory.XSS,
                required_features=[EndpointFeature.IS_UPLOAD_ENDPOINT],
                excluded_features=[],
                priority=5
            ),
            TestSelectionRule(
                name="BFLA - Function Level Authorization on admin endpoint",
                category=TestCategory.BFLA,
                required_features=[EndpointFeature.IS_ADMIN_ENDPOINT],
                excluded_features=[],
                priority=10
            ),
            TestSelectionRule(
                name="Injection Attacks on login endpoint",
                category=TestCategory.INJECTION_ATTACKS,
                required_features=[EndpointFeature.IS_LOGIN_ENDPOINT],
                excluded_features=[],
                priority=9,
                param_name_hints=['username', 'email', 'password', 'login']
            ),
            TestSelectionRule(
                name="Input Validation on search endpoint",
                category=TestCategory.INPUT_VALIDATION,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=5,
                param_name_hints=['q', 'query', 'search', 'input']
            ),
            TestSelectionRule(
                name="HTTP Headers on API endpoint",
                category=TestCategory.HTTP_HEADERS,
                required_features=[EndpointFeature.IS_API_ENDPOINT],
                excluded_features=[],
                priority=4
            ),
            TestSelectionRule(
                name="Security Misconfiguration on sensitive endpoint",
                category=TestCategory.SECURITY_MISCONFIG,
                required_features=[EndpointFeature.IS_SENSITIVE_ENDPOINT],
                excluded_features=[],
                priority=6
            ),
            TestSelectionRule(
                name="Version Disclosure on API endpoint",
                category=TestCategory.VERSION_DISCLOSURE,
                required_features=[EndpointFeature.IS_API_ENDPOINT],
                excluded_features=[],
                priority=3
            ),
            TestSelectionRule(
                name="Mass Assignment on user registration",
                category=TestCategory.MASS_ASSIGNMENT,
                required_features=[EndpointFeature.HAS_USER_PARAM],
                excluded_features=[],
                priority=7,
                param_name_hints=['user', 'name', 'email', 'register']
            ),
            TestSelectionRule(
                name="GraphQL Security on graphql endpoint",
                category=TestCategory.GRAPHQL,
                required_features=[],
                excluded_features=[],
                priority=8,
                required_path_patterns=['graphql']
            ),
            TestSelectionRule(
                name="Spring Boot Actuator on sensitive endpoint",
                category=TestCategory.SPRING_BOOT_ACTUATOR,
                required_features=[EndpointFeature.IS_SENSITIVE_ENDPOINT],
                excluded_features=[],
                priority=6
            ),
            TestSelectionRule(
                name="XSS Reflected on search endpoint",
                category=TestCategory.XSS_REFLECTED,
                required_features=[EndpointFeature.HAS_SEARCH_PARAM],
                excluded_features=[],
                priority=8,
                param_name_hints=['q', 'query', 'search', 'keyword']
            ),
            TestSelectionRule(
                name="CSRF on state-changing endpoint",
                category=TestCategory.CSRF,
                required_features=[EndpointFeature.HAS_BODY_PARAM],
                excluded_features=[],
                priority=7,
                required_path_patterns=['/api/']
            ),
            TestSelectionRule(
                name="Session Fixation on login endpoint",
                category=TestCategory.SESSION_FIXATION,
                required_features=[EndpointFeature.IS_LOGIN_ENDPOINT],
                excluded_features=[],
                priority=8
            ),
            TestSelectionRule(
                name="Cloud Config Exposure on config endpoint",
                category=TestCategory.CLOUD_CONFIG,
                required_features=[EndpointFeature.IS_API_ENDPOINT],
                excluded_features=[],
                priority=5,
                required_path_patterns=['/config', '/api/config', '/settings']
            ),
            TestSelectionRule(
                name="DevOps Config Exposure",
                category=TestCategory.DEV_OPS_CONFIG,
                required_features=[],
                excluded_features=[],
                priority=4,
                required_path_patterns=['/']
            ),
        ]
    
    def select_tests(
        self, 
        features: EndpointFeatures,
        enabled_categories: Optional[Set[TestCategory]] = None
    ) -> List[TestSelection]:
        """
        基于端点特征选择测试
        
        Args:
            features: 端点特征
            enabled_categories: 启用的测试类别
            
        Returns:
            List[TestSelection]: 选中的测试列表
        """
        selections = []
        
        for rule in self.rules:
            if enabled_categories and rule.category not in enabled_categories:
                continue
            
            if not self._matches_rule(features, rule):
                continue
            
            param_name = self._find_matching_param(features, rule)
            
            selection = TestSelection(
                test_name=rule.name,
                test_category=rule.category,
                priority=rule.priority,
                reason=f"Matches rule: {rule.name} (features: {self._get_feature_names(features, rule)})",
                param_name=param_name
            )
            selections.append(selection)
        
        selections.sort(key=lambda x: x.priority, reverse=True)
        return selections
    
    def _matches_rule(self, features: EndpointFeatures, rule: TestSelectionRule) -> bool:
        """检查端点是否匹配规则"""
        if rule.required_features:
            if not features.has_any_feature(rule.required_features):
                return False
        
        if rule.excluded_features:
            if features.has_any_feature(rule.excluded_features):
                return False
        
        if rule.required_path_patterns:
            path_lower = features.path.lower()
            if not any(p in path_lower for p in rule.required_path_patterns):
                return False
        
        if rule.excluded_path_patterns:
            path_lower = features.path.lower()
            if any(p in path_lower for p in rule.excluded_path_patterns):
                return False
        
        return True
    
    def _find_matching_param(self, features: EndpointFeatures, rule: TestSelectionRule) -> Optional[str]:
        """查找匹配的参数名"""
        if not rule.param_name_hints:
            return None
        
        for param in features.param_names:
            param_lower = param.lower()
            for hint in rule.param_name_hints:
                if hint.lower() in param_lower:
                    return param
        
        return None
    
    def _get_feature_names(self, features: EndpointFeatures, rule: TestSelectionRule) -> str:
        """获取匹配的特征名"""
        matched = []
        for feature in rule.required_features:
            if features.has_feature(feature):
                matched.append(feature.value)
        return ", ".join(matched)
    
    def get_test_methods_for_category(self, category: TestCategory) -> str:
        """获取测试类别对应的测试方法名"""
        mapping = {
            TestCategory.SQL_INJECTION: "test_sql_injection",
            TestCategory.XSS: "test_xss",
            TestCategory.COMMAND_INJECTION: "test_command_injection",
            TestCategory.SSRF: "test_ssrf",
            TestCategory.IDOR: "test_idor",
            TestCategory.CORS: "test_cors_misconfiguration",
            TestCategory.CRLF: "test_crlf_injection",
            TestCategory.LFI: "test_lfi",
            TestCategory.SSTI: "test_ssti",
            TestCategory.VERBOSE_ERROR: "test_verbose_error",
            TestCategory.AUTH_BYPASS: "test_unauthorized_access",
            TestCategory.JWT_SECURITY: "test_jwt_security",
            TestCategory.RATE_LIMIT: "test_rate_limiting",
            TestCategory.INFORMATION_DISCLOSURE: "test_information_disclosure",
            TestCategory.BOLA: "test_idor",
            TestCategory.BFLA: "test_bfla",
            TestCategory.INJECTION_ATTACKS: "test_injection_attacks",
            TestCategory.INPUT_VALIDATION: "test_input_validation",
            TestCategory.HTTP_HEADERS: "test_http_headers",
            TestCategory.SECURITY_MISCONFIG: "test_security_misconfig",
            TestCategory.VERSION_DISCLOSURE: "test_version_disclosure",
            TestCategory.MASS_ASSIGNMENT: "test_mass_assignment",
            TestCategory.GRAPHQL: "test_graphql_security",
            TestCategory.SPRING_BOOT_ACTUATOR: "test_spring_boot_actuator",
            TestCategory.XSS_REFLECTED: "test_xss_reflected",
            TestCategory.CSRF: "test_csrf",
            TestCategory.SESSION_FIXATION: "test_session_fixation",
            TestCategory.CLOUD_CONFIG: "test_cloud_config_exposure",
            TestCategory.DEV_OPS_CONFIG: "test_devops_config_exposure",
        }
        return mapping.get(category, "")


def select_tests_for_endpoint(
    endpoint,
    enabled_categories: Optional[Set[TestCategory]] = None
) -> List[TestSelection]:
    """
    为APIEndpoint选择测试用例的便捷函数
    
    Args:
        endpoint: APIEndpoint对象
        enabled_categories: 启用的测试类别
        
    Returns:
        List[TestSelection]: 选中的测试列表
    """
    from .endpoint_analyzer import extract_features_from_endpoint, EndpointAnalyzer
    
    analyzer = EndpointAnalyzer()
    features = extract_features_from_endpoint(endpoint)
    
    selector = TestSelector()
    return selector.select_tests(features, enabled_categories)

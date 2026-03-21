"""
AI Engine Module
AI分析引擎 - 整合站点定性、API分析、敏感信息识别
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class AIProvider(Enum):
    """AI提供商"""
    DEEPSEEK = "deepseek"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


@dataclass
class AIConfig:
    """AI配置"""
    provider: str = "deepseek"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    api_format: str = "openai"
    max_tokens: int = 2000
    temperature: float = 0.7
    timeout: int = 60


@dataclass
class AIResponse:
    """AI响应"""
    success: bool
    content: str = ""
    error: str = ""
    thinking: str = ""
    judgment: str = ""
    result: str = ""


class BaseAIClient:
    """AI客户端基类"""
    
    def __init__(self, config: AIConfig):
        self.config = config
    
    def chat(self, messages: List[Dict], system: str = "") -> AIResponse:
        """发送聊天请求"""
        raise NotImplementedError
    
    def _format_response(self, content: str) -> AIResponse:
        """格式化响应"""
        try:
            thinking_match = re.search(r'<思考>(.*?)</思考>', content, re.DOTALL)
            judgment_match = re.search(r'<判断>(.*?)</判断>', content, re.DOTALL)
            result_match = re.search(r'<结果>(.*?)</结果>', content, re.DOTALL)
            
            return AIResponse(
                success=True,
                content=content,
                thinking=thinking_match.group(1) if thinking_match else "",
                judgment=judgment_match.group(1) if judgment_match else "",
                result=result_match.group(1) if result_match else content
            )
        except Exception as e:
            return AIResponse(success=False, content=content, error=str(e))


class DeepSeekClient(BaseAIClient):
    """DeepSeek AI客户端 (OpenAI 兼容格式)"""
    
    def __init__(self, config: AIConfig):
        super().__init__(config)
        self.api_key = config.api_key
        self.base_url = config.base_url
    
    def chat(self, messages: List[Dict], system: str = "") -> AIResponse:
        """发送聊天请求 (OpenAI 格式)"""
        try:
            import requests
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            full_messages = []
            if system:
                full_messages.append({"role": "system", "content": system})
            full_messages.extend(messages)
            
            payload = {
                "model": self.config.model,
                "messages": full_messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return self._format_response(content)
            else:
                return AIResponse(
                    success=False,
                    error=f"API Error: {response.status_code} - {response.text}"
                )
        except ImportError:
            return AIResponse(success=False, error="requests library not installed")
        except Exception as e:
            return AIResponse(success=False, error=str(e))


class AnthropicClient(BaseAIClient):
    """
    Anthropic AI客户端 (Claude 格式)
    
    Anthropic API 格式:
    - 端点: /v1/messages
    - 认证: x-api-key header
    - body 格式: messages + system + model
    """
    
    def __init__(self, config: AIConfig):
        super().__init__(config)
        self.api_key = config.api_key
        self.base_url = config.base_url
    
    def chat(self, messages: List[Dict], system: str = "") -> AIResponse:
        """发送聊天请求 (Anthropic 格式)"""
        try:
            import requests
            
            headers = {
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01"
            }
            
            full_messages = []
            if system:
                full_messages.append({"role": "user", "content": system})
            full_messages.extend(messages)
            
            payload = {
                "model": self.config.model,
                "messages": full_messages,
                "max_tokens": self.config.max_tokens
            }
            
            response = requests.post(
                f"{self.base_url}/messages",
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data.get("content", [{}])[0].get("text", "")
                return self._format_response(content)
            else:
                return AIResponse(
                    success=False,
                    error=f"API Error: {response.status_code} - {response.text}"
                )
        except ImportError:
            return AIResponse(success=False, error="requests library not installed")
        except Exception as e:
            return AIResponse(success=False, error=str(e))


class SiteProfiler:
    """站点定性分析器"""
    
    SYSTEM_PROMPT = """你是一个专业的Web安全研究员，擅长分析网站的功能和业务类型。

请分析以下网站信息，判断其业务类型和功能特点。

分析维度：
1. 网站整体功能定位（如：电商、社交、办公、内部系统等）
2. 目标用户群体（如：普通用户、管理员、员工等）
3. 核心业务模块（如：用户管理、订单管理、内容管理等）
4. 安全风险识别（如：是否涉及敏感数据、支付等高风险业务）

请用简洁专业的语言给出分析结果。"""
    
    def __init__(self, ai_client: BaseAIClient):
        self.ai_client = ai_client
    
    def analyze(
        self,
        homepage_content: str,
        title: str,
        api_endpoints: List[str]
    ) -> AIResponse:
        """分析站点性质"""
        content = f"""网站标题: {title}

网站内容片段:
{homepage_content[:2000]}

发现的API接口:
{chr(10).join(api_endpoints[:20])}

请根据以上信息，分析这个网站的功能定位和业务类型。"""
        
        return self.ai_client.chat(
            [{"role": "user", "content": content}],
            system=self.SYSTEM_PROMPT
        )


class APIAnalyzer:
    """API分析器 - 用于路径分析、登录需求判断"""
    
    SYSTEM_PROMPT = """你是一个专业的Web安全研究员，擅长分析API接口的功能和安全特征。"""
    
    LOGIN_ANALYSIS_PROMPT = """你是一个专业的Web安全研究员。

请分析以下API接口，判断它是否需要登录才能访问。

分析要点：
1. 接口路径命名（如 /user/info、/admin/* 通常需要登录）
2. 接口功能推断（如获取用户信息、订单列表等通常需要登录）
3. 响应内容分析（如返回用户敏感信息则需要登录）

请按以下格式回答：
<思考>你的分析过程，控制在150字以内</思考>
<判断>需要登录/无需登录/无法确定</判断>
<结果>如果判断为"需要登录"或"无需登录"，这里留空；如果"无法确定"，说明原因</结果>"""
    
    PUBLIC_API_PROMPT = """你是一个专业的Web安全研究员。

结合以下站点定性信息，判断该API接口是否为公共接口（无需任何认证即可访问）。

站点类型: {site_type}

API信息：
- 路径: {api_path}
- 请求方法: {method}
- 响应状态: {status_code}

请按以下格式回答：
<思考>分析过程，控制在100字以内</思考>
<判断>是公共接口/非公共接口/无法确定</判断>
<结果>说明判断依据</结果>"""
    
    def __init__(self, ai_client: BaseAIClient):
        self.ai_client = ai_client
    
    def analyze_login_requirement(
        self,
        api_path: str,
        method: str,
        response_content: str,
        status_code: int
    ) -> AIResponse:
        """分析API是否需要登录"""
        content = f"""API接口信息：
- 路径: {api_path}
- 请求方法: {method}
- 响应状态码: {status_code}

响应内容片段:
{response_content[:1500]}

        {self.LOGIN_ANALYSIS_PROMPT}"""
        
        return self.ai_client.chat(
            [{"role": "user", "content": content}],
            system=self.SYSTEM_PROMPT
        )
    
    def analyze_public_api(
        self,
        api_path: str,
        method: str,
        status_code: int,
        site_type: str
    ) -> AIResponse:
        """判断是否为公共接口"""
        content = self.PUBLIC_API_PROMPT.format(
            site_type=site_type,
            api_path=api_path,
            method=method,
            status_code=status_code
        )
        
        return self.ai_client.chat(
            [{"role": "user", "content": content}],
            system=self.SYSTEM_PROMPT
        )


class DynamicPathAnalyzer:
    """动态路径拼接分析器"""
    
    SYSTEM_PROMPT = """你是一个专业的Web安全研究员，擅长从JavaScript代码中分析API路径的拼接逻辑。

请分析以下JS代码，识别其中的API路径拼接模式：

1. 基础URL拼接：如 baseUrl + "/api/user"
2. 路径片段拼接：如 "/user/" + userId
3. 动态参数拼接：如 "/order/" + orderId + "/detail"

请按以下格式输出：
<思考>分析过程</思考>
<判断>发现/未发现</判断>
<结果>如果发现拼接模式，列出具体的拼接方式和完整路径示例，多个用$$$$分隔</结果>"""
    
    def __init__(self, ai_client: BaseAIClient):
        self.ai_client = ai_client
    
    def analyze(self, js_content: str) -> AIResponse:
        """分析JS中的动态路径拼接"""
        return self.ai_client.chat(
            [{"role": "user", "content": f"请分析以下JS代码中的API路径拼接逻辑：\n\n{js_content[:3000]}"}],
            system=self.SYSTEM_PROMPT
        )


class ParameterInferrer:
    """API参数推断器"""
    
    SYSTEM_PROMPT = """你是一个专业的Web安全研究员，擅长从API响应中推断参数结构。

请分析以下API响应内容，推断可能的参数名称和类型。"""
    
    def __init__(self, ai_client: BaseAIClient):
        self.ai_client = ai_client
    
    def infer(
        self,
        api_path: str,
        method: str,
        response_content: str
    ) -> AIResponse:
        """从响应推断参数"""
        content = f"""API路径: {api_path}
请求方法: {method}

响应内容:
{response_content[:2000]}

请分析响应结构，推断：
1. 可能需要的参数名称
2. 参数类型（string/number/object等）
3. 哪些是可选参数

请按以下格式输出：
<思考>分析过程</思考>
<结果>推断的参数列表，格式：参数名:类型:说明</结果>"""
        
        return self.ai_client.chat(
            [{"role": "user", "content": content}],
            system=self.SYSTEM_PROMPT
        )


class SensitiveInfoAnalyzer:
    """敏感信息AI分析器"""
    
    SYSTEM_PROMPT = """你是一个专业的安全研究员，擅长识别敏感信息泄露。

请扫描以下内容，识别其中可能存在的敏感信息。"""
    
    SENSITIVE_TYPES = [
        "账号密码类",
        "密钥类(AKSK/OSSK)",
        "应用密钥(小程序/AppSecret)",
        "数据库连接信息",
        "Token/JWT",
        "身份证/手机号等个人隐私"
    ]
    
    def __init__(self, ai_client: BaseAIClient):
        self.ai_client = ai_client
    
    def analyze(
        self,
        content: str,
        context: str = ""
    ) -> AIResponse:
        """分析敏感信息"""
        prompt = f"""请扫描以下内容，识别敏感信息。

重点关注：
1. 账号密码（各类登录凭据）
2. 密钥类（AWS密钥、OSS密钥、API密钥等）
3. 应用密钥（小程序AppSecret、AppID等）
4. 数据库连接字符串
5. JWT Token
6. 个人隐私信息（身份证、手机号等）

{'上下文信息：' + context if context else ''}

待扫描内容:
{content[:5000]}

请按以下格式回答：
<思考>分析过程，控制在150字以内</思考>
<判断>有敏感信息/无敏感信息/无法确定</判断>
<结果>如果发现有敏感信息，列出具体内容和类型，多个用$$$$分隔</结果>"""
        
        return self.ai_client.chat(
            [{"role": "user", "content": prompt}],
            system=self.SYSTEM_PROMPT
        )


class AIEngine:
    """
    AI引擎 - 统一的AI客户端接口
    整合所有AI分析能力，提供简单的调用接口
    """
    
    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or self._load_default_config()
        self.client = AIFactory.create_client(self.config)
        self.profiler = SiteProfiler(self.client)
        self.api_analyzer = APIAnalyzer(self.client)
        self.dynamic_analyzer = DynamicPathAnalyzer(self.client)
        self.param_inferrer = ParameterInferrer(self.client)
        self.sensitive_analyzer = SensitiveInfoAnalyzer(self.client)
        self._cache: Dict[str, AIResponse] = {}
    
    def _load_default_config(self) -> AIConfig:
        """从环境变量或配置加载默认配置"""
        import os
        return AIConfig(
            provider=os.environ.get('AI_PROVIDER', 'deepseek'),
            api_key=os.environ.get('DEEPSEEK_API_KEY', ''),
            base_url=os.environ.get('AI_BASE_URL', 'https://api.deepseek.com/v1'),
            model=os.environ.get('AI_MODEL', 'deepseek-chat'),
            max_tokens=int(os.environ.get('AI_MAX_TOKENS', '2000')),
            temperature=float(os.environ.get('AI_TEMPERATURE', '0.7'))
        )
    
    def chat(self, messages: List[Dict], system: str = "") -> AIResponse:
        """简单的聊天接口"""
        return self.client.chat(messages, system)
    
    def predict_endpoints(self, js_content: str, known_endpoints: List[str]) -> List[str]:
        """
        使用LLM预测可能的API端点
        
        Args:
            js_content: JS文件内容
            known_endpoints: 已知的端点列表
        
        Returns:
            预测的新端点列表
        """
        cache_key = f"predict_{hash(js_content[:1000])}"
        if cache_key in self._cache:
            return self._parse_endpoints_from_response(self._cache[cache_key])
        
        prompt = f"""Based on this JavaScript code and known API endpoints, predict other API endpoints that might exist on this server.

Known endpoints:
{chr(10).join(known_endpoints[:15])}

JavaScript code (first 2500 chars):
{js_content[:2500]}

Consider RESTful naming patterns, common CRUD operations, authentication endpoints, and admin interfaces.

List only the most likely endpoints, one per line, format: /path or /v1/path"""
        
        response = self.client.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are an API security researcher. Predict likely API endpoints based on patterns."
        )
        
        self._cache[cache_key] = response
        return self._parse_endpoints_from_response(response)
    
    def _parse_endpoints_from_response(self, response: AIResponse) -> List[str]:
        """从AI响应中解析端点列表"""
        if not response.success:
            return []
        
        endpoints = []
        for line in response.result.strip().split('\n'):
            line = line.strip()
            if line.startswith('/'):
                endpoints.append(line)
        return list(set(endpoints))
    
    def analyze_js_patterns(self, js_content: str) -> Dict[str, Any]:
        """分析JS代码中的API模式"""
        cache_key = f"patterns_{hash(js_content[:1000])}"
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            return {'patterns': [], 'thinking': getattr(cached, 'thinking', ''), 'judgment': getattr(cached, 'judgment', '')}
        
        response = self.dynamic_analyzer.analyze(js_content)
        self._cache[cache_key] = response
        
        patterns = []
        if response.success and response.result:
            for pattern in response.result.split('$$$$'):
                pattern = pattern.strip()
                if pattern:
                    patterns.append(pattern)
        
        return {
            'patterns': patterns,
            'thinking': response.thinking,
            'judgment': response.judgment
        }


class AIFactory:
    """AI工厂类"""
    
    _clients: Dict[str, BaseAIClient] = {}
    
    @classmethod
    def create_client(cls, config: AIConfig) -> BaseAIClient:
        """创建AI客户端
        
        根据 api_format 决定使用 OpenAI 还是 Anthropic 格式:
        - api_format="openai": 使用 DeepSeekClient (/chat/completions)
        - api_format="anthropic": 使用 AnthropicClient (/messages)
        - api_format="deepseek": 使用 DeepSeekClient (兼容 OpenAI 格式)
        """
        if config.api_format == "anthropic":
            return AnthropicClient(config)
        else:
            return DeepSeekClient(config)
    
    @classmethod
    def create_profiler(cls, config: AIConfig) -> SiteProfiler:
        """创建站点定性器"""
        client = cls.create_client(config)
        return SiteProfiler(client)
    
    @classmethod
    def create_api_analyzer(cls, config: AIConfig) -> APIAnalyzer:
        """创建API分析器"""
        client = cls.create_client(config)
        return APIAnalyzer(client)
    
    @classmethod
    def create_dynamic_analyzer(cls, config: AIConfig) -> DynamicPathAnalyzer:
        """创建动态路径分析器"""
        client = cls.create_client(config)
        return DynamicPathAnalyzer(client)
    
    @classmethod
    def create_param_inferrer(cls, config: AIConfig) -> ParameterInferrer:
        """创建参数推断器"""
        client = cls.create_client(config)
        return ParameterInferrer(client)
    
    @classmethod
    def create_sensitive_analyzer(cls, config: AIConfig) -> SensitiveInfoAnalyzer:
        """创建敏感信息分析器"""
        client = cls.create_client(config)
        return SensitiveInfoAnalyzer(client)

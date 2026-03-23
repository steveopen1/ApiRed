"""
AI Engine Module
AI分析引擎 - 整合站点定性、API分析、敏感信息识别
使用 llm 库统一管理多种 LLM 提供商
"""

import json
import re
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

import llm


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
    llm_model_id: str = ""


LLM_MODEL_MAPPING = {
    "deepseek-chat": "deepseek/deepseek-chat",
    "deepseek-coder": "deepseek/deepseek-coder",
    "deepseek-v3": "deepseek/deepseek-chat",
    "gpt-4o": "gpt-4o",
    "gpt-4o-mini": "gpt-4o-mini",
    "gpt-4": "gpt-4",
    "gpt-4-turbo": "gpt-4-turbo",
    "gpt-3.5-turbo": "gpt-3.5-turbo",
    "gpt-4.1": "gpt-4.1",
    "gpt-4.1-mini": "gpt-4.1-mini",
    "claude-3-sonnet": "anthropic/claude-3-sonnet-20240229",
    "claude-3-opus": "anthropic/claude-3-opus-20240229",
    "claude-3-haiku": "anthropic/claude-3-haiku-20240307",
    "claude-3-5-sonnet": "anthropic/claude-3-5-sonnet-latest",
    "claude-3-5-haiku": "anthropic/claude-3-5-haiku-latest",
    "claude-sonnet-4": "anthropic/claude-sonnet-4-0",
    "claude-opus-4": "anthropic/claude-opus-4-0",
    "claude-sonnet-4-5": "anthropic/claude-sonnet-4-5",
    "claude-opus-4-5": "anthropic/claude-opus-4-5",
    "gemini-2.0-flash": "gemini/gemini-2.0-flash",
    "gemini-2.0-pro": "gemini/gemini-2.0-pro-exp-02-05",
    "gemini-1.5-flash": "gemini/gemini-1.5-flash-002",
    "gemini-1.5-pro": "gemini/gemini-1.5-pro-latest",
    "gemini-pro": "gemini/gemini-pro",
    "mistral-large": "mistral/mistral-large-latest",
    "mistral-small": "mistral/mistral-small-latest",
    "mistral-medium": "mistral/mistral-medium-latest",
    "mistral-codestral": "mistral/codestral-latest",
}

PROVIDER_MODEL_PREFIX = {
    "anthropic": "anthropic/",
    "deepseek": "deepseek/",
    "gemini": "gemini/",
    "mistral": "mistral/",
    "ollama": "ollama/",
    "openai": "",
}

PROVIDER_API_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "ollama": "OLLAMA_API_KEY",
    "openai": "OPENAI_API_KEY",
    "custom": "CUSTOM_API_KEY",
}


@dataclass
class AIResponse:
    """AI响应"""
    success: bool
    content: str = ""
    error: str = ""
    thinking: str = ""
    judgment: str = ""
    result: str = ""


class LLMClient:
    """
    LLM 客户端 - 使用 llm 库统一管理多种 LLM 提供商
    
    支持的模型格式 (llm 库标准):
    - OpenAI: gpt-4o, gpt-4o-mini, gpt-4, gpt-3.5-turbo 等
    - Anthropic: anthropic/claude-3-sonnet-20240229, anthropic/claude-3-5-sonnet-latest 等
    - DeepSeek: deepseek/deepseek-chat, deepseek/deepseek-coder 等
    - Google Gemini: gemini/gemini-2.0-flash, gemini/gemini-1.5-pro 等
    - Mistral: mistral/mistral-large-latest, mistral/mistral-small-latest 等
    - Ollama: ollama/llama3, ollama/codestral 等 (需本地安装 ollama)
    """
    
    def __init__(self, config: AIConfig):
        self.config = config
        self._model: Optional[llm.Model] = None
        self._setup_api_keys()
    
    def _setup_api_keys(self):
        """设置 API keys 到环境变量 (llm 库通过环境变量读取)"""
        if not self.config.api_key:
            return
        
        api_format = self.config.api_format.lower()
        model_id = self._get_llm_model_id().lower()
        
        if 'anthropic' in model_id or api_format == 'anthropic':
            os.environ['ANTHROPIC_API_KEY'] = self.config.api_key
        elif 'deepseek' in model_id or api_format == 'deepseek':
            os.environ['DEEPSEEK_API_KEY'] = self.config.api_key
        elif 'gemini' in model_id or api_format == 'gemini':
            os.environ['GEMINI_API_KEY'] = self.config.api_key
        elif 'mistral' in model_id or api_format == 'mistral':
            os.environ['MISTRAL_API_KEY'] = self.config.api_key
        elif 'ollama' in model_id or api_format == 'ollama':
            pass
        else:
            os.environ['OPENAI_API_KEY'] = self.config.api_key
    
    def _get_llm_model_id(self) -> str:
        """获取 llm 库标准的模型 ID"""
        if self.config.llm_model_id:
            return self.config.llm_model_id
        
        if self.config.model in LLM_MODEL_MAPPING:
            return LLM_MODEL_MAPPING[self.config.model]
        
        api_format = self.config.api_format.lower()
        if api_format in PROVIDER_MODEL_PREFIX:
            prefix = PROVIDER_MODEL_PREFIX[api_format]
            if prefix and not self.config.model.startswith(prefix):
                return f"{prefix}{self.config.model}"
        
        return self.config.model
    
    @property
    def model(self) -> llm.Model:
        """获取 llm 模型实例"""
        if self._model is None:
            model_id = self._get_llm_model_id()
            self._model = llm.get_model(model_id)
        return self._model
    
    def chat(self, messages: List[Dict], system: str = "") -> AIResponse:
        """发送聊天请求 (通过 llm 库)"""
        try:
            prompt = self._format_messages_to_prompt(messages, system)
            
            response = self.model.prompt(
                prompt,
                system=system if system and not messages else None,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            )
            
            content = response.text()
            return self._format_response(content)
            
        except Exception as e:
            return AIResponse(success=False, error=str(e))
    
    def _format_messages_to_prompt(self, messages: List[Dict], system: str) -> str:
        """将消息列表格式化为单个 prompt"""
        if len(messages) <= 1 and not system:
            return messages[0].get("content", "") if messages else ""
        
        parts = []
        if system:
            parts.append(f"System: {system}")
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"{role.capitalize()}: {content}")
        return "\n\n".join(parts)
    
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
    
    def __init__(self, ai_client: LLMClient):
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
    
    def __init__(self, ai_client: LLMClient):
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
    
    def __init__(self, ai_client: LLMClient):
        self.ai_client = ai_client
    
    def analyze(self, js_content: str) -> AIResponse:
        """分析JS中的动态路径拼接"""
        return self.ai_client.chat(
            [{"role": "user", "content": f"请分析以下JS代码中的API路径拼接逻辑：\n\n{js_content[:3000]}"}],
            system=self.SYSTEM_PROMPT
        )


class ParameterInferrer:
    """API参数推断器"""
    
    SYSTEM_PROMPT = """你是一个专业的Web安全研究员，擅长从API响应中推断参数结构。"""
    
    def __init__(self, ai_client: LLMClient):
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
    
    def __init__(self, ai_client: LLMClient):
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
    
    MAX_CACHE_SIZE = 100
    
    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or self._load_default_config()
        self.client = AIFactory.create_client(self.config)
        self.profiler = SiteProfiler(self.client)
        self.api_analyzer = APIAnalyzer(self.client)
        self.dynamic_analyzer = DynamicPathAnalyzer(self.client)
        self.param_inferrer = ParameterInferrer(self.client)
        self.sensitive_analyzer = SensitiveInfoAnalyzer(self.client)
        self._cache: Dict[str, AIResponse] = {}
        self._cache_order: List[str] = []
    
    def _add_to_cache(self, key: str, value: AIResponse):
        """添加缓存，带容量限制"""
        if len(self._cache) >= self.MAX_CACHE_SIZE:
            oldest_key = self._cache_order.pop(0)
            self._cache.pop(oldest_key, None)
        self._cache[key] = value
        self._cache_order.append(key)
    
    def _load_default_config(self) -> AIConfig:
        """从统一配置加载默认配置"""
        from ..utils.config import Config
        
        config = Config()
        ai_config = config.get_ai_config()
        
        llm_model_id = ""
        model = ai_config.get('model', 'deepseek-chat')
        api_format = ai_config.get('api_format', 'openai')
        
        if model in LLM_MODEL_MAPPING:
            llm_model_id = LLM_MODEL_MAPPING[model]
        elif api_format in PROVIDER_MODEL_PREFIX:
            prefix = PROVIDER_MODEL_PREFIX[api_format]
            if prefix and not model.startswith(prefix.rstrip('/') + '/'):
                llm_model_id = f"{prefix.rstrip('/')}/{model}"
            else:
                llm_model_id = model
        else:
            llm_model_id = model
        
        return AIConfig(
            provider=ai_config.get('provider', 'deepseek'),
            api_key=ai_config.get('api_key', ''),
            base_url=ai_config.get('base_url', 'https://api.deepseek.com/v1'),
            model=model,
            api_format=api_format,
            llm_model_id=llm_model_id,
            max_tokens=ai_config.get('max_tokens', 2000),
            temperature=ai_config.get('temperature', 0.7)
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
        
        self._add_to_cache(cache_key, response)
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
        self._add_to_cache(cache_key, response)
        
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
    """AI工厂类 - 使用 llm 库统一管理"""
    
    _clients: Dict[str, LLMClient] = {}
    
    @classmethod
    def create_client(cls, config: AIConfig) -> LLMClient:
        """创建AI客户端
        
        使用 llm 库统一管理，通过 llm_model_id 或 model + api_format 确定模型:
        - OpenAI: gpt-4o, gpt-4o-mini 等
        - Anthropic: anthropic/claude-3-sonnet-20240229 等
        - DeepSeek: deepseek/deepseek-chat 等
        """
        return LLMClient(config)
    
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

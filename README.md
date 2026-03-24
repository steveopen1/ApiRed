# ApiRed - Red Team API Security Scanner

[![GitHub release](https://img.shields.io/github/release/0x727/ChkApi_0x727.svg)](https://github.com/0x727/ChkApi_0x727/releases)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> 专为红队视角设计的 API 安全扫描器，从攻击者角度自动化发现目标资产中的 API 接口漏洞

**郑重声明**：本文档所涉及的技术、思路和工具仅供安全检测、安全辅助建设为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担。

---

## 核心特性

| 特性 | 说明 |
|------|------|
| **影子 API 发现** | 从 JS/Webpack 挖掘未公开端点，支持 AST + 正则双引擎 |
| **智能路径分析** | 自动提取父路径前缀、RESTful 模板、通用路径识别 |
| **跨来源 Fuzzing** | HTML/JS/API响应中的路径片段智能组合探测 |
| **递归 JS 提取** | Webpack打包JS中动态import/require的模块递归获取 |
| **HTTP 方法识别** | 支持 axios/fetch/request/$.ajax 等多种客户端 |
| **LLM 智能分析** | 支持 OpenAI/Anthropic/Gemini/DeepSeek/Mistral/Ollama 等主流模型 |
| **Bypass 能力** | 绕过 401/403/404，获取隐藏资源 |
| **敏感凭证挖掘** | JS/响应中提取 AK/SK/Token/JWT |
| **漏洞验证** | 自动验证 SQLi/XSS/SSRF/JWT/OAuth2 |
| **攻击链生成** | 从入口到漏洞的完整调用链路 |
| **OpenAPI 生成** | 自动导出 OpenAPI 3.0 规范 |
| **增量扫描** | 断点续扫，支持检查点恢复 |
| **多目标并行** | 支持 100+ 目标并发扫描 |

---

## 快速开始

### 安装

```bash
pip install -r requirements.txt
```

### 基本用法

```bash
# 目标侦察 - 收集所有 API 攻击面
python3 main.py scan -u https://target.com

# 携带认证 Cookie - 测试会话安全
python3 main.py scan -u https://target.com -c "session=xxx"

# 批量目标 - 快速资产覆盖
python3 main.py scan -f targets.txt

# AI 辅助 - 智能漏洞研判
python3 main.py scan -u https://target.com --ai

# 增量扫描 - 断点续扫
python3 main.py scan -u https://target.com --resume
```

### 查看完整帮助

```bash
python3 main.py scan --help
```

---

## 扫描生命周期

扫描器采用**三阶段 Pipeline**架构，数据在各阶段间通过内存传递：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 0: COLLECT (采集)                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ JS采集      │ -> │ AST解析      │ -> │ 路径提取     │ -> │ 跨源Fuzzing │  │
│  │ (递归深度3) │    │ + 正则双引擎 │    │ + 父路径探测  │    │ + 智能组合   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                              │                                    │         │
│                              └────────────┬───────────────────────┘         │
│                                           ▼                                  │
│                              ┌─────────────────────┐                        │
│                              │ _collector_results  │                        │
│                              │ • js_params         │                        │
│                              │ • ast_routes        │                        │
│                              │ • finder_api_paths  │                        │
│                              │ • env_configs       │                        │
│                              └─────────────────────┘                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 1: ANALYZE (分析)                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ HTTP探测    │ -> │ API评分      │ -> │ 响应聚类     │ -> │ 敏感信息检测│  │
│  │ (验证存活)   │    │ (高价值标记)  │    │ (基线学习)   │    │ (凭证挖掘)  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  产出: api_endpoints (含 is_high_value 标记)                                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STAGE 2: TEST (测试)                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ 参数Fuzzing │ -> │ 漏洞测试     │ -> │ IDOR测试     │ -> │ 报告生成    │  │
│  │ (提取参数)   │    │ (SQLi/XSS)  │    │ (越权检测)   │    │ (证据链)    │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 核心调度方法 (engine.py)

| 方法 | 阶段 | 职责 |
|------|------|------|
| `_run_collectors()` | Stage 0 | 调度采集任务 |
| `_collect_js()` | Stage 0 | JS采集 + AST解析 + 路径提取 |
| `_extract_apis()` | Stage 0 | API规范解析 + 端点聚合 |
| `_fuzz_api_paths()` | Stage 0 | 父路径变异Fuzzing |
| `_cross_source_fuzz()` | Stage 0 | 跨来源智能路径组合 |
| `_probe_parent_paths()` | Stage 0 | 父路径探测验证 |
| `_run_analyzers()` | Stage 1 | 调度分析任务 |
| `_score_apis()` | Stage 1 | HTTP探测 + 评分标定 |
| `_detect_sensitive()` | Stage 1 | 敏感信息检测 |
| `_run_testers()` | Stage 2 | 调度测试任务 |
| `_run_fuzz_test()` | Stage 2 | 参数模糊测试 |
| `_run_vuln_test()` | Stage 2 | 漏洞验证测试 |

---

## 模块架构

```
ApiRed
├── main.py                              # CLI 入口
│
├── core/
│   ├── engine.py                        # ScanEngine 统一调度引擎
│   │   ├── ScanEngine                   # 主扫描器类
│   │   ├── EngineConfig                 # 引擎配置
│   │   ├── ScanCheckpoint               # 检查点快照
│   │   └── ScanResult                   # 扫描结果
│   │
│   ├── collectors/                      # 信息采集模块
│   │   ├── js_collector.py              # JS指纹缓存 + Webpack分析
│   │   │   ├── JSFingerprintCache        # 避免重复AST解析
│   │   │   ├── JSParser                  # JS解析入口
│   │   │   ├── ParsedJSResult            # 解析结果数据结构
│   │   │   └── WebpackAnalyzer           # Webpack chunk分析
│   │   │
│   │   ├── js_ast_analyzer.py            # AST风格JS解析器 (核心)
│   │   │   ├── JavaScriptASTAnalyzer     # AST解析主类
│   │   │   │   ├── parse()               # 解析JS内容
│   │   │   │   ├── parameter_names       # 提取的参数名
│   │   │   │   ├── endpoints             # 发现的端点
│   │   │   │   ├── websocket_endpoints   # WebSocket端点
│   │   │   │   ├── env_configs           # 环境变量配置
│   │   │   │   └── routes                # Vue/React Router路由
│   │   │   │
│   │   │   └── JSASTDifferentialAnalyzer # 差分分析器
│   │   │
│   │   ├── api_path_finder.py            # API路径发现 (25+正则)
│   │   │   ├── ApiPathFinder             # 路径发现器
│   │   │   ├── ApiPathCombiner           # 路径组合器
│   │   │   └── FUZZ_SUFFIXES            # Fuzzing后缀列表
│   │   │
│   │   ├── api_collector.py              # API多源采集
│   │   │   ├── APIAggregator             # API端点聚合器
│   │   │   ├── BaseURLAnalyzer           # 基础URL分析
│   │   │   ├── ServiceAnalyzer           # 服务分析
│   │   │   └── APIPathCombiner           # 路径组合
│   │   │
│   │   ├── inline_js_parser.py           # 内联JS解析
│   │   │   ├── InlineJSParser            # 内联JS提取
│   │   │   └── ResponseBasedAPIDiscovery # 基于响应的API发现
│   │   │
│   │   └── browser_collector.py          # 浏览器动态采集
│   │       ├── HeadlessBrowserCollector  # 无头浏览器
│   │       └── BrowserResource           # 浏览器资源
│   │
│   ├── analyzers/                       # 分析模块
│   │   ├── api_scorer.py                 # API评分器
│   │   │   ├── APIScorer                 # 多维度评分
│   │   │   └── APIEvidenceAggregator     # 证据聚合
│   │   │
│   │   ├── response_cluster.py           # 响应聚类
│   │   │   └── ResponseCluster           # 响应模式聚类
│   │   │
│   │   ├── response_baseline.py          # 响应基线学习
│   │   │   └── ResponseBaselineLearner   # 基线学习器
│   │   │
│   │   ├── response_diff_analyzer.py     # 响应差异分析
│   │   │
│   │   └── sensitive_detector.py         # 敏感信息检测
│   │       └── TwoTierSensitiveDetector  # 两层敏感信息检测
│   │
│   ├── testers/                         # 测试模块
│   │   ├── fuzz_tester.py                # 模糊测试
│   │   │   └── FuzzTester               # 参数Fuzzing
│   │   │
│   │   ├── vulnerability_tester.py       # 漏洞测试
│   │   │   ├── VulnerabilityTester       # 漏洞检测
│   │   │   ├── SSRFTester                # SSRF测试
│   │   │   ├── SQLiTester                # SQL注入测试
│   │   │   └── InfoDisclosureTester      # 信息泄露测试
│   │   │
│   │   ├── idor_tester.py                # IDOR测试
│   │   │   └── IDORTester                # 越权检测
│   │   │
│   │   ├── bypass_techniques.py          # Bypass技术
│   │   │   └── BypassTechniques          # 401/403/404绕过
│   │   │
│   │   ├── fuzzer/                       # Fuzzing引擎
│   │   │   └── smart_fuzzer.py           # 智能Fuzzer
│   │   │
│   │   └── graphql/                      # GraphQL测试
│   │
│   ├── agents/                          # AI Agent系统
│   │   ├── orchestrator.py              # Agent编排器
│   │   ├── discover_agent.py            # 发现Agent
│   │   ├── test_agent.py                # 测试Agent
│   │   └── reflect_agent.py             # 反思Agent
│   │
│   ├── ai/                              # AI引擎
│   │   └── ai_engine.py                 # 统一LLM客户端
│   │
│   ├── exporters/                       # 导出模块
│   │   ├── report_exporter.py           # JSON/HTML/Excel
│   │   ├── openapi_exporter.py          # OpenAPI 3.0
│   │   └── attack_chain_exporter.py     # 攻击链
│   │
│   ├── storage/                         # 存储模块
│   │   ├── db_storage.py                # SQLite存储
│   │   └── file_storage.py              # 文件存储
│   │
│   ├── utils/                          # 工具模块
│   │   ├── http_client.py               # 异步HTTP客户端
│   │   ├── circuit_breaker.py           # 熔断器
│   │   ├── config.py                    # 配置管理
│   │   └── api_spec_parser.py           # API规范解析
│   │
│   ├── services/                       # 服务分析
│   │   └── service_analyzer.py         # 微服务识别
│   │
│   ├── security/                       # 安全检测
│   │   └── security_detector.py        # 未授权/IDOR检测
│   │
│   ├── framework/                      # 框架检测
│   │   └── framework_detector.py       # Web框架识别
│   │
│   ├── dashboard/                      # Web仪表盘
│   │
│   └── models/                         # 数据模型
│       ├── api_endpoint.py             # API端点模型
│       ├── vulnerability.py            # 漏洞模型
│       └── scan_result.py              # 扫描结果模型
│
└── config.yaml                        # 配置文件
```

---

## 核心算法详解

### 1. JS递归提取算法

**目的**: 发现Webpack打包JS中动态import/require的模块

```python
async def _recursive_js_extract(initial_js_urls, max_depth=3):
    """
    递归深度: 最多3层
    每层最多处理: 50个JS URL
    总计最多: 50 * 3 = 150个JS文件
    """
    all_js_content = {}
    visited_urls = set()
    pending_urls = initial_js_urls
    
    for depth in range(max_depth):
        current_batch = pending_urls[:50]
        pending_urls = pending_urls[50:]
        
        # 批量异步请求
        responses = await asyncio.gather(*[
            http_client.request(url) for url in current_batch
        ])
        
        # 提取import/require引入的新JS
        for response in responses:
            new_urls = extract_js_imports(response.content)
            for new_url in new_urls:
                normalized = normalize_js_url(new_url)
                if normalized not in visited:
                    pending_urls.append(normalized)
```

### 2. AST风格解析算法

**目的**: 从JS中提取真实的API路径和参数

**支持的分析类型**:

| 类型 | 说明 | 示例 |
|------|------|------|
| `endpoints` | API端点 | `fetch('/api/users')`, `axios.get('/api/list')` |
| `parameter_names` | 参数名 | `id`, `page`, `userId`, `token` |
| `websocket_endpoints` | WebSocket | `new WebSocket('wss://api.example.com/ws')` |
| `env_configs` | 环境配置 | `BASE_URL`, `API_KEY` |
| `routes` | 前端路由 | `/user/:id`, `/product/:productId` |

**提取逻辑**:

```python
class JavaScriptASTAnalyzer:
    def parse(self, js_content: str) -> 'JavaScriptASTAnalyzer':
        # 1. 字符串字面量提取
        for pattern in STRING_PATTERNS:
            matches = pattern.findall(js_content)
            self._extract_endpoints(matches)
        
        # 2. AST节点分析 (esprima/acorn)
        try:
            ast = espree.parse(js_content)
            self._analyze_ast(ast)
        except:
            pass
        
        # 3. 正则降级 (补充AST遗漏)
        for pattern in REGEX_PATTERNS:
            matches = pattern.findall(js_content)
            self._extract_from_matches(matches)
        
        return self
```

### 3. 跨来源智能路径组合Fuzzing算法

**目的**: 将不同来源的路径片段组合探测隐藏API

```python
async def _cross_source_fuzz():
    """
    数据来源:
    1. HTML响应中的链接 (/user/list, /admin/login)
    2. JS响应中的API (/api/users, /api/products)
    3. API响应中的关联路径 (/user/123/orders)
    4. Inline JS中的路径片段
    
    组合策略:
    - 父路径 + 子路径: /api/users + /list -> /api/users/list
    - 路径 + RESTful后缀: /api/users + /detail -> /api/users/detail
    - 资源 + 操作: /user + /delete -> /user/delete
    """
    all_path_segments = set()
    
    # 收集所有路径片段
    await _collect_all_path_segments(all_path_segments)
    
    # 生成组合目标
    fuzz_targets = _generate_cross_fuzz_targets(all_path_segments)
    
    # 批量探测 (HEAD -> GET降级)
    for batch in chunks(fuzz_targets, 50):
        results = await asyncio.gather(*[
            probe_target(url) for url in batch
        ])
```

### 4. 父路径变异Fuzzing算法

**目的**: 基于已发现的API路径，探测同级的隐藏端点

```python
async def _fuzz_api_paths(js_results):
    """
    输入: JSFingerprintCache中的解析结果
    
    数据提取:
    - parent_paths: 父路径集合
    - js_suffixes: JS中的路径后缀
    - js_resources: JS中的资源名称
    
    变异策略:
    1. 父路径 + 后缀: /api/users + /list -> /api/users/list
    2. 父路径 + 资源: /api/users + /profile -> /api/users/profile
    3. 父路径 + 资源 + RESTful: /api/users + /profile + /detail
    4. 查询参数: /api/users?id=1
    5. 路径参数: /api/users/id/1
    
    参数来源:
    - AST解析的 parameter_names
    - AST解析的 env_configs keys
    - RESTful路由中的 {param}
    - 常见参数集 (id, page, userId...)
    """
    fuzz_targets = []
    
    for parent in parent_paths:
        # 基础探测
        fuzz_targets.append((parent, ''))
        
        # 后缀组合
        for suffix in js_suffixes:
            fuzz_targets.append((parent, f'/{suffix}'))
        
        # 资源+RESTful组合
        for resource in js_resources:
            for rest in RESTFUL_SUFFIXES[:20]:
                fuzz_targets.append((parent, f'/{resource}/{rest}'))
        
        # 参数化探测
        for param in js_params:
            fuzz_targets.append((parent, f'?{param}=1'))
            fuzz_targets.append((parent, f'/{param}/1'))
    
    # 批量探测
    return await probe_batch(fuzz_targets)
```

### 5. 参数Fuzzing算法

**目的**: 发现API端点的有效参数组合

```python
async def _run_fuzz_test():
    """
    参数来源 (优先级):
    1. endpoint.parameters: 端点本身声明的参数
    2. js_params: AST从JS提取的参数名
    3. ast_routes中的{param}: RESTful路由参数
    4. common_params: 常见参数集
    
    Fuzzing策略:
    - 数值类型: 1, 0, -1, 999999
    - 字符串类型: ', ", <script>, OR 1=1
    - 布尔类型: true, false, 1, 0
    - UUID类型: 550e8400-e29b-41d4-a716-446655440000
    
    检测:
    - SQL注入: 响应中包含SQL关键字
    - XSS: 响应中反射输入
    - 敏感信息: 响应中包含凭证/密钥
    """
    discovered_params = set()
    discovered_params.update(js_params)
    discovered_params.update(extract_from_routes(ast_routes))
    discovered_params.update(COMMON_PARAMS)
    
    for endpoint in high_value_apis:
        all_params = endpoint.parameters | discovered_params
        results = await fuzz_tester.fuzz_parameters(
            endpoint.full_url,
            endpoint.method,
            list(all_params)
        )
```

### 6. API评分算法

**目的**: 识别高价值攻击目标

```python
class APIScorer:
    """
    评分维度:
    - 路径特征: 包含admin/user/auth等关键字 (+3分)
    - HTTP方法: POST/PUT/DELETE (+2分), GET (+1分)
    - 参数数量: 有参数 (+1分)
    - 响应状态: 2xx (+2分), 4xx (+1分)
    - 敏感路径: 包含token/key/secret (+5分)
    
    高价值阈值: score >= 5
    """
    def score(self, endpoint) -> int:
        score = 0
        path_lower = endpoint.path.lower()
        
        if any(k in path_lower for k in ['admin', 'user', 'auth', 'login']):
            score += 3
        if endpoint.method in ['POST', 'PUT', 'DELETE']:
            score += 2
        elif endpoint.method == 'GET':
            score += 1
        if endpoint.parameters:
            score += 1
        if any(k in path_lower for k in ['token', 'key', 'secret', 'password']):
            score += 5
        
        return score
```

---

## 数据流架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              内存数据存储                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  _collector_results (Dict)           _js_cache (JSFingerprintCache)         │
│  ┌─────────────────────────┐          ┌─────────────────────────┐          │
│  │ 'js': {                │          │ ParsedJSResult          │          │
│  │   js_params: [...]      │          │ • apis: [...]           │          │
│  │   ast_routes: [...]     │          │ • urls: [...]           │          │
│  │   env_configs: {...}    │          │ • parent_paths: {...}   │          │
│  │   finder_api_paths: [...]         │ • extracted_suffixes: [] │          │
│  │ }                       │          │ • resource_fragments: []│          │
│  │                         │          └─────────────────────────┘          │
│  │ 'api': {...}            │                                                    │
│  └─────────────────────────┘                                                    │
│                                    │                                           │
│                                    ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────┐         │
│  │                    _api_aggregator (APIAggregator)              │         │
│  │  ┌─────────────────────────────────────────────────────────┐    │         │
│  │  │ APIFindResult                                            │    │         │
│  │  │ • path: /api/users                                       │    │         │
│  │  │ • method: GET                                            │    │         │
│  │  │ • source_type: js_parser/ast_analyzer/fuzz_api          │    │         │
│  │  │ • url_type: api_path/probed/fuzzed                       │    │         │
│  │  └─────────────────────────────────────────────────────────┘    │         │
│  └─────────────────────────────────────────────────────────────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              扫描结果输出                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ScanResult                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ api_endpoints[] │  │ vulnerabilities[]│ │ sensitive_data[]│              │
│  │ • path          │  │ • type          │  │ • data_type     │              │
│  │ • method        │  │ • severity      │  │ • matches       │              │
│  │ • parameters    │  │ • evidence      │  │ • severity      │              │
│  │ • is_high_value │  │ • payload       │  │                 │              │
│  │ • full_url      │  │                 │  │                 │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 模块调度链路

### Stage 0: 采集阶段 (collect)

```
_run_collectors()
│
├── _collect_js()
│   │
│   ├── 1. 提取JS URL
│   │   ├── 主页HTML正则提取 <script src="*.js">
│   │   ├── _extract_js_imports_from_content()
│   │   └── _recursive_js_extract() [深度3]
│   │
│   ├── 2. JS解析 (JSFingerprintCache)
│   │   ├── 检查缓存 (content_hash)
│   │   └── 解析并缓存
│   │       ├── api_path_finder.find_api_paths_in_text()
│   │       ├── JavaScriptASTAnalyzer.parse() ← AST双引擎
│   │       │   ├── parameter_names → js_params
│   │       │   ├── endpoints → 端点列表
│   │       │   ├── websocket_endpoints
│   │       │   ├── env_configs
│   │       │   └── routes → ast_routes
│   │       └── inline_parser.parse()
│   │
│   ├── 3. 路径发现
│   │   ├── response_discovery.discover_from_response()
│   │   ├── api_path_finder.get_all_paths()
│   │   └── _probe_parent_paths() [父路径探测]
│   │
│   └── 4. 跨源Fuzzing
│       ├── _fuzz_api_paths() ← 父路径变异
│       │   ├── parent_paths + js_suffixes
│       │   ├── parent_paths + js_resources + RESTful
│       │   └── 带参数的路径组合
│       │
│       └── _cross_source_fuzz() ← 跨来源组合
│           └── 路径片段智能组合探测
│
└── _extract_apis()
    │
    ├── 1. API规范解析
    │   └── APISpecParser.discover_and_parse()
    │       ├── OpenAPI/Swagger
    │       ├── GraphQL schema
    │       └── WADL
    │
    └── 2. 端点聚合
        └── _api_aggregator.add_api()
            │
            └── 产出: _collector_results['api']
```

### Stage 1: 分析阶段 (analyze)

```
_run_analyzers()
│
├── _score_apis()
│   │
│   ├── 1. HTTP探测
│   │   └── 对每个端点发送HTTP请求
│   │
│   ├── 2. 响应聚类
│   │   └── _response_cluster.add_response()
│   │
│   ├── 3. 基线学习
│   │   └── _response_baseline.learn()
│   │
│   └── 4. 评分标定
│       ├── _api_scorer.score() → is_high_value
│       └── 产出: result.alive_apis, result.high_value_apis
│
└── _detect_sensitive()
    │
    ├── 1. 敏感信息检测
    │   └── _sensitive_detector.detect()
    │       ├── AK/SK (AWS, Azure, GCP)
    │       ├── JWT Token
    │       ├── API Key
    │       ├── Password
    │       └── Private Key
    │
    └── 2. 凭证挖掘
        └── 产出: result.sensitive_data[]
```

### Stage 2: 测试阶段 (test)

```
_run_testers()
│
├── _run_fuzz_test()
│   │
│   ├── 1. 参数收集
│   │   ├── _collector_results['js']['js_params']
│   │   ├── ast_routes中的{param}提取
│   │   └── common_params (id, page, userId...)
│   │
│   ├── 2. 参数Fuzzing
│   │   └── _fuzz_tester.fuzz_parameters()
│   │       ├── 数值类型探测
│   │       ├── 字符串类型探测
│   │       └── SQLi/XSS检测
│   │
│   └── 产出: tester_results['fuzz']
│
└── _run_vuln_test()
    │
    ├── 1. SSRF测试
    │   └── _vulnerability_tester.test_ssrf()
    │
    ├── 2. SQL注入测试
    │   └── _vulnerability_tester.test_sqli()
    │
    ├── 3. 信息泄露测试
    │   └── _vulnerability_tester.test_information_disclosure()
    │
    └── 产出: result.vulnerabilities[]
```

---

## 常用命令

| 命令 | 说明 |
|------|------|
| `-u, --url` | 指定目标 URL |
| `-f, --file` | 批量目标文件 |
| `-c, --cookies` | 携带认证 Cookie |
| `--chrome off` | 减少指纹，隐蔽侦察 |
| `--at 1` | 只收集不攻击 |
| `--concurrency 100` | 高并发扫描 |
| `--ai` | 启用 AI 辅助分析 |
| `--resume` | 增量扫描，断点续扫 |
| `--bypass-only` | 仅使用 Bypass 技术 |

---

## 配置说明

### config.yaml

```yaml
scanner:
  concurrency:
    js_requests: 50        # JS 请求并发数
    api_requests: 100       # API 请求并发数
    timeout: 30            # 超时时间(秒)

ai:
  enabled: false
  provider: "deepseek"
  model: "deepseek-chat"
  base_url: "https://api.deepseek.com/v1"
  api_format: "openai"

reporting:
  formats:
    - json
    - html
    - excel
```

---

## AI 模型配置

ApiRed 使用 [llm](https://github.com/simonw/llm) 库统一管理 AI 模型，支持多种提供商：

### 支持的模型

| 提供商 | 环境变量 | 示例模型 |
|--------|----------|----------|
| OpenAI | `OPENAI_API_KEY` | gpt-4o, gpt-4o-mini, gpt-4-turbo |
| Anthropic | `ANTHROPIC_API_KEY` | claude-3-5-sonnet, claude-opus-4 |
| Google Gemini | `GEMINI_API_KEY` | gemini-2.0-flash, gemini-1.5-pro |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat, deepseek-coder |
| Mistral | `MISTRAL_API_KEY` | mistral-large, mistral-small |
| Ollama | 无 (本地) | llama3, codestral |

### 快速配置

```bash
# OpenAI
export OPENAI_API_KEY="sk-xxxx"
export AI_MODEL="gpt-4o-mini"
export AI_API_FORMAT="openai"

# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-xxxx"
export AI_MODEL="claude-3-5-sonnet"
export AI_API_FORMAT="anthropic"

# DeepSeek
export DEEPSEEK_API_KEY="sk-xxxx"
export AI_MODEL="deepseek-chat"
export AI_API_FORMAT="deepseek"

# 自定义 API (硅基流动等)
export CUSTOM_API_KEY="your-api-key"
export AI_BASE_URL="https://api.siliconflow.cn/v1"
export AI_MODEL="Qwen/Qwen2.5-72B-Instruct"
export AI_API_FORMAT="openai"
```

---

## 输出结果

| 格式 | 说明 |
|------|------|
| **SQLite** | WAL 模式优化，批量写入 |
| **JSON** | 完整扫描结果 |
| **Excel** | 分 Sheet 可视化报告 |
| **HTML** | 交互式报告 |

结果目录：`results/{target}/`

---

## 更新日志

### v3.3 - Parameter Fuzzing Integration

- **参数提取链路打通**: AST解析的parameter_names → js_params → fuzzing阶段
- **父路径变异Fuzzing**: 实现 `_fuzz_api_paths()` 实际探测逻辑
  - 父路径 + JS后缀/资源组合
  - 带参数的路径组合 (?param=value 和 /param/1 两种形式)
- **跨来源智能组合**: `_cross_source_fuzz()` 实现路径片段智能组合
- **参数合并策略**: endpoint.parameters ∪ discovered_params ∪ common_params

### v3.2 - Intelligent Path Analysis

- **通用父路径生成**: 不再限制特定前缀，任何 `/path/path` 格式自动提取父路径
- **AST 增强解析**: 支持 axios/fetch/request/$.ajax 等多种 HTTP 客户端
- **RESTful 模板提取**: 自动识别 `{param}` 格式动态参数
- **HTTP 方法识别**: 支持 get/post/put/delete/patch/head/options 等
- **智能 ID 检测**: 自动识别数字/UUID 等 ID 段，避免误生成无效路径
- SSL 验证修复 (--no-ssl-verify 选项生效)
- 相对路径 JS URL 自动转换为绝对 URL
- API 端点正确持久化到数据库

### v3.1 - LLM Integration

- 整合 [llm](https://github.com/simonw/llm) 库，统一管理多种 AI 提供商
- 支持 OpenAI/Anthropic/Gemini/DeepSeek/Mistral/Ollama
- 支持自定义 API（如硅基流动）

### v3.0 - Integration

- ScanEngine 统一扫描引擎
- Agentic AI 智能端点预测
- OpenAPI 3.0 自动导出
- 增量扫描、断点续扫
- 多目标并行扫描
- 攻击链可视化

---

## 致谢

- [jjjjjjjjjjjjs](https://github.com/ttstormxx/jjjjjjjjjjjjjs) - JS 采集思路
- [HaE](https://gh0st.cn/HaE/) - 敏感信息规则
- [wih](https://tophanttechnology.github.io/ARL-doc/function_desc/web_info_hunter/) - 指纹识别规则
- [llm](https://github.com/simonw/llm) - LLM 统一管理库

---

<p align="center">
  <strong>0x727 Team</strong> · Made with security research
</p>

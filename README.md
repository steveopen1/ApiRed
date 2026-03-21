# ApiRed - Red Team API Security Scanner

[![GitHub release](https://img.shields.io/github/release/0x727/ChkApi_0x727.svg)](https://github.com/0x727/ChkApi_0x727/releases)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> 专为红队视角设计的 API 安全扫描器，从攻击者角度自动化发现目标资产中的 API 接口漏洞

**郑重声明**：本文档所涉及的技术、思路和工具仅供安全检测、安全辅助建设为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担。

---

## 理念

**红队视角 = 攻击者思维**

- 不依赖目标提供文档，完全黑盒发现
- 从 JS/静态资源中还原完整 API 攻击面
- 关注"影子 API"——未被记录但可访问的端点
- 模拟真实攻击链路：发现 → 探测 → 利用

---

## 特性

| 特性 | 红队价值 |
|------|----------|
| **影子 API 发现** | 从 JS/Webpack 挖掘未公开端点，攻击面 +40% |
| **智能路径猜测** | LLM 驱动端点预测，补全业务链路 |
| **服务指纹** | 识别微服务架构，发现认证绕过点 |
| **Bypass 能力** | 绕过 401/403/404，获取隐藏资源 |
| **响应差异分析** | 快速定位未授权访问、可越权端点 |
| **敏感凭证挖掘** | JS/响应中提取 AK/SK/Token/JWT |
| **漏洞验证** | 自动验证 SQLi/XSS/SSRF/JWT/OAuth2 |
| **攻击链生成** | 从入口到漏洞的完整调用链路 |
| **OpenAPI 生成** | 自动导出 OpenAPI 3.0 规范 |
| **增量扫描** | 断点续扫，支持检查点恢复 |
| **多目标并行** | 支持 100+ 目标并发扫描 |

---

## 快速开始

### 安装依赖

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

# 激进扫描 - 高并发突破限制
python3 main.py scan -u https://target.com --concurrency 100

# 隐蔽侦察 - 只收集不攻击
python3 main.py scan -u https://target.com --at 1 --chrome off

# AI 辅助 - 智能漏洞研判
python3 main.py scan -u https://target.com --ai

# 多目标并行扫描
python3 main.py scan -f targets.txt --concurrent-targets 10

# 增量扫描 - 断点续扫
python3 main.py scan -u https://target.com --resume

# 禁用 SSL 验证（不推荐）
python3 main.py scan -u https://target.com --no-ssl-verify
```

### 查看帮助

```bash
python3 main.py scan --help
```

---

## 架构设计

```
ApiRed v3.0
├── main.py                     # 统一入口
├── core/
│   ├── scanner.py             # 主扫描器 (Stage1-5)
│   ├── engine.py              # ScanEngine 统一引擎
│   ├── pipeline.py            # 处理流水线
│   ├── agents/                # AI Agent 系统
│   │   ├── base.py          # Agent 基类
│   │   ├── scanner_agent.py  # 扫描 Agent
│   │   ├── analyzer_agent.py # 分析 Agent
│   │   └── tester_agent.py  # 测试 Agent
│   ├── collectors/            # 信息采集
│   │   ├── js_collector.py   # JS指纹缓存 + AST解析
│   │   └── api_collector.py  # API多源采集
│   ├── analyzers/            # 分析引擎
│   │   ├── api_scorer.py     # 统一评分模型
│   │   ├── response_cluster.py# 响应聚类/O(n)优化
│   │   └── sensitive_detector.py# 两级敏感检测
│   ├── testers/              # 测试模块
│   │   ├── fuzz_tester.py    # 模糊测试
│   │   └── vulnerability_tester.py# 漏洞测试 (SQLi/XSS/SSRF/JWT)
│   ├── security/             # 安全检测
│   │   └── security_detector.py# 未授权访问/IDOR检测
│   ├── ai/                  # AI 引擎 (基于 llm 库)
│   │   └── ai_engine.py     # 统一 LLM 客户端
│   ├── exporters/           # 导出模块
│   │   ├── report_exporter.py# JSON/HTML/Excel
│   │   ├── openapi_exporter.py# OpenAPI 3.0
│   │   └── attack_chain_exporter.py# 攻击链可视化
│   ├── plugins.py           # 插件注册表
│   └── dashboard/           # Web 控制面板
├── tests/                   # 测试套件 (63 tests)
└── config.yaml             # 配置文件
```
```

---

## 攻击流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. 资产侦察 (Reconnaissance)                   │
├─────────────────────────────────────────────────────────────────┤
│  JS 采集 → Webpack 分析 → 动态路由还原 → 静态资源挖掘          │
│  "发现目标所有前端资源，不遗漏任何 API 线索"                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   2. API 攻击面构建 (Mapping)                    │
├─────────────────────────────────────────────────────────────────┤
│  正则提取 → AST 解析 → 路径 Fuzz → 服务识别                    │
│  "补全后端 API，识别认证服务、文件服务、用户服务..."            │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  3. 高价值目标标定 (Targeting)                  │
├─────────────────────────────────────────────────────────────────┤
│  多源评分 → 敏感路径标记 → 未授权接口筛选                       │
│  "优先测试 admin/token/config 等高价值端点"                     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   4. 漏洞验证 (Exploitation)                    │
├─────────────────────────────────────────────────────────────────┤
│  Bypass 绕过 → 参数 Fuzz → 越权测试 → 凭证挖掘                   │
│  "绕过认证限制，获取未授权访问，提取敏感凭证"                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   5. 攻击报告 (Reporting)                       │
├─────────────────────────────────────────────────────────────────┤
│  攻击链还原 → 漏洞证据 → 利用建议                               │
│  "提供可直接利用的漏洞详情和修复方案"                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 配置说明

### AI 模型配置

ApiRed 使用 [llm](https://github.com/simonw/llm) 库统一管理多种 LLM 提供商，支持以下模型：

| 提供商 | 环境变量 | API Format | 示例模型 |
|--------|----------|------------|----------|
| OpenAI | `OPENAI_API_KEY` | `openai` | gpt-4o, gpt-4o-mini, gpt-4-turbo |
| Anthropic | `ANTHROPIC_API_KEY` | `anthropic` | claude-3-5-sonnet, claude-opus-4 |
| Google Gemini | `GEMINI_API_KEY` | `gemini` | gemini-2.0-flash, gemini-1.5-pro |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek` | deepseek-chat, deepseek-coder |
| Mistral | `MISTRAL_API_KEY` | `mistral` | mistral-large, mistral-small |
| Ollama | 无 (本地) | `ollama` | llama3, codestral |
| 自定义 | `CUSTOM_API_KEY` | `openai` | Qwen/Qwen2.5-72B-Instruct |

#### 快速配置

```bash
# OpenAI
export OPENAI_API_KEY="sk-xxxx"
export AI_MODEL="gpt-4o-mini"
export AI_API_FORMAT="openai"

# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-xxxx"
export AI_MODEL="claude-3-5-sonnet"
export AI_API_FORMAT="anthropic"

# Google Gemini
export GEMINI_API_KEY="xxxx"
export AI_MODEL="gemini-2.0-flash"
export AI_API_FORMAT="gemini"

# DeepSeek
export DEEPSEEK_API_KEY="sk-xxxx"
export AI_MODEL="deepseek-chat"
export AI_API_FORMAT="deepseek"

# Mistral
export MISTRAL_API_KEY="xxxx"
export AI_MODEL="mistral-large"
export AI_API_FORMAT="mistral"

# Ollama (本地)
export AI_MODEL="llama3"
export AI_API_FORMAT="ollama"

# 自定义 API (硅基流动等)
export CUSTOM_API_KEY="your-api-key"
export AI_BASE_URL="https://api.siliconflow.cn/v1"
export AI_MODEL="Qwen/Qwen2.5-72B-Instruct"
export AI_API_FORMAT="openai"
```

#### 查看所有可用模型

```bash
python -c "import llm; print([m.model_id for m in llm.get_models()])"
```

### config.yaml 关键配置

```yaml
scanner:
  concurrency:
    js_requests: 50        # JS 请求并发数
    api_requests: 100      # API 请求并发数
    timeout: 30            # 超时时间(秒)
  
  bypass:
    enabled: true          # 启用 Bypass
    techniques:
      - header_injection   # Header 注入
      - method_tampering   # 方法混淆
      - path_traversal     # 路径遍历

ai:
  enabled: false
  provider: "deepseek"
  model: "deepseek-chat"
  base_url: "https://api.deepseek.com/v1"
  api_format: "openai"    # openai/anthropic/gemini/deepseek/mistral/ollama
  thresholds:
    high_value_api_score: 5  # 高价值 API 评分阈值

reporting:
  formats:
    - json
    - html
    - excel
```

---

## 红队视角对比

| 工具 | 定位 | 差距 |
|------|------|------|
| **Burp Suite** | 综合平台 | ApiRed 更轻量，专注于 API 链路发现 |
| **Metlo** | 流量分析 | 需要部署 agent，ApiRed 纯黑盒 |
| **Akto** | 测试框架 | 偏向防御，ApiRed 强调攻击视角 |
| **ARL** | 资产侦察 | ApiRed 专注 API，更深入的 JS 分析 |

**ApiRed 优势**：
- 纯黑盒：无需目标配合，快速输出攻击面
- 攻击链：从 JS 到漏洞的完整路径追踪
- 高效：异步并发 + 智能过滤，日均扫描 100+ 目标

---

## 攻击命令

| 选项 | 红队用途 |
|------|----------|
| `-u, --url` | 指定目标 |
| `-f, --file` | 批量目标文件 |
| `-c, --cookies` | 携带认证 Cookie 测试会话劫持 |
| `--chrome off` | 减少指纹，避免被发现 |
| `--at 1` | 只收集不攻击，隐蔽侦察 |
| `--na 1` | 跳过主动探测，无感知扫描 |
| `--concurrency 100` | 高速扫描，抢在封禁前完成 |
| `--ai` | AI 辅助分析敏感接口 |
| `--proxy` | 隐藏真实 IP |
| `--bypass-only` | 仅使用 Bypass 技术获取受限资源 |

---

## 数据存储

| 格式 | 说明 |
|------|------|
| **SQLite** | WAL 模式优化，批量写入 |
| **JSON** | 完整扫描结果 |
| **Excel** | 分 Sheet 可视化 |
| **HTML** | 交互式报告 |

---

## 目录结构

```
results/
└── {target}/
    ├── results.db           # SQLite 数据库
    ├── scan_result.json     # 扫描结果
    ├── {target}.xlsx       # Excel 报告
    └── response/           # 响应包目录
```

---

## 更新日志

### v3.1 - LLM Integration (2026-03)

- **LLM 库整合**：使用 [llm](https://github.com/simonw/llm) 统一管理多种 AI 提供商
- **多模型支持**：OpenAI, Anthropic, Google Gemini, DeepSeek, Mistral, Ollama
- **自定义 API**：支持硅基流动等 OpenAI 兼容 API 服务
- **简化配置**：环境变量配置，开箱即用

### v3.0 - Integration (2026-03)

- **ScanEngine**：统一扫描引擎，整合 Collector → Analyzer → Tester 流程
- **Agentic AI**：LLM 驱动的智能端点预测和漏洞研判
- **OpenAPI 导出**：自动生成 OpenAPI 3.0 规范文档
- **增量扫描**：断点续扫，支持检查点恢复
- **多目标并行**：支持 100+ 目标并发扫描
- **攻击链可视化**：Mermaid 图表 + HTML 交互报告
- **性能优化**：响应聚类 O(n) 算法，AST 解析支持
- **测试覆盖**：63 个单元/集成测试，性能基准测试

### v2.0 - ApiRed (2026-03)

- **品牌升级**：从 ChkApi 重构为 ApiRed，强调红队攻击视角
- 架构重构：模块化拆分，性能优化 60%+
- JS 指纹缓存：重复解析时间 -70%
- API 统一评分：多源证据聚合，高价值发现 +40%
- 响应聚类：404 基线过滤，AI 调用 -80%
- 服务聚合：微服务维度攻击面分析
- 新增 CLI：红队友好命令行
- 扩展配置：支持 Bypass 技术链定制

---

## 致谢

- [jjjjjjjjjjjjs](https://github.com/ttstormxx/jjjjjjjjjjjjjs) - JS 采集思路
- [HaE](https://gh0st.cn/HaE/) - 敏感信息规则
- [wih](https://tophanttechnology.github.io/ARL-doc/function_desc/web_info_hunter/) - 指纹识别规则

---

## 贡献

欢迎提交 Issue 和 Pull Request！

- 提交前请确保代码通过 lint 检查
- 新功能请先创建 Issue 讨论
- PR 提交至 dev 分支

---

<p align="center">
  <strong>0x727 Team</strong> · Made with security research
</p>

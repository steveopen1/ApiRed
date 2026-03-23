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

### 查看所有可用模型

```bash
python -c "import llm; print([m.model_id for m in llm.get_models()])"
```

---

## 扫描流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. 资产侦察 (Reconnaissance)                   │
├─────────────────────────────────────────────────────────────────┤
│  JS 采集 → AST 解析 → 智能父路径生成 → 路径模板提取          │
│  支持 axios/fetch/request/$.ajax 等多种 HTTP 客户端            │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                   2. API 攻击面构建 (Mapping)                    │
├─────────────────────────────────────────────────────────────────┤
│  正则提取 → AST 解析 → 路径 Fuzz → 服务识别                    │
│  通用路径识别 (>=2 层路径自动识别)                              │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                  3. 高价值目标标定 (Targeting)                  │
├─────────────────────────────────────────────────────────────────┤
│  多源评分 → 敏感路径标记 → 未授权接口筛选                       │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                   4. 漏洞验证 (Exploitation)                    │
├─────────────────────────────────────────────────────────────────┤
│  Bypass 绕过 → 参数 Fuzz → 越权测试 → 凭证挖掘                 │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│                   5. 攻击报告 (Reporting)                       │
├─────────────────────────────────────────────────────────────────┤
│  攻击链还原 → 漏洞证据 → 利用建议                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 架构设计

```
ApiRed
├── main.py                        # CLI 入口
├── core/
│   ├── scanner.py                 # 主扫描器
│   ├── engine.py                 # ScanEngine 统一引擎
│   ├── pipeline.py               # 处理流水线
│   ├── dispatcher.py             # 任务调度器
│   ├── knowledge_base.py         # 知识库
│   ├── agents/                   # AI Agent 系统
│   │   ├── orchestrator.py      # Agent 编排器
│   │   ├── discover_agent.py    # 发现 Agent
│   │   ├── test_agent.py        # 测试 Agent
│   │   └── reflect_agent.py     # 反思 Agent
│   ├── ai/                       # AI 引擎 (基于 llm)
│   │   └── ai_engine.py         # 统一 LLM 客户端
│   ├── collectors/              # 信息采集
│   │   ├── js_collector.py     # JS 指纹 + AST 解析 + 智能路径分析
│   │   ├── api_collector.py     # API 多源采集
│   │   └── browser_collector.py # 浏览器采集
│   ├── testers/                  # 测试模块
│   │   ├── fuzz_tester.py       # 模糊测试
│   │   ├── bypass_techniques.py # Bypass 技术
│   │   └── vulnerability_tester.py # 漏洞测试
│   ├── security/                 # 安全检测
│   │   └── security_detector.py # 未授权/IDOR 检测
│   ├── exporters/                # 导出模块
│   │   ├── report_exporter.py   # JSON/HTML/Excel
│   │   ├── openapi_exporter.py  # OpenAPI 3.0
│   │   └── attack_chain_exporter.py # 攻击链
│   └── services/                 # 服务分析
│       └── service_analyzer.py   # 微服务识别
├── tests/                        # 测试套件 (63 tests)
└── config.yaml                   # 配置文件
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

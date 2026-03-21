# ChkApi - API Security Scanner

[![GitHub release](https://img.shields.io/github/release/0x727/ChkApi_0x727.svg)](https://github.com/0x727/ChkApi_0x727/releases)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> 辅助甲方安全人员巡检网站资产，发现并分析 API 安全问题的自动化工具

**郑重声明**：本文档所涉及的技术、思路和工具仅供安全检测、安全辅助建设为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担。

---

## 特性

| 特性 | 描述 |
|------|------|
| **JS 智能解析** | 支持 Webpack 打包分析、动态 import 还原、JS 指纹缓存 |
| **API 多源发现** | 正则 + AST 双引擎提取，Swagger 全版本解析 |
| **智能评分** | 基于多源证据的 API 价值评分，高价值接口优先探测 |
| **漏洞检测** | 未授权访问、SQL注入、XSS、SSRF 等 10+ 类型 |
| **Bypass 能力** | Header注入、方法混淆、路径遍历等 10+ 种绕过技术 |
| **敏感信息** | AWS/GitHub/JWT 等密钥检测，支持自定义规则 |
| **高性能** | 异步并发引擎，50-100 并发，WAL 数据库优化 |
| **服务聚合** | 按微服务维度聚合分析，攻击面可视化 |

---

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt

# 或使用完整安装（含异步支持）
pip install -r requirements.txt aiohttp
```

### 基本用法

```bash
# 单 URL 扫描
python3 chkapi.py -u https://target.com

# 携带 Cookie 认证
python3 chkapi.py -u https://target.com -c "session=xxx"

# 文件批量扫描
python3 chkapi.py -f urls.txt

# 启用 AI 分析
python3 chkapi.py -u https://target.com --ai

# 调整并发数
python3 chkapi.py -u https://target.com --concurrency 100
```

### 查看帮助

```bash
python3 chkapi.py -h
```

---

## 架构设计

```
ChkApi v2.0
├── core/                      # 核心引擎
│   ├── collectors/             # 信息采集
│   │   ├── js_collector.py     # JS指纹缓存 + AST解析
│   │   └── api_collector.py   # API多源采集
│   ├── analyzers/             # 分析引擎
│   │   ├── api_scorer.py      # 统一评分模型
│   │   ├── response_cluster.py # 响应聚类/404过滤
│   │   └── sensitive_detector.py # 两级敏感检测
│   ├── testers/               # 测试模块
│   │   ├── fuzz_tester.py     # 模糊测试
│   │   └── vulnerability_tester.py # 漏洞测试
│   ├── storage/              # 存储层
│   ├── models/               # 数据模型
│   ├── utils/                # 工具类
│   ├── scanner.py             # 主扫描器
│   ├── pipeline.py            # 处理流水线
│   └── dispatcher.py          # 任务调度
├── plugins/                   # 插件系统（兼容v1）
├── cli.py                     # 命令行入口
└── config.yaml               # 配置文件
```

---

## 核心流程

```
┌─────────────────────────────────────────────────────────────────┐
│                        1. 资源发现                               │
├─────────────────────────────────────────────────────────────────┤
│  Chrome/Requests 获取 JS 资源 → Webpack 解析 → 动态 import 还原 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                        2. API 提取                               │
├─────────────────────────────────────────────────────────────────┤
│  正则提取 → AST 解析 → Swagger 解析 → 服务路径发现              │
│  JS 指纹缓存（重复 JS 解析时间 -70%）                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     3. API 评分与优先级                         │
├─────────────────────────────────────────────────────────────────┤
│  多源证据聚合 → 评分模型 → 高价值 API 优先探测（+40%）          │
│  服务级聚合 → 微服务维度风险分析                                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      4. 漏洞检测                                │
├─────────────────────────────────────────────────────────────────┤
│  无参/有参请求 → 响应聚类 → Bypass 绕过 → AI 研判              │
│  404 基线过滤（AI 调用量 -80%）                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                      5. 报告输出                                │
├─────────────────────────────────────────────────────────────────┤
│  JSON/Excel/HTML → 敏感信息报告 → 攻击面可视化                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 配置说明

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
  thresholds:
    high_value_api_score: 5  # 高价值 API 评分阈值

reporting:
  formats:
    - json
    - html
    - excel
```

---

## 竞品对比

| 工具 | Stars | 定位 | ChkApi 优势 |
|------|-------|------|-------------|
| **Akto** | 1.5k | 测试框架 | AI 评分、自动化程度 |
| **Metlo** | 1.8k | 流量分析 | 纯黑盒、免部署 |
| **OWASP Noir** | 1.1k | 端点发现 | 多引擎、更全面 |
| **Cherrybomb** | 1.2k | 规范审计 | 服务聚合、可视化 |

---

## 命令行选项

| 选项 | 说明 |
|------|------|
| `-u, --url` | 目标 URL |
| `-f, --file` | URL 列表文件 |
| `-c, --cookies` | 认证 Cookie |
| `--chrome on/off` | 启用/禁用 Chrome |
| `--at 0/1` | 0=收集+探测, 1=仅收集 |
| `--na 0/1` | 0=扫描API, 1=跳过API扫描 |
| `--concurrency` | 并发数 (默认50) |
| `--ai` | 启用 AI 分析 |
| `--proxy` | 代理服务器 |
| `--output` | 输出目录 |
| `--format` | 输出格式 (json/html) |

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

### v2.0 (2026-03)

- 架构重构：模块化拆分，性能优化 60%+
- JS 指纹缓存：重复解析时间 -70%
- API 统一评分：多源证据聚合，高价值发现 +40%
- 响应聚类：404 基线过滤，AI 调用 -80%
- 服务聚合：微服务维度风险分析
- 新增 CLI：现代化命令行界面
- 扩展配置：支持 AI、Bypass、规则定制

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

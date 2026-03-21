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
| **智能路径猜测** | Base URL + API 字典 Fuzz，补全业务链路 |
| **服务指纹** | 识别微服务架构，发现认证绕过点 |
| **Bypass 能力** | 绕过 401/403/404，获取隐藏资源 |
| **响应差异分析** | 快速定位未授权访问、可越权端点 |
| **敏感凭证挖掘** | JS/响应中提取 AK/SK/Token/JWT |
| **漏洞验证** | 自动验证 SQLi/XSS/SSRF/RCE 等 |
| **攻击链生成** | 从入口到漏洞的完整调用链路 |

---

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 基本用法

```bash
# 目标侦察 - 收集所有 API 攻击面
python3 apired.py -u https://target.com

# 携带认证 Cookie - 测试会话安全
python3 apired.py -u https://target.com -c "session=xxx"

# 批量目标 - 快速资产覆盖
python3 apired.py -f targets.txt

# 激进扫描 - 高并发突破限制
python3 apired.py -u https://target.com --concurrency 100

# 隐蔽侦察 - 只收集不攻击
python3 apired.py -u https://target.com --at 1 --chrome off

# AI 辅助 - 智能漏洞研判
python3 apired.py -u https://target.com --ai
```

### 查看帮助

```bash
python3 apired.py -h
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

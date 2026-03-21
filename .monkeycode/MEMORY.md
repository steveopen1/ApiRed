# 用户指令记忆

本文件记录了用户的指令、偏好和教导，用于在未来的交互中提供参考。

## 格式

### 用户指令条目
用户指令条目应遵循以下格式：

[用户指令摘要]
- Date: [YYYY-MM-DD]
- Context: [提及的场景或时间]
- Instructions:
  - [用户教导或指示的内容，逐行描述]

### 项目知识条目
Agent 在任务执行过程中发现的条目应遵循以下格式：

[项目知识摘要]
- Date: [YYYY-MM-DD]
- Context: Agent 在执行 [具体任务描述] 时发现
- Category: [代码结构|代码模式|代码生成|构建方法|测试方法|依赖关系|环境配置]
- Instructions:
  - [具体的知识点，逐行描述]

## 去重策略
- 添加新条目前，检查是否存在相似或相同的指令
- 若发现重复，跳过新条目或与已有条目合并
- 合并时，更新上下文或日期信息
- 这有助于避免冗余条目，保持记忆文件整洁

## 条目

### ApiRed 优化方案知识

[ApiRed v1.0 优化方案]
- Date: 2026-03-21
- Context: 为 ApiRed 项目制定第 v1.0 版优化方案
- Category: 项目知识
- Instructions:
  - 项目定位：红队视角 API 安全扫描器，黑盒发现 + 影子 API + 攻击链路
  - 竞品分析：Noir(SAST-to-DAST), Akto(1000+用例), Metlo(流量分析), Cherrybomb(OpenAPI验证)
  - ROI 最高 3 条：1) 完善 Agent System 2) 扩充测试用例库 3) 增量扫描生产可用
  - 技术趋势：LLM 端点预测、SAST-to-DAST 桥接、测试用例标准化
  - 架构建议：Scanner/Engine 合并为单一入口，Agent System 完整实现
  - LLM/Agent 融合：三 Agent 协同（ScannerAgent, AnalyzerAgent, TesterAgent）
  - 实施优先级：P0-阻塞(1周) > P1-严重(2周) > P2-优化(1月)
  - 测试用例库目标：1000+ 用例，覆盖 OWASP API Top 10
  - 优化文档位置：docs/optimization/v1.0-optimization.md

### 代码架构知识

[ApiRed 核心架构]
- Date: 2026-03-21
- Context: 分析 ApiRed v3.0 架构
- Category: 代码结构
- Instructions:
  - 入口：main.py 统一入口（CLI）
  - 核心引擎：core/engine.py (ScanEngine) + core/scanner.py (ChkApiScanner)
  - Agent 系统：core/agents/ (base.py, scanner_agent.py, analyzer_agent.py, tester_agent.py)
  - AI 引擎：core/ai/ai_engine.py (AIEngine 类)
  - 采集器：core/collectors/ (js_collector.py, api_collector.py)
  - 分析器：core/analyzers/ (api_scorer.py, response_cluster.py, sensitive_detector.py)
  - 测试器：core/testers/ (fuzz_tester.py, vulnerability_tester.py)
  - 安全检测：core/security/security_detector.py
  - 导出器：core/exporters/ (report_exporter.py, openapi_exporter.py, attack_chain_exporter.py)
  - 插件系统：core/plugins.py (PluginRegistry)
  - 测试套件：tests/ (49 tests passing)

[ApiRed 已知问题]
- Date: 2026-03-21
- Context: 代码审查发现
- Category: 代码结构
- Instructions:
  - Scanner 与 Engine 双入口架构冗余，需合并
  - Agent 实现不完整（AnalyzerAgent/TesterAgent 的 think/chat 是空覆盖）
  - 测试用例仅 SQLi/XSS/SSRF，缺 OWASP Top10
  - ChkApi.py 是遗留文件，应删除

[Git 操作规范]
- Date: 2026-03-21
- Context: 用户指示
- Category: 构建方法
- Instructions:
  - 本地文档（.monkeycode/）不上传到 GitHub
  - 优化方案文档放在 docs/optimization/ 目录
  - CI/CD 配置（.github/workflows/）需要保留在项目中
  - 合并到 master 分支而不是长期在 feature 分支开发
  - .monkeycode/ 和 .github/ 是不同的：前者是本地文档，后者是 CI 配置

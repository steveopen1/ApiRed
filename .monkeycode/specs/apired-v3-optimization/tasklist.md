# ApiRed v3.0 优化实施计划

## Phase 1: 核心修复（1 周）

- [ ] 1. 修复 SSL 安全问题
  - [ ] 1.1 修改 `core/utils/http_client.py`，默认启用 SSL 验证
  - [ ] 1.2 添加 `--no-ssl-verify` 选项供特殊场景使用
  - [ ] 1.3 更新文档说明安全风险

- [ ] 2. 实现 Stage2 API 提取逻辑
  - [ ] 2.1 在 `core/scanner.py` 实现 `_stage2_api_extraction` 方法
  - [ ] 2.2 复用 `collectors/api_collector.py` 中的 `APIAggregator`
  - [ ] 2.3 实现正则 + AST 双模式端点提取
  - [ ] 2.4 实现 BaseURL 分析和路径补全
  - [ ] 2.5 添加 API 端点去重和评分

- [ ] 3. 实现 Stage3 API 测试逻辑
  - [ ] 3.1 在 `core/scanner.py` 实现 `_stage3_api_testing` 方法
  - [ ] 3.2 实现 HTTP 方法检测（GET/POST/PUT/DELETE/PATCH）
  - [ ] 3.3 实现参数自动发现（从 JS/URL/Body 中提取）
  - [ ] 3.4 实现响应状态码分析和指纹识别
  - [ ] 3.5 调用 `ResponseCluster` 进行 404 基线过滤

- [ ] 4. 实现 Stage4 漏洞验证逻辑
  - [ ] 4.1 在 `core/scanner.py` 实现 `_stage4_vulnerability_testing` 方法
  - [ ] 4.2 调用 `testers/fuzz_tester.py` 进行参数模糊测试
  - [ ] 4.3 调用 `testers/vulnerability_tester.py` 进行漏洞检测
  - [ ] 4.4 实现未授权访问检测（调用 `security/security_detector.py`）
  - [ ] 4.5 实现 IDOR 越权检测
  - [ ] 4.6 实现敏感信息泄露检测（调用 `TwoTierSensitiveDetector`）

- [ ] 5. 实现 Agent AI 基础能力
  - [ ] 5.1 在 `core/agents/base.py` 实现 `think()` 方法
  - [ ] 5.2 在 `core/agents/base.py` 实现 `chat()` 方法
  - [ ] 5.3 在 `core/agents/base.py` 实现 `reflect()` 方法
  - [ ] 5.4 实现 `AgentMemory` 记忆管理
  - [ ] 5.5 在 `ScannerAgent` 中实现 JS 智能分析
  - [ ] 5.6 在 `AnalyzerAgent` 中实现风险评估
  - [ ] 5.7 在 `TesterAgent` 中实现载荷生成

- [ ] 6. 实现增量扫描支持
  - [ ] 6.1 在 `core/scanner.py` 添加扫描状态持久化
  - [ ] 6.2 实现断点恢复机制
  - [ ] 6.3 添加 `--resume` 选项
  - [ ] 6.4 实现扫描结果缓存验证

- [ ] 7. 单元测试与验证
  - [ ] 7.1 为 Scanner 核心流程编写集成测试
  - [ ] 7.2 为各 Agent 编写单元测试
  - [ ] 7.3 运行 `python main.py -u https://example.com` 验证完整流程

## Phase 2: 架构重构（1 个月）

- [ ] 8. 创建 ScanEngine 统一入口
  - [ ] 8.1 创建 `core/engine.py`，定义 `ScanEngine` 类
  - [ ] 8.2 设计 Orchestrator 任务编排器
  - [ ] 8.3 实现 Collector → Analyzer → Tester 流程编排
  - [ ] 8.4 迁移 Scanner 逻辑到 ScanEngine

- [ ] 9. 实现插件注册表
  - [ ] 9.1 创建 `core/plugins.py`，定义 `PluginRegistry` 类
  - [ ] 9.2 实现插件加载机制（动态 import）
  - [ ] 9.3 实现 Collector Plugin 接口
  - [ ] 9.4 实现 Tester Plugin 接口
  - [ ] 9.5 实现 Exporter Plugin 接口

- [ ] 10. 重构 Config 为线程安全
  - [ ] 10.1 修改 `core/utils/config.py`，使用 threading.Lock
  - [ ] 10.2 实现双重检查锁定模式
  - [ ] 10.3 添加配置热更新支持
  - [ ] 10.4 编写并发安全测试

- [ ] 11. 扩展测试用例库
  - [ ] 11.1 实现 OWASP API Security Top 10 测试用例
  - [ ] 11.2 实现 SQL 注入检测（ERROR_BASED/BLIND/TIME_BASED）
  - [ ] 11.3 实现 XSS 检测（反射型/存储型/DOM）
  - [ ] 11.4 实现 SSRF 检测
  - [ ] 11.5 实现 JWT 安全测试
  - [ ] 11.6 实现 OAuth2 安全测试
  - [ ] 11.7 实现 Bypass 技术测试（认证/授权/限流）

- [ ] 12. 实现 CI/CD 集成钩子
  - [ ] 12.1 创建 GitHub Actions 工作流
  - [ ] 12.2 实现 GitLab CI 集成
  - [ ] 12.3 添加 JUnit XML 格式报告输出

## Phase 3: 能力增强（3 个月）

- [ ] 13. LLM 驱动的智能路径发现
  - [ ] 13.1 在 `ScannerAgent` 中实现路径预测
  - [ ] 13.2 实现基于上下文的 Fuzz 策略
  - [ ] 13.3 实现语义分析驱动的端点发现
  - [ ] 13.4 优化 AI 调用成本（批量处理 + 缓存）

- [ ] 14. OpenAPI 自动生成
  - [ ] 14.1 创建 `exporters/openapi_exporter.py`
  - [ ] 14.2 实现从扫描结果生成 OpenAPI 3.0 规范
  - [ ] 14.3 实现从 JS 代码推断 API 规范
  - [ ] 14.4 添加 Swagger UI 集成

- [ ] 15. 多目标并行扫描
  - [ ] 15.1 实现目标池管理
  - [ ] 15.2 实现分布式任务分发
  - [ ] 15.3 实现结果聚合
  - [ ] 15.4 添加负载均衡策略

- [ ] 16. 攻击链可视化
  - [ ] 16.1 创建攻击链数据模型
  - [ ] 16.2 实现链路追踪（JS → API → 漏洞）
  - [ ] 16.3 添加 Mermaid 图表生成
  - [ ] 16.4 实现交互式 HTML 报告

- [ ] 17. 性能优化
  - [ ] 17.1 优化响应聚类算法（O(n) 复杂度）
  - [ ] 17.2 引入 AST 解析（替代纯正则）
  - [ ] 17.3 实现扫描结果压缩存储
  - [ ] 17.4 添加性能监控指标

- [ ] 18. 验收测试
  - [ ] 18.1 编写完整的功能验收测试
  - [ ] 18.2 编写性能基准测试
  - [ ] 18.3 编写安全扫描准确性测试
  - [ ] 18.4 执行全面回归测试

## 检查点

- [ ] **检查点 1**: Phase 1 完成，`python main.py -u https://example.com` 完整执行无报错
- [ ] **检查点 2**: Phase 2 完成，插件系统正常工作
- [ ] **检查点 3**: Phase 3 完成，性能和功能指标达标
- [ ] **最终验收**: 所有测试通过，文档完整

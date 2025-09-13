# Implementation Plan

- [x] 1. 设置项目基础架构和核心接口

  - 更新 package.json 配置，添加必要的激活事件和贡献点
  - 创建核心接口定义文件，建立系统边界
  - 设置 TypeScript 配置和项目目录结构
  - 实现基础工具函数和常量定义
  - 创建扩展入口点和基础服务架构
  - _Requirements: 4.1, 4.2_

- [x] 2. 实现文档监听和分析引擎核心
- [x] 2.1 创建文档监听器

  - 实现 DocumentMonitor 类，监听文档打开、编辑和保存事件
  - 添加防抖机制，避免过度分析（500ms 延迟）
  - 实现文件类型过滤，只处理支持的语言文件
  - 编写文档监听器的单元测试
  - _Requirements: 4.2, 7.4_

- [x] 2.2 实现分析引擎协调器

  - 创建 AnalysisEngine 类，协调规则执行和结果处理
  - 实现增量分析逻辑，只分析文档变更部分
  - 添加性能保护机制（超时、文件大小限制）
  - 编写分析引擎的单元测试
  - _Requirements: 7.1, 7.2, 7.3_

- [x] 3. 实现规则引擎基础架构
- [x] 3.1 创建规则引擎核心

  - 实现 RuleEngine 类和 DetectionRule 接口
  - 创建规则注册和执行机制
  - 实现白名单过滤功能，避免误报环境变量引用
  - 编写规则引擎的单元测试
  - _Requirements: 8.1, 8.3_

- [x] 4. 实现 API 密钥检测规则（最高优先级）
- [x] 4.1 创建 API 密钥检测规则定义

  - 创建 src/rules/definitions/api-keys.ts 规则定义文件
  - 实现 OpenAI API 密钥检测（sk-开头模式）
  - 实现 AWS 访问密钥检测（AKIA 开头模式）
  - 实现 GitHub Token 检测（ghp\_开头模式）
  - 实现通用密钥模式检测（api_key、secret、password、token）
  - 注册所有 API 密钥规则到规则引擎
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 4.2 编写 API 密钥检测测试

  - 创建 src/test/rules/api-keys.test.ts 测试文件
  - 编写基于真实 AI 生成代码的测试用例
  - 测试所有 API 密钥检测模式
  - 测试白名单过滤功能
  - 测试快速修复建议生成
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [ ] 5. 实现诊断管理和显示
- [ ] 5.1 创建诊断管理器

  - 创建 src/diagnostics/DiagnosticManager.ts 文件
  - 实现 DiagnosticManager 类，处理 VSCode 诊断 API
  - 将 SecurityIssue 转换为 VSCode Diagnostic 对象
  - 实现诊断的显示、更新和清除功能
  - 添加中文错误信息显示，避免技术术语
  - _Requirements: 4.3, 1.5, 2.4_

- [ ] 5.2 编写诊断管理器测试

  - 创建 src/test/diagnostics/DiagnosticManager.test.ts 测试文件
  - 测试诊断信息的创建和更新
  - 测试诊断信息的清除功能
  - 测试 SecurityIssue 到 VSCode Diagnostic 的转换
  - _Requirements: 4.3, 1.5, 2.4_

- [ ] 6. 实现一键快速修复功能
- [ ] 6.1 创建快速修复提供者

  - 创建 src/quickfix/QuickFixProvider.ts 文件
  - 实现 QuickFixProvider 类，继承 VSCode CodeActionProvider
  - 为 API 密钥问题提供环境变量替换修复
  - 实现批量修复功能，支持一次修复多个问题
  - _Requirements: 1.6, 4.4_

- [ ] 6.2 编写快速修复测试

  - 创建 src/test/quickfix/QuickFixProvider.test.ts 测试文件
  - 测试 API 密钥快速修复功能
  - 测试批量修复功能
  - 测试快速修复的用户体验
  - _Requirements: 1.6, 4.4_

- [ ] 7. 实现 SQL 危险操作检测
- [ ] 7.1 创建 SQL 规则定义

  - 创建 src/rules/definitions/sql-rules.ts 规则定义文件
  - 实现 DELETE FROM 无 WHERE 条件检测
  - 实现 UPDATE SET 无 WHERE 条件检测
  - 实现 DROP TABLE/DATABASE 检测
  - 注册所有 SQL 规则到规则引擎
  - _Requirements: 2.1, 2.2, 2.3_

- [ ] 7.2 编写 SQL 危险操作测试

  - 创建 src/test/rules/sql-rules.test.ts 测试文件
  - 测试所有 SQL 危险操作检测模式
  - 测试 SQL 快速修复建议
  - 编写基于真实场景的测试用例
  - _Requirements: 2.1, 2.2, 2.3_

- [ ] 8. 集成所有组件到扩展入口点
- [ ] 8.1 更新扩展主入口文件

  - 修改 src/extension.ts，集成诊断管理器和快速修复提供者
  - 连接 DocumentMonitor、AnalysisEngine、RuleEngine 和 DiagnosticManager
  - 注册 API 密钥检测规则到规则引擎
  - 实现完整的实时分析工作流程
  - 确保扩展激活时所有服务正常启动
  - _Requirements: 4.1, 4.2, 1.1, 1.2, 1.3, 1.4_

- [ ] 8.2 编写扩展集成测试

  - 创建 src/test/integration/extension-integration.test.ts 测试文件
  - 测试完整的文档分析工作流程
  - 测试 API 密钥检测的端到端功能
  - 测试诊断显示和快速修复的集成
  - _Requirements: 4.1, 4.2_

- [ ] 9. 实现代码注入检测规则
- [ ] 9.1 创建代码注入规则定义

  - 创建 src/rules/definitions/code-injection-rules.ts 规则定义文件
  - 实现 eval() 函数检测和安全替代建议
  - 实现 innerHTML 直接赋值检测和 XSS 风险警告
  - 实现 child_process.exec/spawn 命令注入检测
  - 注册代码注入规则到规则引擎
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 9.2 编写代码注入检测测试

  - 创建 src/test/rules/code-injection-rules.test.ts 测试文件
  - 测试所有代码注入检测模式
  - 编写基于真实攻击场景的测试用例
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 10. 实现框架特定风险检测
- [ ] 10.1 创建框架风险规则定义

  - 创建 src/rules/definitions/framework-rules.ts 规则定义文件
  - 实现 React dangerouslySetInnerHTML 检测
  - 实现 Vue v-html 指令风险检测
  - 实现 React useEffect 无限循环检测
  - 注册框架风险规则到规则引擎
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 10.2 编写框架风险检测测试

  - 创建 src/test/rules/framework-rules.test.ts 测试文件
  - 测试 React 和 Vue 特定风险检测
  - 编写基于真实框架代码的测试用例
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 11. 实现配置错误检测
- [ ] 11.1 创建配置错误规则定义

  - 创建 src/rules/definitions/config-rules.ts 规则定义文件
  - 实现生产环境 debug=true 检测
  - 实现 CORS 配置风险检测（允许所有域名）
  - 实现 Docker 端口暴露风险检测
  - 实现 .env 文件示例值检测
  - 注册配置错误规则到规则引擎
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 11.2 编写配置错误检测测试

  - 创建 src/test/rules/config-rules.test.ts 测试文件
  - 测试所有配置错误检测模式
  - 编写基于真实配置文件的测试用例
  - _Requirements: 6.1, 6.2, 6.3, 6.4_

- [ ] 12. 增强白名单和误报控制
- [ ] 12.1 扩展白名单过滤功能

  - 增强现有白名单机制，支持更多环境变量引用模式
  - 实现注释内容过滤，避免检测注释中的示例代码
  - 实现模板字符串变量检测，避免误报动态内容
  - 实现测试文件特殊处理，降低测试代码的警告级别
  - 更新 RuleEngine 以支持增强的白名单功能
  - _Requirements: 8.1, 8.2, 8.3, 8.5_

- [ ] 12.2 编写白名单机制测试

  - 创建 src/test/rules/whitelist.test.ts 测试文件
  - 测试各种白名单过滤场景
  - 测试误报控制的有效性
  - _Requirements: 8.1, 8.2, 8.3, 8.5_

- [ ] 13. 创建真实场景测试套件
- [ ] 13.1 实现基于真实 AI 生成代码的测试

  - 创建 src/test/scenarios/ 目录
  - 创建 ChatGPT 生成代码的测试用例集合
  - 创建 Claude 生成代码的测试用例集合
  - 实现端到端测试，验证完整的检测和修复流程
  - 添加性能测试，验证大文件和实时分析性能
  - 创建回归测试套件，防止功能退化
  - _Requirements: 所有需求的综合验证_

- [ ] 14. 完善用户体验和文档
- [ ] 14.1 优化错误信息和用户界面
  - 优化所有规则的中文错误信息，确保通俗易懂
  - 添加错误信息中的真实损失案例引用
  - 实现快速修复的用户友好提示
  - 更新 package.json 中的命令和配置描述
  - 更新 README 文档，包含使用示例和截图
  - _Requirements: 4.3, 1.5, 2.4, 3.4_

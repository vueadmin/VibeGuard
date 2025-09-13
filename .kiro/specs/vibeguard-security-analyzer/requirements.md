# Requirements Document

## Introduction

VibeGuard 是一个 VS Code 扩展插件，旨在实时检测代码中的致命错误和安全隐患，帮助开发者（特别是新手）避免常见但危险的编码错误。该插件支持多种编程语言和框架，提供智能的代码分析、实时警告和快速修复建议，从而防止删库、密钥泄露、生产事故等严重问题。

## Requirements

### Requirement 1

**User Story:** 作为开发者，我希望插件能够实时检测 SQL 语句中的危险操作，以便避免意外删除或修改数据库数据

#### Acceptance Criteria

1. WHEN 用户输入不带 WHERE 条件的 DELETE 语句 THEN 系统 SHALL 显示致命错误警告
2. WHEN 用户输入不带 WHERE 条件的 UPDATE 语句 THEN 系统 SHALL 显示致命错误警告
3. WHEN 用户输入 DROP DATABASE 或 DROP TABLE 语句 THEN 系统 SHALL 显示致命错误警告
4. WHEN 用户输入 TRUNCATE TABLE 语句 THEN 系统 SHALL 显示致命错误警告
5. WHEN 检测到 SQL 注入风险（字符串拼接构造 SQL）THEN 系统 SHALL 显示警告并建议使用参数化查询

### Requirement 2

**User Story:** 作为开发者，我希望插件能够检测代码中的敏感信息泄露，以便保护 API 密钥和其他机密数据

#### Acceptance Criteria

1. WHEN 代码中包含硬编码的 API Key（AWS、Azure、Google Cloud 等）THEN 系统 SHALL 显示致命错误警告
2. WHEN 代码中包含明文数据库密码或连接字符串 THEN 系统 SHALL 显示致命错误警告
3. WHEN 代码中包含 JWT Token、OAuth Secret 等认证信息 THEN 系统 SHALL 显示致命错误警告
4. WHEN 检测到敏感信息 THEN 系统 SHALL 提供使用环境变量的快速修复建议

### Requirement 3

**User Story:** 作为开发者，我希望插件能够检测 JavaScript/TypeScript 中的危险代码执行，以便防止安全漏洞

#### Acceptance Criteria

1. WHEN 代码中使用 eval() 函数 THEN 系统 SHALL 显示致命错误警告
2. WHEN 代码中使用 innerHTML 赋值 THEN 系统 SHALL 显示 XSS 风险警告
3. WHEN 代码中使用 child_process.exec THEN 系统 SHALL 显示命令注入风险警告
4. WHEN 检测到危险函数调用 THEN 系统 SHALL 提供安全替代方案的快速修复建议

### Requirement 4

**User Story:** 作为 React 开发者，我希望插件能够检测 React 特有的安全风险和编程陷阱，以便避免 XSS 攻击和性能问题

#### Acceptance Criteria

1. WHEN 代码中使用 dangerouslySetInnerHTML THEN 系统 SHALL 显示 XSS 风险警告
2. WHEN useEffect 缺少依赖数组 THEN 系统 SHALL 显示无限循环风险警告
3. WHEN 组件中有未清理的事件监听器 THEN 系统 SHALL 显示内存泄漏警告
4. WHEN 代码中直接操作 DOM（document.getElementById 等）THEN 系统 SHALL 显示违反 React 原则的警告

### Requirement 5

**User Story:** 作为 Vue 开发者，我希望插件能够检测 Vue 特有的安全风险和编程陷阱，以便避免 XSS 攻击和数据流问题

#### Acceptance Criteria

1. WHEN 代码中使用 v-html 指令 THEN 系统 SHALL 显示 XSS 风险警告
2. WHEN 代码中直接修改 props THEN 系统 SHALL 显示违反单向数据流的错误警告
3. WHEN v-for 缺少 key 属性 THEN 系统 SHALL 显示渲染问题警告
4. WHEN watch 配置可能导致无限循环 THEN 系统 SHALL 显示警告

### Requirement 6

**User Story:** 作为 Node.js 开发者，我希望插件能够检测服务器端特有的安全风险，以便防止命令注入和文件系统攻击

#### Acceptance Criteria

1. WHEN 代码中使用 child_process.exec 执行用户输入 THEN 系统 SHALL 显示命令注入风险警告
2. WHEN 代码中使用 fs.unlink、fs.rmdir 等文件删除操作 THEN 系统 SHALL 显示文件删除风险警告
3. WHEN 代码中存在路径遍历漏洞（直接拼接用户输入路径）THEN 系统 SHALL 显示安全风险警告
4. WHEN Promise 没有 catch 处理 THEN 系统 SHALL 显示未处理异常警告

### Requirement 7

**User Story:** 作为 Python 开发者，我希望插件能够检测 Python 中的危险操作，以便防止代码执行和文件系统风险

#### Acceptance Criteria

1. WHEN 代码中使用 eval() 或 exec() 函数 THEN 系统 SHALL 显示代码执行风险警告
2. WHEN 代码中使用 pickle.load 加载不可信数据 THEN 系统 SHALL 显示安全风险警告
3. WHEN 代码中使用 os.system 执行系统命令 THEN 系统 SHALL 显示命令注入风险警告
4. WHEN Flask/Django 应用中 debug=True THEN 系统 SHALL 显示生产环境配置错误警告

### Requirement 8

**User Story:** 作为开发者，我希望插件能够检测配置文件中的安全问题，以便防止生产环境配置错误

#### Acceptance Criteria

1. WHEN 配置文件中包含明文数据库连接字符串 THEN 系统 SHALL 显示敏感信息泄露警告
2. WHEN CORS 配置允许所有域名（origin: "*"）THEN 系统 SHALL 显示安全配置错误警告
3. WHEN Docker 配置暴露危险端口（SSH、数据库端口）THEN 系统 SHALL 显示安全风险警告
4. WHEN package.json 中包含恶意脚本 THEN 系统 SHALL 显示安全风险警告

### Requirement 9

**User Story:** 作为开发者，我希望插件提供快速修复建议，以便快速解决检测到的安全问题

#### Acceptance Criteria

1. WHEN 检测到安全问题 THEN 系统 SHALL 提供相应的快速修复建议
2. WHEN 用户点击快速修复 THEN 系统 SHALL 自动应用安全的代码替换
3. WHEN 无法自动修复 THEN 系统 SHALL 提供详细的修复指导
4. WHEN 提供修复建议 THEN 系统 SHALL 解释为什么这样修复更安全

### Requirement 10

**User Story:** 作为开发者，我希望插件具有良好的性能表现，以便不影响正常的编码体验

#### Acceptance Criteria

1. WHEN 用户编辑代码 THEN 系统 SHALL 在 500ms 内完成增量分析
2. WHEN 打开大文件（>1MB）THEN 系统 SHALL 使用增量分析避免卡顿
3. WHEN 分析完成 THEN 系统 SHALL 缓存结果以提高后续分析速度
4. WHEN 内存使用超过限制 THEN 系统 SHALL 自动清理缓存

### Requirement 11

**User Story:** 作为开发者，我希望插件支持多语言环境，以便为中文开发者提供友好的用户体验

#### Acceptance Criteria

1. WHEN 检测到安全问题 THEN 系统 SHALL 显示中文错误消息和说明
2. WHEN 提供修复建议 THEN 系统 SHALL 使用中文解释修复原因
3. WHEN 显示警告信息 THEN 系统 SHALL 使用 emoji 和通俗语言增强可读性
4. WHEN 用户查看帮助文档 THEN 系统 SHALL 提供中文版本的说明

### Requirement 12

**User Story:** 作为开发者，我希望插件支持自定义配置，以便根据项目需求调整检测规则

#### Acceptance Criteria

1. WHEN 用户创建配置文件 THEN 系统 SHALL 支持启用/禁用特定规则
2. WHEN 用户配置严重级别 THEN 系统 SHALL 根据配置调整警告级别
3. WHEN 用户配置忽略文件 THEN 系统 SHALL 跳过指定文件的检测
4. WHEN 配置发生变化 THEN 系统 SHALL 自动重新加载并应用新配置
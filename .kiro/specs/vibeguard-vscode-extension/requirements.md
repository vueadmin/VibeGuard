# Requirements Document

## Introduction

VibeGuard 是一个专为非技术用户设计的 VSCode 扩展，旨在保护使用 AI 工具编写代码的设计师、产品经理、运营人员等免受安全风险。项目源于真实案例：一位设计师因硬编码 API 密钥损失了 $5000。该扩展的核心理念是"防止下一个 $5000 的损失"，通过实时检测危险代码模式并提供一键修复功能来保护用户。

## Requirements

### Requirement 1

**User Story:** 作为一个使用 AI 工具编写代码的非技术用户，我希望系统能够自动检测我代码中的 API 密钥硬编码问题，这样我就不会因为密钥泄露而遭受经济损失。

#### Acceptance Criteria

1. WHEN 用户在代码中硬编码 OpenAI API 密钥（sk-开头的字符串）THEN 系统 SHALL 立即显示红色错误提示
2. WHEN 用户在代码中硬编码 AWS 访问密钥（AKIA 开头的字符串）THEN 系统 SHALL 立即显示红色错误提示
3. WHEN 用户在代码中硬编码 GitHub Token（ghp_开头的字符串）THEN 系统 SHALL 立即显示红色错误提示
4. WHEN 用户在代码中使用通用密钥模式（api_key、secret、password、token 等）THEN 系统 SHALL 显示红色错误提示
5. WHEN 检测到硬编码密钥 THEN 错误信息 SHALL 使用中文并包含真实损失案例警示
6. WHEN 用户点击快速修复 THEN 系统 SHALL 自动将硬编码密钥替换为环境变量引用

### Requirement 2

**User Story:** 作为一个使用 AI 生成 SQL 查询的产品经理，我希望系统能够检测危险的 SQL 操作，这样我就不会意外删除整个数据库表。

#### Acceptance Criteria

1. WHEN 用户编写 DELETE FROM 语句但没有 WHERE 条件 THEN 系统 SHALL 显示红色错误提示
2. WHEN 用户编写 UPDATE 语句但没有 WHERE 条件 THEN 系统 SHALL 显示红色错误提示
3. WHEN 用户编写 DROP TABLE 或 DROP DATABASE 语句 THEN 系统 SHALL 显示红色错误提示
4. WHEN 检测到危险 SQL 操作 THEN 错误信息 SHALL 使用中文并解释可能的灾难性后果
5. WHEN 用户点击快速修复 THEN 系统 SHALL 自动添加适当的 WHERE 条件或安全检查

### Requirement 3

**User Story:** 作为一个复制网上代码的运营人员，我希望系统能够检测代码注入风险，这样我的网站就不会被黑客攻击。

#### Acceptance Criteria

1. WHEN 用户在代码中使用 eval() 函数 THEN 系统 SHALL 显示红色错误提示
2. WHEN 用户使用 innerHTML 直接插入用户输入 THEN 系统 SHALL 显示红色错误提示
3. WHEN 用户使用 child_process.exec 或 spawn 执行用户输入 THEN 系统 SHALL 显示红色错误提示
4. WHEN 检测到代码注入风险 THEN 错误信息 SHALL 解释黑客可能的攻击方式
5. WHEN 用户点击快速修复 THEN 系统 SHALL 提供安全的替代方案

### Requirement 4

**User Story:** 作为一个非技术用户，我希望扩展能够提供零配置的使用体验，这样我就不需要学习复杂的配置就能获得保护。

#### Acceptance Criteria

1. WHEN 用户安装扩展 THEN 系统 SHALL 自动激活并开始检测，无需任何配置
2. WHEN 用户打开或编辑任何代码文件 THEN 系统 SHALL 自动开始实时分析
3. WHEN 系统检测到问题 THEN 错误信息 SHALL 使用简单易懂的中文，避免技术术语
4. WHEN 用户看到错误提示 THEN 系统 SHALL 提供一键修复按钮
5. WHEN 用户点击修复按钮 THEN 系统 SHALL 自动应用修复，无需用户理解技术细节

### Requirement 5

**User Story:** 作为一个使用 React 框架的设计师，我希望系统能够检测框架特定的安全风险，这样我就不会在不知情的情况下引入 XSS 漏洞。

#### Acceptance Criteria

1. WHEN 用户在 React 中使用 dangerouslySetInnerHTML 且内容来自用户输入 THEN 系统 SHALL 显示黄色警告
2. WHEN 用户在 Vue 中使用 v-html 指令且内容未经过滤 THEN 系统 SHALL 显示黄色警告
3. WHEN 用户在 useEffect 中缺少依赖数组可能导致无限循环 THEN 系统 SHALL 显示黄色警告
4. WHEN 检测到框架特定风险 THEN 错误信息 SHALL 解释该风险在该框架中的具体危害
5. WHEN 用户点击快速修复 THEN 系统 SHALL 提供框架特定的安全解决方案

### Requirement 6

**User Story:** 作为一个部署应用的创业者，我希望系统能够检测配置错误，这样我就不会在生产环境中暴露敏感信息。

#### Acceptance Criteria

1. WHEN 用户在生产配置中设置 debug=true THEN 系统 SHALL 显示黄色警告
2. WHEN 用户配置 CORS 允许所有域名（*）THEN 系统 SHALL 显示黄色警告
3. WHEN 用户在 Docker 配置中暴露危险端口 THEN 系统 SHALL 显示黄色警告
4. WHEN 用户在 .env 文件中使用示例值或空值 THEN 系统 SHALL 显示黄色警告
5. WHEN 检测到配置错误 THEN 错误信息 SHALL 解释该配置在生产环境中的风险

### Requirement 7

**User Story:** 作为一个需要快速修复问题的用户，我希望系统能够提供高性能的实时检测，这样我的编码体验就不会被打断。

#### Acceptance Criteria

1. WHEN 用户编辑文档 THEN 系统 SHALL 在 500ms 内完成分析并显示结果
2. WHEN 用户编辑大型文件（>1000行）THEN 系统 SHALL 使用增量分析只检查修改的部分
3. WHEN 系统分析失败 THEN 系统 SHALL 静默失败，不影响用户的正常编辑
4. WHEN 用户快速连续输入 THEN 系统 SHALL 使用防抖机制避免过度分析
5. WHEN 系统检测到问题 THEN 诊断信息 SHALL 立即在编辑器中显示，无延迟

### Requirement 8

**User Story:** 作为一个可能遇到误报的用户，我希望系统能够提供准确的检测，这样我就不会被无关的警告打扰。

#### Acceptance Criteria

1. WHEN 代码中的密钥是环境变量引用（如 process.env.API_KEY）THEN 系统 SHALL 不显示警告
2. WHEN 代码中的字符串是注释或文档 THEN 系统 SHALL 不检测其中的模式
3. WHEN 代码中的字符串是模板字符串变量 THEN 系统 SHALL 不误报为硬编码
4. WHEN 系统不确定是否为真正的问题 THEN 系统 SHALL 选择不报告而不是误报
5. WHEN 用户在测试文件中使用示例数据 THEN 系统 SHALL 降低警告级别或不报告
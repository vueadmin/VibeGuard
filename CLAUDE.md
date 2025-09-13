# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VibeGuard is a VS Code extension designed to protect non-technical users who use AI to write code (designers, product managers, etc.) from dangerous coding patterns that could lead to security breaches or data loss. The project originated from a real case where someone lost $5000 due to hardcoded API keys.

**Target Users**: NOT professional developers, but people using AI tools (ChatGPT, Cursor) to write code without understanding security risks.

## Core Project Philosophy

### 🎯 Mission Statement
"防止下一个 $5000 的损失" - 我们的使命是保护那些"不知道自己不知道"的 AI 编程用户。

### 🔑 Key Insights
1. **新兴用户群体**: 越来越多非技术人员开始使用 AI 编写代码
2. **真实风险**: 这些用户缺乏基本的安全意识，容易造成严重损失
3. **预防优于治疗**: 在错误发生前阻止，而不是事后补救

### 💡 Design Principles (优先级排序)
1. **零门槛**: 安装即用，无需任何配置
2. **防呆设计**: 假设用户完全不懂技术
3. **恐吓有效**: 用真实损失案例警醒用户
4. **一键修复**: 用户不需要理解原理，只需要点击
5. **宁缺毋滥**: 只检测会造成严重损失的问题

## Development Commands

```bash
# Install dependencies
pnpm install

# Compile TypeScript
pnpm run compile

# Watch mode (auto-compile on changes)
pnpm run watch

# Run linter
pnpm run lint

# Run tests
pnpm test

# Build for production
pnpm run vscode:prepublish
```

## Architecture & Key Implementation Notes

### Current Status
The project is in early development stage with only a basic "Hello World" VS Code extension scaffold. The actual security analysis features need to be implemented.

### 🚨 Implementation Priority (基于真实危害程度)
1. **Phase 0 - 最紧急** (防止直接经济损失)
   - API 密钥硬编码检测（已知 $5000 损失）
   - 环境变量文件泄露（.env, config.json）
   - 数据库连接字符串暴露

2. **Phase 1 - 核心防护** (防止数据灾难)
   - SQL DELETE/UPDATE 无 WHERE 条件
   - DROP DATABASE/TABLE 操作
   - 批量数据操作无确认

3. **Phase 2 - 安全漏洞** (防止被攻击)
   - eval() 代码注入
   - innerHTML XSS 风险
   - 命令行注入（exec, spawn）

### Planned Architecture (from Kiro specs)
```
src/
├── extension.ts          # VS Code extension entry point
├── analyzer/            # Code analysis engine
│   ├── CodeAnalyzer.ts  # Main analyzer coordinating rules
│   └── IncrementalAnalyzer.ts
├── rules/              # Detection rules by language/framework
│   ├── definitions/    # Rule definitions (sql-rules.ts, javascript-rules.ts, etc.)
│   └── RuleEngine.ts   # Rule execution engine
├── diagnostics/        # VS Code diagnostic integration
│   └── DiagnosticManager.ts
└── quickfix/           # Auto-fix providers
```

### Critical Implementation Principles

1. **Simplicity Over Perfection**: Use regex patterns instead of complex AST parsing. The target users need protection from obvious mistakes, not a perfect static analyzer.

2. **User-Friendly Messages**: All error messages must be in plain Chinese with emojis. Example:
   ```
   ❌ BAD: "SQL001: DELETE statement without WHERE clause"
   ✅ GOOD: "💀 危险！你要删除整个用户表！5000个用户数据会消失！"
   ```

3. **One-Click Fixes**: Users won't understand how to fix issues. Provide automatic fixes they can apply with one click.

4. **Priority Rules** (implement these first):
   - Hardcoded API keys (real $5000 loss case)
   - SQL DELETE/UPDATE without WHERE
   - eval() and similar dangerous functions
   - Password/secret in plain text

### VS Code Extension Specifics

- **Activation**: Currently activates on command, should activate on file open/edit
- **Diagnostics**: Use `vscode.languages.createDiagnosticCollection('vibeguard')`
- **Quick Fixes**: Implement `vscode.CodeActionProvider`
- **Real-time Analysis**: Use `vscode.workspace.onDidChangeTextDocument` with debouncing

## Testing Approach

Focus on real-world dangerous patterns that AI tools commonly generate:
```javascript
// Test cases should include actual AI-generated dangerous code
const testCases = [
  'const apiKey = "sk-xxxxx"',  // OpenAI key hardcoded
  'DELETE FROM users',           // No WHERE clause
  'eval(userInput)',            // Code injection
  'innerHTML = userContent'      // XSS vulnerability
];
```

## Important Context from README

- Real case examples are crucial for user trust
- The tool is positioned as "让 AI 编程更安全" (Make AI programming safer)
- Emphasis on preventing "$5000 losses" resonates with users
- Community-driven approach: encourage users to share their "accident" stories

## 🎨 Future Vision (AI Integration - Phase 3+)

### AI-Assisted Security (后期计划)
1. **智能修复建议**: 使用 AI 生成上下文相关的安全代码
2. **模式学习**: 从用户的代码风格学习，提供个性化建议
3. **实时解释**: AI 解释为什么这段代码危险，用大白话教育用户

### Community Features (需要外部支持)
1. **事故墙**: 展示真实的损失案例（需要网站）
2. **安全英雄榜**: 激励用户修复问题（需要后端）
3. **月度安全报告**: 统计和分享常见问题（需要数据分析）

## Notes on User Communication

1. Always use simple, non-technical language
2. Emphasize real monetary/data loss risks
3. Use emoji to make warnings more noticeable
4. Provide examples of what could go wrong in real scenarios

## Package Manager

This project uses `pnpm`. Always use `pnpm` commands instead of `npm`.

## Detailed Rule Examples

### SQL Security Rules (Priority: CRITICAL)
```typescript
{
  code: 'SQL001',
  severity: 'error',
  message: '💀 致命错误：DELETE 没有 WHERE 条件会删除整个表！这相当于把整个数据库扔进垃圾桶！',
  pattern: /DELETE\s+FROM\s+\w+\s*(?!WHERE)/gi,
  quickFix: {
    title: '添加 WHERE 条件',
    replacement: 'DELETE FROM $1 WHERE id = ?'
  }
}
```

### API Key Detection (Priority: CRITICAL - Real $5000 case)
```typescript
{
  code: 'JS003',
  severity: 'error',
  message: '🔑 密钥泄露！不要在代码中硬编码 API Key',
  pattern: /(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*["'][^"']+["']/gi,
  quickFix: {
    title: '使用环境变量',
    replacement: 'process.env.$1'
  }
}
```

### Code Injection Detection
```typescript
{
  code: 'JS001',
  severity: 'error',
  message: '🔒 eval() 会执行任意代码，黑客最爱！',
  pattern: /\beval\s*\(/g,
  quickFix: {
    title: '使用 JSON.parse() 或其他安全方法',
    replacement: 'JSON.parse'
  }
}
```

## Implementation Strategy (MVP Focus)

### Phase 1: Core Protection (Week 1)
1. **Basic Rule Engine**: Simple regex-based pattern matching
2. **Critical Rules Only**:
   - API key hardcoding (JS003)
   - SQL DELETE without WHERE (SQL001)
   - eval() usage (JS001)
   - innerHTML XSS (JS002)
3. **VS Code Integration**: Basic diagnostics display
4. **Quick Fix**: One-click automatic fixes

### Phase 2: Enhanced Detection (Week 2-3)
1. Expand rule coverage to frameworks (React, Vue, Node.js)
2. Add configuration file scanning (.env, package.json)
3. Implement incremental analysis for performance
4. Add Chinese-friendly error messages with examples

### Phase 3: Community Features (Month 2+)
1. Rule contribution system
2. Real incident reporting
3. Statistics dashboard

## Technical Insights from Original Design

### Performance Optimization (implement only if needed)
- **Incremental Analysis**: Only analyze changed lines, not entire file
- **Debouncing**: 500ms delay before analysis to avoid excessive processing
- **Simple Caching**: Cache analysis results by file path (not AST)

### Error Handling Approach
```typescript
// Always fail gracefully - better to miss a bug than crash the extension
try {
  const issues = analyzeCode(text);
  return issues;
} catch (error) {
  console.error('VibeGuard analysis failed:', error);
  return []; // Return empty array, don't block user
}
```

### Diagnostic Display
```typescript
const diagnostic = new vscode.Diagnostic(
  range,
  issue.message,
  vscode.DiagnosticSeverity.Error
);
diagnostic.code = issue.code;
diagnostic.source = 'VibeGuard';
// Add quick fix data
diagnostic.data = { quickFix: issue.quickFix };
```

## Key Differences from Traditional Linters

1. **Target Audience**: AI code users, not developers
2. **Detection Focus**: Catastrophic errors only, not style
3. **Message Style**: Scary warnings with real consequences
4. **Fix Approach**: Automatic, no understanding required
5. **Configuration**: Zero-config by default

## 📊 Success Metrics (如何衡量成功)

### 短期指标 (MVP)
- 阻止的潜在损失金额（通过检测到的 API 密钥数量估算）
- 一键修复的使用率（>80% 的用户应该使用）
- 误报率（<5%，宁可漏报不要误报）

### 长期指标
- 真实避免的损失案例数
- 用户留存率（安装后继续使用）
- 社区贡献的规则数量

## Common AI-Generated Dangerous Patterns

Based on real incidents, these patterns are frequently generated by AI:
- Hardcoded credentials (ChatGPT loves to use example keys)
- SQL queries without WHERE clauses
- Direct DOM manipulation in React
- Synchronous file operations in Node.js
- Debug mode enabled in production configs

## Remember

This is NOT a tool for developers who want better code quality. This is a safety net for people who don't know what they don't know. Every feature decision should be evaluated against: "Will this prevent a designer from losing $5000?"

## 🚀 Quick Start for AI Developers

当你（AI）开始实现功能时，请按照以下顺序：

1. **先读这个文件** - 理解项目理念和目标用户
2. **实现最小可行功能** - 从 API 密钥检测开始
3. **测试真实场景** - 用 ChatGPT/Claude 生成的代码测试
4. **优化用户体验** - 确保警告信息通俗易懂
5. **快速迭代** - 基于用户反馈持续改进

### 代码实现提示
```typescript
// 记住：简单粗暴但有效 > 复杂完美但难用
// 示例：检测 API 密钥
const apiKeyPattern = /(api[_-]?key|secret|token)\s*[:=]\s*["'][^"']+["']/gi;
// 不需要考虑所有边缘情况，只要能抓住 90% 的问题就够了
```

## 🔗 相关资源

- [VS Code Extension API](https://code.visualstudio.com/api)
- [正则表达式测试](https://regex101.com/)
- [真实泄露案例](https://github.com/search?q=api+key+exposed)

---

**最后提醒**: 每一行代码都要想着那个损失了 $5000 的设计师。我们的目标不是完美，而是有效。
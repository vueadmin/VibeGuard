# 🛠️ VibeGuard 开发指南

本文档为开发者（人类和 AI）提供详细的实现指导。

## 📋 开发前必读

### 理解我们的用户
- **小王（设计师）**: 用 Cursor 写前端，复制了带 API key 的代码，损失 $5000
- **小李（产品经理）**: 用 ChatGPT 写 SQL 查询，不小心删了整个表
- **小张（运营）**: 从网上复制代码，包含 eval()，网站被黑

记住：他们不是程序员，他们只是想快速完成工作。

### 核心开发原则
1. **能用就行** > 完美实现
2. **快速报错** > 精确分析  
3. **中文优先** > 英文术语
4. **一键修复** > 详细解释

## 🚀 快速开始实现

### Step 1: 最小可行产品（24小时内）

```typescript
// 1. 在 extension.ts 中添加文档监听
vscode.workspace.onDidChangeTextDocument((event) => {
  // 获取文档内容
  const text = event.document.getText();
  
  // 运行检测
  const issues = detectDangerousPatterns(text);
  
  // 显示诊断
  updateDiagnostics(event.document, issues);
});

// 2. 实现最简单的检测函数
function detectDangerousPatterns(text: string): Issue[] {
  const issues: Issue[] = [];
  
  // 检测 API 密钥 - 最高优先级！
  const apiKeyPattern = /(api[_-]?key|secret|token|password)\s*[:=]\s*["']([^"']+)["']/gi;
  let match;
  while ((match = apiKeyPattern.exec(text))) {
    issues.push({
      line: getLineNumber(text, match.index),
      message: '🔑 危险！API密钥暴露！这就是那个设计师损失$5000的原因！',
      severity: 'error',
      quickFix: `process.env.${match[1].toUpperCase()}`
    });
  }
  
  return issues;
}
```

### Step 2: 核心规则实现（第一周）

#### 🔑 API 密钥检测（优先级：致命）
```typescript
// 常见的 API 密钥模式
const patterns = [
  // OpenAI
  /sk-[a-zA-Z0-9]{48}/g,
  // AWS
  /AKIA[0-9A-Z]{16}/g,
  // GitHub
  /ghp_[a-zA-Z0-9]{36}/g,
  // 通用模式
  /(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*["'][^"']+["']/gi
];
```

#### 💀 SQL 灾难检测
```typescript
// DELETE 没有 WHERE
/DELETE\s+FROM\s+\w+\s*;/gi

// UPDATE 没有 WHERE  
/UPDATE\s+\w+\s+SET\s+.+\s*;/gi

// DROP 表或数据库
/DROP\s+(TABLE|DATABASE)\s+/gi
```

#### 🔒 代码注入检测
```typescript
// eval 危险
/\beval\s*\(/g

// innerHTML XSS
/\.innerHTML\s*=\s*[^"']/g

// 命令注入
/child_process\.(exec|spawn)\([^)]*\+[^)]*\)/g
```

### Step 3: VS Code 集成

```typescript
// 创建诊断集合
const diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');

// 更新诊断信息
function updateDiagnostics(document: vscode.TextDocument, issues: Issue[]) {
  const diagnostics: vscode.Diagnostic[] = [];
  
  for (const issue of issues) {
    const range = new vscode.Range(
      issue.line - 1, 0,
      issue.line - 1, Number.MAX_VALUE
    );
    
    const diagnostic = new vscode.Diagnostic(
      range,
      issue.message,
      vscode.DiagnosticSeverity.Error
    );
    
    // 关联快速修复
    diagnostic.code = issue.code;
    diagnostic.data = { quickFix: issue.quickFix };
    
    diagnostics.push(diagnostic);
  }
  
  diagnosticCollection.set(document.uri, diagnostics);
}
```

### Step 4: 一键修复实现

```typescript
export class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source === 'VibeGuard' && diagnostic.data?.quickFix) {
        const action = new vscode.CodeAction(
          '🔧 一键修复',
          vscode.CodeActionKind.QuickFix
        );
        
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(
          document.uri,
          diagnostic.range,
          diagnostic.data.quickFix
        );
        
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        
        actions.push(action);
      }
    }
    
    return actions;
  }
}
```

## 📝 测试策略

### 必须测试的场景
1. **真实 AI 生成的代码**
   ```javascript
   // ChatGPT 经常生成这样的代码
   const apiKey = "sk-1234567890abcdef";
   const response = await openai.chat(apiKey, prompt);
   ```

2. **常见的危险操作**
   ```sql
   -- 产品经理常犯的错误
   DELETE FROM users;  -- 没有 WHERE！
   ```

3. **框架特定问题**
   ```javascript
   // React 中的 XSS
   <div dangerouslySetInnerHTML={{__html: userInput}} />
   ```

### 测试文件示例
```typescript
// test/dangerous-patterns.test.ts
describe('API Key Detection', () => {
  it('should detect hardcoded OpenAI keys', () => {
    const code = `const key = "sk-proj-abcd1234"`;
    const issues = detectDangerousPatterns(code);
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('$5000');
  });
});
```

## 🎯 性能优化（仅在必要时）

### 增量分析
```typescript
// 只分析改变的部分
vscode.workspace.onDidChangeTextDocument((event) => {
  if (event.contentChanges.length === 0) return;
  
  // 获取改变的行
  const change = event.contentChanges[0];
  const startLine = change.range.start.line;
  const endLine = change.range.end.line;
  
  // 只检查这些行
  analyzeLines(event.document, startLine, endLine);
});
```

### 防抖处理
```typescript
let timeout: NodeJS.Timeout;

function debounceAnalysis(document: vscode.TextDocument) {
  clearTimeout(timeout);
  timeout = setTimeout(() => {
    analyzeDocument(document);
  }, 500); // 500ms 延迟
}
```

## 🐛 常见问题解决

### 1. 正则表达式匹配问题
```typescript
// 错误：会匹配注释
/api_key\s*=\s*"[^"]+"/g

// 正确：排除注释（简单但有效）
function isInComment(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf('\n', index) + 1;
  const lineText = text.substring(lineStart, index);
  return lineText.includes('//') || lineText.includes('#');
}
```

### 2. 误报处理
```typescript
// 白名单模式
const whitelist = [
  'process.env',
  'import.meta.env',
  '${', // 模板字符串
];

function isWhitelisted(text: string, match: RegExpExecArray): boolean {
  const context = text.substring(match.index - 20, match.index);
  return whitelist.some(pattern => context.includes(pattern));
}
```

## 📊 效果评估

### 关键指标
1. **检测率**: 能发现多少真实问题
2. **误报率**: 错误警告的比例
3. **修复率**: 用户使用一键修复的比例

### 数据收集（匿名）
```typescript
// 记录检测到的问题类型
let detectedIssues = {
  apiKeys: 0,
  sqlDanger: 0,
  codeInjection: 0
};

// 记录修复使用情况
let quickFixUsage = {
  total: 0,
  applied: 0
};
```

## 🚨 发布前检查清单

- [ ] 测试 5 个真实的 AI 生成代码样本
- [ ] 确保所有错误信息都是中文
- [ ] 验证一键修复功能正常工作
- [ ] 检查性能（大文件不应卡顿）
- [ ] 更新 README 中的示例

## 💡 记住

1. **用户不懂技术** - 所有提示必须假设用户完全不懂编程
2. **速度很重要** - 慢一秒可能就是 $5000 的损失
3. **宁缺毋滥** - 漏报比误报好，不要打扰用户的正常工作
4. **真实案例** - 用真实的损失案例来警示用户

---

**开发座右铭**: "每个警告都可能挽救一个设计师的年终奖"
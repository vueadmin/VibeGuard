# VibeGuard 技术实现文档

## 目录
1. [项目架构详解](#项目架构详解)
2. [核心模块实现](#核心模块实现)
3. [规则引擎设计](#规则引擎设计)
4. [性能优化策略](#性能优化策略)
5. [开发环境搭建](#开发环境搭建)
6. [代码实现示例](#代码实现示例)
7. [测试策略](#测试策略)
8. [部署与发布](#部署与发布)

## 项目架构详解

### 技术栈选择理由
- **TypeScript**: 强类型支持，提升代码质量和维护性
- **VS Code Extension API**: 原生支持，功能丰富
- **AST 解析器**: 精准识别代码结构，降低误报率
- **增量分析**: 只处理变更部分，性能优化50%+

### 核心架构设计
```
┌─────────────────────────────────────────────────┐
│                VS Code Editor                    │
├─────────────────────────────────────────────────┤
│           VibeGuard Extension Layer              │
├──────────┬───────────┬───────────┬──────────────┤
│ Analyzer │  Rules    │Diagnostics│   Utils      │
│  Engine  │  Engine   │  Manager  │              │
├──────────┴───────────┴───────────┴──────────────┤
│              Cache & Performance                 │
└─────────────────────────────────────────────────┘
```

### 项目目录结构
```
VibeGuard/
├── package.json                 # 插件配置和依赖
├── tsconfig.json               # TypeScript 配置
├── .eslintrc.json              # 代码规范
├── .vscodeignore               # 打包忽略文件
├── src/
│   ├── extension.ts            # 插件主入口
│   ├── analyzer/
│   │   ├── CodeAnalyzer.ts     # 代码分析器核心
│   │   ├── IncrementalAnalyzer.ts # 增量分析
│   │   └── FileScanner.ts      # 文件扫描器
│   ├── rules/
│   │   ├── RuleEngine.ts       # 规则引擎
│   │   ├── RuleLoader.ts       # 规则加载器
│   │   ├── definitions/        # 规则定义文件
│   │   │   ├── sql-rules.ts
│   │   │   ├── javascript-rules.ts
│   │   │   ├── typescript-rules.ts
│   │   │   ├── react-rules.ts
│   │   │   ├── vue-rules.ts
│   │   │   ├── nodejs-rules.ts
│   │   │   ├── python-rules.ts
│   │   │   └── config-rules.ts
│   │   └── matchers/           # 规则匹配器
│   │       ├── RegexMatcher.ts
│   │       └── ASTMatcher.ts
│   ├── diagnostics/
│   │   ├── DiagnosticManager.ts # 诊断管理
│   │   ├── QuickFixProvider.ts  # 快速修复
│   │   └── MessageFormatter.ts  # 消息格式化
│   ├── parsers/
│   │   ├── JavaScriptParser.ts  # JS/TS 解析
│   │   ├── PythonParser.ts      # Python 解析
│   │   └── SQLParser.ts         # SQL 解析
│   ├── cache/
│   │   ├── CacheManager.ts      # 缓存管理
│   │   └── FileCache.ts         # 文件缓存
│   ├── config/
│   │   ├── Settings.ts          # 配置管理
│   │   └── defaults.ts          # 默认配置
│   └── utils/
│       ├── logger.ts            # 日志工具
│       ├── debounce.ts          # 防抖函数
│       └── performance.ts       # 性能监控
├── test/
│   ├── unit/                    # 单元测试
│   ├── integration/             # 集成测试
│   └── fixtures/                # 测试数据
└── resources/
    ├── icons/                   # 图标资源
    └── templates/               # 模板文件

```

## 核心模块实现

### 1. 插件入口 (extension.ts)
```typescript
import * as vscode from 'vscode';
import { CodeAnalyzer } from './analyzer/CodeAnalyzer';
import { DiagnosticManager } from './diagnostics/DiagnosticManager';
import { RuleEngine } from './rules/RuleEngine';
import { CacheManager } from './cache/CacheManager';
import { Settings } from './config/Settings';

export function activate(context: vscode.ExtensionContext) {
    // 初始化核心组件
    const settings = new Settings();
    const cache = new CacheManager();
    const ruleEngine = new RuleEngine(settings);
    const analyzer = new CodeAnalyzer(ruleEngine, cache);
    const diagnosticManager = new DiagnosticManager();

    // 注册文档变更监听
    const documentChangeListener = vscode.workspace.onDidChangeTextDocument(
        debounce(async (event) => {
            if (shouldAnalyze(event.document)) {
                const issues = await analyzer.analyzeIncremental(event);
                diagnosticManager.updateDiagnostics(event.document, issues);
            }
        }, 500)
    );

    // 注册文件保存监听
    const saveListener = vscode.workspace.onDidSaveTextDocument(
        async (document) => {
            const issues = await analyzer.analyzeFull(document);
            diagnosticManager.updateDiagnostics(document, issues);
        }
    );

    // 注册快速修复提供者
    const quickFixProvider = vscode.languages.registerCodeActionProvider(
        { pattern: '**/*' },
        new QuickFixProvider(diagnosticManager),
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );

    // 注册命令
    const scanCommand = vscode.commands.registerCommand(
        'vibeguard.scanWorkspace',
        async () => {
            await scanWorkspace(analyzer, diagnosticManager);
        }
    );

    // 添加到订阅列表
    context.subscriptions.push(
        documentChangeListener,
        saveListener,
        quickFixProvider,
        scanCommand,
        diagnosticManager
    );

    // 初始扫描
    scanOpenDocuments(analyzer, diagnosticManager);
}

export function deactivate() {
    // 清理资源
}
```

### 2. 代码分析器 (CodeAnalyzer.ts)
```typescript
import { TextDocument, TextDocumentChangeEvent } from 'vscode';
import { RuleEngine } from '../rules/RuleEngine';
import { CacheManager } from '../cache/CacheManager';
import { Issue, Severity } from '../types';

export class CodeAnalyzer {
    constructor(
        private ruleEngine: RuleEngine,
        private cache: CacheManager
    ) {}

    async analyzeIncremental(event: TextDocumentChangeEvent): Promise<Issue[]> {
        const document = event.document;
        const cacheKey = document.uri.toString();
        
        // 获取缓存的分析结果
        let cachedIssues = this.cache.get(cacheKey) || [];
        
        // 处理每个变更
        for (const change of event.contentChanges) {
            const startLine = change.range.start.line;
            const endLine = change.range.end.line;
            
            // 移除受影响行的旧问题
            cachedIssues = cachedIssues.filter(
                issue => issue.line < startLine || issue.line > endLine
            );
            
            // 分析变更的文本
            const newIssues = await this.analyzeText(
                change.text,
                document.languageId,
                startLine
            );
            
            // 合并新问题
            cachedIssues.push(...newIssues);
        }
        
        // 更新缓存
        this.cache.set(cacheKey, cachedIssues);
        
        return cachedIssues;
    }

    async analyzeFull(document: TextDocument): Promise<Issue[]> {
        const text = document.getText();
        const languageId = document.languageId;
        
        // 执行完整分析
        const issues = await this.analyzeText(text, languageId, 0);
        
        // 更新缓存
        this.cache.set(document.uri.toString(), issues);
        
        return issues;
    }

    private async analyzeText(
        text: string,
        languageId: string,
        lineOffset: number
    ): Promise<Issue[]> {
        const issues: Issue[] = [];
        
        // 应用对应语言的规则
        const rules = this.ruleEngine.getRulesForLanguage(languageId);
        
        for (const rule of rules) {
            const matches = await rule.check(text);
            
            for (const match of matches) {
                issues.push({
                    line: match.line + lineOffset,
                    column: match.column,
                    severity: rule.severity,
                    message: rule.message,
                    code: rule.code,
                    quickFix: rule.quickFix
                });
            }
        }
        
        return issues;
    }
}
```

### 3. 规则引擎 (RuleEngine.ts)
```typescript
import { Rule, RuleMatch } from '../types';
import { RegexMatcher } from './matchers/RegexMatcher';
import { ASTMatcher } from './matchers/ASTMatcher';

export class RuleEngine {
    private rules: Map<string, Rule[]> = new Map();
    private regexMatcher: RegexMatcher;
    private astMatcher: ASTMatcher;

    constructor(settings: Settings) {
        this.regexMatcher = new RegexMatcher();
        this.astMatcher = new ASTMatcher();
        this.loadRules(settings);
    }

    private loadRules(settings: Settings) {
        // 加载 SQL 规则
        this.rules.set('sql', [
            {
                code: 'SQL001',
                severity: 'error',
                message: '💀 致命错误：DELETE 没有 WHERE 条件会删除整个表！这相当于把整个数据库扔进垃圾桶！',
                pattern: /DELETE\s+FROM\s+\w+\s*(?!WHERE)/gi,
                quickFix: {
                    title: '添加 WHERE 条件',
                    replacement: 'DELETE FROM $1 WHERE id = ?'
                }
            },
            {
                code: 'SQL002',
                severity: 'error',
                message: '⚠️ UPDATE 语句没有 WHERE 条件，会更新所有记录！',
                pattern: /UPDATE\s+\w+\s+SET\s+.*(?!WHERE)/gi,
                quickFix: {
                    title: '添加 WHERE 条件',
                    replacement: 'UPDATE $1 SET $2 WHERE id = ?'
                }
            },
            {
                code: 'SQL003',
                severity: 'error',
                message: '💣 TRUNCATE 会立即清空整个表，且无法恢复！',
                pattern: /TRUNCATE\s+TABLE\s+\w+/gi,
                quickFix: null
            },
            {
                code: 'SQL004',
                severity: 'error',
                message: '🚨 DROP DATABASE 检测到！这会永久删除整个数据库！',
                pattern: /DROP\s+DATABASE\s+\w+/gi,
                quickFix: null
            },
            {
                code: 'SQL005',
                severity: 'warning',
                message: '⚠️ SQL 注入风险：字符串拼接可能导致注入攻击',
                pattern: /("|')\s*\+.*\+\s*("|')/g,
                quickFix: {
                    title: '使用参数化查询',
                    replacement: '?'
                }
            }
        ]);

        // 加载 JavaScript 基础规则
        this.rules.set('javascript', [
            {
                code: 'JS001',
                severity: 'error',
                message: '🔒 eval() 会执行任意代码，黑客最爱！',
                pattern: /\beval\s*\(/g,
                quickFix: {
                    title: '使用 JSON.parse() 或其他安全方法',
                    replacement: 'JSON.parse'
                }
            },
            {
                code: 'JS002',
                severity: 'warning',
                message: '⚠️ XSS 风险：innerHTML 可能导致脚本注入',
                pattern: /\.innerHTML\s*=/g,
                quickFix: {
                    title: '使用 textContent 或 sanitize',
                    replacement: '.textContent ='
                }
            },
            {
                code: 'JS003',
                severity: 'error',
                message: '🔑 密钥泄露！不要在代码中硬编码 API Key',
                pattern: /(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*["'][^"']+["']/gi,
                quickFix: {
                    title: '使用环境变量',
                    replacement: 'process.env.$1'
                }
            },
            {
                code: 'JS004',
                severity: 'error',
                message: '⚠️ 异步陷阱：forEach 中的 await 不会等待',
                pattern: /\.forEach\s*\(\s*async/g,
                quickFix: {
                    title: '使用 for...of 或 Promise.all',
                    replacement: 'for (const item of items)'
                }
            },
            {
                code: 'JS005',
                severity: 'error',
                message: '🚨 生产环境配置错误：CORS 允许所有域名！',
                pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"][^}]*\}/g,
                quickFix: {
                    title: '限制允许的域名',
                    replacement: "cors({ origin: ['https://example.com'] })"
                }
            }
        ]);

        // 加载 TypeScript 规则
        this.rules.set('typescript', [
            {
                code: 'TS001',
                severity: 'warning',
                message: '⚠️ 类型不安全：避免使用 any，失去了 TypeScript 的意义',
                pattern: /:\s*any\b/g,
                quickFix: {
                    title: '使用具体类型或 unknown',
                    replacement: ': unknown'
                }
            },
            {
                code: 'TS002',
                severity: 'warning',
                message: '⚠️ 非空断言(!)可能导致运行时错误',
                pattern: /\w+!\./g,
                quickFix: {
                    title: '添加空值检查',
                    replacement: '?.'
                }
            },
            {
                code: 'TS003',
                severity: 'error',
                message: '🚨 @ts-ignore 会隐藏类型错误，生产环境禁用',
                pattern: /@ts-ignore/g,
                quickFix: null
            }
        ]);

        // 加载 React 规则
        this.rules.set('react', [
            {
                code: 'REACT001',
                severity: 'error',
                message: '💉 XSS 风险：dangerouslySetInnerHTML 直接注入 HTML',
                pattern: /dangerouslySetInnerHTML/g,
                quickFix: null
            },
            {
                code: 'REACT002',
                severity: 'error',
                message: '♾️ 无限循环风险：useEffect 缺少依赖数组',
                pattern: /useEffect\s*\([^)]+\)\s*(?!,)/g,
                quickFix: {
                    title: '添加依赖数组',
                    replacement: 'useEffect(() => {}, [])'
                }
            },
            {
                code: 'REACT003',
                severity: 'warning',
                message: '⚠️ 内存泄漏：组件卸载时未清理事件监听器',
                pattern: /addEventListener[^}]*useEffect(?!.*removeEventListener)/gs,
                quickFix: null
            },
            {
                code: 'REACT004',
                severity: 'error',
                message: '🚨 直接操作 DOM 违反 React 原则',
                pattern: /document\.(getElementById|querySelector)/g,
                quickFix: {
                    title: '使用 useRef',
                    replacement: 'useRef()'
                }
            }
        ]);

        // 加载 Vue 规则
        this.rules.set('vue', [
            {
                code: 'VUE001',
                severity: 'error',
                message: '💉 XSS 风险：v-html 会直接渲染 HTML',
                pattern: /v-html/g,
                quickFix: null
            },
            {
                code: 'VUE002',
                severity: 'error',
                message: '⚠️ 直接修改 props 违反单向数据流',
                pattern: /this\.\$props\.[\w]+\s*=/g,
                quickFix: null
            },
            {
                code: 'VUE003',
                severity: 'warning',
                message: '⚠️ v-for 缺少 key 会导致渲染问题',
                pattern: /v-for(?!.*:key)/g,
                quickFix: {
                    title: '添加 key 属性',
                    replacement: 'v-for="item in items" :key="item.id"'
                }
            },
            {
                code: 'VUE004',
                severity: 'error',
                message: '♾️ watch 可能导致无限循环',
                pattern: /watch\s*:\s*\{[^}]*deep\s*:\s*true/g,
                quickFix: null
            }
        ]);

        // 加载 Node.js 规则
        this.rules.set('nodejs', [
            {
                code: 'NODE001',
                severity: 'error',
                message: '💀 命令注入风险：child_process.exec 执行任意命令',
                pattern: /child_process\.exec\(/g,
                quickFix: {
                    title: '使用 execFile 或参数化',
                    replacement: 'child_process.execFile'
                }
            },
            {
                code: 'NODE002',
                severity: 'error',
                message: '🗑️ fs.unlink/rmdir 会永久删除文件',
                pattern: /fs\.(unlink|rmdir|rm)\(/g,
                quickFix: {
                    title: '添加文件存在检查',
                    replacement: 'if (fs.existsSync(path)) fs.unlink(path)'
                }
            },
            {
                code: 'NODE003',
                severity: 'warning',
                message: '⚠️ 路径遍历漏洞：直接拼接用户输入的路径',
                pattern: /__dirname\s*\+[^)]*req\.(params|query|body)/g,
                quickFix: {
                    title: '使用 path.join 和验证',
                    replacement: 'path.join(__dirname, sanitize(userInput))'
                }
            },
            {
                code: 'NODE004',
                severity: 'error',
                message: '🚨 未处理的 Promise rejection 会导致进程崩溃',
                pattern: /\.then\([^)]+\)(?!\.catch)/g,
                quickFix: {
                    title: '添加 .catch 处理',
                    replacement: '.then().catch(err => console.error(err))'
                }
            },
            {
                code: 'NODE005',
                severity: 'error',
                message: '💣 rm -rf 检测到！这可能删除整个系统！',
                pattern: /rm\s+-rf\s+\//g,
                quickFix: null
            }
        ]);

        // 加载 Python 规则
        this.rules.set('python', [
            {
                code: 'PY001',
                severity: 'error',
                message: '⚠️ os.remove() 会永久删除文件',
                pattern: /os\.remove\(/g,
                quickFix: {
                    title: '添加文件存在检查',
                    replacement: 'if os.path.exists(file):\n    os.remove(file)'
                }
            },
            {
                code: 'PY002',
                severity: 'error',
                message: '🔒 pickle.load 可执行任意代码，不要加载不可信数据',
                pattern: /pickle\.load/g,
                quickFix: null
            },
            {
                code: 'PY003',
                severity: 'error',
                message: '💀 eval/exec 会执行任意代码',
                pattern: /(eval|exec)\s*\(/g,
                quickFix: null
            },
            {
                code: 'PY004',
                severity: 'error',
                message: '🚨 命令注入：os.system 执行 shell 命令',
                pattern: /os\.system\(/g,
                quickFix: {
                    title: '使用 subprocess.run',
                    replacement: 'subprocess.run'
                }
            },
            {
                code: 'PY005',
                severity: 'error',
                message: '🔴 Flask/Django debug=True 在生产环境会泄露敏感信息',
                pattern: /debug\s*=\s*True/g,
                quickFix: {
                    title: '使用环境变量',
                    replacement: "debug=os.getenv('DEBUG', 'False') == 'True'"
                }
            }
        ]);

        // 加载配置文件规则
        this.rules.set('config', [
            {
                code: 'CFG001',
                severity: 'error',
                message: '🔐 数据库密码暴露！不要在配置文件中明文存储',
                pattern: /(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/g,
                quickFix: {
                    title: '使用环境变量',
                    replacement: '${DATABASE_URL}'
                }
            },
            {
                code: 'CFG002',
                severity: 'error',
                message: '🔑 AWS/Azure/GCP 密钥泄露',
                pattern: /(aws_access_key_id|aws_secret_access_key|azure_storage_account_key)\s*[:=]/gi,
                quickFix: {
                    title: '使用环境变量或密钥管理服务',
                    replacement: 'process.env.$1'
                }
            },
            {
                code: 'CFG003',
                severity: 'warning',
                message: '⚠️ Redis 未设置密码',
                pattern: /redis:\/\/[^:@]+@/g,
                quickFix: null
            },
            {
                code: 'CFG004',
                severity: 'error',
                message: '🚨 Docker 暴露危险端口（SSH/数据库）',
                pattern: /EXPOSE\s+(22|3306|5432|27017|6379)\b/g,
                quickFix: null
            },
            {
                code: 'CFG005',
                severity: 'error',
                message: '💀 package.json 中包含恶意脚本',
                pattern: /"(preinstall|postinstall)"\s*:\s*"[^"]*rm\s+-rf/g,
                quickFix: null
            }
        ]);
    }

    getRulesForLanguage(languageId: string): Rule[] {
        const rules: Rule[] = [];
        
        // 基础语言规则
        const languageMappings: Record<string, string[]> = {
            'javascript': ['javascript'],
            'typescript': ['javascript', 'typescript'],
            'javascriptreact': ['javascript', 'react'],
            'typescriptreact': ['javascript', 'typescript', 'react'],
            'vue': ['javascript', 'vue'],
            'python': ['python'],
            'sql': ['sql'],
            'json': ['config'],
            'yaml': ['config'],
            'yml': ['config'],
            'env': ['config'],
            'dockerfile': ['config']
        };

        // 获取所有适用的规则集
        const ruleSets = languageMappings[languageId] || ['javascript'];
        
        // 检测 Node.js 环境
        if (languageId.includes('javascript') || languageId.includes('typescript')) {
            // 简单检测是否是 Node.js 文件（通过文件内容或路径）
            ruleSets.push('nodejs');
        }
        
        // 合并所有规则
        for (const ruleSet of ruleSets) {
            const ruleList = this.rules.get(ruleSet);
            if (ruleList) {
                rules.push(...ruleList);
            }
        }
        
        return rules;
    }

    async checkRule(rule: Rule, text: string): Promise<RuleMatch[]> {
        if (rule.pattern) {
            return this.regexMatcher.match(rule, text);
        } else if (rule.astPattern) {
            return this.astMatcher.match(rule, text);
        }
        return [];
    }
}
```

## 规则引擎设计

### 支持的语言和框架
- **前端**: JavaScript, TypeScript, React, Vue
- **后端**: Node.js, Python
- **数据库**: SQL (MySQL, PostgreSQL, SQLite)
- **配置文件**: JSON, YAML, .env, Dockerfile, package.json

### 规则定义格式
```typescript
interface Rule {
    code: string;           // 规则编码
    severity: 'error' | 'warning' | 'info';
    message: string;        // 用户友好的提示信息
    pattern?: RegExp;       // 正则匹配模式
    astPattern?: ASTPattern; // AST 匹配模式
    quickFix?: QuickFix;    // 快速修复方案
    metadata?: {
        category: string;   // 分类：security, performance, quality
        tags: string[];     // 标签
        docs: string;       // 文档链接
    };
}
```

### 智能匹配策略
1. **正则快速匹配**: 适用于简单模式，性能高
2. **AST 精准匹配**: 适用于复杂语法，准确度高
3. **混合匹配**: 先正则筛选，再 AST 验证

### 核心检测场景

#### 1. 数据库操作安全
- **无条件删除/更新**: DELETE/UPDATE 缺少 WHERE 条件
- **DROP DATABASE/TABLE**: 检测危险的删表操作
- **SQL 注入**: 字符串拼接构造 SQL
- **TRUNCATE**: 清空表操作

#### 2. 代码执行风险
- **eval/exec**: JavaScript/Python 中执行任意代码
- **child_process**: Node.js 命令注入
- **dangerouslySetInnerHTML**: React XSS 风险
- **v-html**: Vue XSS 风险

#### 3. 敏感信息泄露
- **API Keys**: AWS, Azure, Google Cloud 密钥
- **数据库密码**: 明文存储的连接字符串
- **Token/Secret**: JWT, OAuth 等认证信息
- **生产环境配置**: debug=true, CORS *

#### 4. 文件系统操作
- **rm -rf /**: 危险的删除命令
- **fs.unlink/rmdir**: 无检查的文件删除
- **os.remove**: Python 文件删除
- **路径遍历**: ../../../etc/passwd

#### 5. 异步编程陷阱
- **forEach + async/await**: 不会等待执行
- **未处理的 Promise rejection**: 导致进程崩溃
- **useEffect 依赖缺失**: React 无限循环
- **内存泄漏**: 未清理的事件监听器

## 性能优化策略

### 1. 增量分析优化
```typescript
class IncrementalAnalyzer {
    private changeBuffer: ChangeEvent[] = [];
    private processTimer: NodeJS.Timeout | null = null;

    handleChange(event: TextDocumentChangeEvent) {
        this.changeBuffer.push(event);
        
        if (this.processTimer) {
            clearTimeout(this.processTimer);
        }
        
        this.processTimer = setTimeout(() => {
            this.processBatch();
        }, 500); // 500ms 防抖
    }

    private processBatch() {
        // 合并相邻的变更
        const mergedChanges = this.mergeChanges(this.changeBuffer);
        
        // 批量处理
        for (const change of mergedChanges) {
            this.analyzeChange(change);
        }
        
        this.changeBuffer = [];
    }
}
```

### 2. 缓存策略
```typescript
class CacheManager {
    private cache = new Map<string, CacheEntry>();
    private maxSize = 100; // 最大缓存文件数
    private ttl = 60000; // 60秒过期

    set(key: string, value: any) {
        // LRU 淘汰策略
        if (this.cache.size >= this.maxSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        this.cache.set(key, {
            value,
            timestamp: Date.now()
        });
    }

    get(key: string): any | null {
        const entry = this.cache.get(key);
        
        if (!entry) return null;
        
        // 检查过期
        if (Date.now() - entry.timestamp > this.ttl) {
            this.cache.delete(key);
            return null;
        }
        
        return entry.value;
    }
}
```

### 3. Web Worker 并行处理
```typescript
// worker.ts
self.addEventListener('message', async (event) => {
    const { text, rules } = event.data;
    const results = await analyzeWithRules(text, rules);
    self.postMessage(results);
});

// 主线程
class ParallelAnalyzer {
    private worker: Worker;

    constructor() {
        this.worker = new Worker('worker.js');
    }

    async analyze(text: string, rules: Rule[]): Promise<Issue[]> {
        return new Promise((resolve) => {
            this.worker.postMessage({ text, rules });
            this.worker.onmessage = (event) => {
                resolve(event.data);
            };
        });
    }
}
```

## 开发环境搭建

### 1. 环境准备
```bash
# 安装 Node.js 18+
node --version

# 安装开发工具
npm install -g yo generator-code vsce

# 创建项目
yo code
# 选择: New Extension (TypeScript)
# 名称: vibeguard
```

### 2. 依赖安装
```json
{
  "devDependencies": {
    "@types/vscode": "^1.84.0",
    "@types/node": "20.x",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0",
    "typescript": "^5.0.0",
    "webpack": "^5.0.0",
    "webpack-cli": "^5.0.0",
    "@vscode/test-electron": "^2.3.0"
  },
  "dependencies": {
    "esprima": "^4.0.1",
    "@babel/parser": "^7.0.0",
    "sql-parser": "^1.0.0"
  }
}
```

### 3. 开发命令
```bash
# 编译
npm run compile

# 监听模式
npm run watch

# 测试
npm test

# 打包
vsce package

# 调试
# 按 F5 启动扩展开发主机
```

## 代码实现示例

### 诊断管理器
```typescript
export class DiagnosticManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');
    }

    updateDiagnostics(document: vscode.TextDocument, issues: Issue[]) {
        const diagnostics: vscode.Diagnostic[] = issues.map(issue => {
            const range = new vscode.Range(
                issue.line,
                issue.column,
                issue.line,
                issue.column + 10
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                issue.message,
                this.mapSeverity(issue.severity)
            );

            diagnostic.code = issue.code;
            diagnostic.source = 'VibeGuard';

            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'error': return vscode.DiagnosticSeverity.Error;
            case 'warning': return vscode.DiagnosticSeverity.Warning;
            default: return vscode.DiagnosticSeverity.Information;
        }
    }

    dispose() {
        this.diagnosticCollection.dispose();
    }
}
```

### 快速修复提供者
```typescript
export class QuickFixProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range,
        context: vscode.CodeActionContext
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'VibeGuard') continue;

            const action = new vscode.CodeAction(
                `修复: ${diagnostic.message}`,
                vscode.CodeActionKind.QuickFix
            );

            action.edit = new vscode.WorkspaceEdit();
            
            // 根据诊断代码提供不同的修复
            switch (diagnostic.code) {
                case 'JS003': // API Key
                    const text = document.getText(diagnostic.range);
                    const envVar = text.match(/(\w+)\s*[:=]/)?.[1].toUpperCase();
                    action.edit.replace(
                        document.uri,
                        diagnostic.range,
                        `process.env.${envVar}`
                    );
                    break;
                    
                case 'SQL001': // DELETE without WHERE
                    action.edit.insert(
                        document.uri,
                        diagnostic.range.end,
                        ' WHERE id = ?'
                    );
                    break;
            }

            action.diagnostics = [diagnostic];
            actions.push(action);
        }

        return actions;
    }
}
```

## 测试策略

### 1. 单元测试示例
```typescript
// test/unit/RuleEngine.test.ts
import { RuleEngine } from '../../src/rules/RuleEngine';

describe('RuleEngine', () => {
    let engine: RuleEngine;

    beforeEach(() => {
        engine = new RuleEngine();
    });

    test('检测 SQL 无条件删除', async () => {
        const sql = 'DELETE FROM users';
        const rules = engine.getRulesForLanguage('sql');
        const issues = await engine.checkText(sql, rules);
        
        expect(issues).toHaveLength(1);
        expect(issues[0].code).toBe('SQL001');
    });

    test('检测 JavaScript eval 使用', async () => {
        const js = 'const result = eval(userInput);';
        const rules = engine.getRulesForLanguage('javascript');
        const issues = await engine.checkText(js, rules);
        
        expect(issues).toHaveLength(1);
        expect(issues[0].code).toBe('JS001');
    });

    test('检测 API Key 硬编码', async () => {
        const code = 'const api_key = "sk-1234567890";';
        const rules = engine.getRulesForLanguage('javascript');
        const issues = await engine.checkText(code, rules);
        
        expect(issues).toHaveLength(1);
        expect(issues[0].code).toBe('JS003');
    });
});
```

### 2. 集成测试
```typescript
// test/integration/extension.test.ts
import * as vscode from 'vscode';
import * as path from 'path';

suite('Extension Integration Tests', () => {
    test('检测危险代码并提供诊断', async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: 'javascript',
            content: 'eval("alert(1)")'
        });

        await vscode.window.showTextDocument(doc);
        
        // 等待分析完成
        await new Promise(resolve => setTimeout(resolve, 1000));

        const diagnostics = vscode.languages.getDiagnostics(doc.uri);
        
        assert.strictEqual(diagnostics.length, 1);
        assert.strictEqual(diagnostics[0].message.includes('eval'), true);
    });
});
```

### 3. 性能测试
```typescript
// test/performance/analyzer.perf.ts
describe('Performance Tests', () => {
    test('大文件分析性能', async () => {
        const largeFile = generateLargeFile(10000); // 10000行代码
        
        const startTime = Date.now();
        await analyzer.analyzeFull(largeFile);
        const duration = Date.now() - startTime;
        
        expect(duration).toBeLessThan(1000); // 应在1秒内完成
    });

    test('增量分析性能', async () => {
        const changes = generateChanges(100); // 100个变更
        
        const startTime = Date.now();
        for (const change of changes) {
            await analyzer.analyzeIncremental(change);
        }
        const duration = Date.now() - startTime;
        
        expect(duration).toBeLessThan(500); // 应在500ms内完成
    });
});
```

## 部署与发布

### 1. 构建配置
```javascript
// webpack.config.js
const path = require('path');

module.exports = {
    target: 'node',
    mode: 'production',
    entry: './src/extension.ts',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'extension.js',
        libraryTarget: 'commonjs2'
    },
    externals: {
        vscode: 'commonjs vscode'
    },
    resolve: {
        extensions: ['.ts', '.js']
    },
    module: {
        rules: [{
            test: /\.ts$/,
            exclude: /node_modules/,
            use: 'ts-loader'
        }]
    },
    optimization: {
        minimize: true
    }
};
```

### 2. 发布流程
```bash
# 1. 更新版本号
npm version patch/minor/major

# 2. 构建
npm run compile

# 3. 打包
vsce package

# 4. 本地测试
code --install-extension vibeguard-0.1.0.vsix

# 5. 发布到 Marketplace
vsce publish

# 6. 发布到 GitHub
git tag v0.1.0
git push origin v0.1.0
```

### 3. CI/CD 配置
```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: 18
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run tests
        run: npm test
        
      - name: Build
        run: npm run compile
        
      - name: Package
        run: npx vsce package
        
      - name: Publish to Marketplace
        run: npx vsce publish -p ${{ secrets.VSCE_TOKEN }}
        
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: '*.vsix'
```

## 性能指标

### 目标指标
- **启动时间**: < 500ms
- **增量分析延迟**: < 100ms
- **全文件分析**: < 1s (5000行以内)
- **内存占用**: < 50MB
- **CPU 占用**: < 5%

### 监控方案
```typescript
class PerformanceMonitor {
    private metrics: Map<string, number[]> = new Map();

    measure(name: string, fn: () => void) {
        const start = performance.now();
        fn();
        const duration = performance.now() - start;
        
        if (!this.metrics.has(name)) {
            this.metrics.set(name, []);
        }
        this.metrics.get(name)!.push(duration);
        
        // 每100次输出平均值
        if (this.metrics.get(name)!.length % 100 === 0) {
            this.logMetrics(name);
        }
    }

    private logMetrics(name: string) {
        const values = this.metrics.get(name)!;
        const avg = values.reduce((a, b) => a + b) / values.length;
        const p95 = this.percentile(values, 0.95);
        
        console.log(`[Performance] ${name}: avg=${avg.toFixed(2)}ms, p95=${p95.toFixed(2)}ms`);
    }
}
```

## 风险和解决方案

### 技术风险
1. **AST 解析性能问题**
   - 风险：大文件解析慢
   - 解决：使用 Web Worker，限制解析范围

2. **误报率高**
   - 风险：规则过于严格
   - 解决：提供配置选项，支持规则级别调整

3. **内存泄漏**
   - 风险：缓存无限增长
   - 解决：LRU 缓存，定期清理

### 用户体验风险
1. **过多提示干扰**
   - 解决：智能防抖，批量显示

2. **新手不理解提示**
   - 解决：提供详细文档链接，视频教程

## 后续优化方向

1. **AI 增强**
   - 集成 GPT-4 进行语义分析
   - 智能推荐最佳实践

2. **团队协作**
   - 共享规则库
   - 代码审查集成

3. **多语言支持**
   - Go, Rust, Java 支持
   - 框架特定规则（React, Vue, Django）

4. **性能优化**
   - 预编译规则
   - 增量 AST 更新
   - 智能缓存预热

## 总结

本技术文档提供了 VibeGuard 插件的完整实现方案，包括：
- ✅ 详细的架构设计和模块划分
- ✅ 核心功能的代码实现
- ✅ 性能优化策略
- ✅ 完整的测试方案
- ✅ 部署和发布流程

通过这份文档，开发团队可以快速理解项目架构，并按照既定方案实现一个高质量的 VS Code 安全插件。
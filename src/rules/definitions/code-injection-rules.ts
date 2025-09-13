/**
 * Code Injection Detection Rules
 * 
 * This module defines detection rules for code injection vulnerabilities
 * that could allow attackers to execute malicious code. These rules help
 * prevent XSS, command injection, and other code execution attacks.
 */

import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

/**
 * eval() Function Detection Rule
 * Detects usage of the dangerous eval() function which can execute arbitrary code
 */
export const EVAL_USAGE_RULE: DetectionRule = {
  id: 'CODE_INJECTION_EVAL',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.ERROR,
  pattern: /\beval\s*\(/gi,
  message: '💀 代码注入漏洞！eval() 是最危险的函数！\n🎯 真实威胁：黑客可以通过它执行任意代码，完全控制你的应用！\n🛡️ 安全修复：点击灯泡使用安全替代方案',
  quickFix: {
    title: '🚨 立即替换为安全方案',
    replacement: (match: RegExpExecArray): string => {
      return `// 🚨 危险函数已注释：eval() 存在严重安全风险！\n// 🛡️ 安全替代方案：\n//   - 解析 JSON：使用 JSON.parse()\n//   - 动态函数：使用 new Function()\n//   - 计算表达式：使用专门的表达式解析库\n// ${match[0]}`;
    },
    description: '将极度危险的 eval() 函数替换为安全的替代方案，防止代码注入攻击。'
  },
  whitelist: [
    // Skip comments
    '//.*eval',
    '/\\*.*eval.*\\*/',
    '#.*eval',
    // Skip string literals that mention eval
    '["\'`].*eval.*["\'`]',
    // Skip console/logging
    'console\\..*eval',
    'log.*eval'
  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * innerHTML Direct Assignment Detection Rule
 * Detects direct assignment to innerHTML which can lead to XSS attacks
 */
export const INNERHTML_ASSIGNMENT_RULE: DetectionRule = {
  id: 'CODE_INJECTION_INNERHTML',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.ERROR,
  pattern: /\.innerHTML\s*=\s*[^;]+/gi,
  message: '⚠️ XSS 攻击风险！直接设置 innerHTML 很危险！\n🎯 真实威胁：恶意用户可以注入脚本，窃取其他用户的登录信息！\n🛡️ 安全修复：点击灯泡使用安全方法',
  quickFix: {
    title: '🛡️ 使用安全的内容设置方法',
    replacement: (match: RegExpExecArray): string => {
      const assignment = match[0];
      const safePart = assignment.replace(/\.innerHTML\s*=/, '.textContent =');
      return `// 🛡️ 安全替代方案（选择其一）：\n// 1. 纯文本内容：${safePart}\n// 2. 清理后的 HTML：element.innerHTML = DOMPurify.sanitize(content)\n// 🚨 原始代码已注释：${assignment}`;
    },
    description: '使用 textContent 显示纯文本，或使用 DOMPurify 清理 HTML 内容，防止 XSS 攻击。'
  },
  whitelist: [
    // Skip comments
    '//.*innerHTML',
    '/\\*.*innerHTML.*\\*/',
    '#.*innerHTML',
    // Skip empty string assignments
    '\\.innerHTML\\s*=\\s*["\'`]\\s*["\'`]',
    // Skip simple static HTML without any variables or concatenation
    '\\.innerHTML\\s*=\\s*["\'`]<[^"\'`+]*>\\s*[^"\'`+]*\\s*</[^"\'`+]*>["\'`]\\s*;?\\s*$'
  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * child_process.exec Command Injection Detection Rule
 * Detects usage of child_process.exec with user input which can lead to command injection
 */
export const CHILD_PROCESS_EXEC_RULE: DetectionRule = {
  id: 'CODE_INJECTION_CHILD_PROCESS',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.ERROR,
  pattern: /(?:child_process\.exec|exec)\s*\([^)]*(?:input|param|request|user|form|query|body|filename|userInput|formData|queryParams)[^)]*\)/gi,
  message: '💀 命令注入风险！使用用户输入执行系统命令极其危险！攻击者可以执行任意系统命令！',
  quickFix: {
    title: '使用参数化执行',
    replacement: (match: RegExpExecArray): string => {
      return `// 危险：不要直接拼接用户输入到命令中！\n// 安全替代：使用 execFile() 或 spawn() 并验证参数\n// ${match[0]}`;
    },
    description: '使用 execFile() 或 spawn() 替代 exec()，并严格验证所有参数'
  },
  whitelist: [
    // Skip comments
    '//.*exec',
    '/\\*.*exec.*\\*/',
    '#.*exec',
    // Skip require statements
    'require.*exec',
    'import.*exec',
    // Skip static commands (no variables or user input)
    'exec\\s*\\(\\s*["\'`][^${}+]*["\'`]\\s*[,)]',
    // Skip logging
    'console\\..*exec',
    'log.*exec',

  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * document.write() Detection Rule
 * Detects usage of document.write() which can be dangerous with user input
 */
export const DOCUMENT_WRITE_RULE: DetectionRule = {
  id: 'CODE_INJECTION_DOCUMENT_WRITE',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.WARNING,
  pattern: /document\.write\s*\(/gi,
  message: '⚠️ 潜在风险！document.write() 可能导致 XSS 攻击，特别是处理用户输入时！',
  quickFix: {
    title: '使用现代 DOM 方法',
    replacement: (match: RegExpExecArray): string => {
      return `// 建议使用现代 DOM 方法替代 document.write()\n// 例如：element.textContent 或 element.appendChild()\n// ${match[0]}`;
    },
    description: '使用现代 DOM 操作方法替代 document.write()，如 createElement、textContent 等'
  },
  whitelist: [
    // Skip comments
    '//.*document\\.write',
    '/\\*.*document\\.write.*\\*/',
    '#.*document\\.write',
    // Skip static content with script tags that are safe
    'document\\.write\\s*\\(\\s*["\'`]<script\\s+src\\s*=\\s*["\'`][^"\'`]*["\'`][^>]*></script>["\'`]\\s*\\)',
    // Skip other static content
    'document\\.write\\s*\\(\\s*["\'`][^<>{}$]*["\'`]\\s*\\)',
    // Skip logging/debugging
    'console\\..*document\\.write',
    'log.*document\\.write'
  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * Function Constructor Detection Rule
 * Detects usage of Function constructor which can execute arbitrary code
 */
export const FUNCTION_CONSTRUCTOR_RULE: DetectionRule = {
  id: 'CODE_INJECTION_FUNCTION_CONSTRUCTOR',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.WARNING,
  pattern: /new\s+Function\s*\(/gi,
  message: '⚠️ 代码注入风险！Function 构造器可以执行任意代码！请谨慎使用用户输入！',
  quickFix: {
    title: '验证输入或使用替代方案',
    replacement: (match: RegExpExecArray): string => {
      return `// 警告：Function 构造器存在代码注入风险\n// 请确保严格验证所有输入参数\n${match[0]}`;
    },
    description: '如果必须使用 Function 构造器，请严格验证和清理所有输入参数'
  },
  whitelist: [
    // Skip comments
    '//.*Function',
    '/\\*.*Function.*\\*/',
    '#.*Function',
    // Skip static function creation
    'new\\s+Function\\s*\\(\\s*["\'`][^${}]*["\'`]',
    // Skip logging
    'console\\..*Function',
    'log.*Function'
  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * setTimeout/setInterval with String Detection Rule
 * Detects usage of setTimeout/setInterval with string arguments which can execute code
 */
export const SETTIMEOUT_STRING_RULE: DetectionRule = {
  id: 'CODE_INJECTION_SETTIMEOUT_STRING',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.WARNING,
  pattern: /(?:setTimeout|setInterval)\s*\(\s*["'`][^"'`]*(?:input|param|request|user|form|userInput|formData|requestParam)[^"'`]*["'`]/gi,
  message: '⚠️ 代码注入风险！setTimeout/setInterval 使用字符串参数可能执行恶意代码！',
  quickFix: {
    title: '使用函数替代字符串',
    replacement: (match: RegExpExecArray): string => {
      return `// 安全替代：使用函数而不是字符串\n// 例如：setTimeout(() => { /* 你的代码 */ }, delay)\n// ${match[0]}`;
    },
    description: '使用函数参数替代字符串参数来避免代码注入风险'
  },
  whitelist: [
    // Skip comments
    '//.*setTimeout',
    '/\\*.*setTimeout.*\\*/',
    '#.*setTimeout',
    // Skip static strings without variables
    '(?:setTimeout|setInterval)\\s*\\(\\s*["\'`][^${}]*["\'`]',
    // Skip logging
    'console\\..*setTimeout',
    'log.*setTimeout'
  ],
  languages: ['javascript', 'typescript', '*'],
  enabled: true
};

/**
 * Script Tag Injection Detection Rule
 * Detects dynamic creation of script tags which can lead to XSS
 */
export const SCRIPT_TAG_INJECTION_RULE: DetectionRule = {
  id: 'CODE_INJECTION_SCRIPT_TAG',
  category: SecurityCategory.CODE_INJECTION,
  severity: IssueSeverity.ERROR,
  pattern: /<script[^>]*>.*(?:input|param|request|user|form|query|body).*<\/script>/gis,
  message: '💀 XSS 攻击风险！动态创建包含用户输入的 script 标签极其危险！',
  quickFix: {
    title: '移除动态脚本创建',
    replacement: (match: RegExpExecArray): string => {
      return `<!-- 危险：动态脚本标签已被注释 -->\n<!-- ${match[0]} -->`;
    },
    description: '移除动态脚本标签创建，使用安全的数据传递方式'
  },
  whitelist: [
    // Skip comments
    '<!--.*<script.*-->',
    '//.*<script',
    '/\\*.*<script.*\\*/',
    '#.*<script'
  ],
  languages: ['html', 'javascript', 'typescript', '*'],
  enabled: true
};

/**
 * All Code Injection Detection Rules
 * Export array of all rules for easy registration
 */
export const CODE_INJECTION_RULES: DetectionRule[] = [
  EVAL_USAGE_RULE,
  INNERHTML_ASSIGNMENT_RULE,
  CHILD_PROCESS_EXEC_RULE,
  DOCUMENT_WRITE_RULE,
  FUNCTION_CONSTRUCTOR_RULE,
  SETTIMEOUT_STRING_RULE,
  SCRIPT_TAG_INJECTION_RULE
];

/**
 * Register all code injection rules with the rule engine
 */
export function registerCodeInjectionRules(ruleEngine: { registerRule: (rule: DetectionRule) => void }): void {
  CODE_INJECTION_RULES.forEach(rule => {
    try {
      ruleEngine.registerRule(rule);
      console.log(`VibeGuard: 已注册代码注入检测规则 ${rule.id}`);
    } catch (error) {
      console.error(`VibeGuard: 注册规则失败 ${rule.id}:`, error);
    }
  });
  
  console.log(`VibeGuard: 成功注册 ${CODE_INJECTION_RULES.length} 个代码注入检测规则`);
}
/**
 * Framework-Specific Risk Detection Rules
 * 
 * This module defines detection rules for security risks specific to
 * popular frontend frameworks like React, Vue, and Angular. These rules
 * help prevent XSS attacks and other framework-specific vulnerabilities.
 */

import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

/**
 * React dangerouslySetInnerHTML Detection Rule
 * Detects usage of dangerouslySetInnerHTML which can lead to XSS attacks
 */
export const REACT_DANGEROUS_INNERHTML_RULE: DetectionRule = {
  id: 'FRAMEWORK_REACT_DANGEROUS_INNERHTML',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*[^}]*(?:props|state|input|param|user|form|query|request|data)[^}]*\s*\}\s*\}/gi,
  message: '⚠️ React XSS 风险！dangerouslySetInnerHTML 使用用户数据可能导致跨站脚本攻击！',
  quickFix: {
    title: '使用 DOMPurify 清理内容',
    replacement: (match: RegExpExecArray): string => {
      const content = match[0];
      // Extract the variable part between __html: and }
      const htmlMatch = content.match(/__html\s*:\s*([^}]+)/);
      if (htmlMatch) {
        const htmlContent = htmlMatch[1].trim();
        return content.replace(htmlMatch[1], `DOMPurify.sanitize(${htmlContent})`);
      }
      return `// 安全提示：使用 DOMPurify.sanitize() 清理 HTML 内容\n${content}`;
    },
    description: '使用 DOMPurify 库清理 HTML 内容，防止 XSS 攻击'
  },
  whitelist: [
    // Skip comments
    '//.*dangerouslySetInnerHTML',
    '/\\*.*dangerouslySetInnerHTML.*\\*/',
    '#.*dangerouslySetInnerHTML',
    // Skip static HTML content
    'dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*["\'`][^"\'`{}$]*["\'`]\\s*\\}\\s*\\}',
    // Skip already sanitized content
    'DOMPurify\\.sanitize',
    'sanitizeHtml',
    'xss\\(',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['javascript', 'typescript', 'jsx', 'tsx', '*'],
  enabled: true
};

/**
 * Vue v-html Directive Detection Rule
 * Detects usage of v-html directive with user input which can lead to XSS
 */
export const VUE_V_HTML_RULE: DetectionRule = {
  id: 'FRAMEWORK_VUE_V_HTML',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /v-html\s*=\s*["']?[^"'>]*(?:input|param|user|form|query|request|data|props|\$data|\$props|Input|Data|User|Form|Query|Request)[^"'>]*["']?/gi,
  message: '⚠️ Vue XSS 风险！v-html 指令使用用户数据可能导致跨站脚本攻击！',
  quickFix: {
    title: '使用文本插值或清理内容',
    replacement: (match: RegExpExecArray): string => {
      const content = match[0];
      // Replace v-html with v-text for safety
      const safeContent = content.replace(/v-html/, 'v-text');
      return `<!-- 安全提示：使用 v-text 或 DOMPurify.sanitize() 清理内容 -->\n${safeContent}`;
    },
    description: '使用 v-text 替代 v-html，或使用 DOMPurify 清理 HTML 内容'
  },
  whitelist: [
    // Skip comments
    '<!--.*v-html.*-->',
    '//.*v-html',
    '/\\*.*v-html.*\\*/',
    '#.*v-html',
    // Skip already sanitized content
    'sanitize',
    'DOMPurify',
    'xss\\(',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['vue', 'html', 'javascript', 'typescript', '*'],
  enabled: true
};

/**
 * React useEffect Infinite Loop Detection Rule
 * Detects useEffect hooks that might cause infinite loops due to missing dependencies
 */
export const REACT_USEEFFECT_INFINITE_LOOP_RULE: DetectionRule = {
  id: 'FRAMEWORK_REACT_USEEFFECT_LOOP',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*(?:setState|set[A-Z]\w*|dispatch)[^}]*\}\s*,\s*\[\s*\]\s*\)/gs,
  message: '⚠️ React 性能风险！useEffect 中修改状态但依赖数组为空可能导致无限循环！',
  quickFix: {
    title: '添加正确的依赖项',
    replacement: (match: RegExpExecArray): string => {
      return `// 警告：检查 useEffect 依赖数组是否正确\n// 添加所有在 effect 中使用的状态和 props\n${match[0]}`;
    },
    description: '在 useEffect 的依赖数组中添加所有使用的状态变量和 props'
  },
  whitelist: [
    // Skip comments
    '//.*useEffect',
    '/\\*.*useEffect.*\\*/',
    '#.*useEffect',
    // Skip effects that only run once intentionally
    'useEffect\\s*\\([^,]*,\\s*\\[\\s*\\]\\s*\\)\\s*;?\\s*//.*once',
    'useEffect\\s*\\([^,]*,\\s*\\[\\s*\\]\\s*\\)\\s*;?\\s*/\\*.*once.*\\*/',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['javascript', 'typescript', 'jsx', 'tsx', '*'],
  enabled: true
};

/**
 * Angular bypassSecurityTrust* Methods Detection Rule
 * Detects usage of Angular's security bypass methods which can be dangerous
 */
export const ANGULAR_BYPASS_SECURITY_RULE: DetectionRule = {
  id: 'FRAMEWORK_ANGULAR_BYPASS_SECURITY',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\([^)]*(?:input|param|user|form|query|request|data|Input|Data|Content)[^)]*\)/gi,
  message: '⚠️ Angular 安全风险！绕过安全信任检查可能导致 XSS 攻击！请确保内容已经过清理！',
  quickFix: {
    title: '添加内容清理',
    replacement: (match: RegExpExecArray): string => {
      return `// 安全警告：确保内容已通过 DOMPurify 等工具清理\n// 考虑使用更安全的替代方案\n${match[0]}`;
    },
    description: '在绕过安全检查前，确保使用 DOMPurify 等工具清理用户输入'
  },
  whitelist: [
    // Skip comments
    '//.*bypassSecurityTrust',
    '/\\*.*bypassSecurityTrust.*\\*/',
    '#.*bypassSecurityTrust',
    // Skip static content
    'bypassSecurityTrust\\w*\\s*\\(\\s*["\'`][^"\'`${}]*["\'`]\\s*\\)',
    // Skip already sanitized content
    'DOMPurify\\.sanitize',
    'sanitize',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['typescript', 'javascript', '*'],
  enabled: true
};

/**
 * React Component Props XSS Detection Rule
 * Detects potentially dangerous prop usage that could lead to XSS
 */
export const REACT_PROPS_XSS_RULE: DetectionRule = {
  id: 'FRAMEWORK_REACT_PROPS_XSS',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /<\w+[^>]*(?:href|src|action|formAction)\s*=\s*\{[^}]*(?:props|state|input|param|user|form|query|request)[^}]*\}/gi,
  message: '⚠️ React XSS 风险！在 href、src 等属性中使用用户数据可能导致安全问题！',
  quickFix: {
    title: '验证和清理 URL',
    replacement: (match: RegExpExecArray): string => {
      return `{/* 安全提示：验证和清理 URL，使用 URL 构造器或白名单 */}\n${match[0]}`;
    },
    description: '验证和清理 URL，确保只允许安全的协议和域名'
  },
  whitelist: [
    // Skip comments
    '//.*href',
    '/\\*.*href.*\\*/',
    '<!--.*href.*-->',
    // Skip relative URLs and safe patterns
    'href\\s*=\\s*\\{[^}]*["\'`]/[^"\'`]*["\'`][^}]*\\}',
    'href\\s*=\\s*\\{[^}]*["\'`]#[^"\'`]*["\'`][^}]*\\}',
    'href\\s*=\\s*\\{[^}]*["\'`]mailto:[^"\'`]*["\'`][^}]*\\}',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['javascript', 'typescript', 'jsx', 'tsx', '*'],
  enabled: true
};

/**
 * Vue Template Injection Detection Rule
 * Detects potential template injection in Vue templates
 */
export const VUE_TEMPLATE_INJECTION_RULE: DetectionRule = {
  id: 'FRAMEWORK_VUE_TEMPLATE_INJECTION',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /\{\{[^}]*(?:input|param|user|form|query|request|data|\$data|\$props|Input|Data|User|Form|Query|Request)[^}]*\}\}/gi,
  message: '⚠️ Vue 模板注入风险！直接在模板中使用用户数据可能不安全！请确保数据已经过滤！',
  quickFix: {
    title: '使用过滤器或计算属性',
    replacement: (match: RegExpExecArray): string => {
      const content = match[0];
      return `<!-- 安全提示：使用过滤器或计算属性清理数据 -->\n${content}`;
    },
    description: '使用 Vue 过滤器或计算属性来清理和验证用户数据'
  },
  whitelist: [
    // Skip comments
    '<!--.*\\{\\{.*\\}\\}.*-->',
    '//.*\\{\\{',
    '/\\*.*\\{\\{.*\\*/',
    // Skip safe interpolations (numbers, booleans, etc.)
    '\\{\\{\\s*\\w+\\.(?:length|id|index|key)\\s*\\}\\}',
    '\\{\\{\\s*\\d+\\s*\\}\\}',
    '\\{\\{\\s*(?:true|false)\\s*\\}\\}',
    // Skip filtered content
    '\\{\\{[^}]*\\|[^}]*\\}\\}',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['vue', 'html', '*'],
  enabled: true
};

/**
 * Angular Template Injection Detection Rule
 * Detects potential template injection in Angular templates
 */
export const ANGULAR_TEMPLATE_INJECTION_RULE: DetectionRule = {
  id: 'FRAMEWORK_ANGULAR_TEMPLATE_INJECTION',
  category: SecurityCategory.FRAMEWORK_RISK,
  severity: IssueSeverity.WARNING,
  pattern: /\{\{[^}]*(?:input|param|user|form|query|request|data|Input|Data|User|Form|Query|Request)[^}]*\}\}/gi,
  message: '⚠️ Angular 模板注入风险！直接在模板中使用用户数据可能不安全！',
  quickFix: {
    title: '使用管道或组件方法',
    replacement: (match: RegExpExecArray): string => {
      const content = match[0];
      return `<!-- 安全提示：使用 Angular 管道或组件方法清理数据 -->\n${content}`;
    },
    description: '使用 Angular 管道或组件方法来清理和验证用户数据'
  },
  whitelist: [
    // Skip comments
    '<!--.*\\{\\{.*\\}\\}.*-->',
    '//.*\\{\\{',
    '/\\*.*\\{\\{.*\\*/',
    // Skip safe interpolations
    '\\{\\{\\s*\\w+\\.(?:length|id|index|key)\\s*\\}\\}',
    '\\{\\{\\s*\\d+\\s*\\}\\}',
    '\\{\\{\\s*(?:true|false)\\s*\\}\\}',
    // Skip piped content
    '\\{\\{[^}]*\\|[^}]*\\}\\}',
    // Skip test files
    '\\.test\\.',
    '\\.spec\\.'
  ],
  languages: ['html', 'typescript', '*'],
  enabled: true
};

/**
 * All Framework Risk Detection Rules
 * Export array of all rules for easy registration
 */
export const FRAMEWORK_RISK_RULES: DetectionRule[] = [
  REACT_DANGEROUS_INNERHTML_RULE,
  VUE_V_HTML_RULE,
  REACT_USEEFFECT_INFINITE_LOOP_RULE,
  ANGULAR_BYPASS_SECURITY_RULE,
  REACT_PROPS_XSS_RULE,
  VUE_TEMPLATE_INJECTION_RULE,
  ANGULAR_TEMPLATE_INJECTION_RULE
];

/**
 * Register all framework risk rules with the rule engine
 */
export function registerFrameworkRiskRules(ruleEngine: { registerRule: (rule: DetectionRule) => void }): void {
  FRAMEWORK_RISK_RULES.forEach(rule => {
    try {
      ruleEngine.registerRule(rule);
      console.log(`VibeGuard: 已注册框架风险检测规则 ${rule.id}`);
    } catch (error) {
      console.error(`VibeGuard: 注册规则失败 ${rule.id}:`, error);
    }
  });
  
  console.log(`VibeGuard: 成功注册 ${FRAMEWORK_RISK_RULES.length} 个框架风险检测规则`);
}
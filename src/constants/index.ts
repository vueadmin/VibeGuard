/**
 * Constants and default configurations for VibeGuard
 */

import { PerformanceGuard, VibeGuardConfig } from '../types';

// ============================================================================
// Extension Constants
// ============================================================================

/** Extension identifier */
export const EXTENSION_ID = 'vibeguard';

/** Extension display name */
export const EXTENSION_NAME = 'VibeGuard';

/** Diagnostic collection name */
export const DIAGNOSTIC_COLLECTION_NAME = 'vibeguard';

// ============================================================================
// Default Configuration
// ============================================================================

/** Default extension configuration */
export const DEFAULT_CONFIG: VibeGuardConfig = {
  enableRealTimeAnalysis: true,
  debounceDelay: 500,
  maxFileSize: 1024 * 1024, // 1MB
  supportedLanguages: [
    'javascript',
    'typescript',
    'sql',
    'json',
    'yaml',
    'python',
    'java',
    'csharp',
    'php',
    'go',
    'rust',
    'cpp',
    'c'
  ],
  showQuickFixes: true
};

/** Default performance guard settings */
export const DEFAULT_PERFORMANCE_GUARD: PerformanceGuard = {
  maxAnalysisTime: 5000, // 5 seconds
  maxFileSize: 1024 * 1024, // 1MB
  maxRulesPerAnalysis: 100,
  enableTimeout: true
};

// ============================================================================
// Rule Categories
// ============================================================================

/** Rule category priorities (higher number = higher priority) */
export const RULE_CATEGORY_PRIORITIES = {
  'api-key': 100,
  'sql-danger': 90,
  'code-injection': 80,
  'framework-risk': 70,
  'config-error': 60
} as const;

// ============================================================================
// Error Messages
// ============================================================================

/** Common error messages in Chinese */
export const ERROR_MESSAGES = {
  ANALYSIS_TIMEOUT: '代码分析超时，请检查文件大小或复杂度',
  FILE_TOO_LARGE: '文件过大，无法进行安全分析',
  UNSUPPORTED_LANGUAGE: '不支持的编程语言',
  RULE_EXECUTION_FAILED: '安全规则执行失败',
  EXTENSION_ACTIVATION_FAILED: '扩展激活失败',
  DIAGNOSTIC_UPDATE_FAILED: '诊断信息更新失败'
} as const;

// ============================================================================
// Success Messages
// ============================================================================

/** Success messages in Chinese */
export const SUCCESS_MESSAGES = {
  EXTENSION_ACTIVATED: 'VibeGuard 已激活，正在保护您的代码安全',
  ANALYSIS_COMPLETE: '代码安全分析完成',
  QUICK_FIX_APPLIED: '安全问题已修复',
  NO_ISSUES_FOUND: '未发现安全问题，代码看起来很安全！'
} as const;

// ============================================================================
// Command IDs
// ============================================================================

/** VSCode command identifiers */
export const COMMANDS = {
  ANALYZE_CURRENT_FILE: 'vibeguard.analyzeCurrentFile',
  ANALYZE_WORKSPACE: 'vibeguard.analyzeWorkspace',
  APPLY_QUICK_FIX: 'vibeguard.applyQuickFix',
  SHOW_SETTINGS: 'vibeguard.showSettings'
} as const;

// ============================================================================
// File Extensions
// ============================================================================

/** Supported file extensions by language */
export const SUPPORTED_EXTENSIONS = {
  javascript: ['.js', '.jsx', '.mjs'],
  typescript: ['.ts', '.tsx'],
  sql: ['.sql'],
  json: ['.json'],
  yaml: ['.yml', '.yaml'],
  python: ['.py'],
  java: ['.java'],
  csharp: ['.cs'],
  php: ['.php'],
  go: ['.go'],
  rust: ['.rs'],
  cpp: ['.cpp', '.cc', '.cxx'],
  c: ['.c', '.h']
} as const;

// ============================================================================
// Regular Expression Patterns
// ============================================================================

/** Common regex patterns used across rules */
export const COMMON_PATTERNS = {
  // Environment variable references
  ENV_VAR_REFERENCE: /process\.env\.\w+|os\.environ\[['"][^'"]+['"]\]|\$\{?\w+\}?/g,
  
  // Comments (single and multi-line)
  SINGLE_LINE_COMMENT: /\/\/.*$/gm,
  MULTI_LINE_COMMENT: /\/\*[\s\S]*?\*\//g,
  PYTHON_COMMENT: /#.*$/gm,
  SQL_COMMENT: /--.*$/gm,
  
  // String literals
  SINGLE_QUOTED_STRING: /'([^'\\]|\\.)*'/g,
  DOUBLE_QUOTED_STRING: /"([^"\\]|\\.)*"/g,
  TEMPLATE_LITERAL: /`([^`\\]|\\.)*`/g,
  
  // Common variable names that might contain secrets
  SECRET_VAR_NAMES: /\b(api[_-]?key|secret|password|token|auth|credential|private[_-]?key)\b/gi
} as const;

// ============================================================================
// Whitelist Patterns
// ============================================================================

/** Common patterns that should be whitelisted (not flagged as issues) */
export const WHITELIST_PATTERNS = [
  // Environment variable references
  'process.env.',
  'os.environ',
  '${',
  '$(',
  
  // Placeholder values
  'your-api-key-here',
  'your_api_key',
  'api-key-placeholder',
  'secret-placeholder',
  'password-placeholder',
  
  // Example/demo values
  'sk-example',
  'demo-key',
  'test-key',
  'sample-key',
  
  // Documentation patterns
  '[API_KEY]',
  '<API_KEY>',
  '{API_KEY}',
  'API_KEY_HERE'
] as const;
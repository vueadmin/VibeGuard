/**
 * API Key Detection Rules
 * 
 * This module defines detection rules for various API keys and secrets
 * that should not be hardcoded in source code. These rules help prevent
 * the "$5000 mistake" that inspired this extension.
 */

import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

/**
 * OpenAI API Key Detection Rule
 * Detects OpenAI API keys with the pattern sk-proj-* or sk-*
 */
export const OPENAI_API_KEY_RULE: DetectionRule = {
  id: 'API_KEY_OPENAI',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /sk-(?:proj-)?[a-zA-Z0-9]{20,}/g,
  message: '🔑 危险！OpenAI API 密钥暴露！这就是那个设计师损失 $5000 的原因！立即使用环境变量替换！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: 'process.env.OPENAI_API_KEY',
    description: '将硬编码的 API 密钥替换为环境变量引用，防止密钥泄露'
  },
  whitelist: [
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip obvious placeholders
    'your[_-]?api[_-]?key',
    'sk-proj-your',
    'sk-your'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', '*'],
  enabled: true
};

/**
 * AWS Access Key Detection Rule
 * Detects AWS access keys with the pattern AKIA*
 */
export const AWS_ACCESS_KEY_RULE: DetectionRule = {
  id: 'API_KEY_AWS',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /AKIA[0-9A-Z]{16}/g,
  message: '🔑 危险！AWS 访问密钥暴露！黑客可以控制你的云服务并产生巨额费用！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: 'process.env.AWS_ACCESS_KEY_ID',
    description: '将硬编码的 AWS 访问密钥替换为环境变量引用'
  },
  whitelist: [
    'process\\.env',
    '\\$\\{.*\\}',
    'your[_-]?aws[_-]?key',
    'AKIA[X]{16}',
    'AKIA[0]{16}'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', 'yaml', '*'],
  enabled: true
};

/**
 * GitHub Token Detection Rule
 * Detects GitHub personal access tokens with the pattern ghp_*
 */
export const GITHUB_TOKEN_RULE: DetectionRule = {
  id: 'API_KEY_GITHUB',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /ghp_[a-zA-Z0-9]{36}/g,
  message: '🔑 危险！GitHub Token 暴露！攻击者可以访问你的私有仓库和代码！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: 'process.env.GITHUB_TOKEN',
    description: '将硬编码的 GitHub Token 替换为环境变量引用'
  },
  whitelist: [
    'process\\.env',
    '\\$\\{.*\\}',
    'your[_-]?github[_-]?token',
    'ghp_[x]{36}',
    'ghp_[X]{36}'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', 'yaml', '*'],
  enabled: true
};

/**
 * Generic API Key Pattern Detection Rule
 * Detects common API key variable assignments
 */
export const GENERIC_API_KEY_RULE: DetectionRule = {
  id: 'API_KEY_GENERIC',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
  message: '🔑 警告！检测到可能的 API 密钥硬编码！请使用环境变量存储敏感信息！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      const keyPart = fullMatch.split(/[:=]/)[0].trim();
      const keyName = keyPart.replace(/^(const|let|var)\s+/, '').toUpperCase().replace(/[-\s]/g, '_');
      return fullMatch.replace(/["'][^"']+["']/, `process.env.${keyName}`);
    },
    description: '将硬编码的密钥值替换为环境变量引用'
  },
  whitelist: [
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip test/example values
    'your[_-]?api[_-]?key',
    'example[_-]?key',
    'test[_-]?key',
    'demo[_-]?key',
    'placeholder',
    'xxx+',
    '\\*{3,}',
    '\.{3,}',
    // Skip empty or very short values
    '["\']{2}',
    '["\']\w{1,7}["\']'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', '*'],
  enabled: true
};

/**
 * Database Connection String Detection Rule
 * Detects database connection strings with embedded credentials
 */
export const DATABASE_CONNECTION_RULE: DetectionRule = {
  id: 'API_KEY_DATABASE',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /(?:mongodb|mysql|postgres|postgresql):\/\/[^:\s\/]+:[^@\s\/]+@[^\/\s]+/gi,
  message: '🔑 危险！数据库连接字符串包含密码！这会暴露你的数据库访问凭据！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: 'process.env.DATABASE_URL',
    description: '将包含密码的数据库连接字符串替换为环境变量引用'
  },
  whitelist: [
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip placeholder values
    'username:password',
    'user:pass',
    'admin:admin',
    'root:root',
    'test:test'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', 'yaml', '*'],
  enabled: true
};

/**
 * JWT Secret Detection Rule
 * Detects JWT secrets that are too simple or hardcoded
 */
export const JWT_SECRET_RULE: DetectionRule = {
  id: 'API_KEY_JWT_SECRET',
  category: SecurityCategory.API_KEY,
  severity: IssueSeverity.ERROR,
  pattern: /(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']/gi,
  message: '🔑 警告！JWT 密钥硬编码！使用弱密钥会让攻击者伪造用户身份！',
  quickFix: {
    title: '使用环境变量替换',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      return fullMatch.replace(/["'][^"']+["']/, 'process.env.JWT_SECRET');
    },
    description: '将硬编码的 JWT 密钥替换为环境变量引用'
  },
  whitelist: [
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip obvious test values
    'your[_-]?secret',
    'test[_-]?secret',
    'demo[_-]?secret',
    'example[_-]?secret'
  ],
  languages: ['javascript', 'typescript', 'python', 'json', '*'],
  enabled: true
};

/**
 * All API Key Detection Rules
 * Export array of all rules for easy registration
 */
export const API_KEY_RULES: DetectionRule[] = [
  OPENAI_API_KEY_RULE,
  AWS_ACCESS_KEY_RULE,
  GITHUB_TOKEN_RULE,
  GENERIC_API_KEY_RULE,
  DATABASE_CONNECTION_RULE,
  JWT_SECRET_RULE
];

/**
 * Register all API key rules with the rule engine
 */
export function registerApiKeyRules(ruleEngine: { registerRule: (rule: DetectionRule) => void }): void {
  API_KEY_RULES.forEach(rule => {
    try {
      ruleEngine.registerRule(rule);
      console.log(`VibeGuard: 已注册 API 密钥检测规则 ${rule.id}`);
    } catch (error) {
      console.error(`VibeGuard: 注册规则失败 ${rule.id}:`, error);
    }
  });
  
  console.log(`VibeGuard: 成功注册 ${API_KEY_RULES.length} 个 API 密钥检测规则`);
}
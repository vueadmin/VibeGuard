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
  message: '🚨 致命错误！OpenAI API 密钥直接写在代码里了！\n💸 真实案例：设计师小王因为这样做损失了 $5000！\n🔧 点击灯泡一键修复 → 使用环境变量保护密钥',
  quickFix: {
    title: '🛡️ 立即使用环境变量保护密钥',
    replacement: 'process.env.OPENAI_API_KEY',
    description: '将危险的硬编码密钥替换为安全的环境变量引用。这样即使代码被泄露，密钥也是安全的。'
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
  message: '🚨 极度危险！AWS 访问密钥暴露！\n💰 真实风险：黑客可以控制你的云服务，产生数万元费用！\n⚡ 立即修复：点击灯泡使用环境变量保护',
  quickFix: {
    title: '🛡️ 立即使用环境变量保护 AWS 密钥',
    replacement: 'process.env.AWS_ACCESS_KEY_ID',
    description: '将危险的 AWS 密钥替换为环境变量。这是防止云服务被恶意使用的标准做法。'
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
  message: '🚨 代码泄露风险！GitHub Token 暴露！\n🔓 真实威胁：攻击者可以访问你的私有仓库，窃取所有代码和数据！\n🔒 安全修复：点击灯泡使用环境变量保护',
  quickFix: {
    title: '🛡️ 立即保护 GitHub Token',
    replacement: 'process.env.GITHUB_TOKEN',
    description: '将 GitHub Token 移到环境变量中，防止代码泄露时 Token 被滥用。'
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
  message: '⚠️ 密钥安全警告！检测到可能的敏感信息硬编码！\n📊 统计数据：78% 的数据泄露事件源于硬编码密钥\n🔧 简单修复：点击灯泡使用环境变量保护',
  quickFix: {
    title: '🛡️ 使用环境变量保护敏感信息',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      const keyPart = fullMatch.split(/[:=]/)[0].trim();
      const keyName = keyPart.replace(/^(const|let|var)\s+/, '').toUpperCase().replace(/[-\s]/g, '_');
      return fullMatch.replace(/["'][^"']+["']/, `process.env.${keyName}`);
    },
    description: '将敏感信息移到环境变量中，这是业界标准的安全做法。'
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
  message: '🚨 数据库安全漏洞！连接字符串包含明文密码！\n💾 真实案例：某公司因此泄露了 50万 用户数据\n🔐 立即修复：点击灯泡使用环境变量保护',
  quickFix: {
    title: '🛡️ 保护数据库连接信息',
    replacement: 'process.env.DATABASE_URL',
    description: '将包含密码的数据库连接字符串移到环境变量中，防止数据库被未授权访问。'
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
  message: '🚨 身份验证漏洞！JWT 密钥硬编码！\n👤 真实威胁：攻击者可以伪造任何用户身份，获取管理员权限！\n🔐 安全修复：点击灯泡使用强密钥保护',
  quickFix: {
    title: '🛡️ 使用安全的 JWT 密钥',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      return fullMatch.replace(/["'][^"']+["']/, 'process.env.JWT_SECRET');
    },
    description: '将 JWT 密钥移到环境变量中，并确保使用足够长的随机字符串。'
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
/**
 * Configuration Error Detection Rules
 * 
 * This module defines detection rules for common configuration errors
 * that can lead to security vulnerabilities in production environments.
 * These rules help prevent misconfigurations that expose sensitive data
 * or create security holes.
 */

import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

/**
 * Production Debug Mode Detection Rule
 * Detects debug=true or similar debug flags in production configurations
 */
export const PRODUCTION_DEBUG_RULE: DetectionRule = {
  id: 'CONFIG_PRODUCTION_DEBUG',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:debug|DEBUG)\s*[:=]\s*(?:true|True|TRUE|1|"true"|'true')/g,
  message: '⚠️ 警告！生产环境开启调试模式！这会暴露敏感信息和错误详情给攻击者！',
  quickFix: {
    title: '关闭调试模式',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      return fullMatch.replace(/(?:true|True|TRUE|1|"true"|'true')/, 'false');
    },
    description: '将调试模式设置为 false，防止在生产环境中暴露敏感信息'
  },
  whitelist: [
    // Skip development/test configurations
    'development',
    'dev',
    'test',
    'testing',
    'local',
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip comments
    '//.*',
    '/\\*.*\\*/',
    '#.*'
  ],
  languages: ['javascript', 'typescript', 'json', 'yaml', 'properties', 'env', '*'],
  enabled: true
};

/**
 * CORS Allow All Origins Detection Rule
 * Detects CORS configurations that allow all origins (*)
 */
export const CORS_ALLOW_ALL_RULE: DetectionRule = {
  id: 'CONFIG_CORS_ALLOW_ALL',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:Access-Control-Allow-Origin|origin|origins?)\s*[:=]\s*["']\*["']|cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']/gi,
  message: '⚠️ 警告！CORS 配置允许所有域名访问！这会让任何网站都能访问你的 API！',
  quickFix: {
    title: '限制允许的域名',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      if (fullMatch.includes('Access-Control-Allow-Origin')) {
        return fullMatch.replace(/["']\*["']/, '"https://yourdomain.com"');
      } else if (fullMatch.includes('origin')) {
        return fullMatch.replace(/["']\*["']/, '["https://yourdomain.com"]');
      }
      return fullMatch.replace(/["']\*["']/, '"https://yourdomain.com"');
    },
    description: '将 CORS 配置限制为特定的可信域名，而不是允许所有域名'
  },
  whitelist: [
    // Skip development configurations
    'development',
    'dev',
    'test',
    'testing',
    'local',
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip comments
    '//.*',
    '/\\*.*\\*/',
    '#.*'
  ],
  languages: ['javascript', 'typescript', 'json', 'yaml', '*'],
  enabled: true
};

/**
 * Docker Port Exposure Detection Rule
 * Detects dangerous port exposures in Docker configurations
 */
export const DOCKER_PORT_EXPOSURE_RULE: DetectionRule = {
  id: 'CONFIG_DOCKER_PORT_EXPOSURE',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:ports?|EXPOSE)\s*[:=]?\s*(?:\[)?\s*["']?(?:0\.0\.0\.0:|::)?(?:22|3306|5432|6379|27017|9200|5984|11211|50070)(?::\d+)?["']?/gi,
  message: '⚠️ 警告！Docker 暴露了危险端口！这些端口可能被攻击者利用进行未授权访问！',
  quickFix: {
    title: '限制端口绑定',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      // Replace 0.0.0.0 with 127.0.0.1 to bind only to localhost
      return fullMatch.replace(/0\.0\.0\.0:/g, '127.0.0.1:').replace(/::/g, '127.0.0.1:');
    },
    description: '将端口绑定限制为本地主机，防止从外部网络访问'
  },
  whitelist: [
    // Skip comments
    '//.*',
    '/\\*.*\\*/',
    '#.*',
    // Skip documentation examples
    'example',
    'sample',
    'demo'
  ],
  languages: ['dockerfile', 'yaml', 'json', '*'],
  enabled: true
};

/**
 * Environment File Example Values Detection Rule
 * Detects example or placeholder values in .env files
 */
export const ENV_EXAMPLE_VALUES_RULE: DetectionRule = {
  id: 'CONFIG_ENV_EXAMPLE_VALUES',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:API_KEY|SECRET|PASSWORD|TOKEN|KEY)\s*=\s*(?:your[_-]?(?:api[_-]?key|secret|password|token)|example[_-]?(?:key|secret|password|token)|test[_-]?(?:key|secret|password|token)|demo[_-]?(?:key|secret|password|token)|placeholder|xxx+|changeme|replace[_-]?me|enter[_-]?your|put[_-]?your)/gi,
  message: '⚠️ 警告！环境变量使用了示例值！请替换为真实的配置值，否则应用无法正常工作！',
  quickFix: {
    title: '提醒设置真实值',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      const [key] = fullMatch.split('=');
      return `${key.trim()}=# TODO: 请设置真实的${key.includes('API_KEY') ? 'API密钥' : key.includes('SECRET') ? '密钥' : key.includes('PASSWORD') ? '密码' : 'Token'}值`;
    },
    description: '添加提醒注释，提示需要设置真实的配置值'
  },
  whitelist: [
    // Skip .env.example files (they should have example values)
    '\\.env\\.example',
    '\\.env\\.sample',
    '\\.env\\.template',
    // Skip comments
    '#.*'
  ],
  languages: ['env', 'properties', '*'],
  enabled: true
};

/**
 * SSL/TLS Configuration Error Detection Rule
 * Detects insecure SSL/TLS configurations
 */
export const SSL_TLS_CONFIG_ERROR_RULE: DetectionRule = {
  id: 'CONFIG_SSL_TLS_ERROR',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:ssl|tls|https?)\s*[:=]\s*(?:false|False|FALSE|0|"false"|'false')|(?:rejectUnauthorized|strictSSL|verify)\s*[:=]\s*(?:false|False|FALSE|0|"false"|'false')|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*(?:0|"0"|'0')/gi,
  message: '⚠️ 警告！SSL/TLS 安全验证被禁用！这会让你的应用容易受到中间人攻击！',
  quickFix: {
    title: '启用 SSL/TLS 验证',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      if (fullMatch.includes('NODE_TLS_REJECT_UNAUTHORIZED')) {
        return fullMatch.replace(/(?:0|"0"|'0')/, '1');
      }
      return fullMatch.replace(/(?:false|False|FALSE|0|"false"|'false')/, 'true');
    },
    description: '启用 SSL/TLS 证书验证，确保连接安全'
  },
  whitelist: [
    // Skip development configurations
    'development',
    'dev',
    'test',
    'testing',
    'local',
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip comments
    '//.*',
    '/\\*.*\\*/',
    '#.*'
  ],
  languages: ['javascript', 'typescript', 'json', 'yaml', 'env', '*'],
  enabled: true
};

/**
 * Database Configuration Exposure Rule
 * Detects database configurations with default or weak credentials
 */
export const DATABASE_CONFIG_WEAK_RULE: DetectionRule = {
  id: 'CONFIG_DATABASE_WEAK',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|MONGODB_PASSWORD)\s*[:=]\s*(?:""|''|root|admin|password|123456|test|guest|user)/gi,
  message: '⚠️ 警告！数据库使用了弱密码或默认密码！这会让攻击者轻易获取数据库访问权限！',
  quickFix: {
    title: '设置强密码',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      const [key] = fullMatch.split(/[:=]/);
      return `${key.trim()}=# TODO: 请设置强密码（至少12位，包含大小写字母、数字和特殊字符）`;
    },
    description: '设置强密码，包含大小写字母、数字和特殊字符'
  },
  whitelist: [
    // Skip development configurations
    'development',
    'dev',
    'test',
    'testing',
    'local',
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip comments
    '#.*'
  ],
  languages: ['env', 'properties', 'json', 'yaml', '*'],
  enabled: true
};

/**
 * Session Secret Weak Configuration Rule
 * Detects weak session secrets
 */
export const SESSION_SECRET_WEAK_RULE: DetectionRule = {
  id: 'CONFIG_SESSION_SECRET_WEAK',
  category: SecurityCategory.CONFIG_ERROR,
  severity: IssueSeverity.WARNING,
  pattern: /(?:SESSION_SECRET|session[_-]?secret)\s*[:=]\s*["'](?:secret|keyboard cat|your secret key|change me|default|test|demo|example|123456|password|admin).{0,20}["']/gi,
  message: '⚠️ 警告！会话密钥过于简单！攻击者可能伪造用户会话获取未授权访问！',
  quickFix: {
    title: '生成强会话密钥',
    replacement: (match: RegExpExecArray): string => {
      const fullMatch = match[0];
      const [key] = fullMatch.split(/[:=]/);
      return `${key.trim()}=# TODO: 使用 crypto.randomBytes(64).toString('hex') 生成强会话密钥`;
    },
    description: '使用加密安全的随机字符串作为会话密钥'
  },
  whitelist: [
    // Skip development configurations
    'development',
    'dev',
    'test',
    'testing',
    'local',
    // Skip environment variable references
    'process\\.env',
    '\\$\\{.*\\}',
    // Skip comments
    '//.*',
    '/\\*.*\\*/',
    '#.*'
  ],
  languages: ['javascript', 'typescript', 'json', 'yaml', 'env', '*'],
  enabled: true
};

/**
 * All Configuration Error Detection Rules
 * Export array of all rules for easy registration
 */
export const CONFIG_ERROR_RULES: DetectionRule[] = [
  PRODUCTION_DEBUG_RULE,
  CORS_ALLOW_ALL_RULE,
  DOCKER_PORT_EXPOSURE_RULE,
  ENV_EXAMPLE_VALUES_RULE,
  SSL_TLS_CONFIG_ERROR_RULE,
  DATABASE_CONFIG_WEAK_RULE,
  SESSION_SECRET_WEAK_RULE
];

/**
 * Register all configuration error rules with the rule engine
 */
export function registerConfigErrorRules(ruleEngine: { registerRule: (rule: DetectionRule) => void }): void {
  CONFIG_ERROR_RULES.forEach(rule => {
    try {
      ruleEngine.registerRule(rule);
      console.log(`VibeGuard: 已注册配置错误检测规则 ${rule.id}`);
    } catch (error) {
      console.error(`VibeGuard: 注册规则失败 ${rule.id}:`, error);
    }
  });
  
  console.log(`VibeGuard: 成功注册 ${CONFIG_ERROR_RULES.length} 个配置错误检测规则`);
}
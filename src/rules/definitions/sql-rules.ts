/**
 * SQL Danger Detection Rules
 * 
 * This module defines detection rules for dangerous SQL operations
 * that could lead to data loss or security vulnerabilities.
 * These rules help prevent catastrophic database operations.
 */

import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

/**
 * DELETE FROM without WHERE clause detection rule
 * Detects DELETE statements that could delete all records from a table
 */
export const SQL_DELETE_NO_WHERE_RULE: DetectionRule = {
  id: 'SQL_DELETE_NO_WHERE',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.ERROR,
  pattern: /DELETE\s+FROM\s+\w+\s*(?:;|$)/gim,
  message: '💀 数据库灾难警告！DELETE 没有 WHERE 条件！\n📊 真实案例：产品经理小李因此删除了整个用户表，损失惨重！\n🛡️ 紧急修复：点击灯泡添加安全条件',
  quickFix: {
    title: '🚨 立即添加 WHERE 条件防止数据丢失',
    replacement: (match: RegExpExecArray): string => {
      const statement = match[0].trim();
      // Remove semicolon if present
      const cleanStatement = statement.replace(/;$/, '');
      return `${cleanStatement} WHERE id = ?; -- ⚠️ 请替换为具体的删除条件`;
    },
    description: '添加 WHERE 条件来精确指定要删除的数据，防止误删整个表。'
  },
  whitelist: [
    // Skip comments
    '--.*DELETE',
    '/\\*.*DELETE.*\\*/',
    '//.*DELETE',
    '#.*DELETE',
    // Skip obvious test/example patterns
    'DELETE\\s+FROM\\s+test',
    'DELETE\\s+FROM\\s+example',
    'DELETE\\s+FROM\\s+dummy'
  ],
  languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * UPDATE without WHERE clause detection rule
 * Detects UPDATE statements that could modify all records in a table
 */
export const SQL_UPDATE_NO_WHERE_RULE: DetectionRule = {
  id: 'SQL_UPDATE_NO_WHERE',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.ERROR,
  pattern: /UPDATE\s+\w+\s+SET\s+[^;WHERE]+(?:;|$)/gim,
  message: '💀 数据破坏警告！UPDATE 没有 WHERE 条件！\n📈 真实风险：会修改表中所有记录，可能破坏整个业务数据！\n🔧 立即修复：点击灯泡添加精确条件',
  quickFix: {
    title: '🚨 立即添加 WHERE 条件保护数据',
    replacement: (match: RegExpExecArray): string => {
      const statement = match[0].trim();
      // Remove semicolon if present
      const cleanStatement = statement.replace(/;$/, '');
      return `${cleanStatement} WHERE id = ?; -- ⚠️ 请替换为具体的更新条件`;
    },
    description: '添加 WHERE 条件来精确指定要更新的记录，防止误改所有数据。'
  },
  whitelist: [
    // Skip comments
    '--.*UPDATE',
    '/\\*.*UPDATE.*\\*/',
    '//.*UPDATE',
    '#.*UPDATE',
    // Skip test patterns
    'UPDATE\\s+test',
    'UPDATE\\s+example',
    'UPDATE\\s+dummy'
  ],
  languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * DROP TABLE detection rule
 * Detects DROP TABLE statements that could permanently delete table structure and data
 */
export const SQL_DROP_TABLE_RULE: DetectionRule = {
  id: 'SQL_DROP_TABLE',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.ERROR,
  pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?\w+/gim,
  message: '💀💀💀 毁灭性操作！DROP TABLE 会永久删除整个表！\n⚠️ 真实后果：表结构和所有数据将无法恢复！\n🛡️ 安全提醒：点击灯泡添加备份检查',
  quickFix: {
    title: '🚨 添加安全备份提醒',
    replacement: (match: RegExpExecArray): string => {
      const tableName = match[0].split(/\s+/).pop();
      return `-- ⚠️ 危险操作警告：这将永久删除表 ${tableName}！\n-- 🛡️ 安全检查：请确保已完成数据备份！\n-- 📋 备份命令：BACKUP TABLE ${tableName} TO 'backup_location';\n-- 🔓 确认无误后取消下面的注释：\n-- ${match[0]}`;
    },
    description: '将危险的 DROP TABLE 操作注释掉，并添加详细的安全检查提醒。'
  },
  whitelist: [
    // Skip comments
    '--.*DROP',
    '/\\*.*DROP.*\\*/',
    '//.*DROP',
    '#.*DROP',
    // Skip test/temp tables
    'DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?(?:test|temp|tmp|example|dummy)',
    // Skip migration patterns (common in frameworks)
    'DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?.*_temp',
    'DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?.*_backup'
  ],
  languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * DROP DATABASE detection rule
 * Detects DROP DATABASE statements that could permanently delete entire databases
 */
export const SQL_DROP_DATABASE_RULE: DetectionRule = {
  id: 'SQL_DROP_DATABASE',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.ERROR,
  pattern: /DROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?\w+/gim,
  message: '💀💀💀 终极毁灭操作！DROP DATABASE 会删除整个数据库！\n🔥 真实后果：所有表、数据、用户、权限将全部消失！\n🛡️ 紧急制动：点击灯泡添加多重安全检查',
  quickFix: {
    title: '🚨 添加多重安全检查和备份提醒',
    replacement: (match: RegExpExecArray): string => {
      const dbName = match[0].split(/\s+/).pop();
      return `-- 🚨🚨🚨 终极危险操作警告 🚨🚨🚨\n-- 这将删除整个数据库 ${dbName} 及其所有内容！\n-- \n-- ✅ 安全检查清单：\n-- [ ] 已完成完整数据库备份\n-- [ ] 已通知相关团队成员\n-- [ ] 已确认这是必要操作\n-- [ ] 已准备好恢复计划\n-- \n-- 🔓 确认所有检查项后，取消下面的注释：\n-- ${match[0]}`;
    },
    description: '将极度危险的 DROP DATABASE 操作注释掉，并添加详细的安全检查清单。'
  },
  whitelist: [
    // Skip comments
    '--.*DROP',
    '/\\*.*DROP.*\\*/',
    '//.*DROP',
    '#.*DROP',
    // Skip test databases
    'DROP\\s+(?:DATABASE|SCHEMA)\\s+(?:IF\\s+EXISTS\\s+)?(?:test|temp|tmp|example|dummy)'
  ],
  languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * TRUNCATE TABLE detection rule
 * Detects TRUNCATE statements that quickly delete all data from a table
 */
export const SQL_TRUNCATE_TABLE_RULE: DetectionRule = {
  id: 'SQL_TRUNCATE_TABLE',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.ERROR,
  pattern: /TRUNCATE\s+(?:TABLE\s+)?\w+/gim,
  message: '💀 危险操作！TRUNCATE 会快速删除表中的所有数据且无法回滚！比 DELETE 更危险！',
  quickFix: {
    title: '使用可回滚的 DELETE',
    replacement: (match: RegExpExecArray): string => {
      const tableName = match[0].split(/\s+/).pop();
      return `-- 建议使用可回滚的 DELETE 替代 TRUNCATE\nDELETE FROM ${tableName};\n-- 原始语句（已注释）: -- ${match[0]}`;
    },
    description: '将 TRUNCATE 替换为可回滚的 DELETE 语句'
  },
  whitelist: [
    // Skip comments
    '--.*TRUNCATE',
    '/\\*.*TRUNCATE.*\\*/',
    '//.*TRUNCATE',
    '#.*TRUNCATE',
    // Skip test/temp tables
    'TRUNCATE\\s+(?:TABLE\\s+)?(?:test|temp|tmp|example|dummy)'
  ],
  languages: ['sql', 'javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * SQL Injection via string concatenation detection rule
 * Detects potential SQL injection vulnerabilities in dynamic query construction
 */
export const SQL_INJECTION_CONCAT_RULE: DetectionRule = {
  id: 'SQL_INJECTION_CONCAT',
  category: SecurityCategory.SQL_DANGER,
  severity: IssueSeverity.WARNING,
  pattern: /(?:SELECT|INSERT|UPDATE|DELETE).*\+.*(?:input|param|request|user|form)/gim,
  message: '⚠️ SQL 注入风险！直接拼接用户输入到 SQL 语句中可能导致数据库被攻击！',
  quickFix: {
    title: '使用参数化查询',
    replacement: (match: RegExpExecArray): string => {
      return `-- 使用参数化查询防止 SQL 注入\n-- 示例：db.query('SELECT * FROM users WHERE id = ?', [userId])\n${match[0]}`;
    },
    description: '提醒使用参数化查询或预处理语句来防止 SQL 注入'
  },
  whitelist: [
    // Skip comments
    '--.*(?:SELECT|INSERT|UPDATE|DELETE)',
    '/\\*.*(?:SELECT|INSERT|UPDATE|DELETE).*\\*/',
    '//.*(?:SELECT|INSERT|UPDATE|DELETE)',
    '#.*(?:SELECT|INSERT|UPDATE|DELETE)',
    // Skip logging/debugging contexts
    'console\\.log',
    'print',
    'echo',
    'log'
  ],
  languages: ['javascript', 'typescript', 'python', 'php', 'java', 'csharp', '*'],
  enabled: true
};

/**
 * All SQL Danger Detection Rules
 * Export array of all rules for easy registration
 */
export const SQL_DANGER_RULES: DetectionRule[] = [
  SQL_DELETE_NO_WHERE_RULE,
  SQL_UPDATE_NO_WHERE_RULE,
  SQL_DROP_TABLE_RULE,
  SQL_DROP_DATABASE_RULE,
  SQL_TRUNCATE_TABLE_RULE,
  SQL_INJECTION_CONCAT_RULE
];

/**
 * Register all SQL danger rules with the rule engine
 */
export function registerSqlDangerRules(ruleEngine: { registerRule: (rule: DetectionRule) => void }): void {
  SQL_DANGER_RULES.forEach(rule => {
    try {
      ruleEngine.registerRule(rule);
      console.log(`VibeGuard: 已注册 SQL 危险操作检测规则 ${rule.id}`);
    } catch (error) {
      console.error(`VibeGuard: 注册规则失败 ${rule.id}:`, error);
    }
  });
  
  console.log(`VibeGuard: 成功注册 ${SQL_DANGER_RULES.length} 个 SQL 危险操作检测规则`);
}
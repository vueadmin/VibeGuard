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
  message: '💀 致命错误！DELETE 没有 WHERE 条件会删除整个表的所有数据！这可能导致数据永久丢失！',
  quickFix: {
    title: '添加 WHERE 条件',
    replacement: (match: RegExpExecArray): string => {
      const statement = match[0].trim();
      // Remove semicolon if present
      const cleanStatement = statement.replace(/;$/, '');
      return `${cleanStatement} WHERE id = ?;`;
    },
    description: '添加 WHERE 条件来限制删除范围，防止意外删除所有数据'
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
  message: '💀 致命错误！UPDATE 没有 WHERE 条件会修改表中的所有记录！这可能破坏整个数据集！',
  quickFix: {
    title: '添加 WHERE 条件',
    replacement: (match: RegExpExecArray): string => {
      const statement = match[0].trim();
      // Remove semicolon if present
      const cleanStatement = statement.replace(/;$/, '');
      return `${cleanStatement} WHERE id = ?;`;
    },
    description: '添加 WHERE 条件来限制更新范围，防止意外修改所有记录'
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
  message: '💀 极度危险！DROP TABLE 会永久删除整个表和所有数据！请确认这是你真正想要的操作！',
  quickFix: {
    title: '添加备份提醒',
    replacement: (match: RegExpExecArray): string => {
      return `-- 警告：请先备份数据！\n-- BACKUP TABLE ${match[0].split(/\s+/).pop()} TO 'backup_location';\n${match[0]}`;
    },
    description: '在 DROP TABLE 前添加备份提醒注释'
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
  message: '💀💀💀 毁灭性操作！DROP DATABASE 会删除整个数据库！这是不可逆的灾难性操作！',
  quickFix: {
    title: '添加安全检查',
    replacement: (match: RegExpExecArray): string => {
      return `-- 危险操作警告：这将删除整个数据库！\n-- 请确保已经完成完整备份！\n-- 取消注释下面的行来执行：\n-- ${match[0]}`;
    },
    description: '将 DROP DATABASE 语句注释掉并添加安全警告'
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
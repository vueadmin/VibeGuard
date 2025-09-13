import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { DetectionRule, IssueSeverity, SecurityCategory } from '../../types';

suite('RuleEngine Tests', () => {
  let ruleEngine: RuleEngine;

  setup(() => {
    ruleEngine = new RuleEngine();
  });

  teardown(() => {
    ruleEngine.clearRules();
  });

  test('should create RuleEngine instance', () => {
    assert.ok(ruleEngine);
  });

  test('should register a valid rule', () => {
    const rule: DetectionRule = {
      id: 'TEST_RULE',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /test-pattern/g,
      message: '测试规则',
      languages: ['javascript'],
      enabled: true
    };

    ruleEngine.registerRule(rule);
    const retrievedRule = ruleEngine.getRule('TEST_RULE');
    assert.ok(retrievedRule);
    assert.strictEqual(retrievedRule.id, 'TEST_RULE');
  });

  test('should execute rules and find issues', () => {
    const rule: DetectionRule = {
      id: 'API_KEY_TEST',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /sk-[a-zA-Z0-9]{48}/g,
      message: '🔑 危险！API 密钥暴露！',
      languages: ['javascript'],
      enabled: true
    };
    ruleEngine.registerRule(rule);

    const code = 'const apiKey = "sk-test1234567890abcdef1234567890abcdef1234567890abcdef";';
    const issues = ruleEngine.executeRules(code, 'javascript');

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].code, 'API_KEY_TEST');
    assert.strictEqual(issues[0].severity, IssueSeverity.ERROR);
  });

  test('should respect whitelist patterns', () => {
    const rule: DetectionRule = {
      id: 'API_KEY_WITH_WHITELIST',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /sk-[a-zA-Z0-9]{48}/g,
      message: '🔑 API 密钥暴露！',
      whitelist: ['process\\.env'],
      languages: ['javascript'],
      enabled: true
    };
    ruleEngine.registerRule(rule);

    // Should ignore environment variable references
    const envCode = 'const apiKey = process.env.OPENAI_API_KEY;';
    const envIssues = ruleEngine.executeRules(envCode, 'javascript');
    assert.strictEqual(envIssues.length, 0);

    // Should detect hardcoded keys
    const hardcodedCode = 'const apiKey = "sk-test1234567890abcdef1234567890abcdef1234567890abcdef";';
    const hardcodedIssues = ruleEngine.executeRules(hardcodedCode, 'javascript');
    assert.strictEqual(hardcodedIssues.length, 1);
  });

  test('should generate quick fixes', () => {
    const rule: DetectionRule = {
      id: 'API_KEY_WITH_FIX',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /sk-[a-zA-Z0-9]{48}/g,
      message: '🔑 API 密钥暴露！',
      quickFix: {
        title: '使用环境变量',
        replacement: 'process.env.OPENAI_API_KEY',
        description: '将硬编码密钥替换为环境变量'
      },
      languages: ['javascript'],
      enabled: true
    };
    ruleEngine.registerRule(rule);

    const code = 'const apiKey = "sk-test1234567890abcdef1234567890abcdef1234567890abcdef";';
    const issues = ruleEngine.executeRules(code, 'javascript');

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].quickFix);
    assert.strictEqual(issues[0].quickFix!.title, '使用环境变量');
    assert.strictEqual(issues[0].quickFix!.replacement, 'process.env.OPENAI_API_KEY');
  });

  test('should manage rules by category', () => {
    const apiRule: DetectionRule = {
      id: 'API_RULE',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /api/g,
      message: 'API规则',
      languages: ['javascript'],
      enabled: true
    };

    const sqlRule: DetectionRule = {
      id: 'SQL_RULE',
      category: SecurityCategory.SQL_DANGER,
      severity: IssueSeverity.WARNING,
      pattern: /sql/g,
      message: 'SQL规则',
      languages: ['sql'],
      enabled: false
    };

    ruleEngine.registerRule(apiRule);
    ruleEngine.registerRule(sqlRule);

    const apiRules = ruleEngine.getRulesByCategory(SecurityCategory.API_KEY);
    const sqlRules = ruleEngine.getRulesByCategory(SecurityCategory.SQL_DANGER);

    assert.strictEqual(apiRules.length, 1);
    assert.strictEqual(apiRules[0].id, 'API_RULE');
    assert.strictEqual(sqlRules.length, 1);
    assert.strictEqual(sqlRules[0].id, 'SQL_RULE');

    // Test enabled rules
    const enabledRules = ruleEngine.getEnabledRules();
    assert.strictEqual(enabledRules.length, 1);
    assert.strictEqual(enabledRules[0].id, 'API_RULE');
  });

  test('should handle built-in whitelist patterns', () => {
    const freshRuleEngine = new RuleEngine();
    const rule: DetectionRule = {
      id: 'BUILTIN_WHITELIST_TEST',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      pattern: /secret/g,
      message: '密钥检测',
      languages: ['javascript'],
      enabled: true
    };
    freshRuleEngine.registerRule(rule);

    // Should ignore placeholders
    const placeholderCases = [
      'const secret = "your_api_key";',
      'const secret = "example_key";',
      'const secret = "placeholder";',
      'const secret = "xxxxxxxxxx";'
    ];

    placeholderCases.forEach(code => {
      const issues = freshRuleEngine.executeRules(code, 'javascript');
      assert.strictEqual(issues.length, 0, `Should ignore: ${code}`);
    });

    // Should detect real secrets
    const realSecret = 'const secret = "real_value";';
    const realIssues = freshRuleEngine.executeRules(realSecret, 'javascript');
    assert.strictEqual(realIssues.length, 1);
  });
});
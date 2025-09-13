/**
 * Whitelist Mechanism Tests
 * 
 * Comprehensive tests for the enhanced whitelist filtering functionality
 * to ensure accurate detection while minimizing false positives.
 */

import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { DetectionRule, SecurityCategory, IssueSeverity } from '../../types';

suite('Enhanced Whitelist Mechanism', () => {
  let ruleEngine: RuleEngine;

  // Test rule for API key detection
  const testApiKeyRule: DetectionRule = {
    id: 'TEST_API_KEY',
    category: SecurityCategory.API_KEY,
    severity: IssueSeverity.ERROR,
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    message: 'Test API key detected',
    languages: ['javascript', 'typescript', '*'],
    enabled: true
  };

  // Test rule for SQL danger detection
  const testSqlRule: DetectionRule = {
    id: 'TEST_SQL_DANGER',
    category: SecurityCategory.SQL_DANGER,
    severity: IssueSeverity.ERROR,
    pattern: /DELETE\s+FROM\s+\w+\s*(?:;|$)/gim,
    message: 'Dangerous SQL detected',
    languages: ['sql', 'javascript', '*'],
    enabled: true
  };

  // Test rule for code injection detection
  const testCodeInjectionRule: DetectionRule = {
    id: 'TEST_CODE_INJECTION',
    category: SecurityCategory.CODE_INJECTION,
    severity: IssueSeverity.ERROR,
    pattern: /eval\s*\(/gi,
    message: 'Dangerous eval detected',
    languages: ['javascript', 'typescript', '*'],
    enabled: true
  };

  setup(() => {
    ruleEngine = new RuleEngine();
    ruleEngine.registerRule(testApiKeyRule);
    ruleEngine.registerRule(testSqlRule);
    ruleEngine.registerRule(testCodeInjectionRule);
  });

  suite('Environment Variable Reference Detection', () => {
    test('should ignore process.env access', () => {
      const code = 'const apiKey = process.env.OPENAI_API_KEY;';
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.strictEqual(issues.length, 0, 'Should not detect environment variable access');
    });

    test('should detect hardcoded fallback in process.env', () => {
      const code = 'const apiKey = process.env.API_KEY || "sk-fallbackkey12345678901234567890";';
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.ok(issues.length > 0, 'Should detect hardcoded fallback key');
    });

    test('should ignore shell variable patterns', () => {
      const testCases = [
        'export API_KEY=${OPENAI_API_KEY}',
        'curl -H "Authorization: Bearer $API_TOKEN"',
        '$apiKey = $env:OPENAI_API_KEY',
        'api_key = os.environ["OPENAI_API_KEY"]',
        'api_key = os.getenv("OPENAI_API_KEY")',
        'const key = config.apiKey;',
        'ENV API_KEY=$(API_KEY_SECRET)',
        'run: echo ${{ secrets.OPENAI_API_KEY }}',
        'api_key = var.openai_api_key',
        'ApiKey: !Ref OpenAIApiKey'
      ];

      testCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore environment variable pattern: ${code}`);
      });
    });
  });

  suite('Comment Content Filtering', () => {
    test('should ignore various comment styles', () => {
      const commentCases = [
        '// Example API key: sk-projtest1234567890abcdef1234567890abcdef12345678',
        '# API key example: sk-projtest1234567890abcdef1234567890abcdef12345678',
        '-- DELETE FROM users; -- This would be dangerous',
        '<!-- API key: sk-projtest1234567890abcdef1234567890abcdef12345678 -->',
        '/* API key for testing: sk-projtest1234567890abcdef1234567890abcdef12345678 */',
        '/** @example const key = "sk-projtest1234567890abcdef1234567890abcdef12345678"; */',
        '```javascript\nconst key = "sk-projtest1234567890abcdef1234567890abcdef12345678";\n```',
        '// @ts-ignore: sk-projtest1234567890abcdef1234567890abcdef12345678'
      ];

      commentCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore comment: ${code.substring(0, 50)}...`);
      });
    });

    test('should detect real code after comments', () => {
      const code = `// This is an example: sk-projtest1234567890abcdef1234567890abcdef12345678
const realKey = "sk-projtest9876543210fedcba9876543210fedcba87654321";`;
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.ok(issues.length > 0, 'Should detect real key after comment');
      assert.strictEqual(issues[0].location.line, 1, 'Should detect on the correct line');
    });

    test('should detect actual code with ESLint comments', () => {
      const code = '// eslint-disable-next-line\nconst key = "sk-projtest1234567890abcdef1234567890abcdef12345678";';
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.ok(issues.length > 0, 'Should detect actual key despite ESLint comment');
    });
  });

  suite('Template String Variable Detection', () => {
    test('should ignore template literals with variables', () => {
      const templateCases = [
        'const url = `https://api.openai.com/v1/chat/completions?key=${apiKey}`;',
        'const auth = `Bearer ${process.env.API_KEY}`;',
        'const auth = `Bearer ${config.apiKey}`;',
        'url = f"https://api.openai.com/v1/chat/completions?key={api_key}"',
        'url = "https://api.openai.com/v1/chat/completions?key={}".format(api_key)',
        'url = "https://api.openai.com/v1/chat/completions?key=%s" % api_key',
        'url = "https://api.openai.com/v1/chat/completions?key=#{api_key}"',
        'var url = $"https://api.openai.com/v1/chat/completions?key={apiKey}";'
      ];

      templateCases.forEach(code => {
        const language = code.includes('f"') || code.includes('.format(') ? 'python' :
          code.includes('#{') ? 'ruby' :
            code.includes('$"') ? 'csharp' :
              'javascript';

        const issues = ruleEngine.executeRules(code, language);
        assert.strictEqual(issues.length, 0, `Should ignore template with variable: ${code.substring(0, 50)}...`);
      });
    });

    test('should detect hardcoded keys in templates', () => {
      const code = 'const auth = `Bearer sk-projtest1234567890abcdef1234567890abcdef12345678`;';
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.ok(issues.length > 0, 'Should detect hardcoded key even in template');
    });

    test('should handle code injection context correctly', () => {
      // Safe template with variable should be whitelisted for non-injection rules
      const safeTemplate = 'eval(`console.log("${userInput}")`);';
      const apiKeyIssues = ruleEngine.executeRules(safeTemplate, 'javascript');
      // Should not detect API key issues in safe template
      const apiKeyDetections = apiKeyIssues.filter(issue => issue.code === 'TEST_API_KEY');
      assert.strictEqual(apiKeyDetections.length, 0, 'Should not detect API key in safe template');

      // Should still detect dangerous eval usage
      const dangerousEval = 'eval("console.log(\\"hardcoded\\")");';
      const evalIssues = ruleEngine.executeRules(dangerousEval, 'javascript');
      const evalDetections = evalIssues.filter(issue => issue.code === 'TEST_CODE_INJECTION');
      assert.ok(evalDetections.length > 0, 'Should detect dangerous eval usage');
    });
  });

  suite('Placeholder Value Detection', () => {
    test('should ignore obvious placeholders', () => {
      const placeholderCases = [
        'const key = "your-api-key";',
        'const key = "example-api-key";',
        'const key = "test-api-key";',
        'const key = "demo-api-key";',
        'const key = "placeholder";',
        'const key = "replace-me";',
        'const key = "TODO: add real key";',
        'const key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";',
        'const key = "sk-******************************************";',
        'const key = "sk-..........................................";',
        'const key = "sk-0000000000000000000000000000000000000000";',
        'const key = "sk-1111111111111111111111111111111111111111";',
        'const key = "sk-test1234567890abcdef1234567890abcdef12345678";',
        'const key = "[your-api-key]";',
        'const key = "<your-api-key>";',
        'const key = "{your-api-key}";',
        'const url = "https://api.example.com/key=sk-test1234567890abcdef1234567890abcdef12345678";',
        'const url = "http://localhost:3000/api?key=sk-test1234567890abcdef1234567890abcdef12345678";',
        'const key = "";',
        'const key = "abc";'
      ];

      placeholderCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore placeholder: ${code.substring(0, 50)}...`);
      });
    });

    test('should detect real-looking keys', () => {
      const realKeyCases = [
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";',
        'const key = "AKIATEST567890123456";'
      ];

      realKeyCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.ok(issues.length > 0, `Should detect real-looking key: ${code.substring(0, 50)}...`);
      });
    });

    test('should detect repeated character patterns', () => {
      const repeatedKeys = [
        'sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // Low diversity
        'sk-abababababababababababababababababababab', // Repetitive pattern
        'sk-1234567890123456789012345678901234567890', // Sequential numbers
        'sk-abcdefghijklmnopqrstuvwxyzabcdefghijklmn'  // High diversity - should detect
      ];

      repeatedKeys.forEach((key, index) => {
        const code = `const apiKey = "${key}";`;
        const issues = ruleEngine.executeRules(code, 'javascript');

        if (index === repeatedKeys.length - 1) {
          assert.ok(issues.length > 0, 'Should detect high diversity key');
        } else {
          assert.strictEqual(issues.length, 0, `Should ignore low diversity key: ${key.substring(0, 20)}...`);
        }
      });
    });
  });

  suite('File Context Based Filtering', () => {
    test('should reduce severity for test files', () => {
      const testFilePaths = [
        'src/test/api.test.js',
        'src/tests/integration.spec.ts',
        'test/unit/auth_test.py',
        '__tests__/components/Button.test.tsx',
        'cypress/integration/login.e2e.js'
      ];

      testFilePaths.forEach(filePath => {
        // Use a realistic key that won't be filtered as placeholder
        const code = 'const apiKey = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";';
        const issues = ruleEngine.executeRules(code, 'javascript', filePath);

        assert.strictEqual(issues.length, 1, `Should detect issue in test file: ${filePath}`);
        assert.strictEqual(issues[0].severity, IssueSeverity.WARNING, 'Should reduce severity to WARNING');
        assert.ok(issues[0].message.includes('测试文件中发现问题'), 'Should indicate test file context');
      });
    });

    test('should whitelist obvious test values in test files', () => {
      const testCodes = [
        'const testKey = "sk-testtest1234567890abcdef1234567890abcdef12345678";',
        'const mockApiKey = "sk-mocktest1234567890abcdef1234567890abcdef12345678";',
        'const fakeKey = "sk-faketest1234567890abcdef1234567890abcdef12345678";',
        'const key = "sk-short";' // Less than 20 chars
      ];

      testCodes.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript', 'src/test/api.test.js');
        assert.strictEqual(issues.length, 0, `Should whitelist test value: ${code.substring(0, 30)}...`);
      });
    });

    test('should be very lenient with documentation files', () => {
      const docFilePaths = ['README.md', 'docs/api.md', 'swagger.yaml'];

      docFilePaths.forEach(filePath => {
        // Use a realistic key that won't be filtered as placeholder
        const code = 'const apiKey = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";';
        const issues = ruleEngine.executeRules(code, 'javascript', filePath);

        assert.strictEqual(issues.length, 1, `Should detect issue in doc file: ${filePath}`);
        assert.strictEqual(issues[0].severity, IssueSeverity.INFO, 'Should reduce severity to INFO');
        assert.ok(issues[0].message.includes('文档文件中发现问题'), 'Should indicate doc file context');
      });

      // Should whitelist SQL patterns in documentation
      const sqlCode = 'DELETE FROM users;';
      const sqlIssues = ruleEngine.executeRules(sqlCode, 'sql', 'docs/database.md');
      assert.strictEqual(sqlIssues.length, 0, 'Should whitelist SQL in documentation');

      // Should whitelist keys with doc indicators
      const docIndicatorCodes = [
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"; // example key',
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"; // your key here',
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"; // TODO: update'
      ];

      docIndicatorCodes.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript', 'README.md');
        assert.strictEqual(issues.length, 0, `Should whitelist doc indicator: ${code.substring(0, 50)}...`);
      });
    });

    test('should be very lenient with example files', () => {
      const exampleFilePaths = [
        'examples/basic-usage.js',
        'demo/simple.js',
        'samples/integration.ts',
        'tutorials/step1.js',
        'templates/starter.ts'
      ];

      exampleFilePaths.forEach(filePath => {
        // Even realistic keys should be whitelisted in example files
        const code = 'const apiKey = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";';
        const issues = ruleEngine.executeRules(code, 'javascript', filePath);
        assert.strictEqual(issues.length, 0, `Should whitelist completely in example file: ${filePath}`);
      });

      // Should whitelist SQL patterns in example files
      const sqlCode = 'DELETE FROM users;';
      const sqlIssues = ruleEngine.executeRules(sqlCode, 'sql', 'examples/database.js');
      assert.strictEqual(sqlIssues.length, 0, 'Should whitelist SQL in example files');
    });

    test('should handle template values in config files', () => {
      const configFilePaths = ['package.json', '.env.example', 'docker-compose.yml'];

      const templateCodes = [
        'const key = "${API_KEY}";',
        'const key = "{{API_KEY}}";',
        'const key = "[your-api-key]";',
        'const key = "replace-me";'
      ];

      configFilePaths.forEach(filePath => {
        templateCodes.forEach(code => {
          const issues = ruleEngine.executeRules(code, 'javascript', filePath);
          assert.strictEqual(issues.length, 0, `Should whitelist template in config: ${filePath}`);
        });
      });

      // Should reduce severity for real keys in config files
      const realKeyCode = 'const apiKey = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";';
      const issues = ruleEngine.executeRules(realKeyCode, 'javascript', 'package.json');
      assert.strictEqual(issues.length, 1, 'Should detect real key in config');
      assert.strictEqual(issues[0].severity, IssueSeverity.WARNING, 'Should reduce severity');
      assert.ok(issues[0].message.includes('配置文件中发现问题'), 'Should indicate config file context');
    });
  });

  suite('Edge Cases and Complex Scenarios', () => {
    test('should handle mixed content correctly', () => {
      const code = `
        // This is an example key: sk-exampletest1234567890abcdef1234567890abcdef12345678
        const configKey = process.env.API_KEY;
        const templateUrl = \`https://api.openai.com/v1/chat?key=\${apiKey}\`;
        const realKey = "sk-projtest9876543210fedcba9876543210fedcba87654321"; // This should be detected
        const placeholderKey = "your-api-key-here";
      `;

      const issues = ruleEngine.executeRules(code, 'javascript');

      // Should only detect the real key
      assert.strictEqual(issues.length, 1, 'Should detect only the real key');
      assert.strictEqual(issues[0].location.line, 4, 'Should detect on the correct line');
    });

    test('should handle multiline template strings', () => {
      const code = `
        const query = \`
          DELETE FROM users
          WHERE created_at < '2023-01-01'
        \`;
      `;

      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.strictEqual(issues.length, 0, 'Template string with WHERE clause should be safe');
    });

    test('should handle nested template strings', () => {
      const code = `const auth = \`Bearer \${config.getKey() || process.env.FALLBACK_KEY}\`;`;
      const issues = ruleEngine.executeRules(code, 'javascript');
      assert.strictEqual(issues.length, 0, 'Complex template with safe patterns should be ignored');
    });

    test('should handle language-specific patterns', () => {
      const languageTests = [
        {
          language: 'python',
          code: 'api_key = os.environ.get("OPENAI_API_KEY", "sk-defaulttest1234567890abcdef1234567890abcdef12345678")',
          shouldDetect: true
        },
        {
          language: 'ruby',
          code: 'api_key = ENV["OPENAI_API_KEY"] || "sk-defaulttest1234567890abcdef1234567890abcdef12345678"',
          shouldDetect: true
        }
      ];

      languageTests.forEach(test => {
        const issues = ruleEngine.executeRules(test.code, test.language);

        if (test.shouldDetect) {
          assert.ok(issues.length > 0, `Should detect fallback key in ${test.language}`);
        } else {
          assert.strictEqual(issues.length, 0, `Should not detect in ${test.language}`);
        }
      });
    });

    test('should adjust confidence and tags based on file context', () => {
      // Test file should have lower confidence
      const testFileIssues = ruleEngine.executeRules(
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";',
        'javascript',
        'src/test/api.test.js'
      );

      assert.strictEqual(testFileIssues.length, 1, 'Should detect issue in test file');
      assert.ok(testFileIssues[0].metadata.confidence < 0.9, 'Should have lower confidence in test file');
      assert.ok(testFileIssues[0].metadata.tags.includes('test-file'), 'Should include test-file tag');

      // Documentation file should have much lower confidence
      const docFileIssues = ruleEngine.executeRules(
        'const key = "sk-projtest1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z";',
        'javascript',
        'README.md'
      );

      assert.strictEqual(docFileIssues.length, 1, 'Should detect issue in doc file');
      assert.ok(docFileIssues[0].metadata.confidence < 0.5, 'Should have much lower confidence in doc file');
      assert.ok(docFileIssues[0].metadata.tags.includes('documentation'), 'Should include documentation tag');
    });
  });

  suite('Performance and Boundary Tests', () => {
    test('should handle very long files efficiently', () => {
      const longCode = Array(1000).fill('const validVar = process.env.API_KEY;').join('\n');
      const startTime = Date.now();

      const issues = ruleEngine.executeRules(longCode, 'javascript');
      const duration = Date.now() - startTime;

      assert.strictEqual(issues.length, 0, 'All should be whitelisted');
      assert.ok(duration < 1000, 'Should complete within 1 second');
    });

    test('should handle files with many potential matches', () => {
      const codeWithManyMatches = Array(100).fill(0).map((_, i) =>
        `const key${i} = "sk-example${i.toString().padStart(40, '0')}";`
      ).join('\n');

      const issues = ruleEngine.executeRules(codeWithManyMatches, 'javascript');
      assert.strictEqual(issues.length, 0, 'All should be whitelisted as examples');
    });

    test('should handle malformed regex patterns gracefully', () => {
      // This tests the error handling in whitelist pattern processing
      const ruleWithBadWhitelist: DetectionRule = {
        id: 'TEST_BAD_WHITELIST',
        category: SecurityCategory.API_KEY,
        severity: IssueSeverity.ERROR,
        pattern: /sk-[a-zA-Z0-9]{20,}/g,
        message: 'Test rule with bad whitelist',
        whitelist: ['[invalid regex pattern'], // Invalid regex
        languages: ['javascript'],
        enabled: true
      };

      const testEngine = new RuleEngine();
      testEngine.registerRule(ruleWithBadWhitelist);

      // Should not crash, should handle gracefully
      const issues = testEngine.executeRules('const key = "sk-testtest1234567890abcdef1234567890abcdef12345678";', 'javascript');
      assert.strictEqual(issues.length, 1, 'Should still detect since whitelist failed');
    });
  });
});
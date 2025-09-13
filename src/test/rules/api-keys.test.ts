/**
 * API Key Detection Rules Tests
 * 
 * Comprehensive test suite for API key detection rules based on real-world
 * AI-generated code scenarios. These tests ensure the rules can detect
 * dangerous hardcoded secrets while avoiding false positives.
 */

import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { 
  API_KEY_RULES, 
  registerApiKeyRules,
  OPENAI_API_KEY_RULE,
  AWS_ACCESS_KEY_RULE,
  GITHUB_TOKEN_RULE,
  GENERIC_API_KEY_RULE,
  DATABASE_CONNECTION_RULE,
  JWT_SECRET_RULE
} from '../../rules/definitions/api-keys';
import { DetectionRule, IssueSeverity, SecurityCategory } from '../../types';

suite('API Key Detection Rules Tests', () => {
  let ruleEngine: RuleEngine;

  setup(() => {
    ruleEngine = new RuleEngine();
    registerApiKeyRules(ruleEngine);
  });

  teardown(() => {
    ruleEngine.clearRules();
  });

  suite('OpenAI API Key Detection', () => {
    test('should detect OpenAI API keys with sk- prefix', () => {
      const testCases = [
        {
          name: 'Classic OpenAI key',
          code: 'const apiKey = "sk-test1234567890abcdef1234567890abcdef1234567890abcdef";',
          shouldDetect: true
        },
        {
          name: 'New project-based OpenAI key',
          code: 'const apiKey = "sk-proj-test1234567890abcdef1234567890abcdef12345678";',
          shouldDetect: true
        },
        {
          name: 'OpenAI key in object',
          code: 'const config = { apiKey: "sk-test1234567890abcdef1234567890abcdef1234567890abcdef" };',
          shouldDetect: true
        },
        {
          name: 'OpenAI key in function call',
          code: 'openai.configure("sk-test1234567890abcdef1234567890abcdef1234567890abcdef");',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const openaiIssues = issues.filter(issue => issue.code === 'API_KEY_OPENAI');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(openaiIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(openaiIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(openaiIssues[0].message.includes('OpenAI'));
          assert.ok(openaiIssues[0].message.includes('$5000'));
        } else {
          assert.strictEqual(openaiIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for OpenAI keys', () => {
      const code = 'const apiKey = "sk-test1234567890abcdef1234567890abcdef1234567890abcdef";';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const openaiIssue = issues.find(issue => issue.code === 'API_KEY_OPENAI');

      assert.ok(openaiIssue);
      assert.ok(openaiIssue.quickFix);
      assert.strictEqual(openaiIssue.quickFix.replacement, 'process.env.OPENAI_API_KEY');
      assert.ok(openaiIssue.quickFix.title.includes('环境变量'));
    });

    test('should ignore whitelisted OpenAI patterns', () => {
      const whitelistedCases = [
        'const apiKey = process.env.OPENAI_API_KEY;',
        'const apiKey = ${OPENAI_API_KEY};',
        '// Example: sk-proj-your-key-here',
        'const placeholder = "sk-your-api-key-here";',
        'const example = "sk-proj-your-key";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const openaiIssues = issues.filter(issue => issue.code === 'API_KEY_OPENAI');
        assert.strictEqual(openaiIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('AWS Access Key Detection', () => {
    test('should detect AWS access keys', () => {
      const testCases = [
        {
          name: 'Standard AWS access key',
          code: 'const accessKey = "AKIATEST567890123456";',
          shouldDetect: true
        },
        {
          name: 'AWS key in config object',
          code: 'const awsConfig = { accessKeyId: "AKIATEST44QH8DHBEXAMPLE" };',
          shouldDetect: true
        },
        {
          name: 'AWS key in environment file',
          code: 'AWS_ACCESS_KEY_ID=AKIATEST567890123456',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const awsIssues = issues.filter(issue => issue.code === 'API_KEY_AWS');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(awsIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(awsIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(awsIssues[0].message.includes('AWS'));
          assert.ok(awsIssues[0].message.includes('云服务'));
        } else {
          assert.strictEqual(awsIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should ignore whitelisted AWS patterns', () => {
      const whitelistedCases = [
        'const accessKey = process.env.AWS_ACCESS_KEY_ID;',
        'const accessKey = "${AWS_ACCESS_KEY_ID}";',
        'const placeholder = "AKIAXXXXXXXXXXXXXXXX";',
        'const example = "AKIA0000000000000000";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const awsIssues = issues.filter(issue => issue.code === 'API_KEY_AWS');
        assert.strictEqual(awsIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('GitHub Token Detection', () => {
    test('should detect GitHub personal access tokens', () => {
      const testCases = [
        {
          name: 'GitHub personal access token',
          code: 'const token = "ghp_test567890abcdef1234567890abcdef123456";',
          shouldDetect: true
        },
        {
          name: 'GitHub token in headers',
          code: 'headers: { Authorization: "token ghp_test567890abcdef1234567890abcdef123456" }',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const githubIssues = issues.filter(issue => issue.code === 'API_KEY_GITHUB');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(githubIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(githubIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(githubIssues[0].message.includes('GitHub'));
          assert.ok(githubIssues[0].message.includes('私有仓库'));
        } else {
          assert.strictEqual(githubIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should ignore whitelisted GitHub patterns', () => {
      const whitelistedCases = [
        'const token = process.env.GITHUB_TOKEN;',
        'const token = "${GITHUB_TOKEN}";',
        'const placeholder = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";',
        'const example = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const githubIssues = issues.filter(issue => issue.code === 'API_KEY_GITHUB');
        assert.strictEqual(githubIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('Generic API Key Detection', () => {
    test('should detect generic API key patterns', () => {
      const testCases = [
        {
          name: 'API key assignment',
          code: 'api_key = "abcd1234567890efgh"',
          shouldDetect: true
        },
        {
          name: 'Secret assignment',
          code: 'secret = "my-secret-value-123"',
          shouldDetect: true
        },
        {
          name: 'Password assignment',
          code: 'password = "super-secret-password"',
          shouldDetect: true
        },
        {
          name: 'Token assignment',
          code: 'token = "bearer-token-12345"',
          shouldDetect: true
        },
        {
          name: 'API key with colon',
          code: 'apiKey: "real-api-key-value"',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const genericIssues = issues.filter(issue => issue.code === 'API_KEY_GENERIC');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(genericIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(genericIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(genericIssues[0].message.includes('API 密钥'));
        } else {
          assert.strictEqual(genericIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide dynamic quick fix for generic keys', () => {
      const code = 'api_key = "real-secret-value"';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const genericIssue = issues.find(issue => issue.code === 'API_KEY_GENERIC');

      assert.ok(genericIssue);
      assert.ok(genericIssue.quickFix);
      assert.ok(genericIssue.quickFix.replacement.includes('process.env'));
    });

    test('should ignore whitelisted generic patterns', () => {
      const whitelistedCases = [
        'const api_key = process.env.API_KEY;',
        'const secret = "${SECRET_VALUE}";',
        'const api_key = "your_api_key";',
        'const secret = "example_key";',
        'const password = "test_key";',
        'const token = "demo_key";',
        'const api_key = "placeholder";',
        'const secret = "xxxxxxxxxx";',
        'const password = "***";',
        'const token = "...";',
        'const api_key = "";',
        'const secret = "short";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const genericIssues = issues.filter(issue => issue.code === 'API_KEY_GENERIC');
        assert.strictEqual(genericIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('Database Connection String Detection', () => {
    test('should detect database connection strings with credentials', () => {
      const testCases = [
        {
          name: 'MongoDB connection string',
          code: 'dbUrl = "mongodb://user:password@localhost:27017/mydb"',
          shouldDetect: true
        },
        {
          name: 'MySQL connection string',
          code: 'dbUrl = "mysql://admin:secret123@db.example.com:3306/production"',
          shouldDetect: true
        },
        {
          name: 'PostgreSQL connection string',
          code: 'dbUrl = "postgresql://dbuser:dbpass@localhost/testdb"',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const dbIssues = issues.filter(issue => issue.code === 'API_KEY_DATABASE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(dbIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(dbIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(dbIssues[0].message.includes('数据库'));
        } else {
          assert.strictEqual(dbIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should ignore whitelisted database patterns', () => {
      const whitelistedCases = [
        'const dbUrl = process.env.DATABASE_URL;',
        'const dbUrl = "${DATABASE_URL}";',
        'const dbUrl = "mongodb://username:password@localhost/test";',
        'const dbUrl = "mysql://user:pass@localhost/db";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const dbIssues = issues.filter(issue => issue.code === 'API_KEY_DATABASE');
        assert.strictEqual(dbIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('JWT Secret Detection', () => {
    test('should detect JWT secrets', () => {
      const testCases = [
        {
          name: 'JWT secret assignment',
          code: 'jwt_secret = "my-super-secret-jwt-key"',
          shouldDetect: true
        },
        {
          name: 'Secret key assignment',
          code: 'secret_key = "jwt-signing-secret-123"',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const jwtIssues = issues.filter(issue => issue.code === 'API_KEY_JWT_SECRET');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(jwtIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(jwtIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(jwtIssues[0].message.includes('JWT'));
        } else {
          assert.strictEqual(jwtIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should ignore whitelisted JWT patterns', () => {
      const whitelistedCases = [
        'const jwt_secret = process.env.JWT_SECRET;',
        'const secret_key = "${JWT_SECRET}";',
        'const jwt_secret = "your_secret";',
        'const secret_key = "test_secret";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const jwtIssues = issues.filter(issue => issue.code === 'API_KEY_JWT_SECRET');
        assert.strictEqual(jwtIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('Real-World AI Generated Code Scenarios', () => {
    test('should detect issues in ChatGPT generated OpenAI integration', () => {
      const chatgptCode = `
        import OpenAI from 'openai';
        
        const openai = new OpenAI({
          apiKey: 'sk-proj-test1234567890abcdef1234567890abcdef12345678'
        });
        
        async function generateText(prompt) {
          const response = await openai.chat.completions.create({
            model: 'gpt-3.5-turbo',
            messages: [{ role: 'user', content: prompt }]
          });
          return response.choices[0].message.content;
        }
      `;

      const issues = ruleEngine.executeRules(chatgptCode, 'javascript');
      const openaiIssues = issues.filter(issue => issue.code === 'API_KEY_OPENAI');
      
      assert.strictEqual(openaiIssues.length, 1);
      assert.ok(openaiIssues[0].message.includes('$5000'));
    });

    test('should detect issues in Claude generated AWS SDK code', () => {
      const claudeCode = `
        import AWS from 'aws-sdk';
        
        const s3 = new AWS.S3({
          accessKeyId: 'AKIATEST567890123456',
          secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          region: 'us-west-2'
        });
        
        async function uploadFile(bucket, key, body) {
          return s3.upload({ Bucket: bucket, Key: key, Body: body }).promise();
        }
      `;

      const issues = ruleEngine.executeRules(claudeCode, 'javascript');
      const awsIssues = issues.filter(issue => issue.code === 'API_KEY_AWS');
      
      assert.strictEqual(awsIssues.length, 1);
      assert.ok(awsIssues[0].message.includes('AWS'));
    });

    test('should detect issues in GitHub API integration code', () => {
      const githubCode = `
        const { Octokit } = require('@octokit/rest');
        
        const octokit = new Octokit({
          auth: 'ghp_test567890abcdef1234567890abcdef123456'
        });
        
        async function getRepos() {
          const { data } = await octokit.rest.repos.listForAuthenticatedUser();
          return data;
        }
      `;

      const issues = ruleEngine.executeRules(githubCode, 'javascript');
      const githubIssues = issues.filter(issue => issue.code === 'API_KEY_GITHUB');
      
      assert.strictEqual(githubIssues.length, 1);
      assert.ok(githubIssues[0].message.includes('GitHub'));
    });

    test('should detect issues in database connection code', () => {
      const dbCode = `
        const mongoose = require('mongoose');
        
        // Connect to MongoDB
        mongoose.connect('mongodb://admin:secretpassword@cluster.mongodb.net/production');
        
        const User = mongoose.model('User', {
          name: String,
          email: String
        });
      `;

      const issues = ruleEngine.executeRules(dbCode, 'javascript');
      const dbIssues = issues.filter(issue => issue.code === 'API_KEY_DATABASE');
      
      assert.strictEqual(dbIssues.length, 1);
      assert.ok(dbIssues[0].message.includes('数据库'));
    });

    test('should detect issues in JWT authentication code', () => {
      const jwtCode = `
        const jwt = require('jsonwebtoken');
        
        const JWT_SECRET = 'my-super-secret-jwt-signing-key-123';
        
        function generateToken(payload) {
          return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
        }
        
        function verifyToken(token) {
          return jwt.verify(token, JWT_SECRET);
        }
      `;

      const issues = ruleEngine.executeRules(jwtCode, 'javascript');
      const jwtIssues = issues.filter(issue => issue.code === 'API_KEY_JWT_SECRET');
      
      assert.strictEqual(jwtIssues.length, 1);
      assert.ok(jwtIssues[0].message.includes('JWT'));
    });

    test('should handle mixed scenarios with multiple issues', () => {
      const mixedCode = `
        // Multiple API keys in one file
        openai = 'sk-proj-test1234567890abcdef1234567890abcdef12345678'
        accessKeyId = 'AKIATEST567890123456'
        github = 'ghp_test567890abcdef1234567890abcdef123456'
        database = 'mongodb://user:pass@localhost/db'
        jwt_secret = 'super-secret-jwt-key'
      `;

      const issues = ruleEngine.executeRules(mixedCode, 'javascript');
      
      // Should detect multiple different types of issues
      const openaiIssues = issues.filter(issue => issue.code === 'API_KEY_OPENAI');
      const awsIssues = issues.filter(issue => issue.code === 'API_KEY_AWS');
      const githubIssues = issues.filter(issue => issue.code === 'API_KEY_GITHUB');
      const dbIssues = issues.filter(issue => issue.code === 'API_KEY_DATABASE');
      const jwtIssues = issues.filter(issue => issue.code === 'API_KEY_JWT_SECRET');
      
      assert.strictEqual(openaiIssues.length, 1);
      assert.strictEqual(awsIssues.length, 1);
      assert.strictEqual(githubIssues.length, 1);
      assert.strictEqual(dbIssues.length, 1);
      assert.strictEqual(jwtIssues.length, 1);
      
      // All should be errors
      issues.forEach(issue => {
        assert.strictEqual(issue.severity, IssueSeverity.ERROR);
        assert.ok(issue.quickFix);
      });
    });
  });

  suite('Whitelist and False Positive Prevention', () => {
    test('should ignore environment variable references', () => {
      const envCases = [
        'const apiKey = process.env.OPENAI_API_KEY;',
        'const secret = process.env.SECRET_KEY;',
        'const token = process.env.GITHUB_TOKEN;',
        'const dbUrl = process.env.DATABASE_URL;'
      ];

      envCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore env var: ${code}`);
      });
    });

    test('should ignore template string variables', () => {
      const templateCases = [
        'const apiKey = `${process.env.API_KEY}`;',
        'const secret = "${SECRET_VALUE}";',
        'const token = `Bearer ${authToken}`;'
      ];

      templateCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore template: ${code}`);
      });
    });

    test('should ignore comments and documentation', () => {
      const commentCases = [
        '// Example: sk-proj-your-api-key-here',
        '/* API Key: sk-test1234567890abcdef1234567890abcdef1234567890abcdef */',
        '* @param apiKey - Your OpenAI API key (sk-...)',
        '# Set your API key: export OPENAI_API_KEY=sk-...'
      ];

      commentCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore comment: ${code}`);
      });
    });

    test('should ignore obvious placeholders', () => {
      const placeholderCases = [
        'const apiKey = "your_api_key";',
        'const secret = "example_key";',
        'const token = "placeholder";',
        'const key = "xxxxxxxxxx";',
        'const secret = "***";',
        'const token = "...";',
        'const apiKey = "sk-your-key-here";',
        'const awsKey = "AKIAXXXXXXXXXXXXXXXX";',
        'const githubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";'
      ];

      placeholderCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore placeholder: ${code}`);
      });
    });

    test('should ignore test and demo values', () => {
      const testCases = [
        'const apiKey = "test_key";',
        'const secret = "demo_secret";',
        'const token = "example_token";',
        'const dbUrl = "mongodb://username:password@localhost/test";'
      ];

      testCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore test value: ${code}`);
      });
    });
  });

  suite('Quick Fix Generation', () => {
    test('should generate appropriate quick fixes for all rule types', () => {
      const testCases = [
        {
          code: 'const apiKey = "sk-proj-1234567890abcdef1234567890abcdef12345678";',
          expectedReplacement: 'process.env.OPENAI_API_KEY'
        },
        {
          code: 'const accessKey = "AKIATEST567890123456";',
          expectedReplacement: 'process.env.AWS_ACCESS_KEY_ID'
        },
        {
          code: 'const token = "ghp_test567890abcdef1234567890abcdef123456";',
          expectedReplacement: 'process.env.GITHUB_TOKEN'
        },
        {
          code: 'dbUrl = "mongodb://user:pass@localhost/db"',
          expectedReplacement: 'process.env.DATABASE_URL'
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        assert.ok(issues.length > 0, `Should detect issue in: ${testCase.code}`);
        
        const issue = issues[0];
        assert.ok(issue.quickFix, 'Should have quick fix');
        assert.strictEqual(issue.quickFix.replacement, testCase.expectedReplacement);
        assert.ok(issue.quickFix.title.includes('环境变量'));
      });
    });

    test('should generate dynamic quick fixes for generic patterns', () => {
      const code = 'my_api_key = "secret-value-123"';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const genericIssue = issues.find(issue => issue.code === 'API_KEY_GENERIC');

      assert.ok(genericIssue);
      assert.ok(genericIssue.quickFix);
      assert.ok(genericIssue.quickFix.replacement.includes('process.env'));
      assert.ok(genericIssue.quickFix.replacement.includes('MY_API_KEY'));
    });
  });

  suite('Rule Registration and Management', () => {
    test('should register all API key rules successfully', () => {
      const freshEngine = new RuleEngine();
      registerApiKeyRules(freshEngine);

      const stats = freshEngine.getStatistics();
      assert.strictEqual(stats.totalRules, API_KEY_RULES.length);
      assert.strictEqual(stats.enabledRules, API_KEY_RULES.length);
      
      // Check that all rules are in the API_KEY category
      assert.strictEqual(stats.rulesByCategory[SecurityCategory.API_KEY], API_KEY_RULES.length);
    });

    test('should handle rule registration errors gracefully', () => {
      const mockEngine = {
        registerRule: (rule: DetectionRule) => {
          if (rule.id === 'API_KEY_OPENAI') {
            throw new Error('Mock registration error');
          }
        }
      };

      // Should not throw, but log error
      assert.doesNotThrow(() => {
        registerApiKeyRules(mockEngine);
      });
    });

    test('should retrieve rules by category', () => {
      const apiKeyRules = ruleEngine.getRulesByCategory(SecurityCategory.API_KEY);
      assert.strictEqual(apiKeyRules.length, API_KEY_RULES.length);
      
      apiKeyRules.forEach(rule => {
        assert.strictEqual(rule.category, SecurityCategory.API_KEY);
        assert.strictEqual(rule.enabled, true);
      });
    });
  });

  suite('Multi-language Support', () => {
    test('should detect API keys in different programming languages', () => {
      const languageTests = [
        {
          language: 'python',
          code: 'api_key = "sk-proj-1234567890abcdef1234567890abcdef12345678"'
        },
        {
          language: 'json',
          code: '{"apiKey": "sk-proj-1234567890abcdef1234567890abcdef12345678"}'
        },
        {
          language: 'yaml',
          code: 'api_key: sk-proj-1234567890abcdef1234567890abcdef12345678'
        }
      ];

      languageTests.forEach(test => {
        const issues = ruleEngine.executeRules(test.code, test.language);
        const openaiIssues = issues.filter(issue => issue.code === 'API_KEY_OPENAI');
        assert.strictEqual(openaiIssues.length, 1, `Should detect in ${test.language}`);
      });
    });
  });
});
/**
 * Regression Test Suite
 * 
 * Tests to prevent functionality degradation and ensure consistent behavior
 * across updates. These tests validate that fixes don't break existing features
 * and that the extension maintains its core functionality over time.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { activate, getExtensionServices } from '../../extension';
import { SecurityCategory, IssueSeverity } from '../../types';

suite('Real-World Scenarios - Regression Tests', () => {
  let context: vscode.ExtensionContext;

  suiteSetup(async () => {
    // Create mock extension context
    context = {
      subscriptions: [],
      workspaceState: { get: () => undefined, update: () => Promise.resolve(), keys: () => [] },
      globalState: { 
        get: (key: string, defaultValue?: any) => {
          if (key === 'vibeguard.firstActivation') return false;
          return defaultValue;
        }, 
        update: () => Promise.resolve(), 
        keys: () => [], 
        setKeysForSync: () => {} 
      },
      extensionUri: vscode.Uri.file(__dirname),
      extensionPath: __dirname,
      asAbsolutePath: (relativePath: string) => relativePath,
      storagePath: undefined,
      globalStoragePath: __dirname,
      logPath: __dirname,
      extensionMode: vscode.ExtensionMode.Test,
      secrets: {
        get: () => Promise.resolve(undefined),
        store: () => Promise.resolve(),
        delete: () => Promise.resolve(),
        onDidChange: new vscode.EventEmitter().event
      },
      environmentVariableCollection: {
        persistent: false,
        replace: () => {}, append: () => {}, prepend: () => {},
        get: () => undefined, forEach: () => {}, delete: () => {}, clear: () => {},
        [Symbol.iterator]: function* () {}
      },
      logUri: vscode.Uri.file(__dirname + '/test.log'),
      storageUri: undefined,
      globalStorageUri: vscode.Uri.file(__dirname),
      extension: {} as any,
      languageModelAccessInformation: {} as any
    } as unknown as vscode.ExtensionContext;

    await activate(context);
  });

  /**
   * Test Case 1: Core API Key Detection Regression
   * Ensures that basic API key detection continues to work correctly
   */
  test('Core API Key Detection Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Known patterns that should always be detected
    const knownVulnerabilities = [
      {
        name: 'OpenAI API Key',
        code: 'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";',
        expectedCategory: SecurityCategory.API_KEY,
        expectedSeverity: IssueSeverity.ERROR,
        shouldDetect: true
      },
      {
        name: 'AWS Access Key',
        code: 'const awsKey = "AKIA_EXAMPLE_NOT_REAL_AWS_KEY";',
        expectedCategory: SecurityCategory.API_KEY,
        expectedSeverity: IssueSeverity.ERROR,
        shouldDetect: true
      },
      {
        name: 'GitHub Token',
        code: 'const githubToken = "ghp_EXAMPLE_NOT_REAL_GITHUB_TOKEN_12345";',
        expectedCategory: SecurityCategory.API_KEY,
        expectedSeverity: IssueSeverity.ERROR,
        shouldDetect: true
      },
      {
        name: 'Generic API Key',
        code: 'const config = { apiKey: "your-api-key-here" };',
        expectedCategory: SecurityCategory.API_KEY,
        expectedSeverity: IssueSeverity.ERROR,
        shouldDetect: true
      },
      {
        name: 'Database Password',
        code: 'const dbUrl = "mongodb://user:password123@localhost/db";',
        expectedCategory: SecurityCategory.API_KEY,
        expectedSeverity: IssueSeverity.ERROR,
        shouldDetect: true
      }
    ];

    // Known safe patterns that should NOT be detected
    const safePatterns = [
      {
        name: 'Environment Variable',
        code: 'const apiKey = process.env.OPENAI_API_KEY;',
        shouldDetect: false
      },
      {
        name: 'Comment Example',
        code: '// Example: sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345',
        shouldDetect: false
      },
      {
        name: 'Template String Variable',
        code: 'const url = `https://api.com?key=${apiKey}`;',
        shouldDetect: false
      },
      {
        name: 'Placeholder Text',
        code: 'const placeholder = "YOUR_API_KEY_HERE";',
        shouldDetect: false
      }
    ];

    console.log('Testing known vulnerabilities...');
    for (const vulnerability of knownVulnerabilities) {
      const document = await vscode.workspace.openTextDocument({
        content: vulnerability.code,
        language: 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      if (vulnerability.shouldDetect) {
        const relevantIssues = issues.filter(issue => 
          issue.category === vulnerability.expectedCategory &&
          issue.severity === vulnerability.expectedSeverity
        );
        
        assert.ok(relevantIssues.length > 0, 
          `${vulnerability.name}: Should detect vulnerability in "${vulnerability.code}"`);
        
        console.log(`✓ ${vulnerability.name}: Detected ${relevantIssues.length} issues`);
      } else {
        assert.strictEqual(issues.length, 0, 
          `${vulnerability.name}: Should not detect issues in "${vulnerability.code}"`);
        
        console.log(`✓ ${vulnerability.name}: Correctly ignored`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Testing safe patterns...');
    for (const safePattern of safePatterns) {
      const document = await vscode.workspace.openTextDocument({
        content: safePattern.code,
        language: 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      assert.strictEqual(issues.length, 0, 
        `${safePattern.name}: Should not detect issues in safe pattern "${safePattern.code}"`);
      
      console.log(`✓ ${safePattern.name}: Correctly ignored`);

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Core API key detection regression test passed');
  });

  /**
   * Test Case 2: SQL Danger Detection Regression
   * Ensures SQL danger detection remains accurate
   */
  test('SQL Danger Detection Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const sqlTestCases = [
      {
        name: 'DELETE without WHERE',
        code: 'const query = "DELETE FROM users";',
        shouldDetect: true,
        expectedCategory: SecurityCategory.SQL_DANGER
      },
      {
        name: 'UPDATE without WHERE',
        code: 'const query = "UPDATE products SET price = 0";',
        shouldDetect: true,
        expectedCategory: SecurityCategory.SQL_DANGER
      },
      {
        name: 'DROP TABLE',
        code: 'const query = "DROP TABLE sessions";',
        shouldDetect: true,
        expectedCategory: SecurityCategory.SQL_DANGER
      },
      {
        name: 'TRUNCATE TABLE',
        code: 'const query = "TRUNCATE TABLE logs";',
        shouldDetect: true,
        expectedCategory: SecurityCategory.SQL_DANGER
      },
      {
        name: 'Safe DELETE with WHERE',
        code: 'const query = "DELETE FROM users WHERE id = ?";',
        shouldDetect: false
      },
      {
        name: 'Safe UPDATE with WHERE',
        code: 'const query = "UPDATE products SET price = ? WHERE id = ?";',
        shouldDetect: false
      },
      {
        name: 'Safe SELECT',
        code: 'const query = "SELECT * FROM users WHERE active = true";',
        shouldDetect: false
      }
    ];

    for (const testCase of sqlTestCases) {
      const document = await vscode.workspace.openTextDocument({
        content: testCase.code,
        language: 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      if (testCase.shouldDetect) {
        const sqlIssues = issues.filter(issue => issue.category === testCase.expectedCategory);
        assert.ok(sqlIssues.length > 0, 
          `${testCase.name}: Should detect SQL danger in "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Detected ${sqlIssues.length} SQL issues`);
      } else {
        const sqlIssues = issues.filter(issue => issue.category === SecurityCategory.SQL_DANGER);
        assert.strictEqual(sqlIssues.length, 0, 
          `${testCase.name}: Should not detect SQL danger in safe query "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Correctly ignored safe SQL`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('SQL danger detection regression test passed');
  });

  /**
   * Test Case 3: Code Injection Detection Regression
   * Ensures code injection detection remains effective
   */
  test('Code Injection Detection Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const codeInjectionTestCases = [
      {
        name: 'eval() usage',
        code: 'const result = eval(userInput);',
        shouldDetect: true,
        expectedCategory: SecurityCategory.CODE_INJECTION
      },
      {
        name: 'innerHTML assignment',
        code: 'element.innerHTML = userContent;',
        shouldDetect: true,
        expectedCategory: SecurityCategory.CODE_INJECTION
      },
      {
        name: 'child_process.exec',
        code: 'require("child_process").exec(command);',
        shouldDetect: true,
        expectedCategory: SecurityCategory.CODE_INJECTION
      },
      {
        name: 'document.write',
        code: 'document.write(content);',
        shouldDetect: true,
        expectedCategory: SecurityCategory.CODE_INJECTION
      },
      {
        name: 'Safe textContent',
        code: 'element.textContent = userContent;',
        shouldDetect: false
      },
      {
        name: 'Safe JSON.parse',
        code: 'const data = JSON.parse(jsonString);',
        shouldDetect: false
      }
    ];

    for (const testCase of codeInjectionTestCases) {
      const document = await vscode.workspace.openTextDocument({
        content: testCase.code,
        language: 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      if (testCase.shouldDetect) {
        const codeInjectionIssues = issues.filter(issue => issue.category === testCase.expectedCategory);
        assert.ok(codeInjectionIssues.length > 0, 
          `${testCase.name}: Should detect code injection in "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Detected ${codeInjectionIssues.length} code injection issues`);
      } else {
        const codeInjectionIssues = issues.filter(issue => issue.category === SecurityCategory.CODE_INJECTION);
        assert.strictEqual(codeInjectionIssues.length, 0, 
          `${testCase.name}: Should not detect code injection in safe code "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Correctly ignored safe code`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Code injection detection regression test passed');
  });

  /**
   * Test Case 4: Framework Risk Detection Regression
   * Ensures React/Vue specific detection continues to work
   */
  test('Framework Risk Detection Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const frameworkTestCases = [
      {
        name: 'React dangerouslySetInnerHTML',
        code: '<div dangerouslySetInnerHTML={{ __html: userContent }} />',
        language: 'typescriptreact',
        shouldDetect: true,
        expectedCategory: SecurityCategory.FRAMEWORK_RISK
      },
      {
        name: 'Vue v-html directive',
        code: '<div v-html="userContent"></div>',
        language: 'vue',
        shouldDetect: true,
        expectedCategory: SecurityCategory.FRAMEWORK_RISK
      },
      {
        name: 'React useEffect without dependencies',
        code: 'useEffect(() => { fetchData(); });',
        language: 'typescriptreact',
        shouldDetect: true,
        expectedCategory: SecurityCategory.FRAMEWORK_RISK
      },
      {
        name: 'Safe React component',
        code: '<div>{userContent}</div>',
        language: 'typescriptreact',
        shouldDetect: false
      },
      {
        name: 'Safe useEffect with dependencies',
        code: 'useEffect(() => { fetchData(); }, [userId]);',
        language: 'typescriptreact',
        shouldDetect: false
      }
    ];

    for (const testCase of frameworkTestCases) {
      const document = await vscode.workspace.openTextDocument({
        content: testCase.code,
        language: testCase.language
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      if (testCase.shouldDetect) {
        const frameworkIssues = issues.filter(issue => issue.category === testCase.expectedCategory);
        assert.ok(frameworkIssues.length > 0, 
          `${testCase.name}: Should detect framework risk in "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Detected ${frameworkIssues.length} framework issues`);
      } else {
        const frameworkIssues = issues.filter(issue => issue.category === SecurityCategory.FRAMEWORK_RISK);
        assert.strictEqual(frameworkIssues.length, 0, 
          `${testCase.name}: Should not detect framework risk in safe code "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Correctly ignored safe framework code`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Framework risk detection regression test passed');
  });

  /**
   * Test Case 5: Quick Fix Functionality Regression
   * Ensures quick fixes continue to work correctly
   */
  test('Quick Fix Functionality Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const quickFixTestCases = [
      {
        name: 'API Key Quick Fix',
        code: 'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";',
        expectedQuickFix: true,
        expectedFixTitle: '环境变量'
      },
      {
        name: 'SQL DELETE Quick Fix',
        code: 'const query = "DELETE FROM users";',
        expectedQuickFix: true,
        expectedFixTitle: 'WHERE'
      },
      {
        name: 'Generic Secret Quick Fix',
        code: 'const secret = "hardcoded-secret-key";',
        expectedQuickFix: true,
        expectedFixTitle: '环境变量'
      }
    ];

    for (const testCase of quickFixTestCases) {
      const document = await vscode.workspace.openTextDocument({
        content: testCase.code,
        language: 'javascript'
      });

      // Analyze and create diagnostics
      const issues = await services.analysisEngine.analyzeDocument(document);
      services.diagnosticManager.updateDiagnostics(document, issues);
      
      const diagnostics = vscode.languages.getDiagnostics(document.uri);
      
      if (testCase.expectedQuickFix && diagnostics.length > 0) {
        const firstDiagnostic = diagnostics[0];
        const context: vscode.CodeActionContext = {
          diagnostics: [firstDiagnostic],
          only: undefined,
          triggerKind: vscode.CodeActionTriggerKind.Automatic
        };

        const codeActions = await services.quickFixProvider.provideCodeActions(
          document, firstDiagnostic.range, context, new vscode.CancellationTokenSource().token
        );

        assert.ok(codeActions && codeActions.length > 0, 
          `${testCase.name}: Should provide quick fix for "${testCase.code}"`);
        
        const hasExpectedFix = codeActions.some(action => 
          action.title.includes(testCase.expectedFixTitle)
        );
        
        assert.ok(hasExpectedFix, 
          `${testCase.name}: Should provide quick fix containing "${testCase.expectedFixTitle}"`);
        
        console.log(`✓ ${testCase.name}: Quick fix available - "${codeActions[0].title}"`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Quick fix functionality regression test passed');
  });

  /**
   * Test Case 6: Whitelist Functionality Regression
   * Ensures whitelist filtering continues to work correctly
   */
  test('Whitelist Functionality Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const whitelistTestCases = [
      {
        name: 'Environment Variable Reference',
        code: 'const apiKey = process.env.OPENAI_API_KEY;',
        shouldBeWhitelisted: true
      },
      {
        name: 'Config Object Environment Variable',
        code: 'const config = { apiKey: process.env.API_KEY };',
        shouldBeWhitelisted: true
      },
      {
        name: 'Template String with Environment Variable',
        code: 'const url = `https://api.com?key=${process.env.API_KEY}`;',
        shouldBeWhitelisted: true
      },
      {
        name: 'Comment with API Key Example',
        code: '// Example API key: sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345',
        shouldBeWhitelisted: true
      },
      {
        name: 'Multiline Comment with API Key',
        code: '/* API Key: sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345 */',
        shouldBeWhitelisted: true
      },
      {
        name: 'Hardcoded API Key (should NOT be whitelisted)',
        code: 'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";',
        shouldBeWhitelisted: false
      }
    ];

    for (const testCase of whitelistTestCases) {
      const document = await vscode.workspace.openTextDocument({
        content: testCase.code,
        language: 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      
      if (testCase.shouldBeWhitelisted) {
        assert.strictEqual(issues.length, 0, 
          `${testCase.name}: Should be whitelisted and not detect issues in "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Correctly whitelisted`);
      } else {
        assert.ok(issues.length > 0, 
          `${testCase.name}: Should NOT be whitelisted and should detect issues in "${testCase.code}"`);
        console.log(`✓ ${testCase.name}: Correctly detected (not whitelisted)`);
      }

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Whitelist functionality regression test passed');
  });

  /**
   * Test Case 7: Extension Activation Regression
   * Ensures the extension activates correctly and all services are initialized
   */
  test('Extension Activation Regression', async () => {
    // Test extension services are properly initialized
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available after activation');
    
    // Test all core services are present
    assert.ok(services.ruleEngine, 'Rule engine should be initialized');
    assert.ok(services.analysisEngine, 'Analysis engine should be initialized');
    assert.ok(services.documentMonitor, 'Document monitor should be initialized');
    assert.ok(services.diagnosticManager, 'Diagnostic manager should be initialized');
    assert.ok(services.quickFixProvider, 'Quick fix provider should be initialized');

    // Test rule engine has rules loaded
    const stats = services.ruleEngine.getStatistics();
    assert.ok(stats.totalRules > 0, 'Rule engine should have rules loaded');
    assert.ok(stats.enabledRules > 0, 'Rule engine should have enabled rules');
    
    console.log(`Extension activation: ${stats.totalRules} total rules, ${stats.enabledRules} enabled`);

    // Test diagnostic collection is created
    const diagnosticCollection = services.diagnosticManager.getDiagnosticCollection();
    assert.ok(diagnosticCollection, 'Diagnostic collection should be created');
    assert.strictEqual(diagnosticCollection.name, 'VibeGuard', 'Diagnostic collection should have correct name');

    console.log('Extension activation regression test passed');
  });

  /**
   * Test Case 8: Message Localization Regression
   * Ensures error messages remain in Chinese and user-friendly
   */
  test('Message Localization Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const testCode = `
const openaiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const query = "DELETE FROM users";
eval("test");
`;

    const document = await vscode.workspace.openTextDocument({
      content: testCode,
      language: 'javascript'
    });

    const issues = await services.analysisEngine.analyzeDocument(document);
    
    // Verify all messages are in Chinese and user-friendly
    issues.forEach((issue, index) => {
      assert.ok(issue.message, `Issue ${index} should have a message`);
      assert.ok(typeof issue.message === 'string', `Issue ${index} message should be string`);
      
      // Check for Chinese characters (basic check)
      const hasChinese = /[\u4e00-\u9fff]/.test(issue.message);
      assert.ok(hasChinese, `Issue ${index} message should contain Chinese characters: "${issue.message}"`);
      
      // Check for user-friendly terms (should contain warning indicators)
      const hasWarningIndicator = /[🔑💀⚠️🚨]/.test(issue.message) || 
                                  issue.message.includes('危险') || 
                                  issue.message.includes('警告') ||
                                  issue.message.includes('风险');
      
      assert.ok(hasWarningIndicator, 
        `Issue ${index} message should contain warning indicators: "${issue.message}"`);
      
      console.log(`✓ Message ${index}: ${issue.message.substring(0, 50)}...`);
    });

    console.log('Message localization regression test passed');

    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
  });

  /**
   * Test Case 9: Performance Regression
   * Ensures performance hasn't degraded
   */
  test('Performance Regression', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Test with moderately complex code
    const complexCode = Array.from({ length: 100 }, (_, i) => 
      `const var${i} = "value${i}"; const apiKey${i} = "sk-proj-test${i}";`
    ).join('\n');

    const document = await vscode.workspace.openTextDocument({
      content: complexCode,
      language: 'javascript'
    });

    // Measure analysis performance
    const startTime = Date.now();
    const issues = await services.analysisEngine.analyzeDocument(document);
    const analysisTime = Date.now() - startTime;

    // Measure diagnostic update performance
    const diagnosticStartTime = Date.now();
    services.diagnosticManager.updateDiagnostics(document, issues);
    const diagnosticTime = Date.now() - diagnosticStartTime;

    console.log(`Performance: Analysis(${analysisTime}ms) + Diagnostics(${diagnosticTime}ms) = ${analysisTime + diagnosticTime}ms`);
    console.log(`Found ${issues.length} issues in ${complexCode.split('\n').length} lines`);

    // Performance regression thresholds
    assert.ok(analysisTime < 2000, `Analysis should complete within 2 seconds (took ${analysisTime}ms)`);
    assert.ok(diagnosticTime < 500, `Diagnostic update should complete within 500ms (took ${diagnosticTime}ms)`);

    console.log('Performance regression test passed');

    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
  });

  suiteTeardown(async () => {
    // Clean up any remaining documents
    await vscode.commands.executeCommand('workbench.action.closeAllEditors');
    console.log('All regression tests completed successfully');
  });
});
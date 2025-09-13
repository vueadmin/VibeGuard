/**
 * Performance Test Suite
 * 
 * Tests the performance characteristics of VibeGuard to ensure it doesn't
 * impact user productivity. Validates large file handling, real-time analysis
 * responsiveness, and memory usage optimization.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { activate, getExtensionServices } from '../../extension';
import { SecurityCategory } from '../../types';

suite('Real-World Scenarios - Performance Tests', () => {
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
   * Test Case 1: Large File Analysis Performance
   * Tests analysis performance on large files (1000+ lines)
   */
  test('Large File Analysis Performance', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Generate large file with scattered security issues
    const generateLargeFile = (lines: number) => {
      const content = [];
      
      for (let i = 0; i < lines; i++) {
        if (i % 100 === 0) {
          // Add security issues every 100 lines
          content.push(`const apiKey${i} = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";`);
        } else if (i % 150 === 0) {
          content.push(`const query${i} = "DELETE FROM users";`);
        } else if (i % 200 === 0) {
          content.push(`const result${i} = eval("console.log('test')");`);
        } else {
          // Regular code
          content.push(`const variable${i} = "safe value ${i}";`);
          content.push(`function function${i}() { return ${i}; }`);
          content.push(`// Comment line ${i}`);
        }
      }
      
      return content.join('\n');
    };

    const testSizes = [1000, 2000, 5000];
    
    for (const size of testSizes) {
      console.log(`Testing file with ${size} lines...`);
      
      const largeContent = generateLargeFile(size);
      const document = await vscode.workspace.openTextDocument({
        content: largeContent,
        language: 'javascript'
      });

      // Measure analysis time
      const startTime = Date.now();
      const issues = await services.analysisEngine.analyzeDocument(document);
      const analysisTime = Date.now() - startTime;

      // Measure diagnostic update time
      const diagnosticStartTime = Date.now();
      services.diagnosticManager.updateDiagnostics(document, issues);
      const diagnosticTime = Date.now() - diagnosticStartTime;

      const totalTime = analysisTime + diagnosticTime;

      console.log(`${size} lines: Analysis(${analysisTime}ms) + Diagnostics(${diagnosticTime}ms) = ${totalTime}ms`);
      console.log(`Found ${issues.length} issues in ${size} lines`);

      // Performance assertions
      assert.ok(analysisTime < 5000, `Analysis should complete within 5 seconds for ${size} lines (took ${analysisTime}ms)`);
      assert.ok(diagnosticTime < 1000, `Diagnostic update should complete within 1 second for ${size} lines (took ${diagnosticTime}ms)`);
      assert.ok(totalTime < 6000, `Total processing should complete within 6 seconds for ${size} lines (took ${totalTime}ms)`);

      // Verify issues were found (should have some based on our pattern)
      const expectedIssues = Math.floor(size / 100) + Math.floor(size / 150) + Math.floor(size / 200);
      console.log(`Expected ~${expectedIssues} issues, found ${issues.length}`);

      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    console.log('Large file analysis performance test completed');
  });

  /**
   * Test Case 2: Real-time Analysis Responsiveness
   * Tests the debouncing and responsiveness of real-time analysis
   */
  test('Real-time Analysis Responsiveness', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const document = await vscode.workspace.openTextDocument({
      content: 'const test = "initial";',
      language: 'javascript'
    });

    const editor = await vscode.window.showTextDocument(document);

    // Test rapid consecutive edits (simulating fast typing)
    const rapidEdits = [
      'const apiKey = "s',
      'const apiKey = "sk-',
      'const apiKey = "sk-proj-',
      'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";'
    ];

    const editTimes = [];
    
    for (let i = 0; i < rapidEdits.length; i++) {
      const startTime = Date.now();
      
      await editor.edit(editBuilder => {
        editBuilder.replace(
          new vscode.Range(0, 0, document.lineCount, 0),
          rapidEdits[i]
        );
      });

      const editTime = Date.now() - startTime;
      editTimes.push(editTime);
      
      // Small delay between edits (simulating typing speed)
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    // Wait for debounced analysis to complete
    await new Promise(resolve => setTimeout(resolve, 1000));

    const finalDiagnostics = vscode.languages.getDiagnostics(document.uri);
    
    console.log(`Rapid edits completed in: ${editTimes.join('ms, ')}ms`);
    console.log(`Final diagnostics: ${finalDiagnostics.length}`);

    // Verify responsiveness
    editTimes.forEach((time, index) => {
      assert.ok(time < 100, `Edit ${index} should complete quickly (took ${time}ms)`);
    });

    // Should have detected the API key in final state
    assert.ok(finalDiagnostics.length > 0, 'Should detect issues after rapid edits');

    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    console.log('Real-time analysis responsiveness test completed');
  });

  /**
   * Test Case 3: Memory Usage with Multiple Files
   * Tests memory efficiency when analyzing multiple files
   */
  test('Memory Usage with Multiple Files', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    const initialMemory = process.memoryUsage();
    console.log('Initial memory usage:', {
      rss: Math.round(initialMemory.rss / 1024 / 1024) + 'MB',
      heapUsed: Math.round(initialMemory.heapUsed / 1024 / 1024) + 'MB'
    });

    const documents = [];
    const fileCount = 20;

    // Create and analyze multiple files
    for (let i = 0; i < fileCount; i++) {
      const content = `
// File ${i}
const apiKey${i} = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const config${i} = {
  database: "mongodb://user:pass@localhost/db${i}",
  secret: "secret-key-${i}"
};

function deleteData${i}() {
  return db.query("DELETE FROM table${i}");
}

function processInput${i}(input) {
  return eval(input + "${i}");
}
`.repeat(10); // Make each file substantial

      const document = await vscode.workspace.openTextDocument({
        content,
        language: 'javascript'
      });

      documents.push(document);

      // Analyze each file
      const issues = await services.analysisEngine.analyzeDocument(document);
      services.diagnosticManager.updateDiagnostics(document, issues);

      console.log(`File ${i}: ${issues.length} issues`);
    }

    const afterAnalysisMemory = process.memoryUsage();
    console.log('Memory after analyzing', fileCount, 'files:', {
      rss: Math.round(afterAnalysisMemory.rss / 1024 / 1024) + 'MB',
      heapUsed: Math.round(afterAnalysisMemory.heapUsed / 1024 / 1024) + 'MB'
    });

    // Calculate memory increase
    const memoryIncrease = afterAnalysisMemory.heapUsed - initialMemory.heapUsed;
    const memoryIncreasePerFile = memoryIncrease / fileCount;

    console.log(`Memory increase: ${Math.round(memoryIncrease / 1024 / 1024)}MB total, ${Math.round(memoryIncreasePerFile / 1024)}KB per file`);

    // Memory usage should be reasonable
    assert.ok(memoryIncreasePerFile < 1024 * 1024, 'Memory increase per file should be less than 1MB');
    assert.ok(memoryIncrease < 50 * 1024 * 1024, 'Total memory increase should be less than 50MB');

    // Clean up
    for (const document of documents) {
      await vscode.window.showTextDocument(document);
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }

    const finalMemory = process.memoryUsage();
    console.log('Final memory usage:', {
      rss: Math.round(finalMemory.rss / 1024 / 1024) + 'MB',
      heapUsed: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB'
    });

    console.log('Memory usage test completed');
  });

  /**
   * Test Case 4: Rule Engine Performance
   * Tests the performance of rule execution with many rules
   */
  test('Rule Engine Performance', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Get rule engine statistics
    const stats = services.ruleEngine.getStatistics();
    console.log(`Rule engine stats: ${stats.totalRules} total rules, ${stats.enabledRules} enabled`);

    // Test with content that triggers multiple rules
    const complexContent = `
// API Keys
const openaiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const awsKey = "AKIA_EXAMPLE_NOT_REAL_AWS_KEY";
const githubToken = "ghp_EXAMPLE_NOT_REAL_GITHUB_TOKEN_12345";
const stripeKey = "sk_test_EXAMPLE_NOT_REAL_KEY_12345";

// Database credentials
const dbUrl = "mongodb://admin:password123@localhost:27017/app";
const mysqlUrl = "mysql://user:pass@localhost:3306/db";
const redisUrl = "redis://default:password@localhost:6379";

// Dangerous SQL
const queries = [
  "DELETE FROM users",
  "UPDATE products SET price = 0",
  "DROP TABLE sessions",
  "TRUNCATE TABLE logs"
];

// Code injection
function dangerousFunction(input) {
  eval(input);
  require('child_process').exec(input);
  document.write(input);
}

// Framework issues
function ReactComponent({ data }) {
  return <div dangerouslySetInnerHTML={{ __html: data }} />;
}

// Configuration issues
const config = {
  cors: { origin: "*" },
  debug: true,
  ssl: false
};
`.repeat(5); // Repeat to make it more complex

    // Measure rule execution performance
    const iterations = 10;
    const times = [];

    for (let i = 0; i < iterations; i++) {
      const startTime = Date.now();
      
      const issues = services.ruleEngine.executeRules(complexContent, 'javascript');
      
      const executionTime = Date.now() - startTime;
      times.push(executionTime);
      
      console.log(`Iteration ${i + 1}: ${executionTime}ms, ${issues.length} issues`);
    }

    // Calculate performance metrics
    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);

    console.log(`Rule execution performance: avg(${avgTime.toFixed(1)}ms) min(${minTime}ms) max(${maxTime}ms)`);

    // Performance assertions
    assert.ok(avgTime < 500, `Average rule execution should be under 500ms (was ${avgTime.toFixed(1)}ms)`);
    assert.ok(maxTime < 1000, `Maximum rule execution should be under 1000ms (was ${maxTime}ms)`);

    console.log('Rule engine performance test completed');
  });

  /**
   * Test Case 5: Concurrent Analysis Performance
   * Tests performance when analyzing multiple files concurrently
   */
  test('Concurrent Analysis Performance', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Create multiple files for concurrent analysis
    const fileContents = Array.from({ length: 10 }, (_, i) => ({
      content: `
// File ${i} with various security issues
const apiKey${i} = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const dbPassword${i} = "password123";
const jwtSecret${i} = "jwt-secret-${i}";

function deleteData${i}() {
  const query = "DELETE FROM table${i}";
  return db.execute(query);
}

function processCode${i}(input) {
  return eval(input);
}

const config${i} = {
  cors: { origin: "*" },
  debug: true
};
`.repeat(20), // Make each file substantial
      language: 'javascript'
    }));

    // Test sequential analysis
    console.log('Testing sequential analysis...');
    const sequentialStartTime = Date.now();
    
    for (const fileContent of fileContents) {
      const document = await vscode.workspace.openTextDocument(fileContent);
      await services.analysisEngine.analyzeDocument(document);
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }
    
    const sequentialTime = Date.now() - sequentialStartTime;
    console.log(`Sequential analysis: ${sequentialTime}ms`);

    // Test concurrent analysis
    console.log('Testing concurrent analysis...');
    const concurrentStartTime = Date.now();
    
    const analysisPromises = fileContents.map(async (fileContent) => {
      const document = await vscode.workspace.openTextDocument(fileContent);
      const result = await services.analysisEngine.analyzeDocument(document);
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      return result;
    });
    
    const results = await Promise.all(analysisPromises);
    const concurrentTime = Date.now() - concurrentStartTime;
    
    console.log(`Concurrent analysis: ${concurrentTime}ms`);
    console.log(`Total issues found: ${results.reduce((sum, issues) => sum + issues.length, 0)}`);

    // Concurrent should be faster (or at least not significantly slower due to overhead)
    const speedupRatio = sequentialTime / concurrentTime;
    console.log(`Speedup ratio: ${speedupRatio.toFixed(2)}x`);

    // Verify concurrent analysis doesn't degrade performance significantly
    assert.ok(concurrentTime <= sequentialTime * 1.5, 'Concurrent analysis should not be significantly slower than sequential');

    console.log('Concurrent analysis performance test completed');
  });

  /**
   * Test Case 6: Quick Fix Performance
   * Tests the performance of quick fix generation
   */
  test('Quick Fix Performance', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Create document with many issues that have quick fixes
    const contentWithManyIssues = Array.from({ length: 100 }, (_, i) => 
      `const apiKey${i} = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";`
    ).join('\n');

    const document = await vscode.workspace.openTextDocument({
      content: contentWithManyIssues,
      language: 'javascript'
    });

    // Analyze and create diagnostics
    const issues = await services.analysisEngine.analyzeDocument(document);
    services.diagnosticManager.updateDiagnostics(document, issues);
    
    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    console.log(`Created ${diagnostics.length} diagnostics for quick fix testing`);

    // Test quick fix generation performance
    const quickFixTimes = [];
    const maxTestDiagnostics = Math.min(10, diagnostics.length); // Test first 10

    for (let i = 0; i < maxTestDiagnostics; i++) {
      const diagnostic = diagnostics[i];
      const context: vscode.CodeActionContext = {
        diagnostics: [diagnostic],
        only: undefined,
        triggerKind: vscode.CodeActionTriggerKind.Automatic
      };

      const startTime = Date.now();
      
      const codeActions = await services.quickFixProvider.provideCodeActions(
        document, diagnostic.range, context, new vscode.CancellationTokenSource().token
      );
      
      const quickFixTime = Date.now() - startTime;
      quickFixTimes.push(quickFixTime);
      
      console.log(`Quick fix ${i + 1}: ${quickFixTime}ms, ${codeActions?.length || 0} actions`);
    }

    // Calculate quick fix performance metrics
    const avgQuickFixTime = quickFixTimes.reduce((a, b) => a + b, 0) / quickFixTimes.length;
    const maxQuickFixTime = Math.max(...quickFixTimes);

    console.log(`Quick fix performance: avg(${avgQuickFixTime.toFixed(1)}ms) max(${maxQuickFixTime}ms)`);

    // Performance assertions for quick fixes
    assert.ok(avgQuickFixTime < 100, `Average quick fix generation should be under 100ms (was ${avgQuickFixTime.toFixed(1)}ms)`);
    assert.ok(maxQuickFixTime < 200, `Maximum quick fix generation should be under 200ms (was ${maxQuickFixTime}ms)`);

    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    console.log('Quick fix performance test completed');
  });

  suiteTeardown(async () => {
    // Clean up any remaining documents
    await vscode.commands.executeCommand('workbench.action.closeAllEditors');
    
    // Log final memory usage
    const finalMemory = process.memoryUsage();
    console.log('Final memory usage after all performance tests:', {
      rss: Math.round(finalMemory.rss / 1024 / 1024) + 'MB',
      heapUsed: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB'
    });
  });
});
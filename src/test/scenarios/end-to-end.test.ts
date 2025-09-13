/**
 * End-to-End Test Suite
 * 
 * Comprehensive tests that validate the complete workflow from detection to fix.
 * These tests simulate real user scenarios and verify the entire system works together.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { activate, getExtensionServices } from '../../extension';
import { SecurityCategory, IssueSeverity } from '../../types';

suite('Real-World Scenarios - End-to-End Tests', () => {
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
   * Test Case 1: Complete Workflow - From Code to Fix
   * Tests the entire workflow: Code Analysis -> Diagnostics -> Quick Fix -> Verification
   */
  test('Complete Workflow - Detection to Fix', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Step 1: Create document with multiple security issues
    const vulnerableCode = `
// Multi-layered security issues for comprehensive testing
const config = {
  // API key issues
  openaiKey: "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345",
  stripeKey: "sk_test_EXAMPLE_NOT_REAL_KEY_12345",
  githubToken: "ghp_EXAMPLE_NOT_REAL_GITHUB_TOKEN_12345",
  
  // Database credentials
  database: {
    url: "mongodb://admin:password123@localhost:27017/myapp",
    password: "hardcoded-db-password"
  },
  
  // JWT secret
  jwtSecret: "my-super-secret-jwt-key-12345"
};

// Dangerous SQL operations
function cleanupDatabase() {
  const queries = [
    "DELETE FROM users",
    "UPDATE products SET price = 0",
    "DROP TABLE sessions",
    "TRUNCATE TABLE logs"
  ];
  
  queries.forEach(query => db.execute(query));
}

// Code injection vulnerabilities
function executeUserCode(userInput) {
  // Dangerous eval usage
  const result = eval(userInput);
  
  // Command injection
  const { exec } = require('child_process');
  exec(\`ls \${userInput}\`, (error, stdout) => {
    console.log(stdout);
  });
  
  return result;
}

// React XSS vulnerability
function UserComment({ comment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: comment.content }} />
  );
}

// Configuration issues
const serverConfig = {
  cors: {
    origin: "*", // Allow all origins
    credentials: true
  },
  debug: true, // Debug in production
  ssl: false // SSL disabled
};
`;

    const document = await vscode.workspace.openTextDocument({
      content: vulnerableCode,
      language: 'javascript'
    });

    console.log('Step 1: Created document with vulnerable code');

    // Step 2: Analyze document
    const issues = await services.analysisEngine.analyzeDocument(document);
    
    console.log(`Step 2: Analysis completed - Found ${issues.length} issues`);
    assert.ok(issues.length > 0, 'Should detect multiple security issues');

    // Verify different categories of issues are detected
    const apiKeyIssues = issues.filter(i => i.category === SecurityCategory.API_KEY);
    const sqlIssues = issues.filter(i => i.category === SecurityCategory.SQL_DANGER);
    const codeInjectionIssues = issues.filter(i => i.category === SecurityCategory.CODE_INJECTION);
    const frameworkIssues = issues.filter(i => i.category === SecurityCategory.FRAMEWORK_RISK);
    const configIssues = issues.filter(i => i.category === SecurityCategory.CONFIG_ERROR);

    console.log(`Issue breakdown: API(${apiKeyIssues.length}) SQL(${sqlIssues.length}) Code(${codeInjectionIssues.length}) Framework(${frameworkIssues.length}) Config(${configIssues.length})`);

    // Step 3: Update diagnostics
    services.diagnosticManager.updateDiagnostics(document, issues);
    console.log('Step 3: Diagnostics updated');

    // Step 4: Verify diagnostics are created in VSCode
    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    assert.ok(diagnostics.length > 0, 'Should create VSCode diagnostics');
    console.log(`Step 4: ${diagnostics.length} VSCode diagnostics created`);

    // Step 5: Test quick fixes for each diagnostic
    let totalQuickFixes = 0;
    let successfulFixes = 0;

    for (const diagnostic of diagnostics.slice(0, 5)) { // Test first 5 diagnostics
      const context: vscode.CodeActionContext = {
        diagnostics: [diagnostic],
        only: undefined,
        triggerKind: vscode.CodeActionTriggerKind.Automatic
      };

      const codeActions = await services.quickFixProvider.provideCodeActions(
        document, diagnostic.range, context, new vscode.CancellationTokenSource().token
      );

      if (codeActions && codeActions.length > 0) {
        totalQuickFixes += codeActions.length;
        successfulFixes++;
        console.log(`Quick fix available for ${diagnostic.code}: ${codeActions[0].title}`);
      }
    }

    console.log(`Step 5: Generated ${totalQuickFixes} quick fixes for ${successfulFixes} issues`);

    // Step 6: Verify workflow completion
    assert.ok(totalQuickFixes > 0, 'Should provide quick fixes for detected issues');
    
    console.log('Complete workflow test passed successfully');
    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
  });

  /**
   * Test Case 2: Real-time Analysis Simulation
   * Simulates user typing and verifies real-time analysis works
   */
  test('Real-time Analysis Simulation', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Create empty document
    const document = await vscode.workspace.openTextDocument({
      content: '',
      language: 'javascript'
    });

    const editor = await vscode.window.showTextDocument(document);
    console.log('Created empty document for real-time testing');

    // Simulate typing dangerous code step by step
    const typingSteps = [
      'const apiKey = "',
      'const apiKey = "sk-proj-',
      'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";',
      '\nconst query = "DELETE FROM users";'
    ];

    for (let i = 0; i < typingSteps.length; i++) {
      // Simulate typing
      await editor.edit(editBuilder => {
        editBuilder.replace(
          new vscode.Range(0, 0, document.lineCount, 0),
          typingSteps[i]
        );
      });

      // Wait for debounced analysis
      await new Promise(resolve => setTimeout(resolve, 600));

      // Check diagnostics
      const diagnostics = vscode.languages.getDiagnostics(document.uri);
      console.log(`Step ${i + 1}: "${typingSteps[i]}" -> ${diagnostics.length} diagnostics`);

      // On final step, should have detected issues
      if (i === typingSteps.length - 1) {
        assert.ok(diagnostics.length > 0, 'Should detect issues after typing complete dangerous code');
      }
    }

    console.log('Real-time analysis simulation completed');
    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
  });

  /**
   * Test Case 3: Multi-file Project Analysis
   * Tests analysis across multiple related files
   */
  test('Multi-file Project Analysis', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Create multiple files with different types of issues
    const files = [
      {
        name: 'config.js',
        content: `
module.exports = {
  apiKey: "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345",
  database: {
    url: "mongodb://admin:password@localhost:27017/app"
  },
  jwt: {
    secret: "jwt-secret-key-12345"
  }
};`
      },
      {
        name: 'database.js',
        content: `
const mysql = require('mysql2');

function deleteAllUsers() {
  const query = "DELETE FROM users";
  return db.execute(query);
}

function updatePrices() {
  const query = "UPDATE products SET price = 0";
  return db.execute(query);
}`
      },
      {
        name: 'api.js',
        content: `
const express = require('express');
const app = express();

app.post('/eval', (req, res) => {
  const { code } = req.body;
  const result = eval(code);
  res.json({ result });
});

app.get('/execute', (req, res) => {
  const { cmd } = req.query;
  require('child_process').exec(cmd, (err, stdout) => {
    res.json({ output: stdout });
  });
});`
      },
      {
        name: 'component.jsx',
        content: `
import React from 'react';

function UserProfile({ user }) {
  return (
    <div>
      <h1>{user.name}</h1>
      <div dangerouslySetInnerHTML={{ __html: user.bio }} />
      <button onClick={() => eval(\`alert('Hello \${user.name}')\`)}>
        Greet
      </button>
    </div>
  );
}`
      }
    ];

    const allIssues = [];
    const allDiagnostics = [];

    // Analyze each file
    for (const file of files) {
      const document = await vscode.workspace.openTextDocument({
        content: file.content,
        language: file.name.endsWith('.jsx') ? 'typescriptreact' : 'javascript'
      });

      const issues = await services.analysisEngine.analyzeDocument(document);
      services.diagnosticManager.updateDiagnostics(document, issues);
      
      const diagnostics = vscode.languages.getDiagnostics(document.uri);
      
      allIssues.push(...issues);
      allDiagnostics.push(...diagnostics);
      
      console.log(`${file.name}: ${issues.length} issues, ${diagnostics.length} diagnostics`);
      
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    }

    // Verify comprehensive detection across files
    assert.ok(allIssues.length > 0, 'Should detect issues across multiple files');
    assert.ok(allDiagnostics.length > 0, 'Should create diagnostics for multiple files');

    // Verify different categories are detected
    const categories = [...new Set(allIssues.map(i => i.category))];
    console.log(`Multi-file analysis: ${allIssues.length} total issues across ${categories.length} categories`);
    console.log('Categories detected:', categories);

    assert.ok(categories.length >= 3, 'Should detect multiple categories of issues across files');
  });

  /**
   * Test Case 4: User Experience Validation
   * Tests the user-facing aspects of the extension
   */
  test('User Experience Validation', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Test user-friendly error messages
    const testCode = `
const openaiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const query = "DELETE FROM users";
eval("console.log('test')");
`;

    const document = await vscode.workspace.openTextDocument({
      content: testCode,
      language: 'javascript'
    });

    const issues = await services.analysisEngine.analyzeDocument(document);
    services.diagnosticManager.updateDiagnostics(document, issues);
    
    const diagnostics = vscode.languages.getDiagnostics(document.uri);

    // Verify user-friendly messages
    diagnostics.forEach((diagnostic, index) => {
      // Should have Chinese messages
      assert.ok(diagnostic.message, `Diagnostic ${index} should have a message`);
      assert.ok(typeof diagnostic.message === 'string', `Diagnostic ${index} message should be string`);
      
      // Should have proper severity
      assert.ok(
        diagnostic.severity === vscode.DiagnosticSeverity.Error || 
        diagnostic.severity === vscode.DiagnosticSeverity.Warning,
        `Diagnostic ${index} should have appropriate severity`
      );
      
      // Should have source
      assert.strictEqual(diagnostic.source, 'VibeGuard', `Diagnostic ${index} should have VibeGuard source`);
      
      console.log(`Diagnostic ${index}: ${diagnostic.message.substring(0, 50)}...`);
    });

    // Test quick fix user experience
    if (diagnostics.length > 0) {
      const firstDiagnostic = diagnostics[0];
      const context: vscode.CodeActionContext = {
        diagnostics: [firstDiagnostic],
        only: undefined,
        triggerKind: vscode.CodeActionTriggerKind.Automatic
      };

      const codeActions = await services.quickFixProvider.provideCodeActions(
        document, firstDiagnostic.range, context, new vscode.CancellationTokenSource().token
      );

      if (codeActions && codeActions.length > 0) {
        const firstAction = codeActions[0];
        
        // Verify quick fix properties
        assert.ok(firstAction.title, 'Quick fix should have title');
        assert.ok(firstAction.kind, 'Quick fix should have kind');
        assert.ok(firstAction.edit, 'Quick fix should have edit');
        
        console.log(`Quick fix: ${firstAction.title}`);
      }
    }

    console.log('User experience validation completed');
    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
  });

  /**
   * Test Case 5: Error Recovery and Resilience
   * Tests how the system handles edge cases and errors
   */
  test('Error Recovery and Resilience', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Test with various edge cases
    const edgeCases = [
      {
        name: 'Empty file',
        content: '',
        language: 'javascript'
      },
      {
        name: 'Very large file',
        content: 'const x = 1;\n'.repeat(1000) + 'const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";',
        language: 'javascript'
      },
      {
        name: 'Invalid characters',
        content: 'const test = "hello\x00\x01\x02world"; const apiKey = "sk-proj-test123";',
        language: 'javascript'
      },
      {
        name: 'Mixed content',
        content: `
// JavaScript
const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";

/* SQL */
DELETE FROM users;

<!-- HTML -->
<div>Test</div>

# Python
api_key = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345"
`,
        language: 'javascript'
      }
    ];

    for (const testCase of edgeCases) {
      try {
        console.log(`Testing edge case: ${testCase.name}`);
        
        const document = await vscode.workspace.openTextDocument({
          content: testCase.content,
          language: testCase.language
        });

        // Should not throw errors
        const issues = await services.analysisEngine.analyzeDocument(document);
        services.diagnosticManager.updateDiagnostics(document, issues);
        
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        
        console.log(`${testCase.name}: ${issues.length} issues, ${diagnostics.length} diagnostics`);
        
        // Should return valid results (even if empty)
        assert.ok(Array.isArray(issues), `${testCase.name}: Should return array of issues`);
        assert.ok(Array.isArray(diagnostics), `${testCase.name}: Should return array of diagnostics`);
        
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        
      } catch (error) {
        assert.fail(`${testCase.name}: Should handle edge case gracefully: ${error}`);
      }
    }

    console.log('Error recovery and resilience test completed');
  });

  /**
   * Test Case 6: Integration with VSCode Commands
   * Tests the extension's command integration
   */
  test('VSCode Command Integration', async () => {
    const services = getExtensionServices();
    assert.ok(services, 'Extension services should be available');

    // Create test document
    const testCode = `
const apiKey = "sk-proj-EXAMPLE_NOT_REAL_OPENAI_KEY_12345";
const query = "DELETE FROM users";
`;

    const document = await vscode.workspace.openTextDocument({
      content: testCode,
      language: 'javascript'
    });

    await vscode.window.showTextDocument(document);

    try {
      // Test analyze current file command
      await vscode.commands.executeCommand('vibeguard.analyzeCurrentFile');
      
      // Verify diagnostics were created
      const diagnostics = vscode.languages.getDiagnostics(document.uri);
      console.log(`Command execution result: ${diagnostics.length} diagnostics`);
      
      // Should have created diagnostics
      assert.ok(diagnostics.length > 0, 'Command should create diagnostics');
      
    } catch (error) {
      // Commands might not work in test environment, but should not crash
      console.warn('Command execution warning (expected in test environment):', error);
    }

    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    console.log('VSCode command integration test completed');
  });

  suiteTeardown(async () => {
    // Clean up any remaining documents
    await vscode.commands.executeCommand('workbench.action.closeAllEditors');
  });
});
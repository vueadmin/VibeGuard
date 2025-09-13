/**
 * QuickFixProvider Tests
 * 
 * Comprehensive test suite for the QuickFixProvider class that provides
 * one-click fixes for security issues. Tests cover API key fixes, SQL fixes,
 * batch operations, and user experience scenarios.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { QuickFixProvider } from '../../quickfix/QuickFixProvider';
import { 
  SecurityIssue, 
  IssueSeverity, 
  SecurityCategory,
  ImpactLevel,
  EffortLevel
} from '../../types';

suite('QuickFixProvider Tests', () => {
  let quickFixProvider: QuickFixProvider;
  let mockDiagnosticCollection: vscode.DiagnosticCollection;
  let mockDocument: vscode.TextDocument;
  let mockCancellationToken: vscode.CancellationToken;

  setup(() => {
    // Create mock diagnostic collection
    mockDiagnosticCollection = {
      name: 'vibeguard',
      set: () => {},
      delete: () => {},
      clear: () => {},
      forEach: () => {},
      get: () => [],
      has: () => false,
      dispose: () => {},
      [Symbol.iterator]: function* () {}
    } as unknown as vscode.DiagnosticCollection;

    quickFixProvider = new QuickFixProvider(mockDiagnosticCollection);

    // Create mock document with realistic content
    mockDocument = {
      uri: vscode.Uri.file('/test/file.js'),
      fileName: '/test/file.js',
      isUntitled: false,
      languageId: 'javascript',
      version: 1,
      isDirty: false,
      isClosed: false,
      save: async () => true,
      eol: vscode.EndOfLine.LF,
      lineCount: 10,
      encoding: 'utf8',
      getText: (range?: vscode.Range) => {
        const lines = [
          'const openai = new OpenAI({',
          '  apiKey: "sk-proj-1234567890abcdef1234567890abcdef12345678"',
          '});',
          '',
          'const query = "DELETE FROM users";',
          'const updateQuery = "UPDATE users SET active = false";',
          '',
          'eval(userInput);',
          'element.innerHTML = userContent;',
          'exec(command);'
        ];
        
        if (!range) {
          return lines.join('\n');
        }
        
        if (range.start.line === range.end.line) {
          const line = lines[range.start.line] || '';
          return line.substring(range.start.character, range.end.character);
        }
        
        return lines.slice(range.start.line, range.end.line + 1).join('\n');
      },
      getWordRangeAtPosition: () => new vscode.Range(0, 0, 0, 10),
      lineAt: (line: number) => ({
        lineNumber: line,
        text: [
          'const openai = new OpenAI({',
          '  apiKey: "sk-proj-1234567890abcdef1234567890abcdef12345678"',
          '});',
          '',
          'const query = "DELETE FROM users";',
          'const updateQuery = "UPDATE users SET active = false";',
          '',
          'eval(userInput);',
          'element.innerHTML = userContent;',
          'exec(command);'
        ][line] || '',
        range: new vscode.Range(line, 0, line, 100),
        rangeIncludingLineBreak: new vscode.Range(line, 0, line + 1, 0),
        firstNonWhitespaceCharacterIndex: 0,
        isEmptyOrWhitespace: false
      }),
      offsetAt: () => 0,
      positionAt: () => new vscode.Position(0, 0),
      validateRange: (range: vscode.Range) => range,
      validatePosition: (position: vscode.Position) => position
    } as unknown as vscode.TextDocument;

    // Create mock cancellation token
    mockCancellationToken = {
      isCancellationRequested: false,
      onCancellationRequested: () => ({ dispose: () => {} })
    } as vscode.CancellationToken;
  });

  suite('API Key Quick Fixes', () => {
    test('should provide environment variable fix for OpenAI API key', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      assert.ok(actions.length > 0);

      // Find the environment variable fix
      const envVarFix = actions.find(action => 
        action.title.includes('环境变量') && action.title.includes('OPENAI_API_KEY')
      );

      assert.ok(envVarFix, 'Should provide environment variable fix');
      assert.strictEqual(envVarFix.kind, vscode.CodeActionKind.QuickFix);
      assert.strictEqual(envVarFix.isPreferred, true);
      assert.ok(envVarFix.diagnostics?.includes(diagnostic));

      // Check the edit
      assert.ok(envVarFix.edit);
      const edits = envVarFix.edit.get(mockDocument.uri);
      assert.ok(edits && edits.length > 0);
      assert.strictEqual(edits[0].newText, 'process.env.OPENAI_API_KEY');
    });

    test('should provide environment variable fix for AWS API key', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_AWS',
        range: new vscode.Range(1, 10, 1, 30),
        message: '🔑 危险！AWS 访问密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 30);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const envVarFix = actions.find(action => 
        action.title.includes('AWS_ACCESS_KEY_ID')
      );

      assert.ok(envVarFix);
      assert.ok(envVarFix.edit);
      const edits = envVarFix.edit.get(mockDocument.uri);
      assert.strictEqual(edits![0].newText, 'process.env.AWS_ACCESS_KEY_ID');
    });

    test('should provide environment variable fix for GitHub token', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_GITHUB',
        range: new vscode.Range(1, 10, 1, 30),
        message: '🔑 危险！GitHub Token 暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 30);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const envVarFix = actions.find(action => 
        action.title.includes('GITHUB_TOKEN')
      );

      assert.ok(envVarFix);
      assert.ok(envVarFix.edit);
      const edits = envVarFix.edit.get(mockDocument.uri);
      assert.strictEqual(edits![0].newText, 'process.env.GITHUB_TOKEN');
    });

    test('should provide config file replacement fix', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const configFix = actions.find(action => 
        action.title.includes('配置文件')
      );

      assert.ok(configFix);
      assert.strictEqual(configFix.kind, vscode.CodeActionKind.Refactor);
      
      const edits = configFix.edit!.get(mockDocument.uri);
      assert.strictEqual(edits![0].newText, 'config.apiKey');
    });

    test('should provide comment out fix', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const commentFix = actions.find(action => 
        action.title.includes('注释')
      );

      assert.ok(commentFix);
      
      const edits = commentFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('// TODO: 移除硬编码密钥'));
    });
  });

  suite('SQL Quick Fixes', () => {
    test('should provide WHERE clause fix for DELETE statement', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'SQL_DELETE_NO_WHERE',
        range: new vscode.Range(4, 14, 4, 35),
        message: '💀 致命错误！DELETE 没有 WHERE 条件！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(4, 14, 4, 35);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const whereFix = actions.find(action => 
        action.title.includes('WHERE 条件')
      );

      assert.ok(whereFix);
      assert.strictEqual(whereFix.kind, vscode.CodeActionKind.QuickFix);
      assert.strictEqual(whereFix.isPreferred, true);
      
      const edits = whereFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('WHERE id = ?'));
    });

    test('should provide WHERE clause fix for UPDATE statement', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'SQL_UPDATE_NO_WHERE',
        range: new vscode.Range(5, 16, 5, 50),
        message: '💀 致命错误！UPDATE 没有 WHERE 条件！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(5, 16, 5, 50);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const whereFix = actions.find(action => 
        action.title.includes('WHERE 条件')
      );

      assert.ok(whereFix);
      const edits = whereFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('WHERE id = ?'));
    });

    test('should provide safety check for DROP TABLE', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'SQL_DROP_TABLE',
        range: new vscode.Range(4, 0, 4, 20),
        message: '💀 致命错误！DROP TABLE 操作！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(4, 0, 4, 20);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const safetyFix = actions.find(action => 
        action.title.includes('安全确认')
      );

      assert.ok(safetyFix);
      const edits = safetyFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('// 危险操作！请确认后取消注释'));
    });
  });

  suite('Code Injection Quick Fixes', () => {
    test('should provide JSON.parse replacement for eval', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'CODE_INJECTION_EVAL',
        range: new vscode.Range(7, 0, 7, 17),
        message: '⚠️ eval() 函数存在代码注入风险！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(7, 0, 7, 17);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const jsonParseFix = actions.find(action => 
        action.title.includes('JSON.parse')
      );

      assert.ok(jsonParseFix);
      assert.strictEqual(jsonParseFix.isPreferred, true);
      
      const edits = jsonParseFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('JSON.parse('));
    });

    test('should provide textContent replacement for innerHTML', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'CODE_INJECTION_INNERHTML',
        range: new vscode.Range(8, 0, 8, 30),
        message: '⚠️ innerHTML 直接赋值存在 XSS 风险！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(8, 0, 8, 30);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const textContentFix = actions.find(action => 
        action.title.includes('textContent')
      );

      assert.ok(textContentFix);
      assert.strictEqual(textContentFix.isPreferred, true);
      
      const edits = textContentFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('.textContent ='));
    });

    test('should provide input validation for exec', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'CODE_INJECTION_EXEC',
        range: new vscode.Range(9, 0, 9, 15),
        message: '⚠️ exec() 函数存在命令注入风险！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(9, 0, 9, 15);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const validationFix = actions.find(action => 
        action.title.includes('输入验证')
      );

      assert.ok(validationFix);
      
      const edits = validationFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('添加输入验证'));
      assert.ok(edits![0].newText.includes('无效输入'));
    });
  });

  suite('Batch Fix Operations', () => {
    test('should provide batch fix for multiple API key issues', async () => {
      const diagnostics = [
        createMockDiagnostic({
          code: 'API_KEY_OPENAI',
          range: new vscode.Range(1, 10, 1, 58),
          message: '🔑 OpenAI API 密钥暴露！'
        }),
        createMockDiagnostic({
          code: 'API_KEY_AWS',
          range: new vscode.Range(2, 10, 2, 30),
          message: '🔑 AWS 访问密钥暴露！'
        }),
        createMockDiagnostic({
          code: 'API_KEY_GITHUB',
          range: new vscode.Range(3, 10, 3, 35),
          message: '🔑 GitHub Token 暴露！'
        })
      ];

      const context = createCodeActionContext(diagnostics);
      const range = new vscode.Range(1, 0, 3, 50);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const batchFix = actions.find(action => 
        action.title.includes('批量修复') && action.title.includes('API 密钥')
      );

      assert.ok(batchFix);
      assert.ok(batchFix.title.includes('3个'));
      assert.strictEqual(batchFix.kind, vscode.CodeActionKind.QuickFix);
      assert.ok(batchFix.diagnostics?.length === 3);
    });

    test('should provide batch fix for multiple SQL issues', async () => {
      const diagnostics = [
        createMockDiagnostic({
          code: 'SQL_DELETE_NO_WHERE',
          range: new vscode.Range(4, 14, 4, 35),
          message: '💀 DELETE 没有 WHERE 条件！'
        }),
        createMockDiagnostic({
          code: 'SQL_UPDATE_NO_WHERE',
          range: new vscode.Range(5, 16, 5, 50),
          message: '💀 UPDATE 没有 WHERE 条件！'
        })
      ];

      const context = createCodeActionContext(diagnostics);
      const range = new vscode.Range(4, 0, 5, 60);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const batchFix = actions.find(action => 
        action.title.includes('批量修复') && action.title.includes('SQL 危险操作')
      );

      assert.ok(batchFix);
      assert.ok(batchFix.title.includes('2个'));
    });

    test('should provide fix all action for mixed issues', async () => {
      const diagnostics = [
        createMockDiagnostic({
          code: 'API_KEY_OPENAI',
          range: new vscode.Range(1, 10, 1, 58),
          message: '🔑 OpenAI API 密钥暴露！'
        }),
        createMockDiagnostic({
          code: 'SQL_DELETE_NO_WHERE',
          range: new vscode.Range(4, 14, 4, 35),
          message: '💀 DELETE 没有 WHERE 条件！'
        }),
        createMockDiagnostic({
          code: 'CODE_INJECTION_EVAL',
          range: new vscode.Range(7, 0, 7, 17),
          message: '⚠️ eval() 函数存在代码注入风险！'
        })
      ];

      const context = createCodeActionContext(diagnostics);
      const range = new vscode.Range(0, 0, 9, 50);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const fixAllAction = actions.find(action => 
        action.title.includes('修复所有安全问题')
      );

      assert.ok(fixAllAction);
      assert.ok(fixAllAction.title.includes('3个'));
      assert.strictEqual(fixAllAction.kind, vscode.CodeActionKind.SourceFixAll);
      assert.strictEqual(fixAllAction.isPreferred, true);
      assert.ok(fixAllAction.diagnostics?.length === 3);
    });

    test('should respect batch size limits', async () => {
      // Create provider with small batch size
      const limitedProvider = new QuickFixProvider(mockDiagnosticCollection, {
        maxBatchSize: 2
      });

      const diagnostics = Array.from({ length: 5 }, (_, i) => 
        createMockDiagnostic({
          code: 'API_KEY_OPENAI',
          range: new vscode.Range(i, 10, i, 58),
          message: `🔑 API 密钥暴露 ${i}！`
        })
      );

      const context = createCodeActionContext(diagnostics);
      const range = new vscode.Range(0, 0, 4, 60);

      const actions = await limitedProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const fixAllAction = actions.find(action => 
        action.title.includes('修复所有安全问题')
      );

      // Should only process first 2 diagnostics due to batch size limit
      assert.ok(fixAllAction);
      assert.ok(fixAllAction.title.includes('2个'));
    });
  });

  suite('User Experience', () => {
    test('should provide preferred actions for critical issues', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const preferredActions = actions.filter(action => action.isPreferred);
      assert.ok(preferredActions.length > 0, 'Should have preferred actions');
      
      // Environment variable fix should be preferred
      const envVarFix = preferredActions.find(action => 
        action.title.includes('环境变量')
      );
      assert.ok(envVarFix, 'Environment variable fix should be preferred');
    });

    test('should provide descriptive action titles', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      // Check that all actions have descriptive, user-friendly titles
      for (const action of actions) {
        assert.ok(action.title.length > 5, 'Action title should be descriptive');
        assert.ok(
          action.title.includes('🔧') || 
          action.title.includes('📁') || 
          action.title.includes('⚠️') ||
          action.title.includes('🚀') ||
          action.title.includes('🛡️') ||
          action.title.includes('🔒'),
          'Action title should include helpful emoji'
        );
      }
    });

    test('should handle empty diagnostic list gracefully', async () => {
      const context = createCodeActionContext([]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assert.ok(Array.isArray(actions));
      assert.strictEqual(actions.length, 0);
    });

    test('should handle non-VibeGuard diagnostics gracefully', async () => {
      const nonVibeGuardDiagnostic = createMockDiagnostic({
        code: 'OTHER_TOOL_ERROR',
        range: new vscode.Range(1, 10, 1, 58),
        message: 'Some other tool error',
        source: 'OtherTool'
      });

      const context = createCodeActionContext([nonVibeGuardDiagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assert.ok(Array.isArray(actions));
      assert.strictEqual(actions.length, 0);
    });

    test('should provide generic fixes for unknown issue types', async () => {
      const unknownDiagnostic = createMockDiagnostic({
        code: 'UNKNOWN_ISSUE_TYPE',
        range: new vscode.Range(1, 10, 1, 58),
        message: '未知安全问题'
      });

      const context = createCodeActionContext([unknownDiagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      assert.ok(actions.length > 0);
      
      const commentFix = actions.find(action => 
        action.title.includes('注释')
      );
      assert.ok(commentFix, 'Should provide generic comment fix');
    });
  });

  suite('Error Handling', () => {
    test('should handle malformed diagnostics gracefully', async () => {
      const malformedDiagnostic = {
        range: new vscode.Range(1, 10, 1, 58),
        message: '测试错误',
        severity: vscode.DiagnosticSeverity.Error,
        source: 'VibeGuard',
        code: undefined // Malformed: undefined code
      } as unknown as vscode.Diagnostic;

      const context = createCodeActionContext([malformedDiagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      // Should not throw
      assert.doesNotThrow(async () => {
        const actions = await quickFixProvider.provideCodeActions(
          mockDocument,
          range,
          context,
          mockCancellationToken
        );
        assert.ok(Array.isArray(actions));
      });
    });

    test('should handle document read errors gracefully', async () => {
      const faultyDocument = {
        ...mockDocument,
        getText: () => {
          throw new Error('Document read error');
        }
      } as vscode.TextDocument;

      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      // Should not throw and should return empty array
      const actions = await quickFixProvider.provideCodeActions(
        faultyDocument,
        range,
        context,
        mockCancellationToken
      );

      assert.ok(Array.isArray(actions));
      assert.strictEqual(actions.length, 0);
    });

    test('should handle cancellation token gracefully', async () => {
      const cancelledToken = {
        isCancellationRequested: true,
        onCancellationRequested: () => ({ dispose: () => {} })
      } as vscode.CancellationToken;

      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(1, 10, 1, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(1, 10, 1, 58);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        cancelledToken
      );

      // Should handle cancellation gracefully
      assert.ok(Array.isArray(actions));
    });
  });

  suite('Real-World Scenarios', () => {
    test('should handle ChatGPT generated OpenAI integration code', async () => {
      // Simulate real ChatGPT generated code with hardcoded API key
      const realisticDocument = {
        ...mockDocument,
        getText: (range?: vscode.Range) => {
          const code = `
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: 'sk-proj-1234567890abcdef1234567890abcdef12345678'
});

async function generateText(prompt) {
  const response = await openai.chat.completions.create({
    model: 'gpt-3.5-turbo',
    messages: [{ role: 'user', content: prompt }]
  });
  return response.choices[0].message.content;
}
          `.trim();
          
          if (!range) {
            return code;
          }
          return code.split('\n')[range.start.line]?.substring(range.start.character, range.end.character) || '';
        }
      } as vscode.TextDocument;

      const diagnostic = createMockDiagnostic({
        code: 'API_KEY_OPENAI',
        range: new vscode.Range(3, 10, 3, 58),
        message: '🔑 危险！OpenAI API 密钥暴露！这就是那个设计师损失 $5000 的原因！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(3, 10, 3, 58);

      const actions = await quickFixProvider.provideCodeActions(
        realisticDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      assert.ok(actions.length > 0);
      
      const envVarFix = actions.find(action => 
        action.title.includes('OPENAI_API_KEY')
      );
      assert.ok(envVarFix);
      
      const edits = envVarFix.edit!.get(realisticDocument.uri);
      assert.strictEqual(edits![0].newText, 'process.env.OPENAI_API_KEY');
    });

    test('should handle Claude generated SQL query with missing WHERE clause', async () => {
      const diagnostic = createMockDiagnostic({
        code: 'SQL_DELETE_NO_WHERE',
        range: new vscode.Range(4, 14, 4, 35),
        message: '💀 致命错误！DELETE 没有 WHERE 条件会删除整个表！'
      });

      const context = createCodeActionContext([diagnostic]);
      const range = new vscode.Range(4, 14, 4, 35);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      const whereFix = actions.find(action => 
        action.title.includes('WHERE 条件保护')
      );

      assert.ok(whereFix);
      assert.ok(whereFix.title.includes('🛡️'));
      
      const edits = whereFix.edit!.get(mockDocument.uri);
      assert.ok(edits![0].newText.includes('WHERE id = ?'));
    });

    test('should handle multiple security issues in single file', async () => {
      const diagnostics = [
        createMockDiagnostic({
          code: 'API_KEY_OPENAI',
          range: new vscode.Range(1, 10, 1, 58),
          message: '🔑 OpenAI API 密钥暴露！'
        }),
        createMockDiagnostic({
          code: 'SQL_DELETE_NO_WHERE',
          range: new vscode.Range(4, 14, 4, 35),
          message: '💀 DELETE 没有 WHERE 条件！'
        }),
        createMockDiagnostic({
          code: 'CODE_INJECTION_EVAL',
          range: new vscode.Range(7, 0, 7, 17),
          message: '⚠️ eval() 函数存在代码注入风险！'
        }),
        createMockDiagnostic({
          code: 'CODE_INJECTION_INNERHTML',
          range: new vscode.Range(8, 0, 8, 30),
          message: '⚠️ innerHTML 直接赋值存在 XSS 风险！'
        })
      ];

      const context = createCodeActionContext(diagnostics);
      const range = new vscode.Range(0, 0, 9, 50);

      const actions = await quickFixProvider.provideCodeActions(
        mockDocument,
        range,
        context,
        mockCancellationToken
      );

      assertActionsExist(actions);
      // Should provide individual fixes
      assert.ok(actions.some(action => action.title.includes('OPENAI_API_KEY')));
      assert.ok(actions.some(action => action.title.includes('WHERE 条件')));
      assert.ok(actions.some(action => action.title.includes('JSON.parse')));
      assert.ok(actions.some(action => action.title.includes('textContent')));

      // Should provide batch fixes
      assert.ok(actions.some(action => action.title.includes('批量修复')));
      assert.ok(actions.some(action => action.title.includes('修复所有安全问题')));

      // Fix all action should handle all issues
      const fixAllAction = actions.find(action => 
        action.title.includes('修复所有安全问题')
      );
      assert.ok(fixAllAction);
      assert.ok(fixAllAction.title.includes('4个'));
    });
  });

  // Helper functions
  function createMockDiagnostic(options: {
    code: string;
    range: vscode.Range;
    message: string;
    source?: string;
    severity?: vscode.DiagnosticSeverity;
  }): vscode.Diagnostic {
    const diagnostic = new vscode.Diagnostic(
      options.range,
      options.message,
      options.severity || vscode.DiagnosticSeverity.Error
    );
    
    diagnostic.code = options.code;
    diagnostic.source = options.source || 'VibeGuard';
    
    return diagnostic;
  }

  function createCodeActionContext(diagnostics: vscode.Diagnostic[]): vscode.CodeActionContext {
    return {
      diagnostics,
      only: undefined,
      triggerKind: vscode.CodeActionTriggerKind.Automatic
    };
  }

  function assertActionsExist(actions: vscode.CodeAction[] | null | undefined): asserts actions is vscode.CodeAction[] {
    assert.ok(actions, 'Actions should not be null or undefined');
    assert.ok(Array.isArray(actions), 'Actions should be an array');
  }
});
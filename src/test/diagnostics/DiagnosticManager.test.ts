/**
 * DiagnosticManager Tests
 * 
 * Comprehensive test suite for the DiagnosticManager class that handles
 * VSCode diagnostic display and management. Tests cover SecurityIssue to
 * VSCode Diagnostic conversion, diagnostic updates, and user-friendly messaging.
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { DiagnosticManager } from '../../diagnostics/DiagnosticManager';
import { 
  SecurityIssue, 
  IssueSeverity, 
  SecurityCategory,
  ImpactLevel,
  EffortLevel
} from '../../types';

suite('DiagnosticManager Tests', () => {
  let diagnosticManager: DiagnosticManager;
  let mockDocument: vscode.TextDocument;

  setup(() => {
    diagnosticManager = new DiagnosticManager();
    
    // Create minimal mock document - we only need uri for diagnostic collection
    mockDocument = {
      uri: vscode.Uri.file('/test/file.js')
    } as vscode.TextDocument;
  });

  teardown(() => {
    try {
      diagnosticManager.dispose();
    } catch (error) {
      // Ignore disposal errors in tests
    }
  });

  suite('Diagnostic Collection Management', () => {
    test('should create diagnostic collection with correct name', () => {
      const collection = diagnosticManager.getDiagnosticCollection();
      assert.ok(collection);
      assert.strictEqual(collection.name, 'vibeguard');
    });

    test('should clear all diagnostics', () => {
      const testIssue = createTestSecurityIssue();
      diagnosticManager.updateDiagnostics(mockDocument, [testIssue]);
      
      // Verify diagnostic was added
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics && diagnostics.length > 0);
      
      // Clear all diagnostics
      diagnosticManager.clearAllDiagnostics();
      
      // Verify all diagnostics are cleared
      const clearedDiagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(!clearedDiagnostics || clearedDiagnostics.length === 0);
    });

    test('should clear diagnostics for specific document', () => {
      const testIssue = createTestSecurityIssue();
      diagnosticManager.updateDiagnostics(mockDocument, [testIssue]);
      
      // Verify diagnostic was added
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics && diagnostics.length > 0);
      
      // Clear diagnostics for this document
      diagnosticManager.clearDiagnostics(mockDocument);
      
      // Verify diagnostics are cleared
      const clearedDiagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(!clearedDiagnostics || clearedDiagnostics.length === 0);
    });
  });

  suite('SecurityIssue to VSCode Diagnostic Conversion', () => {
    test('should convert API key issue to diagnostic correctly', () => {
      const apiKeyIssue: SecurityIssue = {
        id: 'test-api-key-1',
        code: 'API_KEY_OPENAI',
        category: SecurityCategory.API_KEY,
        severity: IssueSeverity.ERROR,
        message: '🔑 危险！OpenAI API 密钥暴露！这就是那个设计师损失 $5000 的原因！',
        description: 'OpenAI API 密钥不应该硬编码在代码中',
        location: {
          line: 0,
          column: 15,
          length: 20,
          startOffset: 15,
          endOffset: 35
        },
        quickFix: {
          title: '使用环境变量',
          replacement: 'process.env.OPENAI_API_KEY',
          description: '将硬编码的密钥替换为环境变量引用'
        },
        metadata: {
          ruleId: 'API_KEY_OPENAI',
          language: 'javascript',
          confidence: 0.95,
          impact: ImpactLevel.CRITICAL,
          effort: EffortLevel.EASY,
          tags: ['security', 'api-key']
        }
      };

      diagnosticManager.updateDiagnostics(mockDocument, [apiKeyIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 1);
      
      const diagnostic = diagnostics[0];
      assert.strictEqual(diagnostic.severity, vscode.DiagnosticSeverity.Error);
      assert.strictEqual(diagnostic.code, 'API_KEY_OPENAI');
      assert.strictEqual(diagnostic.source, 'VibeGuard');
      assert.ok(diagnostic.message.includes('OpenAI API 密钥暴露'));
      assert.ok(diagnostic.message.includes('建议：使用环境变量'));
      assert.ok(diagnostic.message.includes('修复难度：简单'));
      
      // Check range
      assert.strictEqual(diagnostic.range.start.line, 0);
      assert.strictEqual(diagnostic.range.start.character, 15);
      assert.strictEqual(diagnostic.range.end.line, 0);
      assert.strictEqual(diagnostic.range.end.character, 35);
    });

    test('should convert SQL danger issue to diagnostic correctly', () => {
      const sqlIssue: SecurityIssue = {
        id: 'test-sql-1',
        code: 'SQL_DELETE_NO_WHERE',
        category: SecurityCategory.SQL_DANGER,
        severity: IssueSeverity.ERROR,
        message: '💀 致命错误！DELETE 没有 WHERE 条件会删除整个表！',
        description: 'DELETE 语句缺少 WHERE 条件',
        location: {
          line: 2,
          column: 0,
          length: 25,
          startOffset: 40,
          endOffset: 65
        },
        quickFix: {
          title: '添加 WHERE 条件',
          replacement: 'DELETE FROM users WHERE id = ?;',
          description: '添加 WHERE 条件限制删除范围'
        },
        metadata: {
          ruleId: 'SQL_DELETE_NO_WHERE',
          language: 'sql',
          confidence: 0.9,
          impact: ImpactLevel.CRITICAL,
          effort: EffortLevel.MEDIUM,
          tags: ['sql', 'data-loss']
        }
      };

      diagnosticManager.updateDiagnostics(mockDocument, [sqlIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 1);
      
      const diagnostic = diagnostics[0];
      assert.strictEqual(diagnostic.severity, vscode.DiagnosticSeverity.Error);
      assert.strictEqual(diagnostic.code, 'SQL_DELETE_NO_WHERE');
      assert.ok(diagnostic.message.includes('DELETE 没有 WHERE 条件'));
      assert.ok(diagnostic.message.includes('建议：添加 WHERE 条件'));
      assert.ok(diagnostic.message.includes('修复难度：中等'));
    });

    test('should convert framework risk issue to diagnostic correctly', () => {
      const frameworkIssue: SecurityIssue = {
        id: 'test-framework-1',
        code: 'REACT_DANGEROUS_HTML',
        category: SecurityCategory.FRAMEWORK_RISK,
        severity: IssueSeverity.WARNING,
        message: '⚠️ React dangerouslySetInnerHTML 可能导致 XSS 攻击！',
        description: 'dangerouslySetInnerHTML 使用未经过滤的内容',
        location: {
          line: 5,
          column: 10,
          length: 30,
          startOffset: 110,
          endOffset: 140
        },
        metadata: {
          ruleId: 'REACT_DANGEROUS_HTML',
          language: 'javascript',
          confidence: 0.8,
          impact: ImpactLevel.HIGH,
          effort: EffortLevel.MEDIUM,
          tags: ['react', 'xss']
        }
      };

      diagnosticManager.updateDiagnostics(mockDocument, [frameworkIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 1);
      
      const diagnostic = diagnostics[0];
      assert.strictEqual(diagnostic.severity, vscode.DiagnosticSeverity.Warning);
      assert.strictEqual(diagnostic.code, 'REACT_DANGEROUS_HTML');
      assert.ok(diagnostic.message.includes('dangerouslySetInnerHTML'));
      assert.ok(diagnostic.message.includes('建议：使用框架提供的安全方法'));
    });

    test('should handle different severity levels correctly', () => {
      const issues: SecurityIssue[] = [
        createTestSecurityIssue({ severity: IssueSeverity.ERROR }),
        createTestSecurityIssue({ severity: IssueSeverity.WARNING }),
        createTestSecurityIssue({ severity: IssueSeverity.INFO })
      ];

      diagnosticManager.updateDiagnostics(mockDocument, issues);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 3);
      
      assert.strictEqual(diagnostics[0].severity, vscode.DiagnosticSeverity.Error);
      assert.strictEqual(diagnostics[1].severity, vscode.DiagnosticSeverity.Warning);
      assert.strictEqual(diagnostics[2].severity, vscode.DiagnosticSeverity.Information);
    });
  });

  suite('Message Enhancement', () => {
    test('should enhance API key messages with user-friendly tips', () => {
      const apiKeyIssue = createTestSecurityIssue({
        category: SecurityCategory.API_KEY,
        message: '🔑 危险！API 密钥暴露！',
        metadata: { 
          ruleId: 'API_KEY_TEST',
          language: 'javascript',
          confidence: 0.9,
          impact: ImpactLevel.HIGH,
          effort: EffortLevel.EASY,
          tags: ['test']
        }
      });

      diagnosticManager.updateDiagnostics(mockDocument, [apiKeyIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.message.includes('建议：使用环境变量存储密钥'));
      assert.ok(diagnostic.message.includes('修复难度：简单（一键修复）'));
    });

    test('should enhance SQL danger messages with specific tips', () => {
      const sqlIssue = createTestSecurityIssue({
        category: SecurityCategory.SQL_DANGER,
        message: '💀 致命错误！SQL 操作危险！',
        metadata: { 
          ruleId: 'SQL_TEST',
          language: 'sql',
          confidence: 0.9,
          impact: ImpactLevel.CRITICAL,
          effort: EffortLevel.MEDIUM,
          tags: ['test']
        }
      });

      diagnosticManager.updateDiagnostics(mockDocument, [sqlIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.message.includes('建议：添加 WHERE 条件限制操作范围'));
      assert.ok(diagnostic.message.includes('修复难度：中等（需要少量修改）'));
    });

    test('should enhance code injection messages with security tips', () => {
      const injectionIssue = createTestSecurityIssue({
        category: SecurityCategory.CODE_INJECTION,
        message: '⚠️ 代码注入风险！',
        metadata: { 
          ruleId: 'INJECTION_TEST',
          language: 'javascript',
          confidence: 0.8,
          impact: ImpactLevel.HIGH,
          effort: EffortLevel.HARD,
          tags: ['test']
        }
      });

      diagnosticManager.updateDiagnostics(mockDocument, [injectionIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.message.includes('建议：使用安全的替代方法处理用户输入'));
      assert.ok(diagnostic.message.includes('修复难度：困难（需要重构代码）'));
    });
  });

  suite('Related Information', () => {
    test('should create related information for issues with descriptions', () => {
      const issueWithDescription = createTestSecurityIssue({
        message: '简短消息',
        description: '这是详细的描述信息，解释了问题的具体原因和影响'
      });

      diagnosticManager.updateDiagnostics(mockDocument, [issueWithDescription]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.relatedInformation);
      assert.ok(diagnostic.relatedInformation.length > 0);
      
      const descriptionInfo = diagnostic.relatedInformation.find(info => 
        info.message.includes('详细说明')
      );
      assert.ok(descriptionInfo);
      assert.ok(descriptionInfo.message.includes('这是详细的描述信息'));
    });

    test('should create related information for quick fixes', () => {
      const issueWithQuickFix = createTestSecurityIssue({
        quickFix: {
          title: '使用环境变量',
          replacement: 'process.env.API_KEY',
          description: '将硬编码密钥替换为环境变量'
        }
      });

      diagnosticManager.updateDiagnostics(mockDocument, [issueWithQuickFix]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.relatedInformation);
      
      const quickFixInfo = diagnostic.relatedInformation.find(info => 
        info.message.includes('快速修复')
      );
      assert.ok(quickFixInfo);
      assert.ok(quickFixInfo.message.includes('使用环境变量'));
      assert.ok(quickFixInfo.message.includes('将硬编码密钥替换为环境变量'));
    });
  });

  suite('Diagnostic Tags', () => {
    test('should add unnecessary tag for critical API key issues', () => {
      const criticalApiKeyIssue = createTestSecurityIssue({
        category: SecurityCategory.API_KEY,
        severity: IssueSeverity.ERROR
      });

      diagnosticManager.updateDiagnostics(mockDocument, [criticalApiKeyIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(diagnostic.tags);
      assert.ok(diagnostic.tags.includes(vscode.DiagnosticTag.Unnecessary));
    });

    test('should not add unnecessary tag for non-API key issues', () => {
      const sqlIssue = createTestSecurityIssue({
        category: SecurityCategory.SQL_DANGER,
        severity: IssueSeverity.ERROR
      });

      diagnosticManager.updateDiagnostics(mockDocument, [sqlIssue]);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      const diagnostic = diagnostics![0];
      
      assert.ok(!diagnostic.tags || !diagnostic.tags.includes(vscode.DiagnosticTag.Unnecessary));
    });
  });

  suite('Diagnostic Grouping', () => {
    test('should group similar diagnostics when enabled', () => {
      const similarIssues = [
        createTestSecurityIssue({ code: 'API_KEY_OPENAI', location: { line: 0, column: 0, length: 10, startOffset: 0, endOffset: 10 } }),
        createTestSecurityIssue({ code: 'API_KEY_OPENAI', location: { line: 1, column: 0, length: 10, startOffset: 20, endOffset: 30 } }),
        createTestSecurityIssue({ code: 'API_KEY_OPENAI', location: { line: 2, column: 0, length: 10, startOffset: 40, endOffset: 50 } })
      ];

      const groupingManager = new DiagnosticManager({ groupSimilarIssues: true });
      groupingManager.updateDiagnostics(mockDocument, similarIssues);
      
      const diagnostics = groupingManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 1); // Should be grouped into one
      
      const groupedDiagnostic = diagnostics[0];
      assert.ok(groupedDiagnostic.message.includes('在此文件中发现 3 个相同问题'));
      
      groupingManager.dispose();
    });

    test('should not group different types of issues', () => {
      const differentIssues = [
        createTestSecurityIssue({ code: 'API_KEY_OPENAI' }),
        createTestSecurityIssue({ code: 'SQL_DELETE_NO_WHERE' }),
        createTestSecurityIssue({ code: 'REACT_DANGEROUS_HTML' })
      ];

      const groupingManager = new DiagnosticManager({ groupSimilarIssues: true });
      groupingManager.updateDiagnostics(mockDocument, differentIssues);
      
      const diagnostics = groupingManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 3); // Should not be grouped
      
      groupingManager.dispose();
    });

    test('should respect grouping configuration', () => {
      const similarIssues = [
        createTestSecurityIssue({ code: 'API_KEY_OPENAI' }),
        createTestSecurityIssue({ code: 'API_KEY_OPENAI' })
      ];

      const noGroupingManager = new DiagnosticManager({ groupSimilarIssues: false });
      noGroupingManager.updateDiagnostics(mockDocument, similarIssues);
      
      const diagnostics = noGroupingManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 2); // Should not be grouped
      
      noGroupingManager.dispose();
    });
  });

  suite('Diagnostic Limits', () => {
    test('should limit diagnostics per file', () => {
      const manyIssues = Array.from({ length: 100 }, (_, i) => 
        createTestSecurityIssue({ 
          id: `issue-${i}`,
          location: { line: i, column: 0, length: 10, startOffset: i * 20, endOffset: i * 20 + 10 }
        })
      );

      const limitedManager = new DiagnosticManager({ maxDiagnosticsPerFile: 25 });
      limitedManager.updateDiagnostics(mockDocument, manyIssues);
      
      const diagnostics = limitedManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 25); // Should be limited
      
      limitedManager.dispose();
    });
  });

  suite('Error Handling', () => {
    test('should handle conversion errors gracefully', () => {
      const invalidIssue = {
        ...createTestSecurityIssue(),
        location: null as any // Invalid location
      };

      // Should not throw
      assert.doesNotThrow(() => {
        diagnosticManager.updateDiagnostics(mockDocument, [invalidIssue]);
      });
    });

    test('should handle disposal errors gracefully', () => {
      // Should not throw even if already disposed
      diagnosticManager.dispose();
      assert.doesNotThrow(() => {
        diagnosticManager.dispose();
      });
    });

    test('should handle clear operations on disposed manager', () => {
      diagnosticManager.dispose();
      
      // Should not throw
      assert.doesNotThrow(() => {
        diagnosticManager.clearDiagnostics(mockDocument);
        diagnosticManager.clearAllDiagnostics();
      });
    });
  });

  suite('Real-World Scenarios', () => {
    test('should handle mixed severity issues correctly', () => {
      const mixedIssues: SecurityIssue[] = [
        createTestSecurityIssue({
          code: 'API_KEY_OPENAI',
          category: SecurityCategory.API_KEY,
          severity: IssueSeverity.ERROR,
          message: '🔑 危险！OpenAI API 密钥暴露！'
        }),
        createTestSecurityIssue({
          code: 'REACT_DANGEROUS_HTML',
          category: SecurityCategory.FRAMEWORK_RISK,
          severity: IssueSeverity.WARNING,
          message: '⚠️ React XSS 风险！',
          location: { line: 1, column: 0, length: 15, startOffset: 20, endOffset: 35 }
        }),
        createTestSecurityIssue({
          code: 'CONFIG_DEBUG_PROD',
          category: SecurityCategory.CONFIG_ERROR,
          severity: IssueSeverity.INFO,
          message: 'ℹ️ 生产环境配置建议',
          location: { line: 2, column: 0, length: 12, startOffset: 40, endOffset: 52 }
        })
      ];

      diagnosticManager.updateDiagnostics(mockDocument, mixedIssues);
      
      const diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.ok(diagnostics);
      assert.strictEqual(diagnostics.length, 3);
      
      // Check that each diagnostic has appropriate severity and enhanced messages
      const errorDiagnostic = diagnostics.find(d => d.severity === vscode.DiagnosticSeverity.Error);
      const warningDiagnostic = diagnostics.find(d => d.severity === vscode.DiagnosticSeverity.Warning);
      const infoDiagnostic = diagnostics.find(d => d.severity === vscode.DiagnosticSeverity.Information);
      
      assert.ok(errorDiagnostic);
      assert.ok(warningDiagnostic);
      assert.ok(infoDiagnostic);
      
      assert.ok(errorDiagnostic.message.includes('建议：使用环境变量'));
      assert.ok(warningDiagnostic.message.includes('建议：使用框架提供的安全方法'));
      assert.ok(infoDiagnostic.message.includes('建议：检查生产环境配置'));
    });

    test('should update diagnostics correctly when issues change', () => {
      // Initial issues
      const initialIssues = [createTestSecurityIssue({ code: 'API_KEY_OPENAI' })];
      diagnosticManager.updateDiagnostics(mockDocument, initialIssues);
      
      let diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.strictEqual(diagnostics!.length, 1);
      assert.strictEqual(diagnostics![0].code, 'API_KEY_OPENAI');
      
      // Updated issues
      const updatedIssues = [
        createTestSecurityIssue({ code: 'SQL_DELETE_NO_WHERE' }),
        createTestSecurityIssue({ code: 'REACT_DANGEROUS_HTML' })
      ];
      diagnosticManager.updateDiagnostics(mockDocument, updatedIssues);
      
      diagnostics = diagnosticManager.getDiagnosticCollection().get(mockDocument.uri);
      assert.strictEqual(diagnostics!.length, 2);
      assert.ok(diagnostics!.some(d => d.code === 'SQL_DELETE_NO_WHERE'));
      assert.ok(diagnostics!.some(d => d.code === 'REACT_DANGEROUS_HTML'));
      assert.ok(!diagnostics!.some(d => d.code === 'API_KEY_OPENAI'));
    });
  });

  // Helper function to create test SecurityIssue objects
  function createTestSecurityIssue(overrides: Partial<SecurityIssue> = {}): SecurityIssue {
    return {
      id: 'test-issue-1',
      code: 'TEST_RULE',
      category: SecurityCategory.API_KEY,
      severity: IssueSeverity.ERROR,
      message: '测试安全问题',
      description: '这是一个测试用的安全问题描述',
      location: {
        line: 0,
        column: 10,
        length: 15,
        startOffset: 10,
        endOffset: 25
      },
      quickFix: {
        title: '测试修复',
        replacement: 'process.env.TEST_VAR',
        description: '这是一个测试修复'
      },
      metadata: {
        ruleId: 'TEST_RULE',
        language: 'javascript',
        confidence: 0.9,
        impact: ImpactLevel.HIGH,
        effort: EffortLevel.EASY,
        tags: ['test']
      },
      ...overrides
    };
  }
});
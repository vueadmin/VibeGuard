/**
 * Unit tests for AnalysisEngine
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { AnalysisEngine } from '../../analyzer/AnalysisEngine';
import { IRuleEngine, SecurityIssue, DetectionRule, IssueSeverity, SecurityCategory, ImpactLevel, EffortLevel } from '../../types';

// Mock rule engine
class MockRuleEngine implements IRuleEngine {
  public executeRulesCalled = false;
  public lastText = '';
  public lastLanguage = '';
  public mockIssues: SecurityIssue[] = [];

  executeRules(text: string, language: string): SecurityIssue[] {
    this.executeRulesCalled = true;
    this.lastText = text;
    this.lastLanguage = language;
    return this.mockIssues;
  }

  registerRule(rule: DetectionRule): void {
    // Mock implementation
  }

  getRulesByCategory(category: string): DetectionRule[] {
    return [];
  }

  getEnabledRules(): DetectionRule[] {
    return [
      {
        id: 'API_KEY_OPENAI',
        category: 'api-key',
        severity: IssueSeverity.ERROR,
        pattern: /sk-[a-zA-Z0-9]{48}/g,
        message: 'API key detected',
        languages: ['javascript'],
        enabled: true,
        whitelist: []
      } as DetectionRule
    ];
  }

  reset() {
    this.executeRulesCalled = false;
    this.lastText = '';
    this.lastLanguage = '';
    this.mockIssues = [];
  }

  setMockIssues(issues: SecurityIssue[]) {
    this.mockIssues = issues;
  }
}

suite('AnalysisEngine Test Suite', () => {
  let analysisEngine: AnalysisEngine;
  let mockRuleEngine: MockRuleEngine;

  const mockSecurityIssue: SecurityIssue = {
    id: 'test-issue-1',
    code: 'API_KEY_HARDCODED',
    category: SecurityCategory.API_KEY,
    severity: IssueSeverity.ERROR,
    message: '🔑 危险！API 密钥硬编码！',
    description: 'Hardcoded API key detected',
    location: {
      line: 0,
      column: 15,
      length: 12,
      startOffset: 15,
      endOffset: 27
    },
    metadata: {
      ruleId: 'API_KEY_OPENAI',
      language: 'javascript',
      confidence: 0.9,
      impact: ImpactLevel.HIGH,
      effort: EffortLevel.EASY,
      tags: ['security', 'api-key']
    }
  };

  const mockTextDocument = {
    fileName: 'test.js',
    languageId: 'javascript',
    isUntitled: false,
    lineCount: 10,
    getText: () => 'const apiKey = "sk-test123";',
    uri: { toString: () => 'file:///test.js' },
    offsetAt: (position: vscode.Position) => position.line * 20 + position.character,
    lineAt: (line: number) => ({ text: 'const apiKey = "sk-test123";' })
  } as vscode.TextDocument;

  setup(() => {
    mockRuleEngine = new MockRuleEngine();
    analysisEngine = new AnalysisEngine();
    analysisEngine.setRuleEngine(mockRuleEngine);
  });

  teardown(() => {
    if (analysisEngine) {
      analysisEngine.dispose();
    }
  });

  test('should initialize with default performance guard', () => {
    const guard = analysisEngine.getPerformanceGuard();
    assert.strictEqual(guard.maxAnalysisTime, 5000);
    assert.strictEqual(guard.maxFileSize, 1024 * 1024);
    assert.strictEqual(guard.enableTimeout, true);
  });

  test('should accept custom performance guard', () => {
    const customEngine = new AnalysisEngine({
      maxAnalysisTime: 3000,
      maxFileSize: 512 * 1024
    });

    const guard = customEngine.getPerformanceGuard();
    assert.strictEqual(guard.maxAnalysisTime, 3000);
    assert.strictEqual(guard.maxFileSize, 512 * 1024);

    customEngine.dispose();
  });

  test('should set rule engine', () => {
    const newEngine = new AnalysisEngine();
    
    // Should not throw when setting rule engine
    assert.doesNotThrow(() => {
      newEngine.setRuleEngine(mockRuleEngine);
    });

    newEngine.dispose();
  });

  test('should analyze a valid document', async () => {
    mockRuleEngine.setMockIssues([mockSecurityIssue]);

    const issues = await analysisEngine.analyzeDocument(mockTextDocument);

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].id, mockSecurityIssue.id);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, true);
    assert.strictEqual(mockRuleEngine.lastText, 'const apiKey = "sk-test123";');
    assert.strictEqual(mockRuleEngine.lastLanguage, 'javascript');
  });

  test('should skip untitled documents', async () => {
    const untitledDoc = {
      ...mockTextDocument,
      isUntitled: true
    } as vscode.TextDocument;

    const issues = await analysisEngine.analyzeDocument(untitledDoc);

    assert.strictEqual(issues.length, 0);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, false);
  });

  test('should skip unsupported languages', async () => {
    const unsupportedDoc = {
      ...mockTextDocument,
      languageId: 'plaintext'
    } as vscode.TextDocument;

    const issues = await analysisEngine.analyzeDocument(unsupportedDoc);

    assert.strictEqual(issues.length, 0);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, false);
  });

  test('should analyze text content', async () => {
    mockRuleEngine.setMockIssues([mockSecurityIssue]);
    const text = 'const secret = "sk-test123";';
    
    const issues = await analysisEngine.analyzeText(text, 'javascript');

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, true);
    assert.strictEqual(mockRuleEngine.lastText, text);
    assert.strictEqual(mockRuleEngine.lastLanguage, 'javascript');
  });

  test('should skip empty text', async () => {
    const issues = await analysisEngine.analyzeText('', 'javascript');

    assert.strictEqual(issues.length, 0);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, false);
  });

  test('should skip unsupported languages in text analysis', async () => {
    const issues = await analysisEngine.analyzeText('test code', 'plaintext');

    assert.strictEqual(issues.length, 0);
    assert.strictEqual(mockRuleEngine.executeRulesCalled, false);
  });

  test('should perform incremental analysis', async () => {
    const mockChanges: vscode.TextDocumentContentChangeEvent[] = [
      {
        range: new vscode.Range(0, 0, 0, 10),
        rangeOffset: 0,
        rangeLength: 10,
        text: 'new content'
      }
    ];

    const issues = await analysisEngine.analyzeIncremental(mockTextDocument, mockChanges);

    assert.ok(Array.isArray(issues));
  });

  test('should handle empty changes in incremental analysis', async () => {
    const issues = await analysisEngine.analyzeIncremental(mockTextDocument, []);

    assert.strictEqual(issues.length, 0);
  });

  test('should handle missing rule engine gracefully', async () => {
    const engineWithoutRules = new AnalysisEngine();
    // Don't set rule engine

    const issues = await engineWithoutRules.analyzeDocument(mockTextDocument);
    assert.strictEqual(issues.length, 0);

    engineWithoutRules.dispose();
  });

  test('should update performance guard settings', () => {
    const newSettings = {
      maxAnalysisTime: 3000,
      maxFileSize: 512 * 1024
    };

    analysisEngine.updatePerformanceGuard(newSettings);
    const guard = analysisEngine.getPerformanceGuard();

    assert.strictEqual(guard.maxAnalysisTime, 3000);
    assert.strictEqual(guard.maxFileSize, 512 * 1024);
  });

  test('should provide cache statistics', () => {
    const stats = analysisEngine.getCacheStats();
    assert.ok(typeof stats.size === 'number');
    assert.ok(typeof stats.hitRate === 'number');
  });

  test('should clear cache', async () => {
    // Populate cache
    await analysisEngine.analyzeText('test code', 'javascript');
    
    // Clear cache
    analysisEngine.clearCache();
    
    const stats = analysisEngine.getCacheStats();
    assert.strictEqual(stats.size, 0);
  });

  test('should clean up resources on dispose', () => {
    analysisEngine.dispose();
    
    const stats = analysisEngine.getCacheStats();
    assert.strictEqual(stats.size, 0);
  });
});
/**
 * Unit tests for DocumentMonitor
 */

import * as assert from 'assert';
import * as vscode from 'vscode';
import { DocumentMonitor } from '../../monitor/DocumentMonitor';
import { IAnalysisEngine } from '../../types';

// Mock analysis engine
class MockAnalysisEngine implements IAnalysisEngine {
  public analyzeDocumentCalled = false;
  public analyzeTextCalled = false;
  public analyzeIncrementalCalled = false;

  async analyzeDocument(document: vscode.TextDocument) {
    this.analyzeDocumentCalled = true;
    return [];
  }

  async analyzeText(text: string, language: string) {
    this.analyzeTextCalled = true;
    return [];
  }

  async analyzeIncremental(document: vscode.TextDocument, changes: vscode.TextDocumentContentChangeEvent[]) {
    this.analyzeIncrementalCalled = true;
    return [];
  }

  setRuleEngine(ruleEngine: any): void {
    // Mock implementation
  }

  dispose(): void {
    // Mock implementation
  }

  reset() {
    this.analyzeDocumentCalled = false;
    this.analyzeTextCalled = false;
    this.analyzeIncrementalCalled = false;
  }
}

suite('DocumentMonitor Test Suite', () => {
  let documentMonitor: DocumentMonitor;
  let mockAnalysisEngine: MockAnalysisEngine;

  setup(() => {
    mockAnalysisEngine = new MockAnalysisEngine();
    documentMonitor = new DocumentMonitor(mockAnalysisEngine);
  });

  teardown(() => {
    if (documentMonitor) {
      documentMonitor.dispose();
    }
  });

  test('should initialize with default configuration', () => {
    assert.ok(documentMonitor);
    assert.strictEqual(documentMonitor.isActive(), false);
  });

  test('should have valid configuration', () => {
    const config = documentMonitor.getConfig();
    assert.strictEqual(config.enableRealTimeAnalysis, true);
    assert.strictEqual(config.debounceDelay, 500);
    assert.strictEqual(config.maxFileSize, 1024 * 1024);
    assert.ok(config.supportedLanguages.includes('javascript'));
  });

  test('should start and stop monitoring', () => {
    documentMonitor.startMonitoring();
    assert.strictEqual(documentMonitor.isActive(), true);

    documentMonitor.stopMonitoring();
    assert.strictEqual(documentMonitor.isActive(), false);
  });

  test('should not start monitoring twice', () => {
    documentMonitor.startMonitoring();
    assert.strictEqual(documentMonitor.isActive(), true);
    
    documentMonitor.startMonitoring(); // Should not throw or change state
    assert.strictEqual(documentMonitor.isActive(), true);
  });

  test('should update configuration', () => {
    const newConfig = {
      debounceDelay: 1000,
      maxFileSize: 2048
    };

    documentMonitor.updateConfig(newConfig);
    const config = documentMonitor.getConfig();

    assert.strictEqual(config.debounceDelay, 1000);
    assert.strictEqual(config.maxFileSize, 2048);
  });

  test('should handle document open events', () => {
    const mockDocument = {
      fileName: 'test.js',
      languageId: 'javascript',
      isUntitled: false,
      getText: () => 'const test = "value";'
    } as vscode.TextDocument;

    documentMonitor.startMonitoring();
    
    // This should not throw
    assert.doesNotThrow(() => {
      documentMonitor.onDocumentOpen(mockDocument);
    });
  });

  test('should handle document change events', () => {
    const mockDocument = {
      fileName: 'test.js',
      languageId: 'javascript',
      isUntitled: false,
      getText: () => 'const test = "value";'
    } as vscode.TextDocument;

    const mockChangeEvent = {
      document: mockDocument,
      contentChanges: [],
      reason: undefined
    } as vscode.TextDocumentChangeEvent;

    documentMonitor.startMonitoring();
    
    // This should not throw
    assert.doesNotThrow(() => {
      documentMonitor.onDocumentChange(mockChangeEvent);
    });
  });

  test('should handle missing analysis engine gracefully', () => {
    const monitorWithoutEngine = new DocumentMonitor(null as any);
    
    const mockDocument = {
      fileName: 'test.js',
      languageId: 'javascript',
      isUntitled: false,
      getText: () => 'const test = "value";'
    } as vscode.TextDocument;

    monitorWithoutEngine.startMonitoring();
    
    // Should not throw even with null engine
    assert.doesNotThrow(() => {
      monitorWithoutEngine.onDocumentOpen(mockDocument);
    });

    monitorWithoutEngine.dispose();
  });

  test('should clean up resources on dispose', () => {
    documentMonitor.startMonitoring();
    assert.strictEqual(documentMonitor.isActive(), true);

    documentMonitor.dispose();
    assert.strictEqual(documentMonitor.isActive(), false);
  });
});
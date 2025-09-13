/**
 * Document Monitor for VibeGuard
 * 
 * Monitors document events (open, edit, save) and triggers security analysis
 * with debouncing and file type filtering.
 */

import * as vscode from 'vscode';
import { IDocumentMonitor, IAnalysisEngine, VibeGuardConfig } from '../types';
import { 
  getLanguageFromDocument, 
  isLanguageSupported, 
  isFileSizeAcceptable,
  debounce,
  logInfo,
  logWarning,
  logError,
  getExtensionConfig
} from '../utils';

/**
 * Configuration for document monitoring
 */
export interface MonitorConfig {
  /** Debounce delay in milliseconds */
  debounceDelay: number;
  /** Supported programming languages */
  supportedLanguages: string[];
  /** Maximum file size in bytes */
  maxFileSize: number;
}

/**
 * Document monitor implementation
 */
export class DocumentMonitor implements IDocumentMonitor {
  private disposables: vscode.Disposable[] = [];
  private debouncedAnalyze: (document: vscode.TextDocument) => void;
  private config: VibeGuardConfig;
  private isMonitoring = false;

  constructor(private analysisEngine: IAnalysisEngine) {
    this.config = getExtensionConfig();
    
    // Create debounced analysis function
    this.debouncedAnalyze = debounce(
      (document: vscode.TextDocument) => this.triggerAnalysis(document),
      this.config.debounceDelay
    );
    
    logInfo('DocumentMonitor initialized', 'DocumentMonitor');
  }

  /**
   * Start monitoring document events
   */
  public startMonitoring(): void {
    if (this.isMonitoring) {
      logWarning('Document monitoring is already active', 'DocumentMonitor');
      return;
    }

    try {
      // Monitor document open events
      this.disposables.push(
        vscode.workspace.onDidOpenTextDocument(this.onDocumentOpen.bind(this))
      );

      // Monitor document change events
      this.disposables.push(
        vscode.workspace.onDidChangeTextDocument((event) => this.onDocumentChange(event))
      );

      // Monitor document save events
      this.disposables.push(
        vscode.workspace.onDidSaveTextDocument(this.onDocumentSave.bind(this))
      );

      // Monitor configuration changes
      this.disposables.push(
        vscode.workspace.onDidChangeConfiguration(this.onConfigurationChange.bind(this))
      );

      // Analyze currently open documents
      this.analyzeOpenDocuments();

      this.isMonitoring = true;
      logInfo('Document monitoring started', 'DocumentMonitor');
    } catch (error) {
      logError(error as Error, 'Failed to start document monitoring');
      throw error;
    }
  }

  /**
   * Stop monitoring document events
   */
  public stopMonitoring(): void {
    if (!this.isMonitoring) {
      return;
    }

    try {
      // Dispose all event listeners
      this.disposables.forEach(disposable => disposable.dispose());
      this.disposables = [];

      this.isMonitoring = false;
      logInfo('Document monitoring stopped', 'DocumentMonitor');
    } catch (error) {
      logError(error as Error, 'Failed to stop document monitoring');
    }
  }

  /**
   * Handle document open events
   */
  public onDocumentOpen(document: vscode.TextDocument): void {
    try {
      if (this.shouldAnalyzeDocument(document)) {
        logInfo(`Document opened: ${document.fileName}`, 'DocumentMonitor');
        this.debouncedAnalyze(document);
      }
    } catch (error) {
      logError(error as Error, `Failed to handle document open: ${document.fileName}`);
    }
  }

  /**
   * Handle document change events
   */
  public onDocumentChange(event: vscode.TextDocumentChangeEvent): void {
    try {
      if (this.shouldAnalyzeDocument(event.document)) {
        // Use debounced analysis for change events to avoid excessive analysis
        this.debouncedAnalyze(event.document);
      }
    } catch (error) {
      logError(error as Error, `Failed to handle document change: ${event.document.fileName}`);
    }
  }

  /**
   * Handle document save events
   */
  private onDocumentSave(document: vscode.TextDocument): void {
    try {
      if (this.shouldAnalyzeDocument(document)) {
        logInfo(`Document saved: ${document.fileName}`, 'DocumentMonitor');
        // Immediate analysis on save (no debouncing)
        this.triggerAnalysis(document);
      }
    } catch (error) {
      logError(error as Error, `Failed to handle document save: ${document.fileName}`);
    }
  }

  /**
   * Handle configuration changes
   */
  private onConfigurationChange(event: vscode.ConfigurationChangeEvent): void {
    if (event.affectsConfiguration('vibeguard')) {
      try {
        this.config = getExtensionConfig();
        
        // Recreate debounced function with new delay
        this.debouncedAnalyze = debounce(
          (document: vscode.TextDocument) => this.triggerAnalysis(document),
          this.config.debounceDelay
        );
        
        logInfo('Configuration updated', 'DocumentMonitor');
      } catch (error) {
        logError(error as Error, 'Failed to handle configuration change');
      }
    }
  }

  /**
   * Analyze all currently open documents
   */
  private analyzeOpenDocuments(): void {
    try {
      const openDocuments = vscode.workspace.textDocuments;
      let analyzedCount = 0;

      for (const document of openDocuments) {
        if (this.shouldAnalyzeDocument(document)) {
          this.debouncedAnalyze(document);
          analyzedCount++;
        }
      }

      if (analyzedCount > 0) {
        logInfo(`Analyzing ${analyzedCount} open documents`, 'DocumentMonitor');
      }
    } catch (error) {
      logError(error as Error, 'Failed to analyze open documents');
    }
  }

  /**
   * Check if a document should be analyzed
   */
  private shouldAnalyzeDocument(document: vscode.TextDocument): boolean {
    try {
      // Skip if real-time analysis is disabled
      if (!this.config.enableRealTimeAnalysis) {
        return false;
      }

      // Skip untitled documents
      if (document.isUntitled) {
        return false;
      }

      // Check language support
      const language = getLanguageFromDocument(document);
      if (!isLanguageSupported(language)) {
        return false;
      }

      // Check if language is in supported list
      if (!this.config.supportedLanguages.includes(language)) {
        return false;
      }

      // Check file size
      if (!isFileSizeAcceptable(document, this.config)) {
        logWarning(
          `File too large for analysis: ${document.fileName} (${document.getText().length} chars)`,
          'DocumentMonitor'
        );
        return false;
      }

      return true;
    } catch (error) {
      logError(error as Error, `Failed to check if document should be analyzed: ${document.fileName}`);
      return false;
    }
  }

  /**
   * Trigger analysis for a document
   */
  private async triggerAnalysis(document: vscode.TextDocument): Promise<void> {
    try {
      if (!this.analysisEngine) {
        logWarning('Analysis engine not available', 'DocumentMonitor');
        return;
      }

      logInfo(`Triggering analysis for: ${document.fileName}`, 'DocumentMonitor');
      
      // Trigger analysis (fire and forget - errors handled by analysis engine)
      this.analysisEngine.analyzeDocument(document).catch(error => {
        logError(error as Error, `Analysis failed for: ${document.fileName}`);
      });
    } catch (error) {
      logError(error as Error, `Failed to trigger analysis: ${document.fileName}`);
    }
  }

  /**
   * Get current monitoring status
   */
  public isActive(): boolean {
    return this.isMonitoring;
  }

  /**
   * Get current configuration
   */
  public getConfig(): VibeGuardConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<VibeGuardConfig>): void {
    try {
      this.config = { ...this.config, ...newConfig };
      
      // Update debounced function if delay changed
      if (newConfig.debounceDelay !== undefined) {
        this.debouncedAnalyze = debounce(
          (document: vscode.TextDocument) => this.triggerAnalysis(document),
          this.config.debounceDelay
        );
      }
      
      logInfo('Configuration updated programmatically', 'DocumentMonitor');
    } catch (error) {
      logError(error as Error, 'Failed to update configuration');
    }
  }

  /**
   * Dispose of all resources
   */
  public dispose(): void {
    this.stopMonitoring();
  }
}
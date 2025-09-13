/**
 * Analysis Engine for VibeGuard
 * 
 * Coordinates rule execution and result processing with performance protection
 * and incremental analysis capabilities.
 */

import * as vscode from 'vscode';
import { 
  IAnalysisEngine, 
  IRuleEngine, 
  SecurityIssue, 
  PerformanceGuard,
  VibeGuardError,
  ErrorCategory
} from '../types';
import { 
  getLanguageFromDocument,
  isLanguageSupported,
  isFileSizeAcceptable,
  executeWithTimeout,
  measureExecutionTime,
  createTimer,
  logInfo,
  logWarning,
  logError,
  getExtensionConfig
} from '../utils';
import { DEFAULT_PERFORMANCE_GUARD } from '../constants';

/**
 * Analysis result with performance metrics
 */
interface AnalysisResult {
  issues: SecurityIssue[];
  metrics: {
    duration: number;
    rulesExecuted: number;
    fileSize: number;
    language: string;
  };
}

/**
 * Analysis engine implementation
 */
export class AnalysisEngine implements IAnalysisEngine {
  private ruleEngine: IRuleEngine | null = null;
  private performanceGuard: PerformanceGuard;
  private analysisCache = new Map<string, { issues: SecurityIssue[]; timestamp: number }>();
  private readonly cacheTimeout = 30000; // 30 seconds

  constructor(performanceGuard?: Partial<PerformanceGuard>) {
    this.performanceGuard = { ...DEFAULT_PERFORMANCE_GUARD, ...performanceGuard };
    logInfo('AnalysisEngine initialized', 'AnalysisEngine');
  }

  /**
   * Set the rule engine for analysis
   */
  public setRuleEngine(ruleEngine: IRuleEngine): void {
    this.ruleEngine = ruleEngine;
    logInfo('Rule engine attached to analysis engine', 'AnalysisEngine');
  }

  /**
   * Analyze a complete document
   */
  public async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
    try {
      const timer = createTimer();
      
      // Validate document
      if (!this.validateDocument(document)) {
        return [];
      }

      const language = getLanguageFromDocument(document);
      const text = document.getText();
      
      logInfo(`Starting analysis for ${document.fileName} (${language})`, 'AnalysisEngine');

      // Check cache first
      const cacheKey = this.getCacheKey(document.uri.toString(), text);
      const cachedResult = this.getCachedResult(cacheKey);
      if (cachedResult) {
        logInfo(`Using cached result for ${document.fileName}`, 'AnalysisEngine');
        return cachedResult;
      }

      // Perform analysis with timeout protection
      const result = await this.performAnalysisWithProtection(text, language, document.fileName);
      
      if (result) {
        // Cache the result
        this.cacheResult(cacheKey, result.issues);
        
        logInfo(
          `Analysis completed for ${document.fileName}: ${result.issues.length} issues found in ${timer.elapsed()}ms`,
          'AnalysisEngine'
        );
        
        return result.issues;
      }

      return [];
    } catch (error) {
      this.handleAnalysisError(error as Error, document.fileName);
      return [];
    }
  }

  /**
   * Analyze text content
   */
  public async analyzeText(text: string, language: string): Promise<SecurityIssue[]> {
    try {
      if (!this.validateTextInput(text, language)) {
        return [];
      }

      logInfo(`Starting text analysis (${language}, ${text.length} chars)`, 'AnalysisEngine');

      // Check cache
      const cacheKey = this.getCacheKey(`text-${language}`, text);
      const cachedResult = this.getCachedResult(cacheKey);
      if (cachedResult) {
        return cachedResult;
      }

      // Perform analysis
      const result = await this.performAnalysisWithProtection(text, language, 'text-input');
      
      if (result) {
        this.cacheResult(cacheKey, result.issues);
        return result.issues;
      }

      return [];
    } catch (error) {
      this.handleAnalysisError(error as Error, 'text-input');
      return [];
    }
  }

  /**
   * Perform incremental analysis on document changes
   */
  public async analyzeIncremental(
    document: vscode.TextDocument,
    changes: vscode.TextDocumentContentChangeEvent[]
  ): Promise<SecurityIssue[]> {
    try {
      if (!this.validateDocument(document) || !changes.length) {
        return [];
      }

      const language = getLanguageFromDocument(document);
      logInfo(`Starting incremental analysis for ${document.fileName}`, 'AnalysisEngine');

      // For now, we'll implement a simple approach: analyze the entire document
      // In a more sophisticated implementation, we could analyze only the changed regions
      // and merge with existing results
      
      // Extract changed text regions with context
      const changedRegions = this.extractChangedRegions(document, changes);
      
      if (changedRegions.length === 0) {
        return [];
      }

      // If changes are too extensive, fall back to full document analysis
      const totalChangedChars = changedRegions.reduce((sum, region) => sum + region.length, 0);
      const documentSize = document.getText().length;
      
      if (totalChangedChars > documentSize * 0.3) { // More than 30% changed
        logInfo('Extensive changes detected, performing full analysis', 'AnalysisEngine');
        return this.analyzeDocument(document);
      }

      // Analyze changed regions
      const allIssues: SecurityIssue[] = [];
      
      for (const region of changedRegions) {
        const regionIssues = await this.analyzeText(region, language);
        allIssues.push(...regionIssues);
      }

      // Remove duplicates and adjust line numbers
      const uniqueIssues = this.deduplicateIssues(allIssues);
      
      logInfo(
        `Incremental analysis completed: ${uniqueIssues.length} issues found in changed regions`,
        'AnalysisEngine'
      );

      return uniqueIssues;
    } catch (error) {
      this.handleAnalysisError(error as Error, document.fileName);
      // Fall back to full document analysis on error
      return this.analyzeDocument(document);
    }
  }

  /**
   * Perform analysis with performance protection
   */
  private async performAnalysisWithProtection(
    text: string,
    language: string,
    fileName: string
  ): Promise<AnalysisResult | null> {
    if (!this.ruleEngine) {
      logWarning('Rule engine not available', 'AnalysisEngine');
      return null;
    }

    const operation = async (): Promise<AnalysisResult> => {
      const { result: issues, duration } = await measureExecutionTime(
        () => Promise.resolve(this.ruleEngine!.executeRules(text, language)),
        `Rule execution for ${fileName}`
      );

      return {
        issues,
        metrics: {
          duration,
          rulesExecuted: this.ruleEngine!.getEnabledRules().length,
          fileSize: text.length,
          language
        }
      };
    };

    if (this.performanceGuard.enableTimeout) {
      return executeWithTimeout(
        operation,
        this.performanceGuard.maxAnalysisTime,
        `Analysis timeout for ${fileName}`
      );
    }

    return operation();
  }

  /**
   * Validate document for analysis
   */
  private validateDocument(document: vscode.TextDocument): boolean {
    try {
      // Skip untitled documents
      if (document.isUntitled) {
        return false;
      }

      // Check language support
      const language = getLanguageFromDocument(document);
      if (!isLanguageSupported(language)) {
        return false;
      }

      // Check file size
      const config = getExtensionConfig();
      if (!isFileSizeAcceptable(document, config)) {
        logWarning(
          `File too large for analysis: ${document.fileName}`,
          'AnalysisEngine'
        );
        return false;
      }

      // Check performance guard limits
      const fileSize = Buffer.byteLength(document.getText(), 'utf8');
      if (fileSize > this.performanceGuard.maxFileSize) {
        logWarning(
          `File exceeds performance guard limit: ${document.fileName} (${fileSize} bytes)`,
          'AnalysisEngine'
        );
        return false;
      }

      return true;
    } catch (error) {
      logError(error as Error, `Document validation failed: ${document.fileName}`);
      return false;
    }
  }

  /**
   * Validate text input for analysis
   */
  private validateTextInput(text: string, language: string): boolean {
    if (!text || text.trim().length === 0) {
      return false;
    }

    if (!isLanguageSupported(language)) {
      return false;
    }

    const textSize = Buffer.byteLength(text, 'utf8');
    if (textSize > this.performanceGuard.maxFileSize) {
      logWarning(
        `Text input too large: ${textSize} bytes`,
        'AnalysisEngine'
      );
      return false;
    }

    return true;
  }

  /**
   * Extract changed regions from document changes
   */
  private extractChangedRegions(
    document: vscode.TextDocument,
    changes: vscode.TextDocumentContentChangeEvent[]
  ): string[] {
    const regions: string[] = [];
    const text = document.getText();

    try {
      for (const change of changes) {
        if (change.range) {
          // Get the changed region with some context
          const startLine = Math.max(0, change.range.start.line - 2);
          const endLine = Math.min(document.lineCount - 1, change.range.end.line + 2);
          
          const startOffset = document.offsetAt(new vscode.Position(startLine, 0));
          const endOffset = document.offsetAt(new vscode.Position(endLine, document.lineAt(endLine).text.length));
          
          const region = text.substring(startOffset, endOffset);
          if (region.trim()) {
            regions.push(region);
          }
        } else {
          // Full document change
          regions.push(text);
        }
      }
    } catch (error) {
      logError(error as Error, 'Failed to extract changed regions');
      // Fall back to full text
      regions.push(text);
    }

    return regions;
  }

  /**
   * Remove duplicate issues
   */
  private deduplicateIssues(issues: SecurityIssue[]): SecurityIssue[] {
    const seen = new Set<string>();
    const unique: SecurityIssue[] = [];

    for (const issue of issues) {
      const key = `${issue.code}-${issue.location.line}-${issue.location.column}-${issue.message}`;
      if (!seen.has(key)) {
        seen.add(key);
        unique.push(issue);
      }
    }

    return unique;
  }

  /**
   * Generate cache key for analysis results
   */
  private getCacheKey(identifier: string, content: string): string {
    // Simple hash function for cache key
    let hash = 0;
    const str = identifier + content;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString();
  }

  /**
   * Get cached analysis result
   */
  private getCachedResult(cacheKey: string): SecurityIssue[] | null {
    const cached = this.analysisCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.issues;
    }
    
    if (cached) {
      this.analysisCache.delete(cacheKey);
    }
    
    return null;
  }

  /**
   * Cache analysis result
   */
  private cacheResult(cacheKey: string, issues: SecurityIssue[]): void {
    // Limit cache size
    if (this.analysisCache.size > 100) {
      const oldestKey = this.analysisCache.keys().next().value;
      if (oldestKey) {
        this.analysisCache.delete(oldestKey);
      }
    }

    this.analysisCache.set(cacheKey, {
      issues: [...issues], // Deep copy
      timestamp: Date.now()
    });
  }

  /**
   * Clear analysis cache
   */
  public clearCache(): void {
    this.analysisCache.clear();
    logInfo('Analysis cache cleared', 'AnalysisEngine');
  }

  /**
   * Handle analysis errors
   */
  private handleAnalysisError(error: Error, context: string): void {
    const vibeGuardError = new VibeGuardError(
      `Analysis failed: ${error.message}`,
      'ANALYSIS_FAILED',
      ErrorCategory.ANALYSIS,
      true
    );

    logError(vibeGuardError, `Analysis error in ${context}`);
  }

  /**
   * Get performance metrics
   */
  public getPerformanceGuard(): PerformanceGuard {
    return { ...this.performanceGuard };
  }

  /**
   * Update performance guard settings
   */
  public updatePerformanceGuard(guard: Partial<PerformanceGuard>): void {
    this.performanceGuard = { ...this.performanceGuard, ...guard };
    logInfo('Performance guard updated', 'AnalysisEngine');
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.analysisCache.size,
      hitRate: 0 // TODO: Implement hit rate tracking
    };
  }

  /**
   * Dispose of resources
   */
  public dispose(): void {
    this.clearCache();
    this.ruleEngine = null;
    logInfo('AnalysisEngine disposed', 'AnalysisEngine');
  }
}
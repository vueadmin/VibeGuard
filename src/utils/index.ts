/**
 * Utility functions for VibeGuard
 */

import * as vscode from 'vscode';
import { SUPPORTED_EXTENSIONS, WHITELIST_PATTERNS, COMMON_PATTERNS } from '../constants';
import { SecurityIssue, IssueLocation, VibeGuardConfig } from '../types';

// ============================================================================
// Language Detection
// ============================================================================

/**
 * Get the programming language from a VSCode document
 */
export function getLanguageFromDocument(document: vscode.TextDocument): string {
  return document.languageId;
}

/**
 * Get the programming language from a file path
 */
export function getLanguageFromPath(filePath: string): string | null {
  const extension = getFileExtension(filePath);
  
  for (const [language, extensions] of Object.entries(SUPPORTED_EXTENSIONS)) {
    if ((extensions as readonly string[]).includes(extension)) {
      return language;
    }
  }
  
  return null;
}

/**
 * Check if a language is supported
 */
export function isLanguageSupported(language: string): boolean {
  return Object.keys(SUPPORTED_EXTENSIONS).includes(language);
}

/**
 * Get file extension from path
 */
export function getFileExtension(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  return lastDot === -1 ? '' : filePath.substring(lastDot);
}

// ============================================================================
// Text Processing
// ============================================================================

/**
 * Remove comments from code text
 */
export function removeComments(text: string, language: string): string {
  let result = text;
  
  switch (language) {
    case 'javascript':
    case 'typescript':
    case 'java':
    case 'csharp':
    case 'cpp':
    case 'c':
    case 'go':
    case 'rust':
      // Remove single-line comments
      result = result.replace(COMMON_PATTERNS.SINGLE_LINE_COMMENT, '');
      // Remove multi-line comments
      result = result.replace(COMMON_PATTERNS.MULTI_LINE_COMMENT, '');
      break;
      
    case 'python':
      result = result.replace(COMMON_PATTERNS.PYTHON_COMMENT, '');
      break;
      
    case 'sql':
      result = result.replace(COMMON_PATTERNS.SQL_COMMENT, '');
      break;
  }
  
  return result;
}

/**
 * Check if text contains environment variable references
 */
export function containsEnvVarReference(text: string): boolean {
  return COMMON_PATTERNS.ENV_VAR_REFERENCE.test(text);
}

/**
 * Check if text matches any whitelist pattern
 */
export function isWhitelisted(text: string): boolean {
  return WHITELIST_PATTERNS.some(pattern => 
    text.toLowerCase().includes(pattern.toLowerCase())
  );
}

/**
 * Extract line and column from text offset
 */
export function getLineAndColumn(text: string, offset: number): { line: number; column: number } {
  const lines = text.substring(0, offset).split('\n');
  return {
    line: lines.length - 1,
    column: lines[lines.length - 1].length
  };
}

/**
 * Create issue location from match result
 */
export function createIssueLocation(text: string, match: RegExpExecArray): IssueLocation {
  const startOffset = match.index!;
  const endOffset = startOffset + match[0].length;
  const { line, column } = getLineAndColumn(text, startOffset);
  
  return {
    line,
    column,
    length: match[0].length,
    startOffset,
    endOffset
  };
}

// ============================================================================
// Configuration
// ============================================================================

/**
 * Get extension configuration
 */
export function getExtensionConfig(): VibeGuardConfig {
  const config = vscode.workspace.getConfiguration('vibeguard');
  
  return {
    enableRealTimeAnalysis: config.get('enableRealTimeAnalysis', true),
    debounceDelay: config.get('debounceDelay', 500),
    maxFileSize: config.get('maxFileSize', 1024 * 1024),
    supportedLanguages: config.get('supportedLanguages', [
      'javascript', 'typescript', 'sql', 'json', 'yaml', 'python', 'java', 'csharp', 'php'
    ]),
    showQuickFixes: config.get('showQuickFixes', true)
  };
}

/**
 * Check if file size is within limits
 */
export function isFileSizeAcceptable(document: vscode.TextDocument, config: VibeGuardConfig): boolean {
  const fileSize = Buffer.byteLength(document.getText(), 'utf8');
  return fileSize <= config.maxFileSize;
}

// ============================================================================
// Debouncing
// ============================================================================

/**
 * Create a debounced function
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

// ============================================================================
// Error Handling
// ============================================================================

/**
 * Safely execute an async operation with timeout
 */
export async function executeWithTimeout<T>(
  operation: () => Promise<T>,
  timeout: number,
  timeoutMessage: string = '操作超时'
): Promise<T | null> {
  try {
    return await Promise.race([
      operation(),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error(timeoutMessage)), timeout)
      )
    ]);
  } catch (error) {
    console.warn('Operation failed or timed out:', error);
    return null;
  }
}

/**
 * Log error with context
 */
export function logError(error: Error, context: string): void {
  console.error(`[VibeGuard] ${context}:`, error);
}

/**
 * Log warning with context
 */
export function logWarning(message: string, context?: string): void {
  const fullMessage = context ? `[VibeGuard] ${context}: ${message}` : `[VibeGuard] ${message}`;
  console.warn(fullMessage);
}

/**
 * Log info with context
 */
export function logInfo(message: string, context?: string): void {
  const fullMessage = context ? `[VibeGuard] ${context}: ${message}` : `[VibeGuard] ${message}`;
  console.log(fullMessage);
}

// ============================================================================
// VSCode Integration
// ============================================================================

/**
 * Convert SecurityIssue to VSCode Diagnostic
 */
export function securityIssueToDiagnostic(issue: SecurityIssue): vscode.Diagnostic {
  const range = new vscode.Range(
    issue.location.line,
    issue.location.column,
    issue.location.line,
    issue.location.column + issue.location.length
  );
  
  const severity = issue.severity === 'error' 
    ? vscode.DiagnosticSeverity.Error
    : issue.severity === 'warning'
    ? vscode.DiagnosticSeverity.Warning
    : vscode.DiagnosticSeverity.Information;
  
  const diagnostic = new vscode.Diagnostic(range, issue.message, severity);
  diagnostic.code = issue.code;
  diagnostic.source = 'VibeGuard';
  
  return diagnostic;
}

/**
 * Show information message to user
 */
export function showInfoMessage(message: string): void {
  vscode.window.showInformationMessage(`VibeGuard: ${message}`);
}

/**
 * Show warning message to user
 */
export function showWarningMessage(message: string): void {
  vscode.window.showWarningMessage(`VibeGuard: ${message}`);
}

/**
 * Show error message to user
 */
export function showErrorMessage(message: string): void {
  vscode.window.showErrorMessage(`VibeGuard: ${message}`);
}

// ============================================================================
// Performance Utilities
// ============================================================================

/**
 * Measure execution time of a function
 */
export async function measureExecutionTime<T>(
  operation: () => Promise<T>,
  label: string
): Promise<{ result: T; duration: number }> {
  const startTime = Date.now();
  const result = await operation();
  const duration = Date.now() - startTime;
  
  logInfo(`${label} completed in ${duration}ms`);
  
  return { result, duration };
}

/**
 * Create a simple performance timer
 */
export function createTimer(): { elapsed: () => number } {
  const startTime = Date.now();
  return {
    elapsed: () => Date.now() - startTime
  };
}

// ============================================================================
// String Utilities
// ============================================================================

/**
 * Escape special regex characters
 */
export function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Generate unique ID
 */
export function generateId(): string {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
}

/**
 * Truncate text to specified length
 */
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) {
    return text;
  }
  return text.substring(0, maxLength - 3) + '...';
}
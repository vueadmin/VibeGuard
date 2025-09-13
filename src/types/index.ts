/**
 * Core type definitions for VibeGuard VSCode Extension
 * 
 * This file defines the fundamental interfaces and types used throughout
 * the extension to establish clear system boundaries and contracts.
 */

import * as vscode from 'vscode';

// ============================================================================
// Security Issue Types
// ============================================================================

/**
 * Represents a security issue found in code
 */
export interface SecurityIssue {
  /** Unique identifier for this issue */
  id: string;
  /** Issue code for categorization */
  code: string;
  /** Category of the security issue */
  category: SecurityCategory;
  /** Severity level */
  severity: IssueSeverity;
  /** Human-readable message in Chinese */
  message: string;
  /** Detailed description */
  description: string;
  /** Location in the document */
  location: IssueLocation;
  /** Optional quick fix suggestion */
  quickFix?: QuickFix;
  /** Additional metadata */
  metadata: IssueMetadata;
}

/**
 * Location information for a security issue
 */
export interface IssueLocation {
  /** Line number (0-based) */
  line: number;
  /** Column number (0-based) */
  column: number;
  /** Length of the problematic text */
  length: number;
  /** Start offset in the document */
  startOffset: number;
  /** End offset in the document */
  endOffset: number;
}

/**
 * Quick fix suggestion for a security issue
 */
export interface QuickFix {
  /** Title of the fix action */
  title: string;
  /** Replacement text or function */
  replacement: string;
  /** Description of what the fix does */
  description: string;
}

/**
 * Additional metadata for security issues
 */
export interface IssueMetadata {
  /** ID of the rule that detected this issue */
  ruleId: string;
  /** Programming language */
  language: string;
  /** Confidence level (0-1) */
  confidence: number;
  /** Impact level */
  impact: ImpactLevel;
  /** Effort required to fix */
  effort: EffortLevel;
  /** Additional tags */
  tags: string[];
}

// ============================================================================
// Enums
// ============================================================================

/**
 * Categories of security issues
 */
export enum SecurityCategory {
  API_KEY = 'api-key',
  SQL_DANGER = 'sql-danger',
  CODE_INJECTION = 'code-injection',
  FRAMEWORK_RISK = 'framework-risk',
  CONFIG_ERROR = 'config-error'
}

/**
 * Severity levels for issues
 */
export enum IssueSeverity {
  ERROR = 'error',
  WARNING = 'warning',
  INFO = 'info'
}

/**
 * Impact levels
 */
export enum ImpactLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Effort levels for fixes
 */
export enum EffortLevel {
  EASY = 'easy',
  MEDIUM = 'medium',
  HARD = 'hard'
}

// ============================================================================
// Rule Engine Types
// ============================================================================

/**
 * Interface for detection rules
 */
export interface DetectionRule {
  /** Unique rule identifier */
  id: string;
  /** Rule category */
  category: string;
  /** Default severity */
  severity: IssueSeverity;
  /** Regular expression pattern */
  pattern: RegExp;
  /** Error message template */
  message: string;
  /** Optional quick fix template */
  quickFix?: QuickFixTemplate;
  /** Whitelist patterns to ignore */
  whitelist?: string[];
  /** Supported languages */
  languages: string[];
  /** Whether the rule is enabled */
  enabled: boolean;
}

/**
 * Template for generating quick fixes
 */
export interface QuickFixTemplate {
  /** Title of the fix */
  title: string;
  /** Replacement text or function */
  replacement: string | ((match: RegExpExecArray) => string);
  /** Description of the fix */
  description: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Global configuration for the extension
 */
export interface VibeGuardConfig {
  /** Enable real-time analysis */
  enableRealTimeAnalysis: boolean;
  /** Debounce delay in milliseconds */
  debounceDelay: number;
  /** Maximum file size to analyze */
  maxFileSize: number;
  /** Supported programming languages */
  supportedLanguages: string[];
  /** Show quick fixes */
  showQuickFixes: boolean;
}

/**
 * Rule-specific configuration
 */
export interface RuleConfig {
  /** Rule settings by rule ID */
  rules: { [ruleId: string]: RuleSettings };
  /** Global settings */
  global: GlobalSettings;
}

/**
 * Settings for individual rules
 */
export interface RuleSettings {
  /** Whether the rule is enabled */
  enabled: boolean;
  /** Override severity */
  severity?: IssueSeverity;
  /** Custom message */
  customMessage?: string;
  /** Custom whitelist */
  whitelist?: string[];
}

/**
 * Global rule engine settings
 */
export interface GlobalSettings {
  /** Enable real-time analysis */
  enableRealTimeAnalysis: boolean;
  /** Debounce delay */
  debounceDelay: number;
  /** Maximum file size */
  maxFileSize: number;
  /** Supported languages */
  supportedLanguages: string[];
  /** Show quick fixes */
  showQuickFixes: boolean;
}

// ============================================================================
// Service Interfaces
// ============================================================================

/**
 * Document monitoring service interface
 */
export interface IDocumentMonitor {
  /** Start monitoring documents */
  startMonitoring(): void;
  /** Stop monitoring documents */
  stopMonitoring(): void;
  /** Handle document change events */
  onDocumentChange(event: vscode.TextDocumentChangeEvent): void;
  /** Handle document open events */
  onDocumentOpen(document: vscode.TextDocument): void;
  /** Dispose of resources */
  dispose(): void;
}

/**
 * Analysis engine interface
 */
export interface IAnalysisEngine {
  /** Analyze a complete document */
  analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]>;
  /** Analyze text content */
  analyzeText(text: string, language: string): Promise<SecurityIssue[]>;
  /** Perform incremental analysis */
  analyzeIncremental(
    document: vscode.TextDocument, 
    changes: vscode.TextDocumentContentChangeEvent[]
  ): Promise<SecurityIssue[]>;
  /** Set the rule engine */
  setRuleEngine(ruleEngine: IRuleEngine): void;
  /** Dispose of resources */
  dispose(): void;
}

/**
 * Rule engine interface
 */
export interface IRuleEngine {
  /** Execute all applicable rules */
  executeRules(text: string, language: string, filePath?: string): SecurityIssue[];
  /** Register a new rule */
  registerRule(rule: DetectionRule): void;
  /** Get rules by category */
  getRulesByCategory(category: string): DetectionRule[];
  /** Get all enabled rules */
  getEnabledRules(): DetectionRule[];
  /** Get statistics about registered rules */
  getStatistics(): {
    totalRules: number;
    enabledRules: number;
    rulesByCategory: { [category: string]: number };
    rulesBySeverity: { [severity: string]: number };
  };
}

/**
 * Diagnostic management interface
 */
export interface IDiagnosticManager {
  /** Update diagnostics for a document */
  updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]): void;
  /** Clear diagnostics for a document */
  clearDiagnostics(document: vscode.TextDocument): void;
  /** Get the diagnostic collection */
  getDiagnosticCollection(): vscode.DiagnosticCollection;
  /** Dispose of resources */
  dispose(): void;
}

/**
 * Quick fix provider interface
 */
export interface IQuickFixProvider extends vscode.CodeActionProvider {
  /** Provide code actions for diagnostics */
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.CodeAction[]>;
}

// ============================================================================
// Error Handling Types
// ============================================================================

/**
 * Custom error class for VibeGuard
 */
export class VibeGuardError extends Error {
  constructor(
    message: string,
    public code: string,
    public category: ErrorCategory,
    public recoverable: boolean = true
  ) {
    super(message);
    this.name = 'VibeGuardError';
  }
}

/**
 * Error categories
 */
export enum ErrorCategory {
  ANALYSIS = 'analysis',
  RULE = 'rule',
  SYSTEM = 'system',
  CONFIGURATION = 'configuration'
}

/**
 * Error handler interface
 */
export interface IErrorHandler {
  /** Handle analysis errors */
  handleAnalysisError(error: Error, document: vscode.TextDocument): void;
  /** Handle rule execution errors */
  handleRuleError(error: Error, rule: DetectionRule): void;
  /** Report general errors */
  reportError(error: Error, context: string): void;
}

// ============================================================================
// File Context Types
// ============================================================================

/**
 * File context information for enhanced whitelist filtering
 */
export interface FileContext {
  /** Whether this is a test file */
  isTestFile: boolean;
  /** Whether this is a documentation file */
  isDocumentationFile: boolean;
  /** Whether this is an example/demo file */
  isExampleFile: boolean;
  /** Whether this is a configuration file */
  isConfigFile: boolean;
  /** File path (if available) */
  filePath?: string;
  /** File extension */
  fileExtension?: string;
}

/**
 * File type classification
 */
export enum FileType {
  TEST = 'test',
  DOCUMENTATION = 'documentation',
  EXAMPLE = 'example',
  CONFIG = 'config',
  SOURCE = 'source',
  UNKNOWN = 'unknown'
}

// ============================================================================
// Performance Types
// ============================================================================

/**
 * Performance guard configuration
 */
export interface PerformanceGuard {
  /** Maximum analysis time in milliseconds */
  maxAnalysisTime: number;
  /** Maximum file size in bytes */
  maxFileSize: number;
  /** Maximum rules per analysis */
  maxRulesPerAnalysis: number;
  /** Enable timeout protection */
  enableTimeout: boolean;
}

/**
 * Performance metrics
 */
export interface PerformanceMetrics {
  /** Analysis duration in milliseconds */
  analysisDuration: number;
  /** Number of rules executed */
  rulesExecuted: number;
  /** Number of issues found */
  issuesFound: number;
  /** File size analyzed */
  fileSize: number;
  /** Timestamp */
  timestamp: number;
}
/**
 * Rule Engine Implementation
 * 
 * This class manages and executes detection rules for security issues.
 * It provides rule registration, execution, and whitelist filtering capabilities.
 */

import * as vscode from 'vscode';
import {
  DetectionRule,
  SecurityIssue,
  IRuleEngine,
  SecurityCategory,
  IssueSeverity,
  ImpactLevel,
  EffortLevel,
  IssueLocation,
  QuickFix,
  VibeGuardError,
  ErrorCategory
} from '../types';

/**
 * Default rule engine implementation
 */
export class RuleEngine implements IRuleEngine {
  private rules: Map<string, DetectionRule> = new Map();
  private rulesByCategory: Map<string, DetectionRule[]> = new Map();

  constructor() {
    this.initializeCategories();
  }

  /**
   * Initialize rule categories
   */
  private initializeCategories(): void {
    Object.values(SecurityCategory).forEach(category => {
      this.rulesByCategory.set(category, []);
    });
  }

  /**
   * Register a new detection rule
   */
  registerRule(rule: DetectionRule): void {
    try {
      // Validate rule
      this.validateRule(rule);

      // Store rule
      this.rules.set(rule.id, rule);

      // Add to category index
      if (!this.rulesByCategory.has(rule.category)) {
        this.rulesByCategory.set(rule.category, []);
      }
      this.rulesByCategory.get(rule.category)!.push(rule);

      console.log(`VibeGuard: 已注册规则 ${rule.id} (${rule.category})`);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new VibeGuardError(
        `规则注册失败: ${rule.id} - ${errorMessage}`,
        'RULE_REGISTRATION_FAILED',
        ErrorCategory.RULE,
        false
      );
    }
  }

  /**
   * Validate a detection rule
   */
  private validateRule(rule: DetectionRule): void {
    if (!rule.id || typeof rule.id !== 'string') {
      throw new Error('规则必须有有效的 ID');
    }

    if (!rule.pattern || !(rule.pattern instanceof RegExp)) {
      throw new Error('规则必须有有效的正则表达式模式');
    }

    if (!rule.message || typeof rule.message !== 'string') {
      throw new Error('规则必须有有效的错误信息');
    }

    if (!rule.category || typeof rule.category !== 'string') {
      throw new Error('规则必须有有效的分类');
    }

    if (!Object.values(IssueSeverity).includes(rule.severity)) {
      throw new Error('规则必须有有效的严重程度');
    }

    if (!Array.isArray(rule.languages)) {
      throw new Error('规则必须指定支持的语言列表');
    }

    if (this.rules.has(rule.id)) {
      throw new Error(`规则 ID 已存在: ${rule.id}`);
    }
  }

  /**
   * Execute all applicable rules on text
   */
  executeRules(text: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const enabledRules = this.getEnabledRules().filter(rule => 
      rule.languages.includes(language) || rule.languages.includes('*')
    );

    for (const rule of enabledRules) {
      try {
        const ruleIssues = this.executeRule(rule, text, language);
        issues.push(...ruleIssues);
      } catch (error) {
        console.warn(`VibeGuard: 规则执行失败 ${rule.id}:`, error);
        // Continue with other rules - don't let one rule failure break everything
      }
    }

    return issues;
  }

  /**
   * Execute a single rule
   */
  private executeRule(rule: DetectionRule, text: string, language: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const lines = text.split('\n');
    
    // Reset regex lastIndex to ensure consistent behavior
    rule.pattern.lastIndex = 0;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      let match: RegExpExecArray | null;

      // Reset pattern for each line
      rule.pattern.lastIndex = 0;

      while ((match = rule.pattern.exec(line)) !== null) {
        // Check whitelist before creating issue
        if (this.isWhitelisted(match[0], line, rule)) {
          // If global flag is set, continue to next match
          if (rule.pattern.global) {
            continue;
          } else {
            break;
          }
        }

        const issue = this.createSecurityIssue(rule, match, lineIndex, language, text);
        issues.push(issue);

        // If pattern is not global, break after first match
        if (!rule.pattern.global) {
          break;
        }
      }
    }

    return issues;
  }

  /**
   * Check if a match should be whitelisted
   */
  private isWhitelisted(matchText: string, line: string, rule: DetectionRule): boolean {
    // Check custom whitelist patterns first
    if (rule.whitelist && rule.whitelist.length > 0) {
      for (const whitelistPattern of rule.whitelist) {
        try {
          const regex = new RegExp(whitelistPattern, 'i');
          if (regex.test(line) || regex.test(matchText)) {
            return true;
          }
        } catch (error) {
          console.warn(`VibeGuard: 白名单模式无效 "${whitelistPattern}":`, error);
        }
      }
    }

    // Always check built-in whitelist
    return this.isBuiltInWhitelisted(matchText, line);
  }

  /**
   * Built-in whitelist checks for common false positives
   */
  private isBuiltInWhitelisted(matchText: string, line: string): boolean {
    // Skip environment variable references
    if (line.includes('process.env') || line.includes('$env:') || line.includes('${')) {
      return true;
    }

    // Skip comments
    if (line.trim().startsWith('//') || line.trim().startsWith('*') || line.trim().startsWith('#')) {
      return true;
    }

    // Skip template strings with variables
    if (line.includes('${') && line.includes('}')) {
      return true;
    }

    // Skip obvious placeholders
    const placeholderPatterns = [
      /your[_-]?api[_-]?key/i,
      /example[_-]?key/i,
      /placeholder/i,
      /xxx+/i,
      /\*+/,
      /\.{3,}/
    ];

    for (const pattern of placeholderPatterns) {
      if (pattern.test(matchText) || pattern.test(line)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Create a SecurityIssue from a rule match
   */
  private createSecurityIssue(
    rule: DetectionRule,
    match: RegExpExecArray,
    lineIndex: number,
    language: string,
    fullText: string
  ): SecurityIssue {
    const matchText = match[0];
    const columnIndex = match.index || 0;
    
    // Calculate offsets
    const lines = fullText.split('\n');
    let startOffset = 0;
    for (let i = 0; i < lineIndex; i++) {
      startOffset += lines[i].length + 1; // +1 for newline
    }
    startOffset += columnIndex;

    const location: IssueLocation = {
      line: lineIndex,
      column: columnIndex,
      length: matchText.length,
      startOffset,
      endOffset: startOffset + matchText.length
    };

    const quickFix = this.createQuickFix(rule, match);

    const issue: SecurityIssue = {
      id: `${rule.id}_${lineIndex}_${columnIndex}`,
      code: rule.id,
      category: rule.category as SecurityCategory,
      severity: rule.severity,
      message: rule.message,
      description: rule.message,
      location,
      ...(quickFix && { quickFix }),
      metadata: {
        ruleId: rule.id,
        language,
        confidence: 0.9, // High confidence for pattern matches
        impact: this.getImpactLevel(rule.category),
        effort: EffortLevel.EASY, // Most fixes are easy
        tags: [rule.category, language]
      }
    };

    return issue;
  }

  /**
   * Create a quick fix from rule template
   */
  private createQuickFix(rule: DetectionRule, match: RegExpExecArray): QuickFix | undefined {
    if (!rule.quickFix) {
      return undefined;
    }

    let replacement: string;
    if (typeof rule.quickFix.replacement === 'function') {
      replacement = rule.quickFix.replacement(match);
    } else {
      replacement = rule.quickFix.replacement;
    }

    return {
      title: rule.quickFix.title,
      replacement,
      description: rule.quickFix.description
    };
  }

  /**
   * Get impact level based on category
   */
  private getImpactLevel(category: string): ImpactLevel {
    switch (category) {
      case SecurityCategory.API_KEY:
        return ImpactLevel.CRITICAL;
      case SecurityCategory.SQL_DANGER:
        return ImpactLevel.CRITICAL;
      case SecurityCategory.CODE_INJECTION:
        return ImpactLevel.HIGH;
      case SecurityCategory.FRAMEWORK_RISK:
        return ImpactLevel.MEDIUM;
      case SecurityCategory.CONFIG_ERROR:
        return ImpactLevel.MEDIUM;
      default:
        return ImpactLevel.LOW;
    }
  }

  /**
   * Get rules by category
   */
  getRulesByCategory(category: string): DetectionRule[] {
    return this.rulesByCategory.get(category) || [];
  }

  /**
   * Get all enabled rules
   */
  getEnabledRules(): DetectionRule[] {
    return Array.from(this.rules.values()).filter(rule => rule.enabled);
  }

  /**
   * Get all rules
   */
  getAllRules(): DetectionRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Get rule by ID
   */
  getRule(id: string): DetectionRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Enable/disable a rule
   */
  setRuleEnabled(id: string, enabled: boolean): void {
    const rule = this.rules.get(id);
    if (rule) {
      rule.enabled = enabled;
      console.log(`VibeGuard: 规则 ${id} ${enabled ? '已启用' : '已禁用'}`);
    }
  }

  /**
   * Update rule severity
   */
  setRuleSeverity(id: string, severity: IssueSeverity): void {
    const rule = this.rules.get(id);
    if (rule) {
      rule.severity = severity;
      console.log(`VibeGuard: 规则 ${id} 严重程度已更新为 ${severity}`);
    }
  }

  /**
   * Clear all rules (useful for testing)
   */
  clearRules(): void {
    this.rules.clear();
    this.rulesByCategory.clear();
    this.initializeCategories();
  }

  /**
   * Get statistics about registered rules
   */
  getStatistics(): {
    totalRules: number;
    enabledRules: number;
    rulesByCategory: { [category: string]: number };
    rulesBySeverity: { [severity: string]: number };
  } {
    const allRules = this.getAllRules();
    const enabledRules = this.getEnabledRules();

    const rulesByCategory: { [category: string]: number } = {};
    const rulesBySeverity: { [severity: string]: number } = {};

    allRules.forEach(rule => {
      rulesByCategory[rule.category] = (rulesByCategory[rule.category] || 0) + 1;
      rulesBySeverity[rule.severity] = (rulesBySeverity[rule.severity] || 0) + 1;
    });

    return {
      totalRules: allRules.length,
      enabledRules: enabledRules.length,
      rulesByCategory,
      rulesBySeverity
    };
  }
}
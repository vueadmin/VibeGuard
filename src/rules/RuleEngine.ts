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
  ErrorCategory,
  FileContext,
  FileType
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
  executeRules(text: string, language: string, filePath?: string): SecurityIssue[] {
    const issues: SecurityIssue[] = [];
    const enabledRules = this.getEnabledRules().filter(rule => 
      rule.languages.includes(language) || rule.languages.includes('*')
    );

    // Determine file context for special handling
    const fileContext = this.getFileContext(filePath);

    for (const rule of enabledRules) {
      try {
        const ruleIssues = this.executeRule(rule, text, language, fileContext);
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
  private executeRule(rule: DetectionRule, text: string, language: string, fileContext: FileContext): SecurityIssue[] {
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
        if (this.isWhitelisted(match[0], line, rule, fileContext)) {
          // If global flag is set, continue to next match
          if (rule.pattern.global) {
            continue;
          } else {
            break;
          }
        }

        const issue = this.createSecurityIssue(rule, match, lineIndex, language, text, fileContext);
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
  private isWhitelisted(matchText: string, line: string, rule: DetectionRule, fileContext: FileContext): boolean {
    // Check file context based whitelist first
    if (this.isFileContextWhitelisted(matchText, line, rule, fileContext)) {
      return true;
    }

    // Check custom whitelist patterns
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
    return this.isBuiltInWhitelisted(matchText, line, rule);
  }

  /**
   * Built-in whitelist checks for common false positives
   */
  private isBuiltInWhitelisted(matchText: string, line: string, rule: DetectionRule): boolean {
    // Enhanced environment variable reference patterns
    if (this.isEnvironmentVariableReference(line)) {
      return true;
    }

    // Enhanced comment detection
    if (this.isCommentContent(line)) {
      return true;
    }

    // Enhanced template string variable detection
    if (this.isTemplateStringVariable(line, rule)) {
      return true;
    }

    // Skip obvious placeholders and example values
    if (this.isPlaceholderValue(matchText, line)) {
      return true;
    }

    return false;
  }

  /**
   * Enhanced environment variable reference detection
   * Supports various patterns for environment variable access
   */
  private isEnvironmentVariableReference(line: string): boolean {
    const envPatterns = [
      // Node.js style
      /process\.env\./,
      // PowerShell style
      /\$env:/,
      // Shell style
      /\$\{[A-Z_][A-Z0-9_]*\}/,
      /\$[A-Z_][A-Z0-9_]*/,
      // Python os.environ
      /os\.environ/,
      // Python os.getenv
      /os\.getenv/,
      // Dotenv style
      /dotenv\./,
      // Config object access
      /config\.[a-zA-Z_][a-zA-Z0-9_]*[Kk]ey/,
      /config\.[a-zA-Z_][a-zA-Z0-9_]*[Ss]ecret/,
      /config\.[a-zA-Z_][a-zA-Z0-9_]*[Tt]oken/,
      // Environment variable assignment patterns
      /=\s*process\.env/,
      /=\s*\$\{/,
      // Docker/Kubernetes env var patterns
      /\$\([A-Z_][A-Z0-9_]*\)/,
      // Terraform/HCL variable patterns
      /var\.[a-zA-Z_][a-zA-Z0-9_]*/,
      // AWS CloudFormation/CDK patterns
      /Ref:\s*[A-Z][a-zA-Z0-9]*/,
      /!Ref\s+[A-Z][a-zA-Z0-9]*/,
      // GitHub Actions secrets
      /secrets\.[A-Z_][A-Z0-9_]*/,
      // Azure DevOps variables
      /variables\.[a-zA-Z_][a-zA-Z0-9_]*/
    ];

    return envPatterns.some(pattern => pattern.test(line));
  }

  /**
   * Enhanced comment content detection
   * Detects various comment styles and documentation
   */
  private isCommentContent(line: string): boolean {
    const trimmedLine = line.trim();
    
    // Single line comments
    if (trimmedLine.startsWith('//') || 
        trimmedLine.startsWith('#') || 
        trimmedLine.startsWith('*') ||
        trimmedLine.startsWith('<!--') ||
        trimmedLine.startsWith('--') ||
        trimmedLine.startsWith(';') ||  // Assembly/Lisp comments
        trimmedLine.startsWith('%') ||  // LaTeX/Matlab comments
        trimmedLine.startsWith("'")) {  // VB comments
      return true;
    }

    // Multi-line comment content (inside /* */ blocks)
    if (trimmedLine.includes('/*') || trimmedLine.includes('*/')) {
      return true;
    }

    // JSDoc/documentation comments
    if (trimmedLine.startsWith('/**') || trimmedLine.includes('@param') || 
        trimmedLine.includes('@returns') || trimmedLine.includes('@example')) {
      return true;
    }

    // Markdown code blocks and documentation
    if (trimmedLine.startsWith('```') || trimmedLine.startsWith('~~~') ||
        trimmedLine.match(/^\s*\|.*\|.*\|/)) { // Markdown tables
      return true;
    }

    // YAML/JSON comments and documentation
    if (trimmedLine.match(/^\s*#.*:/) || // YAML comments with colons
        trimmedLine.includes('// @ts-ignore') ||
        trimmedLine.includes('// eslint-disable') ||
        trimmedLine.includes('// prettier-ignore')) {
      return true;
    }

    return false;
  }

  /**
   * Enhanced template string variable detection
   * Detects dynamic content that shouldn't be flagged as hardcoded
   */
  private isTemplateStringVariable(line: string, rule: DetectionRule): boolean {
    // Template literals with variables
    if (line.includes('${') && line.includes('}')) {
      // Code injection rules should still detect dangerous template usage
      if (rule.category === SecurityCategory.CODE_INJECTION) {
        // Only whitelist if the template contains obvious safe variables
        const safeVariablePatterns = [
          /\$\{[a-zA-Z_][a-zA-Z0-9_]*\}/,  // Simple variable names
          /\$\{config\./,                   // Config object access
          /\$\{process\.env\./,             // Environment variables
          /\$\{[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\}/ // Object property access
        ];
        return safeVariablePatterns.some(pattern => pattern.test(line));
      }
      return true;
    }

    // String interpolation patterns in various languages
    const interpolationPatterns = [
      // Python f-strings
      /f["'][^"']*\{[^}]+\}[^"']*["']/,
      // Python .format()
      /\.format\(/,
      // Python % formatting
      /%[sd]/,
      // Ruby string interpolation
      /#\{[^}]+\}/,
      // PHP variable interpolation
      /\$\{[^}]+\}/,
      // C# string interpolation
      /\$"[^"]*\{[^}]+\}[^"]*"/,
      // JavaScript template literals (already covered above)
      // Bash parameter expansion
      /\$\{[^}]+:-[^}]*\}/,
      // PowerShell string interpolation
      /"[^"]*\$\([^)]+\)[^"]*"/
    ];

    return interpolationPatterns.some(pattern => pattern.test(line));
  }

  /**
   * Enhanced placeholder value detection
   * Detects obvious example/placeholder values that shouldn't trigger warnings
   */
  private isPlaceholderValue(matchText: string, line: string): boolean {
    const placeholderPatterns = [
      // Generic placeholders
      /your[_-]?(?:api[_-]?)?key/i,
      /example[_-]?(?:api[_-]?)?key/i,
      /test[_-]?(?:api[_-]?)?key/i,
      /demo[_-]?(?:api[_-]?)?key/i,
      /sample[_-]?(?:api[_-]?)?key/i,
      /placeholder/i,
      /replace[_-]?me/i,
      /change[_-]?me/i,
      /todo/i,
      /fixme/i,
      
      // Obvious fake values
      /xxx+/i,
      /\*{3,}/,
      /\.{3,}/,
      /_{3,}/,
      /-{3,}/,
      /={3,}/,
      /0{8,}/,
      /1{8,}/,
      /abc+/i,
      /123+/,
      
      // Common test values
      /sk-test/i,
      /sk-fake/i,
      /sk-example/i,
      /akia[x0]{16}/i,
      /ghp_[x0]{36}/i,
      
      // Documentation patterns
      /\[your[_-]?key\]/i,
      /<your[_-]?key>/i,
      /\{your[_-]?key\}/i,
      /<api[_-]?key>/i,
      /\[api[_-]?key\]/i,
      /\{api[_-]?key\}/i,
      
      // Common placeholder domains and values
      /example\.com/i,
      /localhost/i,
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
      /username:password/i,
      /user:pass/i,
      /admin:admin/i,
      /root:root/i,
      /test:test/i,
      
      // Empty or very short values
      /^["']{2}$/,
      /^["']\w{1,3}["']$/,
      
      // Base64-like but obviously fake
      /^[A-Za-z0-9+/]{8,}={0,2}$/ // Only if it's all the same character repeated
    ];

    // Check if the match text or line contains placeholder patterns
    for (const pattern of placeholderPatterns) {
      if (pattern.test(matchText) || pattern.test(line)) {
        return true;
      }
    }

    // Check for repeated characters (likely placeholders)
    if (matchText.length > 8) {
      const uniqueChars = new Set(matchText.toLowerCase()).size;
      const repetitionRatio = uniqueChars / matchText.length;
      if (repetitionRatio < 0.3) { // Less than 30% unique characters
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
    fullText: string,
    fileContext: FileContext
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
    
    // Adjust severity based on file context
    const adjustedSeverity = this.adjustSeverityForFileContext(rule.severity, fileContext, rule);
    
    // Adjust confidence based on file context
    const adjustedConfidence = this.adjustConfidenceForFileContext(0.9, fileContext, rule);

    const issue: SecurityIssue = {
      id: `${rule.id}_${lineIndex}_${columnIndex}`,
      code: rule.id,
      category: rule.category as SecurityCategory,
      severity: adjustedSeverity,
      message: this.adjustMessageForFileContext(rule.message, fileContext),
      description: rule.message,
      location,
      ...(quickFix && { quickFix }),
      metadata: {
        ruleId: rule.id,
        language,
        confidence: adjustedConfidence,
        impact: this.getImpactLevel(rule.category),
        effort: EffortLevel.EASY, // Most fixes are easy
        tags: this.getTagsForFileContext([rule.category, language], fileContext)
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

  /**
   * Get file context information for enhanced whitelist filtering
   */
  private getFileContext(filePath?: string): FileContext {
    if (!filePath) {
      return {
        isTestFile: false,
        isDocumentationFile: false,
        isExampleFile: false,
        isConfigFile: false
      };
    }

    const fileName = filePath.toLowerCase();
    const fileExtension = fileName.split('.').pop() || '';

    return {
      isTestFile: this.isTestFile(fileName),
      isDocumentationFile: this.isDocumentationFile(fileName),
      isExampleFile: this.isExampleFile(fileName),
      isConfigFile: this.isConfigFile(fileName),
      filePath,
      fileExtension
    };
  }

  /**
   * Check if file is a test file
   */
  private isTestFile(fileName: string): boolean {
    const testPatterns = [
      // Common test file patterns
      /\.test\./,
      /\.spec\./,
      /_test\./,
      /_spec\./,
      /test_.*\./,
      /spec_.*\./,
      
      // Test directories
      /\/test\//,
      /\/tests\//,
      /\/spec\//,
      /\/specs\//,
      /\/__tests__\//,
      /\/__test__\//,
      /\/testing\//,
      
      // Framework specific
      /\.e2e\./,
      /\.integration\./,
      /\.unit\./,
      /cypress\//,
      /jest\//,
      /mocha\//,
      /vitest\//,
      
      // File names
      /^test/,
      /^spec/,
      /test\.js$/,
      /test\.ts$/,
      /spec\.js$/,
      /spec\.ts$/
    ];

    return testPatterns.some(pattern => pattern.test(fileName));
  }

  /**
   * Check if file is a documentation file
   */
  private isDocumentationFile(fileName: string): boolean {
    const docPatterns = [
      // Common documentation files
      /readme/,
      /changelog/,
      /license/,
      /contributing/,
      /code_of_conduct/,
      /security/,
      /support/,
      /authors/,
      /credits/,
      /acknowledgments/,
      
      // Documentation extensions
      /\.md$/,
      /\.rst$/,
      /\.txt$/,
      /\.adoc$/,
      /\.asciidoc$/,
      
      // Documentation directories
      /\/docs\//,
      /\/doc\//,
      /\/documentation\//,
      /\/wiki\//,
      /\/guide\//,
      /\/guides\//,
      /\/manual\//,
      /\/help\//,
      
      // API documentation
      /swagger/,
      /openapi/,
      /postman/,
      /insomnia/
    ];

    return docPatterns.some(pattern => pattern.test(fileName));
  }

  /**
   * Check if file is an example/demo file
   */
  private isExampleFile(fileName: string): boolean {
    const examplePatterns = [
      // Example file patterns
      /example/,
      /demo/,
      /sample/,
      /tutorial/,
      /playground/,
      /sandbox/,
      /template/,
      /boilerplate/,
      /starter/,
      /scaffold/,
      
      // Example directories
      /\/examples\//,
      /\/example\//,
      /\/demos\//,
      /\/demo\//,
      /\/samples\//,
      /\/sample\//,
      /\/tutorials\//,
      /\/tutorial\//,
      /\/playground\//,
      /\/templates\//,
      /\/template\//,
      
      // Common example file names
      /^example/,
      /^demo/,
      /^sample/,
      /\.example\./,
      /\.demo\./,
      /\.sample\./,
      /\.template\./
    ];

    return examplePatterns.some(pattern => pattern.test(fileName));
  }

  /**
   * Check if file is a configuration file
   */
  private isConfigFile(fileName: string): boolean {
    const configPatterns = [
      // Configuration file extensions
      /\.config\./,
      /\.conf$/,
      /\.cfg$/,
      /\.ini$/,
      /\.properties$/,
      /\.yaml$/,
      /\.yml$/,
      /\.toml$/,
      /\.json$/,
      /\.env$/,
      /\.env\./,
      
      // Specific config files
      /package\.json$/,
      /tsconfig/,
      /webpack/,
      /babel/,
      /eslint/,
      /prettier/,
      /jest\.config/,
      /vitest\.config/,
      /vite\.config/,
      /rollup\.config/,
      /gulpfile/,
      /gruntfile/,
      /makefile$/,
      /dockerfile$/,
      /docker-compose/,
      /\.gitignore$/,
      /\.gitattributes$/,
      /\.editorconfig$/,
      /\.nvmrc$/,
      /\.node-version$/,
      
      // Configuration directories
      /\/config\//,
      /\/configs\//,
      /\/configuration\//,
      /\/settings\//,
      /\/\.vscode\//,
      /\/\.github\//,
      /\/\.gitlab\//
    ];

    return configPatterns.some(pattern => pattern.test(fileName));
  }

  /**
   * Adjust severity based on file context
   */
  private adjustSeverityForFileContext(originalSeverity: IssueSeverity, fileContext: FileContext, rule: DetectionRule): IssueSeverity {
    // Test files: Reduce severity for most issues
    if (fileContext.isTestFile) {
      if (originalSeverity === IssueSeverity.ERROR) {
        return IssueSeverity.WARNING;
      }
      if (originalSeverity === IssueSeverity.WARNING) {
        return IssueSeverity.INFO;
      }
    }

    // Documentation and example files: Significantly reduce severity
    if (fileContext.isDocumentationFile || fileContext.isExampleFile) {
      if (originalSeverity === IssueSeverity.ERROR) {
        return IssueSeverity.INFO;
      }
      if (originalSeverity === IssueSeverity.WARNING) {
        return IssueSeverity.INFO;
      }
    }

    // Configuration files: Keep high severity for real issues, but reduce for templates
    if (fileContext.isConfigFile) {
      // If it looks like a template value, reduce severity
      if (rule.category === SecurityCategory.API_KEY) {
        return IssueSeverity.WARNING;
      }
    }

    return originalSeverity;
  }

  /**
   * Adjust confidence based on file context
   */
  private adjustConfidenceForFileContext(originalConfidence: number, fileContext: FileContext, rule: DetectionRule): number {
    // Test files: Lower confidence as they often contain fake data
    if (fileContext.isTestFile) {
      return Math.max(0.3, originalConfidence - 0.4);
    }

    // Documentation and example files: Much lower confidence
    if (fileContext.isDocumentationFile || fileContext.isExampleFile) {
      return Math.max(0.2, originalConfidence - 0.6);
    }

    // Configuration files: Moderate confidence reduction for templates
    if (fileContext.isConfigFile) {
      return Math.max(0.5, originalConfidence - 0.2);
    }

    return originalConfidence;
  }

  /**
   * Adjust message based on file context
   */
  private adjustMessageForFileContext(originalMessage: string, fileContext: FileContext): string {
    if (fileContext.isTestFile) {
      return `📝 测试文件中发现问题：${originalMessage}`;
    }

    if (fileContext.isDocumentationFile) {
      return `📚 文档文件中发现问题：${originalMessage}`;
    }

    if (fileContext.isExampleFile) {
      return `💡 示例文件中发现问题：${originalMessage}`;
    }

    if (fileContext.isConfigFile) {
      return `⚙️ 配置文件中发现问题：${originalMessage}`;
    }

    return originalMessage;
  }

  /**
   * Get tags based on file context
   */
  private getTagsForFileContext(baseTags: string[], fileContext: FileContext): string[] {
    const tags = [...baseTags];

    if (fileContext.isTestFile) {
      tags.push('test-file');
    }

    if (fileContext.isDocumentationFile) {
      tags.push('documentation');
    }

    if (fileContext.isExampleFile) {
      tags.push('example');
    }

    if (fileContext.isConfigFile) {
      tags.push('config');
    }

    if (fileContext.fileExtension) {
      tags.push(`ext-${fileContext.fileExtension}`);
    }

    return tags;
  }

  /**
   * File context based whitelist filtering
   */
  private isFileContextWhitelisted(matchText: string, line: string, rule: DetectionRule, fileContext: FileContext): boolean {
    // Test files: More lenient for API keys and secrets (often contain test data)
    if (fileContext.isTestFile) {
      // Allow obvious test values in test files
      const testValuePatterns = [
        /test/i,
        /mock/i,
        /fake/i,
        /dummy/i,
        /stub/i,
        /fixture/i,
        /spec/i
      ];

      if (testValuePatterns.some(pattern => pattern.test(matchText) || pattern.test(line))) {
        return true;
      }

      // For API key rules in test files, be more lenient
      if (rule.category === SecurityCategory.API_KEY) {
        // Allow shorter keys that are obviously for testing
        if (matchText.length < 20) {
          return true;
        }
        
        // Allow keys that contain test indicators
        if (/test|mock|fake|dummy|example/i.test(matchText)) {
          return true;
        }
      }
    }

    // Documentation files: Whitelist keys with clear doc indicators
    if (fileContext.isDocumentationFile) {
      if (rule.category === SecurityCategory.API_KEY) {
        // Whitelist keys that have clear documentation indicators
        const hasDocIndicators = /example|sample|your|replace|todo|fixme/i.test(line);
        if (hasDocIndicators) {
          return true;
        }
        // Otherwise, let it through to be detected but with reduced severity
      }
      
      // Be very lenient with SQL in documentation
      if (rule.category === SecurityCategory.SQL_DANGER) {
        return true;
      }
    }

    // Example files: Very lenient, similar to documentation
    if (fileContext.isExampleFile) {
      // Allow most patterns in example files
      if (rule.category === SecurityCategory.API_KEY || 
          rule.category === SecurityCategory.SQL_DANGER) {
        return true;
      }
    }

    // Configuration files: More strict but allow template values
    if (fileContext.isConfigFile) {
      // Allow template/placeholder values in config files
      const configPlaceholderPatterns = [
        /\$\{[^}]+\}/,           // Template variables
        /<%[^%]+%>/,             // EJS templates
        /\{\{[^}]+\}\}/,         // Handlebars templates
        /\[[^\]]+\]/,            // Bracket placeholders
        /<[^>]+>/,               // Angle bracket placeholders
        /your[_-]?/i,            // "your_api_key" style
        /replace[_-]?me/i,       // "replace_me" style
        /change[_-]?me/i,        // "change_me" style
        /set[_-]?me/i            // "set_me" style
      ];

      if (configPlaceholderPatterns.some(pattern => pattern.test(matchText) || pattern.test(line))) {
        return true;
      }
    }

    return false;
  }
}
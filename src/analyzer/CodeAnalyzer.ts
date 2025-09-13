import * as vscode from 'vscode';
import { RuleEngine } from '../rules/RuleEngine';
import { CacheManager } from '../cache/CacheManager';
import { Issue, RuleMatch } from '../types';
import { Logger } from '../utils/logger';

export class CodeAnalyzer {
    constructor(
        private ruleEngine: RuleEngine,
        private cache: CacheManager
    ) {}

    /**
     * \u589e\u91cf\u5206\u6790\u6587\u6863\u53d8\u66f4
     */
    async analyzeIncremental(event: vscode.TextDocumentChangeEvent): Promise<Issue[]> {
        const document = event.document;
        const cacheKey = document.uri.toString();
        
        // \u83b7\u53d6\u7f13\u5b58\u7684\u5206\u6790\u7ed3\u679c
        let cachedIssues = this.cache.get<Issue[]>(cacheKey) || [];
        
        // \u5904\u7406\u6bcf\u4e2a\u53d8\u66f4
        for (const change of event.contentChanges) {
            const startLine = change.range.start.line;
            const endLine = change.range.end.line;
            
            // \u79fb\u9664\u53d7\u5f71\u54cd\u884c\u7684\u65e7\u95ee\u9898
            cachedIssues = cachedIssues.filter(
                issue => issue.line < startLine || issue.line > endLine
            );
            
            // \u5206\u6790\u53d8\u66f4\u7684\u6587\u672c
            const lines = change.text.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const lineText = lines[i];
                const lineNumber = startLine + i;
                
                // \u68c0\u67e5\u8fd9\u4e00\u884c
                const lineIssues = await this.analyzeLine(
                    lineText,
                    document.languageId,
                    lineNumber
                );
                
                cachedIssues.push(...lineIssues);
            }

            // \u8c03\u6574\u540e\u7eed\u884c\u7684\u884c\u53f7
            const lineDiff = lines.length - 1 - (endLine - startLine);
            if (lineDiff !== 0) {
                cachedIssues = cachedIssues.map(issue => {
                    if (issue.line > endLine) {
                        return {
                            ...issue,
                            line: issue.line + lineDiff,
                            endLine: issue.endLine ? issue.endLine + lineDiff : undefined
                        };
                    }
                    return issue;
                });
            }
        }
        
        // \u66f4\u65b0\u7f13\u5b58
        this.cache.set(cacheKey, cachedIssues);
        
        return cachedIssues;
    }

    /**
     * \u5168\u6587\u6863\u5206\u6790
     */
    async analyzeFull(document: vscode.TextDocument): Promise<Issue[]> {
        const startTime = Date.now();
        const text = document.getText();
        const languageId = document.languageId;
        
        Logger.debug(`\u5f00\u59cb\u5206\u6790\u6587\u4ef6: ${document.uri.fsPath}`);
        
        // \u6267\u884c\u5b8c\u6574\u5206\u6790
        const issues = await this.analyzeText(text, languageId);
        
        // \u66f4\u65b0\u7f13\u5b58
        this.cache.set(document.uri.toString(), issues);
        
        const duration = Date.now() - startTime;
        Logger.debug(`\u6587\u4ef6\u5206\u6790\u5b8c\u6210: ${document.uri.fsPath}, \u8017\u65f6: ${duration}ms, \u95ee\u9898\u6570: ${issues.length}`);
        
        return issues;
    }

    /**
     * \u5206\u6790\u6587\u672c\u5185\u5bb9
     */
    private async analyzeText(text: string, languageId: string): Promise<Issue[]> {
        const issues: Issue[] = [];
        
        // \u83b7\u53d6\u9002\u7528\u7684\u89c4\u5219
        const rules = this.ruleEngine.getRulesForLanguage(languageId);
        
        // \u5e94\u7528\u6bcf\u4e2a\u89c4\u5219
        for (const rule of rules) {
            try {
                const matches = await this.checkRule(rule, text);
                
                for (const match of matches) {
                    issues.push({
                        line: match.line,
                        column: match.column,
                        endLine: match.endLine,
                        endColumn: match.endColumn,
                        severity: rule.severity,
                        message: rule.message,
                        code: rule.code,
                        quickFix: rule.quickFix
                    });
                }
            } catch (error) {
                Logger.error(`\u89c4\u5219 ${rule.code} \u6267\u884c\u5931\u8d25`, error);
            }
        }
        
        // \u6309\u884c\u53f7\u6392\u5e8f
        issues.sort((a, b) => a.line - b.line || a.column - b.column);
        
        return issues;
    }

    /**
     * \u5206\u6790\u5355\u884c\u6587\u672c
     */
    private async analyzeLine(lineText: string, languageId: string, lineNumber: number): Promise<Issue[]> {
        const issues: Issue[] = [];
        
        // \u83b7\u53d6\u9002\u7528\u7684\u89c4\u5219
        const rules = this.ruleEngine.getRulesForLanguage(languageId);
        
        // \u5e94\u7528\u6bcf\u4e2a\u89c4\u5219\u5230\u8fd9\u4e00\u884c
        for (const rule of rules) {
            if (!rule.pattern) continue; // \u53ea\u5904\u7406\u6b63\u5219\u89c4\u5219
            
            try {
                const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
                let match;
                
                while ((match = regex.exec(lineText)) !== null) {
                    issues.push({
                        line: lineNumber,
                        column: match.index,
                        endColumn: match.index + match[0].length,
                        severity: rule.severity,
                        message: rule.message,
                        code: rule.code,
                        quickFix: rule.quickFix
                    });
                    
                    // \u9632\u6b62\u65e0\u9650\u5faa\u73af
                    if (!regex.global) break;
                }
            } catch (error) {
                Logger.error(`\u5355\u884c\u89c4\u5219 ${rule.code} \u6267\u884c\u5931\u8d25`, error);
            }
        }
        
        return issues;
    }

    /**
     * \u68c0\u67e5\u5355\u4e2a\u89c4\u5219
     */
    private async checkRule(rule: any, text: string): Promise<RuleMatch[]> {
        const matches: RuleMatch[] = [];
        
        // \u5982\u679c\u89c4\u5219\u6709\u81ea\u5b9a\u4e49\u68c0\u67e5\u51fd\u6570
        if (rule.check) {
            return await rule.check(text);
        }
        
        // \u4f7f\u7528\u6b63\u5219\u8868\u8fbe\u5f0f\u5339\u914d
        if (rule.pattern) {
            const lines = text.split('\n');
            const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
            
            for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
                const line = lines[lineIndex];
                let match;
                
                // \u91cd\u7f6e\u6b63\u5219\u8868\u8fbe\u5f0f
                regex.lastIndex = 0;
                
                while ((match = regex.exec(line)) !== null) {
                    matches.push({
                        line: lineIndex,
                        column: match.index,
                        endColumn: match.index + match[0].length,
                        matchedText: match[0]
                    });
                    
                    // \u9632\u6b62\u65e0\u9650\u5faa\u73af
                    if (!regex.global) break;
                }
            }
        }
        
        return matches;
    }
}
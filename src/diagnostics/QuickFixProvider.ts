import * as vscode from 'vscode';
import { DiagnosticManager } from './DiagnosticManager';
import { RuleEngine } from '../rules/RuleEngine';
import { Logger } from '../utils/logger';

export class QuickFixProvider implements vscode.CodeActionProvider {
    constructor(
        private diagnosticManager: DiagnosticManager,
        private ruleEngine: RuleEngine
    ) {}

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // \u904d\u5386\u6240\u6709\u8bca\u65ad
        for (const diagnostic of context.diagnostics) {
            // \u53ea\u5904\u7406 VibeGuard \u7684\u8bca\u65ad
            if (diagnostic.source !== 'VibeGuard') {
                continue;
            }

            // \u83b7\u53d6\u89c4\u5219
            const rule = this.ruleEngine.getRuleByCode(diagnostic.code as string);
            if (!rule || !rule.quickFix) {
                continue;
            }

            // \u521b\u5efa\u5feb\u901f\u4fee\u590d\u52a8\u4f5c
            const action = new vscode.CodeAction(
                rule.quickFix.title,
                vscode.CodeActionKind.QuickFix
            );

            action.edit = new vscode.WorkspaceEdit();
            
            // \u83b7\u53d6\u9700\u8981\u66ff\u6362\u7684\u6587\u672c
            const diagnosticText = document.getText(diagnostic.range);
            
            // \u5e94\u7528\u4fee\u590d
            if (rule.quickFix.replacement !== undefined) {
                action.edit.replace(
                    document.uri,
                    diagnostic.range,
                    rule.quickFix.replacement
                );
            } else if (rule.quickFix.transform) {
                // \u4f7f\u7528\u8f6c\u6362\u51fd\u6570
                const newText = rule.quickFix.transform(diagnosticText);
                action.edit.replace(
                    document.uri,
                    diagnostic.range,
                    newText
                );
            }

            action.diagnostics = [diagnostic];
            action.isPreferred = true;
            
            actions.push(action);

            // \u6dfb\u52a0"\u5ffd\u7565\u6b64\u95ee\u9898"\u9009\u9879
            const ignoreAction = this.createIgnoreAction(document, diagnostic);
            if (ignoreAction) {
                actions.push(ignoreAction);
            }

            // \u6dfb\u52a0"\u7981\u7528\u6b64\u89c4\u5219"\u9009\u9879
            const disableRuleAction = this.createDisableRuleAction(document, diagnostic, rule.code);
            if (disableRuleAction) {
                actions.push(disableRuleAction);
            }
        }

        return actions;
    }

    /**
     * \u521b\u5efa\u5ffd\u7565\u6b64\u95ee\u9898\u7684\u52a8\u4f5c
     */
    private createIgnoreAction(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction | null {
        const line = diagnostic.range.start.line;
        const lineText = document.lineAt(line).text;
        
        // \u68c0\u67e5\u8bed\u8a00\u7c7b\u578b
        const languageId = document.languageId;
        let commentPrefix = '//';
        let ignoreComment = '';
        
        if (languageId === 'python') {
            commentPrefix = '#';
            ignoreComment = `${commentPrefix} vibeguard-ignore-next-line`;
        } else if (languageId === 'sql') {
            commentPrefix = '--';
            ignoreComment = `${commentPrefix} vibeguard-ignore-next-line`;
        } else if (['javascript', 'typescript', 'javascriptreact', 'typescriptreact', 'vue'].includes(languageId)) {
            ignoreComment = `// vibeguard-ignore-next-line`;
        } else {
            return null;
        }

        const action = new vscode.CodeAction(
            '\u5ffd\u7565\u6b64\u95ee\u9898',
            vscode.CodeActionKind.QuickFix
        );

        action.edit = new vscode.WorkspaceEdit();
        
        // \u5728\u5f53\u524d\u884c\u4e4b\u524d\u63d2\u5165\u5ffd\u7565\u6ce8\u91ca
        const position = new vscode.Position(line, 0);
        const indentation = lineText.match(/^\s*/)?.[0] || '';
        action.edit.insert(
            document.uri,
            position,
            `${indentation}${ignoreComment}\n`
        );

        action.diagnostics = [diagnostic];
        
        return action;
    }

    /**
     * \u521b\u5efa\u7981\u7528\u89c4\u5219\u7684\u52a8\u4f5c
     */
    private createDisableRuleAction(document: vscode.TextDocument, diagnostic: vscode.Diagnostic, ruleCode: string): vscode.CodeAction | null {
        const action = new vscode.CodeAction(
            `\u7981\u7528\u89c4\u5219 ${ruleCode}`,
            vscode.CodeActionKind.QuickFix
        );

        action.edit = new vscode.WorkspaceEdit();
        
        // \u5728\u6587\u4ef6\u5f00\u5934\u6dfb\u52a0\u7981\u7528\u6ce8\u91ca
        const languageId = document.languageId;
        let disableComment = '';
        
        if (languageId === 'python') {
            disableComment = `# vibeguard-disable ${ruleCode}\n`;
        } else if (languageId === 'sql') {
            disableComment = `-- vibeguard-disable ${ruleCode}\n`;
        } else {
            disableComment = `// vibeguard-disable ${ruleCode}\n`;
        }

        action.edit.insert(
            document.uri,
            new vscode.Position(0, 0),
            disableComment
        );

        action.diagnostics = [diagnostic];
        
        return action;
    }
}
import * as vscode from 'vscode';
import { Issue } from '../types';
import { Logger } from '../utils/logger';

export class DiagnosticManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private issueMap: Map<string, Issue[]> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');
    }

    /**
     * \u66f4\u65b0\u6587\u6863\u7684\u8bca\u65ad\u4fe1\u606f
     */
    updateDiagnostics(document: vscode.TextDocument, issues: Issue[]) {
        const diagnostics: vscode.Diagnostic[] = [];
        
        for (const issue of issues) {
            const diagnostic = this.createDiagnostic(issue, document);
            diagnostics.push(diagnostic);
        }

        // \u4fdd\u5b58\u95ee\u9898\u5217\u8868\u4ee5\u4fbf\u5feb\u901f\u4fee\u590d\u4f7f\u7528
        this.issueMap.set(document.uri.toString(), issues);
        
        // \u8bbe\u7f6e\u8bca\u65ad
        this.diagnosticCollection.set(document.uri, diagnostics);
        
        Logger.debug(`\u66f4\u65b0\u8bca\u65ad: ${document.uri.fsPath}, \u95ee\u9898\u6570: ${issues.length}`);
    }

    /**
     * \u521b\u5efa\u5355\u4e2a\u8bca\u65ad\u5bf9\u8c61
     */
    private createDiagnostic(issue: Issue, document: vscode.TextDocument): vscode.Diagnostic {
        // \u521b\u5efa\u8303\u56f4
        const startPos = new vscode.Position(issue.line, issue.column);
        const endPos = issue.endLine !== undefined && issue.endColumn !== undefined
            ? new vscode.Position(issue.endLine, issue.endColumn)
            : new vscode.Position(issue.line, Math.min(issue.column + 20, document.lineAt(issue.line).text.length));
        
        const range = new vscode.Range(startPos, endPos);
        
        // \u521b\u5efa\u8bca\u65ad
        const diagnostic = new vscode.Diagnostic(
            range,
            issue.message,
            this.mapSeverity(issue.severity)
        );
        
        // \u8bbe\u7f6e\u989d\u5916\u5c5e\u6027
        diagnostic.code = issue.code;
        diagnostic.source = 'VibeGuard';
        
        // \u6dfb\u52a0\u76f8\u5173\u4fe1\u606f
        if (issue.quickFix) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `\u5feb\u901f\u4fee\u590d: ${issue.quickFix.title}`
                )
            ];
        }
        
        return diagnostic;
    }

    /**
     * \u6620\u5c04\u4e25\u91cd\u7ea7\u522b
     */
    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'error':
                return vscode.DiagnosticSeverity.Error;
            case 'warning':
                return vscode.DiagnosticSeverity.Warning;
            case 'info':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    /**
     * \u83b7\u53d6\u6587\u6863\u7684\u95ee\u9898\u5217\u8868
     */
    getIssues(documentUri: string): Issue[] {
        return this.issueMap.get(documentUri) || [];
    }

    /**
     * \u6e05\u9664\u6307\u5b9a\u6587\u6863\u7684\u8bca\u65ad
     */
    clearDocumentDiagnostics(document: vscode.TextDocument) {
        this.diagnosticCollection.delete(document.uri);
        this.issueMap.delete(document.uri.toString());
    }

    /**
     * \u6e05\u9664\u6240\u6709\u8bca\u65ad
     */
    clearAll() {
        this.diagnosticCollection.clear();
        this.issueMap.clear();
    }

    /**
     * \u91ca\u653e\u8d44\u6e90
     */
    dispose() {
        this.diagnosticCollection.dispose();
        this.issueMap.clear();
    }
}
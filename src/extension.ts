import * as vscode from 'vscode';
import { CodeAnalyzer } from './analyzer/CodeAnalyzer';
import { DiagnosticManager } from './diagnostics/DiagnosticManager';
import { RuleEngine } from './rules/RuleEngine';
import { CacheManager } from './cache/CacheManager';
import { Settings } from './config/Settings';
import { QuickFixProvider } from './diagnostics/QuickFixProvider';
import { debounce } from './utils/debounce';
import { Logger } from './utils/logger';

let analyzer: CodeAnalyzer;
let diagnosticManager: DiagnosticManager;
let settings: Settings;
let isEnabled = true;

export function activate(context: vscode.ExtensionContext) {
    Logger.info('VibeGuard \u6b63\u5728\u542f\u52a8...');

    // \u521d\u59cb\u5316\u6838\u5fc3\u7ec4\u4ef6
    settings = new Settings();
    const cache = new CacheManager();
    const ruleEngine = new RuleEngine(settings);
    analyzer = new CodeAnalyzer(ruleEngine, cache);
    diagnosticManager = new DiagnosticManager();

    // \u83b7\u53d6\u914d\u7f6e
    const config = vscode.workspace.getConfiguration('vibeguard');
    isEnabled = config.get<boolean>('enable', true);
    const debounceDelay = config.get<number>('debounceDelay', 500);

    // \u6ce8\u518c\u6587\u6863\u53d8\u66f4\u76d1\u542c
    const documentChangeListener = vscode.workspace.onDidChangeTextDocument(
        debounce(async (event) => {
            if (!isEnabled || !shouldAnalyze(event.document)) {
                return;
            }
            try {
                const issues = await analyzer.analyzeIncremental(event);
                diagnosticManager.updateDiagnostics(event.document, issues);
            } catch (error) {
                Logger.error('\u589e\u91cf\u5206\u6790\u5931\u8d25', error);
            }
        }, debounceDelay)
    );

    // \u6ce8\u518c\u6587\u4ef6\u4fdd\u5b58\u76d1\u542c
    const saveListener = vscode.workspace.onDidSaveTextDocument(
        async (document) => {
            if (!isEnabled || !shouldAnalyze(document)) {
                return;
            }
            try {
                const issues = await analyzer.analyzeFull(document);
                diagnosticManager.updateDiagnostics(document, issues);
            } catch (error) {
                Logger.error('\u5168\u6587\u4ef6\u5206\u6790\u5931\u8d25', error);
            }
        }
    );

    // \u6ce8\u518c\u6587\u4ef6\u6253\u5f00\u76d1\u542c
    const openListener = vscode.workspace.onDidOpenTextDocument(
        async (document) => {
            if (!isEnabled || !shouldAnalyze(document)) {
                return;
            }
            try {
                const issues = await analyzer.analyzeFull(document);
                diagnosticManager.updateDiagnostics(document, issues);
            } catch (error) {
                Logger.error('\u6253\u5f00\u6587\u4ef6\u5206\u6790\u5931\u8d25', error);
            }
        }
    );

    // \u6ce8\u518c\u5feb\u901f\u4fee\u590d\u63d0\u4f9b\u8005
    const quickFixProvider = vscode.languages.registerCodeActionsProvider(
        { pattern: '**/*' },
        new QuickFixProvider(diagnosticManager, ruleEngine),
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    );

    // \u6ce8\u518c\u626b\u63cf\u5de5\u4f5c\u533a\u547d\u4ee4
    const scanCommand = vscode.commands.registerCommand(
        'vibeguard.scanWorkspace',
        async () => {
            if (!isEnabled) {
                vscode.window.showWarningMessage('VibeGuard \u5f53\u524d\u5df2\u7981\u7528');
                return;
            }
            await scanWorkspace(analyzer, diagnosticManager);
        }
    );

    // \u6ce8\u518c\u542f\u7528/\u7981\u7528\u547d\u4ee4
    const toggleCommand = vscode.commands.registerCommand(
        'vibeguard.toggleEnable',
        async () => {
            isEnabled = !isEnabled;
            await vscode.workspace.getConfiguration('vibeguard').update('enable', isEnabled, true);
            
            if (isEnabled) {
                vscode.window.showInformationMessage('VibeGuard \u5df2\u542f\u7528');
                await scanOpenDocuments(analyzer, diagnosticManager);
            } else {
                vscode.window.showInformationMessage('VibeGuard \u5df2\u7981\u7528');
                diagnosticManager.clearAll();
            }
        }
    );

    // \u6ce8\u518c\u914d\u7f6e\u53d8\u66f4\u76d1\u542c
    const configChangeListener = vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('vibeguard')) {
            const config = vscode.workspace.getConfiguration('vibeguard');
            isEnabled = config.get<boolean>('enable', true);
            settings.reload();
            
            if (isEnabled) {
                scanOpenDocuments(analyzer, diagnosticManager);
            } else {
                diagnosticManager.clearAll();
            }
        }
    });

    // \u6dfb\u52a0\u5230\u8ba2\u9605\u5217\u8868
    context.subscriptions.push(
        documentChangeListener,
        saveListener,
        openListener,
        quickFixProvider,
        scanCommand,
        toggleCommand,
        configChangeListener,
        diagnosticManager
    );

    // \u521d\u59cb\u626b\u63cf\u5df2\u6253\u5f00\u7684\u6587\u6863
    if (isEnabled) {
        scanOpenDocuments(analyzer, diagnosticManager);
    }

    // \u663e\u793a\u542f\u52a8\u6d88\u606f
    vscode.window.showInformationMessage('VibeGuard \u5df2\u542f\u52a8\uff0c\u5f00\u59cb\u4fdd\u62a4\u4f60\u7684\u4ee3\u7801\u5b89\u5168\uff01');
    Logger.info('VibeGuard \u542f\u52a8\u6210\u529f');
}

export function deactivate() {
    Logger.info('VibeGuard \u6b63\u5728\u5173\u95ed...');
    diagnosticManager?.dispose();
}

/**
 * \u68c0\u67e5\u6587\u6863\u662f\u5426\u5e94\u8be5\u88ab\u5206\u6790
 */
function shouldAnalyze(document: vscode.TextDocument): boolean {
    // \u8fc7\u6ee4\u975e\u6587\u4ef6\u65b9\u6848
    if (document.uri.scheme !== 'file') {
        return false;
    }

    // \u68c0\u67e5\u6587\u4ef6\u5927\u5c0f
    const config = vscode.workspace.getConfiguration('vibeguard');
    const maxFileSize = config.get<number>('maxFileSize', 500000);
    if (document.getText().length > maxFileSize) {
        return false;
    }

    // \u68c0\u67e5\u6392\u9664\u6587\u4ef6\u5939
    const excludedFolders = config.get<string[]>('excludedFolders', ['node_modules', '.git', 'dist', 'build']);
    const filePath = document.uri.fsPath;
    for (const folder of excludedFolders) {
        if (filePath.includes(`/${folder}/`) || filePath.includes(`\\${folder}\\`)) {
            return false;
        }
    }

    // \u68c0\u67e5\u652f\u6301\u7684\u8bed\u8a00
    const supportedLanguages = [
        'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
        'vue', 'python', 'sql', 'json', 'yaml', 'yml', 'dockerfile',
        'plaintext', 'markdown', 'html', 'css', 'scss', 'less'
    ];

    return supportedLanguages.includes(document.languageId);
}

/**
 * \u626b\u63cf\u6240\u6709\u5df2\u6253\u5f00\u7684\u6587\u6863
 */
async function scanOpenDocuments(analyzer: CodeAnalyzer, diagnosticManager: DiagnosticManager) {
    const documents = vscode.workspace.textDocuments;
    let count = 0;

    for (const document of documents) {
        if (shouldAnalyze(document)) {
            try {
                const issues = await analyzer.analyzeFull(document);
                diagnosticManager.updateDiagnostics(document, issues);
                count++;
            } catch (error) {
                Logger.error(`\u5206\u6790\u6587\u4ef6\u5931\u8d25: ${document.uri.fsPath}`, error);
            }
        }
    }

    if (count > 0) {
        vscode.window.showInformationMessage(`VibeGuard: \u5df2\u626b\u63cf ${count} \u4e2a\u6587\u4ef6`);
    }
}

/**
 * \u626b\u63cf\u6574\u4e2a\u5de5\u4f5c\u533a
 */
async function scanWorkspace(analyzer: CodeAnalyzer, diagnosticManager: DiagnosticManager) {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('\u6ca1\u6709\u6253\u5f00\u7684\u5de5\u4f5c\u533a');
        return;
    }

    const progress = vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'VibeGuard: \u6b63\u5728\u626b\u63cf\u5de5\u4f5c\u533a...',
        cancellable: true
    }, async (progress, token) => {
        let totalFiles = 0;
        let scannedFiles = 0;
        let totalIssues = 0;

        // \u67e5\u627e\u6240\u6709\u6587\u4ef6
        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,vue,py,sql,json,yaml,yml,env,dockerfile}',
            '**/node_modules/**'
        );

        totalFiles = files.length;

        for (const file of files) {
            if (token.isCancellationRequested) {
                break;
            }

            try {
                const document = await vscode.workspace.openTextDocument(file);
                
                if (shouldAnalyze(document)) {
                    const issues = await analyzer.analyzeFull(document);
                    diagnosticManager.updateDiagnostics(document, issues);
                    totalIssues += issues.length;
                    scannedFiles++;

                    // \u66f4\u65b0\u8fdb\u5ea6
                    const percentage = Math.round((scannedFiles / totalFiles) * 100);
                    progress.report({
                        increment: 100 / totalFiles,
                        message: `\u5df2\u626b\u63cf ${scannedFiles}/${totalFiles} \u4e2a\u6587\u4ef6 (${percentage}%)`
                    });
                }
            } catch (error) {
                Logger.error(`\u626b\u63cf\u6587\u4ef6\u5931\u8d25: ${file.fsPath}`, error);
            }
        }

        return { scannedFiles, totalIssues };
    });

    const result = await progress;
    if (result) {
        vscode.window.showInformationMessage(
            `VibeGuard: \u626b\u63cf\u5b8c\u6210\uff0c\u68c0\u67e5\u4e86 ${result.scannedFiles} \u4e2a\u6587\u4ef6\uff0c\u53d1\u73b0 ${result.totalIssues} \u4e2a\u95ee\u9898`
        );
    }
}
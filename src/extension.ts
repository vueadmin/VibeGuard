/**
 * VibeGuard VSCode Extension Entry Point
 * 
 * This extension helps protect non-technical users from security risks
 * when using AI tools to generate code. It provides real-time detection
 * of dangerous patterns like hardcoded API keys, SQL injection risks,
 * and other security vulnerabilities.
 */

import * as vscode from 'vscode';
import { 
  EXTENSION_NAME, 
  COMMANDS, 
  SUCCESS_MESSAGES, 
  ERROR_MESSAGES,
  DIAGNOSTIC_COLLECTION_NAME 
} from './constants';
import { 
  getExtensionConfig, 
  logInfo, 
  logError, 
  showInfoMessage, 
  showErrorMessage 
} from './utils';
import { 
  VibeGuardConfig, 
  IDocumentMonitor, 
  IAnalysisEngine, 
  IRuleEngine,
  IDiagnosticManager,
  IQuickFixProvider 
} from './types';

// Import core components
import { DocumentMonitor } from './monitor/DocumentMonitor';
import { AnalysisEngine } from './analyzer/AnalysisEngine';
import { RuleEngine } from './rules/RuleEngine';
import { DiagnosticManager } from './diagnostics/DiagnosticManager';
import { QuickFixProvider } from './quickfix/QuickFixProvider';

// Import rule definitions
import { registerApiKeyRules } from './rules/definitions/api-keys';
import { registerSqlDangerRules } from './rules/definitions/sql-rules';

/**
 * Extension context and services
 */
interface ExtensionServices {
  config: VibeGuardConfig;
  diagnosticCollection: vscode.DiagnosticCollection;
  documentMonitor: IDocumentMonitor;
  analysisEngine: IAnalysisEngine;
  ruleEngine: IRuleEngine;
  diagnosticManager: IDiagnosticManager;
  quickFixProvider: IQuickFixProvider;
}

let services: ExtensionServices | null = null;

/**
 * Extension activation function
 * Called when the extension is activated
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
  try {
    logInfo('正在激活 VibeGuard 扩展...');

    // Initialize configuration
    const config = getExtensionConfig();

    // Initialize core services
    logInfo('正在初始化核心服务...');
    
    // 1. Initialize Rule Engine
    const ruleEngine = new RuleEngine();
    
    // 2. Initialize Analysis Engine
    const analysisEngine = new AnalysisEngine();
    analysisEngine.setRuleEngine(ruleEngine);
    
    // 3. Initialize Diagnostic Manager
    const diagnosticManager = new DiagnosticManager({
      collectionName: DIAGNOSTIC_COLLECTION_NAME,
      maxDiagnosticsPerFile: 50,
      groupSimilarIssues: true
    });
    
    // Get diagnostic collection from manager and register it
    const diagnosticCollection = diagnosticManager.getDiagnosticCollection();
    context.subscriptions.push(diagnosticCollection);
    
    // 4. Initialize Quick Fix Provider
    const quickFixProvider = new QuickFixProvider(diagnosticCollection);
    
    // 5. Initialize Document Monitor with diagnostic manager
    const documentMonitor = new DocumentMonitor(analysisEngine, diagnosticManager);

    // Connect Analysis Engine to Diagnostic Manager
    connectAnalysisEngineToServices(analysisEngine, diagnosticManager);

    // Initialize services object
    services = {
      config,
      diagnosticCollection,
      documentMonitor,
      analysisEngine,
      ruleEngine,
      diagnosticManager,
      quickFixProvider
    };

    // Register all detection rules
    await registerDetectionRules(ruleEngine);

    // Register VSCode providers and commands
    registerVSCodeProviders(context, quickFixProvider);
    registerCommands(context);
    registerConfigurationChangeListener(context);

    // Start real-time monitoring
    if (config.enableRealTimeAnalysis) {
      documentMonitor.startMonitoring();
      logInfo('实时文档监控已启动');
    }

    // Show activation message
    logInfo(SUCCESS_MESSAGES.EXTENSION_ACTIVATED);
    
    // Only show user message if this is the first activation
    const isFirstActivation = context.globalState.get('vibeguard.firstActivation', true);
    if (isFirstActivation) {
      showInfoMessage('VibeGuard 已激活！正在保护您的代码安全 🛡️');
      await context.globalState.update('vibeguard.firstActivation', false);
    }

    logInfo(`VibeGuard 扩展激活完成 - 已注册 ${ruleEngine.getEnabledRules().length} 个检测规则`);

  } catch (error) {
    logError(error as Error, '扩展激活失败');
    showErrorMessage(ERROR_MESSAGES.EXTENSION_ACTIVATION_FAILED);
    throw error;
  }
}

/**
 * Extension deactivation function
 * Called when the extension is deactivated
 */
export function deactivate(): void {
  try {
    logInfo('正在停用 VibeGuard 扩展...');
    
    // Clean up services
    if (services) {
      // Stop document monitoring
      if (services.documentMonitor) {
        services.documentMonitor.stopMonitoring();
        services.documentMonitor.dispose();
      }
      
      // Dispose analysis engine
      if (services.analysisEngine) {
        services.analysisEngine.dispose();
      }
      
      // Dispose diagnostic manager
      if (services.diagnosticManager) {
        services.diagnosticManager.dispose();
      }
      
      // Dispose diagnostic collection
      if (services.diagnosticCollection) {
        services.diagnosticCollection.dispose();
      }
      
      services = null;
    }
    
    logInfo('VibeGuard 扩展已停用');
  } catch (error) {
    logError(error as Error, '扩展停用时发生错误');
  }
}

/**
 * Register extension commands
 */
function registerCommands(context: vscode.ExtensionContext): void {
  // Analyze current file command
  const analyzeCurrentFileCommand = vscode.commands.registerCommand(
    COMMANDS.ANALYZE_CURRENT_FILE,
    async () => {
      try {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
          showInfoMessage('请先打开一个文件');
          return;
        }

        if (!services?.analysisEngine) {
          showErrorMessage('分析引擎未初始化');
          return;
        }

        showInfoMessage('正在分析当前文件...');
        logInfo(`开始分析文件: ${activeEditor.document.fileName}`);
        
        // Perform analysis
        const issues = await services.analysisEngine.analyzeDocument(activeEditor.document);
        
        // Update diagnostics
        if (services.diagnosticManager) {
          services.diagnosticManager.updateDiagnostics(activeEditor.document, issues);
        }
        
        // Show results
        const message = issues.length > 0 
          ? `发现 ${issues.length} 个安全问题` 
          : '未发现安全问题 ✅';
        showInfoMessage(message);
        
        logInfo(`分析完成: ${activeEditor.document.fileName} - ${issues.length} 个问题`);
        
      } catch (error) {
        logError(error as Error, '分析当前文件失败');
        showErrorMessage('分析文件时发生错误');
      }
    }
  );

  // Analyze workspace command
  const analyzeWorkspaceCommand = vscode.commands.registerCommand(
    COMMANDS.ANALYZE_WORKSPACE,
    async () => {
      try {
        if (!vscode.workspace.workspaceFolders) {
          showInfoMessage('请先打开一个工作区');
          return;
        }

        if (!services?.analysisEngine) {
          showErrorMessage('分析引擎未初始化');
          return;
        }

        showInfoMessage('正在分析工作区文件...');
        logInfo('开始分析工作区');
        
        // Get all open text documents
        const documents = vscode.workspace.textDocuments;
        let totalIssues = 0;
        let analyzedFiles = 0;
        
        for (const document of documents) {
          if (!document.isUntitled && services.documentMonitor) {
            try {
              const issues = await services.analysisEngine.analyzeDocument(document);
              
              if (services.diagnosticManager) {
                services.diagnosticManager.updateDiagnostics(document, issues);
              }
              
              totalIssues += issues.length;
              analyzedFiles++;
            } catch (error) {
              logError(error as Error, `分析文件失败: ${document.fileName}`);
            }
          }
        }
        
        const message = `工作区分析完成：分析了 ${analyzedFiles} 个文件，发现 ${totalIssues} 个安全问题`;
        showInfoMessage(message);
        logInfo(message);
        
      } catch (error) {
        logError(error as Error, '分析工作区失败');
        showErrorMessage('分析工作区时发生错误');
      }
    }
  );

  // Register commands with context
  context.subscriptions.push(analyzeCurrentFileCommand);
  context.subscriptions.push(analyzeWorkspaceCommand);

  logInfo('命令注册完成');
}

/**
 * Register configuration change listener
 */
function registerConfigurationChangeListener(context: vscode.ExtensionContext): void {
  const configChangeListener = vscode.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration('vibeguard')) {
      try {
        // Update configuration
        if (services) {
          services.config = getExtensionConfig();
          logInfo('配置已更新');
        }
      } catch (error) {
        logError(error as Error, '更新配置失败');
      }
    }
  });

  context.subscriptions.push(configChangeListener);
}

/**
 * Register all detection rules with the rule engine
 */
async function registerDetectionRules(ruleEngine: IRuleEngine): Promise<void> {
  try {
    logInfo('正在注册检测规则...');
    
    // Register API key detection rules (highest priority)
    registerApiKeyRules(ruleEngine);
    
    // Register SQL danger detection rules
    registerSqlDangerRules(ruleEngine);
    
    const stats = ruleEngine.getStatistics();
    logInfo(`规则注册完成 - 总计: ${stats.totalRules}, 已启用: ${stats.enabledRules}`);
    
  } catch (error) {
    logError(error as Error, '注册检测规则失败');
    throw error;
  }
}

/**
 * Connect analysis engine to diagnostic services
 */
function connectAnalysisEngineToServices(
  analysisEngine: IAnalysisEngine,
  diagnosticManager: IDiagnosticManager
): void {
  // The analysis engine will be used by document monitor
  // and the diagnostic manager will be called to update diagnostics
  // This connection is handled through the document monitor workflow
  logInfo('分析引擎已连接到诊断服务');
}

/**
 * Register VSCode providers
 */
function registerVSCodeProviders(
  context: vscode.ExtensionContext,
  quickFixProvider: IQuickFixProvider
): void {
  try {
    // Register code action provider for quick fixes
    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' }, // Apply to all file schemes
      quickFixProvider,
      {
        providedCodeActionKinds: [
          vscode.CodeActionKind.QuickFix,
          vscode.CodeActionKind.Refactor,
          vscode.CodeActionKind.SourceFixAll
        ]
      }
    );
    
    context.subscriptions.push(codeActionProvider);
    logInfo('代码操作提供者已注册');
    
  } catch (error) {
    logError(error as Error, '注册 VSCode 提供者失败');
    throw error;
  }
}

/**
 * Get current extension services (for use by other modules)
 */
export function getExtensionServices(): ExtensionServices | null {
  return services;
}

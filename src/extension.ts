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
import { VibeGuardConfig } from './types';

/**
 * Extension context and services
 */
interface ExtensionServices {
  config: VibeGuardConfig;
  diagnosticCollection: vscode.DiagnosticCollection;
  // Additional services will be added in subsequent tasks:
  // documentMonitor?: IDocumentMonitor;
  // analysisEngine?: IAnalysisEngine;
  // diagnosticManager?: IDiagnosticManager;
  // quickFixProvider?: IQuickFixProvider;
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
    
    // Create diagnostic collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    context.subscriptions.push(diagnosticCollection);

    // Initialize services
    services = {
      config,
      diagnosticCollection
    };

    // Register commands
    registerCommands(context);

    // Register configuration change listener
    registerConfigurationChangeListener(context);

    // Show activation message
    logInfo(SUCCESS_MESSAGES.EXTENSION_ACTIVATED);
    
    // Only show user message if this is the first activation
    const isFirstActivation = context.globalState.get('vibeguard.firstActivation', true);
    if (isFirstActivation) {
      showInfoMessage('已激活！正在保护您的代码安全 🛡️');
      await context.globalState.update('vibeguard.firstActivation', false);
    }

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
      services.diagnosticCollection.dispose();
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

        // TODO: Implement analysis logic in subsequent tasks
        showInfoMessage('分析功能将在后续任务中实现');
        logInfo(`分析文件: ${activeEditor.document.fileName}`);
        
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

        // TODO: Implement workspace analysis in subsequent tasks
        showInfoMessage('工作区分析功能将在后续任务中实现');
        logInfo('开始分析工作区');
        
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
 * Get current extension services (for use by other modules)
 */
export function getExtensionServices(): ExtensionServices | null {
  return services;
}

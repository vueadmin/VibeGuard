/**
 * VibeGuard VSCode Extension Entry Point
 * 
 * This extension helps protect non-technical users from security risks
 * when using AI tools to generate code. It provides real-time detection
 * of dangerous patterns like hardcoded API keys, SQL injection risks,
 * and other security vulnerabilities.
 * 
 * Core workflow:
 * 1. DocumentMonitor listens for file changes
 * 2. AnalysisEngine coordinates rule execution
 * 3. RuleEngine executes detection rules
 * 4. DiagnosticManager displays issues in VSCode
 * 5. QuickFixProvider offers one-click fixes
 */

import * as vscode from 'vscode';
import { 
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
import { registerCodeInjectionRules } from './rules/definitions/code-injection-rules';
import { registerFrameworkRiskRules } from './rules/definitions/framework-rules';
import { registerConfigErrorRules } from './rules/definitions/config-rules';

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
 * 
 * Initialization sequence:
 * 1. Initialize Rule Engine and register detection rules
 * 2. Initialize Analysis Engine and connect to Rule Engine
 * 3. Initialize Diagnostic Manager for VSCode integration
 * 4. Initialize Quick Fix Provider for one-click fixes
 * 5. Initialize Document Monitor for real-time analysis
 * 6. Register VSCode providers and commands
 * 7. Start real-time monitoring workflow
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
  try {
    // Prevent duplicate activation
    if (services) {
      logInfo('VibeGuard 扩展已经激活');
      return;
    }
    
    logInfo('正在激活 VibeGuard 扩展...');

    // Initialize configuration
    const config = getExtensionConfig();
    logInfo(`配置加载完成 - 实时分析: ${config.enableRealTimeAnalysis}, 防抖延迟: ${config.debounceDelay}ms`);

    // Initialize core services in proper order
    logInfo('正在初始化核心服务...');
    
    // 1. Initialize Rule Engine first (foundation for all analysis)
    const ruleEngine = new RuleEngine();
    logInfo('规则引擎初始化完成');
    
    // 2. Initialize Analysis Engine and connect to Rule Engine
    const analysisEngine = new AnalysisEngine();
    analysisEngine.setRuleEngine(ruleEngine);
    logInfo('分析引擎初始化完成并连接到规则引擎');
    
    // 3. Initialize Diagnostic Manager for VSCode integration
    const diagnosticManager = new DiagnosticManager({
      collectionName: DIAGNOSTIC_COLLECTION_NAME,
      maxDiagnosticsPerFile: 50,
      groupSimilarIssues: true
    });
    
    // Get diagnostic collection from manager and register it with VSCode
    const diagnosticCollection = diagnosticManager.getDiagnosticCollection();
    context.subscriptions.push(diagnosticCollection);
    logInfo('诊断管理器初始化完成并注册到 VSCode');
    
    // 4. Initialize Quick Fix Provider for one-click fixes
    const quickFixProvider = new QuickFixProvider(diagnosticCollection);
    logInfo('快速修复提供者初始化完成');
    
    // 5. Initialize Document Monitor with complete workflow
    const documentMonitor = new DocumentMonitor(analysisEngine, diagnosticManager);
    logInfo('文档监控器初始化完成');

    // Initialize services object for global access
    services = {
      config,
      diagnosticCollection,
      documentMonitor,
      analysisEngine,
      ruleEngine,
      diagnosticManager,
      quickFixProvider
    };

    // Register all detection rules (API keys have highest priority)
    await registerDetectionRules(ruleEngine);

    // Verify all components are properly integrated
    verifyComponentIntegration();

    // Register VSCode providers and commands
    registerVSCodeProviders(context, quickFixProvider);
    registerCommands(context);
    registerConfigurationChangeListener(context);

    // Start real-time monitoring workflow
    if (config.enableRealTimeAnalysis) {
      documentMonitor.startMonitoring();
      logInfo('实时文档监控已启动 - 开始保护代码安全');
    } else {
      logInfo('实时分析已禁用 - 可通过命令手动分析');
    }

    // Show activation success
    logInfo(SUCCESS_MESSAGES.EXTENSION_ACTIVATED);
    
    // Show user-friendly activation message (only on first activation)
    const isFirstActivation = context.globalState.get('vibeguard.firstActivation', true);
    if (isFirstActivation) {
      showInfoMessage('VibeGuard 已激活！正在保护您的代码安全 🛡️');
      await context.globalState.update('vibeguard.firstActivation', false);
    }

    // Log final activation summary
    const ruleStats = ruleEngine.getStatistics();
    logInfo(`VibeGuard 扩展激活完成 - 已注册 ${ruleStats.enabledRules} 个检测规则 (总计 ${ruleStats.totalRules} 个)`);
    logInfo(`规则分布: ${Object.entries(ruleStats.rulesByCategory).map(([cat, count]) => `${cat}: ${count}`).join(', ')}`);

  } catch (error) {
    logError(error as Error, '扩展激活失败');
    showErrorMessage(ERROR_MESSAGES.EXTENSION_ACTIVATION_FAILED);
    throw error;
  }
}

/**
 * Extension deactivation function
 * Called when the extension is deactivated
 * Ensures proper cleanup of all services and resources
 */
export function deactivate(): void {
  try {
    logInfo('正在停用 VibeGuard 扩展...');
    
    // Clean up services in reverse order of initialization
    if (services) {
      // 1. Stop document monitoring first
      if (services.documentMonitor) {
        logInfo('停止文档监控...');
        services.documentMonitor.stopMonitoring();
        services.documentMonitor.dispose();
      }
      
      // 2. Clear diagnostics (clear all by clearing each document)
      if (services.diagnosticManager) {
        logInfo('清理诊断信息...');
        // Clear diagnostics for all open documents
        vscode.workspace.textDocuments.forEach(doc => {
          services!.diagnosticManager.clearDiagnostics(doc);
        });
        services.diagnosticManager.dispose();
      }
      
      // 3. Dispose diagnostic collection
      if (services.diagnosticCollection) {
        services.diagnosticCollection.dispose();
      }
      
      // 4. Dispose analysis engine
      if (services.analysisEngine) {
        logInfo('清理分析引擎...');
        services.analysisEngine.dispose();
      }
      
      // 5. Clear rule engine (no explicit dispose method, but log for completeness)
      if (services.ruleEngine) {
        const stats = services.ruleEngine.getStatistics();
        logInfo(`规则引擎清理完成 - 已清理 ${stats.totalRules} 个规则`);
      }
      
      // 6. Clear services reference
      services = null;
    }
    
    logInfo('VibeGuard 扩展已完全停用 - 所有资源已清理');
  } catch (error) {
    logError(error as Error, '扩展停用时发生错误');
  }
}

/**
 * Register extension commands for manual analysis and control
 */
function registerCommands(context: vscode.ExtensionContext): void {
  try {
    // Analyze current file command - triggers the complete analysis workflow
    const analyzeCurrentFileCommand = vscode.commands.registerCommand(
      COMMANDS.ANALYZE_CURRENT_FILE,
      async () => {
      try {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
          showInfoMessage('请先打开一个文件');
          return;
        }

        if (!services?.analysisEngine || !services?.diagnosticManager) {
          showErrorMessage('分析服务未初始化');
          return;
        }

        showInfoMessage('正在分析当前文件...');
        logInfo(`手动分析开始: ${activeEditor.document.fileName}`);
        
        // Perform complete analysis using the integrated workflow
        const issues = await services.analysisEngine.analyzeDocument(activeEditor.document);
        
        // Update diagnostics through the diagnostic manager
        services.diagnosticManager.updateDiagnostics(activeEditor.document, issues);
        
        // Show user-friendly results
        const message = issues.length > 0 
          ? `发现 ${issues.length} 个安全问题 - 请查看编辑器中的红色波浪线` 
          : '未发现安全问题 ✅ 代码看起来很安全！';
        showInfoMessage(message);
        
        // Log detailed results for debugging
        if (issues.length > 0) {
          const issuesByCategory = issues.reduce((acc, issue) => {
            acc[issue.category] = (acc[issue.category] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);
          
          logInfo(`分析完成: ${activeEditor.document.fileName} - ${issues.length} 个问题`);
          logInfo(`问题分布: ${Object.entries(issuesByCategory).map(([cat, count]) => `${cat}: ${count}`).join(', ')}`);
        } else {
          logInfo(`分析完成: ${activeEditor.document.fileName} - 无安全问题`);
        }
        
      } catch (error) {
        logError(error as Error, '分析当前文件失败');
        showErrorMessage('分析文件时发生错误，请查看开发者控制台了解详情');
      }
    }
  );

  // Analyze workspace command - analyzes all open documents
  const analyzeWorkspaceCommand = vscode.commands.registerCommand(
    COMMANDS.ANALYZE_WORKSPACE,
    async () => {
      try {
        if (!vscode.workspace.workspaceFolders) {
          showInfoMessage('请先打开一个工作区');
          return;
        }

        if (!services?.analysisEngine || !services?.diagnosticManager) {
          showErrorMessage('分析服务未初始化');
          return;
        }

        showInfoMessage('正在分析工作区文件...');
        logInfo('工作区批量分析开始');
        
        // Get all open text documents
        const documents = vscode.workspace.textDocuments;
        let totalIssues = 0;
        let analyzedFiles = 0;
        const issuesByCategory: Record<string, number> = {};
        
        // Analyze each document using the integrated workflow
        for (const document of documents) {
          if (!document.isUntitled) {
            try {
              logInfo(`分析文件: ${document.fileName}`);
              const issues = await services.analysisEngine.analyzeDocument(document);
              
              // Update diagnostics for each file
              services.diagnosticManager.updateDiagnostics(document, issues);
              
              // Collect statistics
              totalIssues += issues.length;
              analyzedFiles++;
              
              // Track issues by category
              issues.forEach(issue => {
                issuesByCategory[issue.category] = (issuesByCategory[issue.category] || 0) + 1;
              });
              
            } catch (error) {
              logError(error as Error, `分析文件失败: ${document.fileName}`);
            }
          }
        }
        
        // Show comprehensive results
        const message = totalIssues > 0
          ? `工作区分析完成：分析了 ${analyzedFiles} 个文件，发现 ${totalIssues} 个安全问题`
          : `工作区分析完成：分析了 ${analyzedFiles} 个文件，未发现安全问题 ✅`;
        
        showInfoMessage(message);
        
        // Log detailed statistics
        logInfo(`工作区分析完成 - 文件: ${analyzedFiles}, 问题: ${totalIssues}`);
        if (Object.keys(issuesByCategory).length > 0) {
          logInfo(`问题分布: ${Object.entries(issuesByCategory).map(([cat, count]) => `${cat}: ${count}`).join(', ')}`);
        }
        
      } catch (error) {
        logError(error as Error, '分析工作区失败');
        showErrorMessage('分析工作区时发生错误，请查看开发者控制台了解详情');
      }
    }
  );

  // Fix all issues command - applies all available quick fixes
  const fixAllIssuesCommand = vscode.commands.registerCommand(
    'vibeguard.fixAllIssues',
    async () => {
      try {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
          showInfoMessage('请先打开一个文件');
          return;
        }

        if (!services?.diagnosticCollection || !services?.quickFixProvider) {
          showErrorMessage('修复服务未初始化');
          return;
        }

        // Get all diagnostics for the current document
        const diagnostics = services.diagnosticCollection.get(activeEditor.document.uri);
        if (!diagnostics || diagnostics.length === 0) {
          showInfoMessage('当前文件没有发现安全问题 ✅');
          return;
        }

        const vibeguardDiagnostics = diagnostics.filter(d => d.source === 'VibeGuard');
        if (vibeguardDiagnostics.length === 0) {
          showInfoMessage('当前文件没有 VibeGuard 检测到的问题');
          return;
        }

        // Show confirmation dialog
        const choice = await vscode.window.showWarningMessage(
          `发现 ${vibeguardDiagnostics.length} 个安全问题，是否一键修复？`,
          { modal: true },
          '🚀 立即修复',
          '📋 查看详情',
          '❌ 取消'
        );

        if (choice === '🚀 立即修复') {
          showInfoMessage('正在修复所有安全问题...');
          
          // Create a context for code actions
          const context: vscode.CodeActionContext = {
            diagnostics: vibeguardDiagnostics,
            only: [vscode.CodeActionKind.SourceFixAll],
            triggerKind: vscode.CodeActionTriggerKind.Invoke
          };

          // Get fix all action
          const actions = await services.quickFixProvider.provideCodeActions(
            activeEditor.document,
            new vscode.Range(0, 0, activeEditor.document.lineCount, 0),
            context,
            new vscode.CancellationTokenSource().token
          );

          const fixAllAction = actions?.find(action => 
            action.kind?.contains(vscode.CodeActionKind.SourceFixAll)
          );

          if (fixAllAction && fixAllAction.edit) {
            await vscode.workspace.applyEdit(fixAllAction.edit);
            showInfoMessage(`✅ 成功修复 ${vibeguardDiagnostics.length} 个安全问题！`);
            logInfo(`批量修复完成 - 修复了 ${vibeguardDiagnostics.length} 个问题`);
          } else {
            showInfoMessage('部分问题需要手动修复，请点击代码中的灯泡图标');
          }
        } else if (choice === '📋 查看详情') {
          // Show problems panel
          vscode.commands.executeCommand('workbench.panel.markers.view.focus');
        }

      } catch (error) {
        logError(error as Error, '批量修复失败');
        showErrorMessage('修复过程中发生错误，请手动修复或查看开发者控制台');
      }
    }
  );

  // Show security report command
  const showSecurityReportCommand = vscode.commands.registerCommand(
    'vibeguard.showSecurityReport',
    async () => {
      try {
        if (!services?.diagnosticCollection) {
          showErrorMessage('报告服务未初始化');
          return;
        }

        // Collect all diagnostics from all documents
        let totalIssues = 0;
        const issuesByCategory: Record<string, number> = {};
        const issuesBySeverity: Record<string, number> = {};
        const fileStats: Array<{ file: string; issues: number }> = [];

        // Iterate through all documents with diagnostics
        services.diagnosticCollection.forEach((uri, diagnostics) => {
          const vibeguardDiagnostics = diagnostics.filter(d => d.source === 'VibeGuard');
          if (vibeguardDiagnostics.length > 0) {
            totalIssues += vibeguardDiagnostics.length;
            fileStats.push({
              file: vscode.workspace.asRelativePath(uri),
              issues: vibeguardDiagnostics.length
            });

            // Categorize issues
            vibeguardDiagnostics.forEach(diagnostic => {
              const code = diagnostic.code?.toString() || 'unknown';
              const category = code.split('_')[0];
              issuesByCategory[category] = (issuesByCategory[category] || 0) + 1;

              const severity = diagnostic.severity === vscode.DiagnosticSeverity.Error ? 'error' : 'warning';
              issuesBySeverity[severity] = (issuesBySeverity[severity] || 0) + 1;
            });
          }
        });

        // Generate report content
        const reportLines = [
          '# VibeGuard 安全检测报告 🛡️',
          '',
          `**生成时间**: ${new Date().toLocaleString('zh-CN')}`,
          '',
          '## 📊 总体统计',
          '',
          `- **总问题数**: ${totalIssues}`,
          `- **受影响文件**: ${fileStats.length}`,
          `- **错误级别**: ${issuesBySeverity.error || 0}`,
          `- **警告级别**: ${issuesBySeverity.warning || 0}`,
          '',
          '## 🏷️ 问题分类',
          ''
        ];

        // Add category breakdown
        Object.entries(issuesByCategory).forEach(([category, count]) => {
          const categoryNames: Record<string, string> = {
            'API': '🔑 API 密钥安全',
            'SQL': '💾 SQL 危险操作',
            'CODE': '💻 代码注入风险',
            'FRAMEWORK': '⚛️ 框架特定风险',
            'CONFIG': '⚙️ 配置错误'
          };
          const categoryName = categoryNames[category] || category;
          reportLines.push(`- **${categoryName}**: ${count} 个问题`);
        });

        reportLines.push('', '## 📁 文件详情', '');

        // Add file breakdown
        fileStats
          .sort((a, b) => b.issues - a.issues)
          .forEach(stat => {
            reportLines.push(`- \`${stat.file}\`: ${stat.issues} 个问题`);
          });

        if (totalIssues === 0) {
          reportLines.push('', '🎉 **恭喜！没有发现安全问题，代码很安全！**');
        } else {
          reportLines.push(
            '',
            '## 🚀 建议操作',
            '',
            '1. 点击代码中的 💡 灯泡图标查看具体修复建议',
            '2. 使用 `Ctrl+Shift+P` → "VibeGuard: 一键修复所有安全问题"',
            '3. 查看 [安全最佳实践](https://vibeguard.dev/docs) 了解更多',
            '',
            '---',
            '',
            '💡 **提示**: 定期运行安全检测，保护代码免受安全威胁！'
          );
        }

        // Create and show report document
        const reportContent = reportLines.join('\n');
        const doc = await vscode.workspace.openTextDocument({
          content: reportContent,
          language: 'markdown'
        });

        await vscode.window.showTextDocument(doc, {
          preview: true,
          viewColumn: vscode.ViewColumn.Beside
        });

        logInfo(`安全报告已生成 - 总问题: ${totalIssues}, 文件: ${fileStats.length}`);

      } catch (error) {
        logError(error as Error, '生成安全报告失败');
        showErrorMessage('生成报告时发生错误，请查看开发者控制台了解详情');
      }
    }
  );

  // Learn security command
  const learnSecurityCommand = vscode.commands.registerCommand(
    'vibeguard.learnSecurity',
    async () => {
      try {
        const choice = await vscode.window.showInformationMessage(
          '选择学习内容：',
          '📚 用户指南',
          '🏆 最佳实践',
          '🌐 在线文档',
          '💬 社区讨论'
        );

        switch (choice) {
          case '📚 用户指南':
            // Open user guide
            const userGuideUri = vscode.Uri.joinPath(
              vscode.extensions.getExtension('vibeguard.vibeguard')?.extensionUri || vscode.Uri.file(''),
              'docs',
              'USER_GUIDE.md'
            );
            try {
              const doc = await vscode.workspace.openTextDocument(userGuideUri);
              await vscode.window.showTextDocument(doc);
            } catch {
              vscode.env.openExternal(vscode.Uri.parse('https://vibeguard.dev/docs/user-guide'));
            }
            break;

          case '🏆 最佳实践':
            // Open best practices
            const bestPracticesUri = vscode.Uri.joinPath(
              vscode.extensions.getExtension('vibeguard.vibeguard')?.extensionUri || vscode.Uri.file(''),
              'docs',
              'BEST_PRACTICES.md'
            );
            try {
              const doc = await vscode.workspace.openTextDocument(bestPracticesUri);
              await vscode.window.showTextDocument(doc);
            } catch {
              vscode.env.openExternal(vscode.Uri.parse('https://vibeguard.dev/docs/best-practices'));
            }
            break;

          case '🌐 在线文档':
            vscode.env.openExternal(vscode.Uri.parse('https://vibeguard.dev/docs'));
            break;

          case '💬 社区讨论':
            vscode.env.openExternal(vscode.Uri.parse('https://discord.gg/vibeguard'));
            break;
        }

      } catch (error) {
        logError(error as Error, '打开学习资源失败');
        showErrorMessage('打开学习资源时发生错误');
      }
    }
  );

    // Register commands with context
    context.subscriptions.push(analyzeCurrentFileCommand);
    context.subscriptions.push(analyzeWorkspaceCommand);
    context.subscriptions.push(fixAllIssuesCommand);
    context.subscriptions.push(showSecurityReportCommand);
    context.subscriptions.push(learnSecurityCommand);

    logInfo('所有命令注册完成');
  } catch (error) {
    // Handle command registration errors (e.g., duplicate registration in tests)
    if (error instanceof Error && error.message.includes('already exists')) {
      logInfo('命令已存在，跳过注册（可能在测试环境中）');
    } else {
      logError(error as Error, '命令注册失败');
      throw error;
    }
  }
}

/**
 * Register configuration change listener to update all services when settings change
 */
function registerConfigurationChangeListener(context: vscode.ExtensionContext): void {
  const configChangeListener = vscode.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration('vibeguard')) {
      try {
        if (!services) {
          return;
        }

        // Update configuration
        const newConfig = getExtensionConfig();
        const oldConfig = services.config;
        services.config = newConfig;
        
        logInfo('配置更新检测到');
        
        // Handle real-time analysis toggle
        if (oldConfig.enableRealTimeAnalysis !== newConfig.enableRealTimeAnalysis) {
          if (newConfig.enableRealTimeAnalysis) {
            services.documentMonitor.startMonitoring();
            logInfo('实时分析已启用');
            showInfoMessage('实时代码分析已启用');
          } else {
            services.documentMonitor.stopMonitoring();
            logInfo('实时分析已禁用');
            showInfoMessage('实时代码分析已禁用');
          }
        }
        
        // Handle debounce delay changes
        if (oldConfig.debounceDelay !== newConfig.debounceDelay) {
          // Restart monitoring to apply new debounce delay
          if (newConfig.enableRealTimeAnalysis) {
            services.documentMonitor.stopMonitoring();
            services.documentMonitor.startMonitoring();
          }
          logInfo(`防抖延迟已更新: ${newConfig.debounceDelay}ms`);
        }
        
        // Handle supported languages changes
        if (JSON.stringify(oldConfig.supportedLanguages) !== JSON.stringify(newConfig.supportedLanguages)) {
          logInfo(`支持的语言已更新: ${newConfig.supportedLanguages.join(', ')}`);
        }
        
        // Handle file size limit changes
        if (oldConfig.maxFileSize !== newConfig.maxFileSize) {
          logInfo(`文件大小限制已更新: ${newConfig.maxFileSize} 字节`);
        }
        
        logInfo('所有服务配置已同步更新');
        
      } catch (error) {
        logError(error as Error, '更新配置失败');
        showErrorMessage('配置更新失败，请重新加载扩展');
      }
    }
  });

  context.subscriptions.push(configChangeListener);
  logInfo('配置变更监听器已注册');
}

/**
 * Register all detection rules with the rule engine
 * Priority order: API Keys (highest) -> SQL Danger -> Code Injection -> Framework -> Config
 */
async function registerDetectionRules(ruleEngine: IRuleEngine): Promise<void> {
  try {
    logInfo('正在注册检测规则...');
    
    // Register API key detection rules (highest priority - prevents $5000 mistakes)
    logInfo('注册 API 密钥检测规则...');
    registerApiKeyRules(ruleEngine);
    
    // Register SQL danger detection rules (prevents data loss)
    logInfo('注册 SQL 危险操作检测规则...');
    registerSqlDangerRules(ruleEngine);
    
    // Register code injection detection rules (prevents XSS and command injection)
    logInfo('注册代码注入检测规则...');
    registerCodeInjectionRules(ruleEngine);
    
    // Register framework-specific risk detection rules (prevents framework-specific vulnerabilities)
    logInfo('注册框架风险检测规则...');
    registerFrameworkRiskRules(ruleEngine);
    
    // Register configuration error detection rules (prevents production misconfigurations)
    logInfo('注册配置错误检测规则...');
    registerConfigErrorRules(ruleEngine);
    
    // Get final statistics
    const stats = ruleEngine.getStatistics();
    logInfo(`规则注册完成 - 总计: ${stats.totalRules}, 已启用: ${stats.enabledRules}`);
    logInfo(`按类别分布: ${Object.entries(stats.rulesByCategory).map(([cat, count]) => `${cat}: ${count}`).join(', ')}`);
    logInfo(`按严重程度分布: ${Object.entries(stats.rulesBySeverity).map(([sev, count]) => `${sev}: ${count}`).join(', ')}`);
    
  } catch (error) {
    logError(error as Error, '注册检测规则失败');
    throw error;
  }
}

/**
 * Verify that all components are properly connected for the real-time analysis workflow
 * 
 * Workflow verification:
 * 1. DocumentMonitor -> AnalysisEngine (for triggering analysis)
 * 2. AnalysisEngine -> RuleEngine (for executing rules)
 * 3. DocumentMonitor -> DiagnosticManager (for updating diagnostics)
 * 4. DiagnosticManager -> VSCode (for displaying issues)
 * 5. QuickFixProvider -> VSCode (for providing fixes)
 */
function verifyComponentIntegration(): void {
  if (!services) {
    throw new Error('服务未初始化');
  }

  // Verify all components are initialized
  const components = [
    { name: '文档监控器', service: services.documentMonitor },
    { name: '分析引擎', service: services.analysisEngine },
    { name: '规则引擎', service: services.ruleEngine },
    { name: '诊断管理器', service: services.diagnosticManager },
    { name: '快速修复提供者', service: services.quickFixProvider }
  ];

  for (const component of components) {
    if (!component.service) {
      throw new Error(`${component.name}未正确初始化`);
    }
  }

  // Verify rule engine has rules
  const ruleStats = services.ruleEngine.getStatistics();
  if (ruleStats.enabledRules === 0) {
    throw new Error('规则引擎没有启用的规则');
  }

  logInfo('所有组件集成验证通过 - 实时分析工作流程已就绪');
}

/**
 * Register VSCode providers for complete integration
 * This connects our services to VSCode's UI and user interactions
 */
function registerVSCodeProviders(
  context: vscode.ExtensionContext,
  quickFixProvider: IQuickFixProvider
): void {
  try {
    // Register code action provider for quick fixes across all supported languages
    const supportedLanguages = services?.config.supportedLanguages || ['*'];
    let documentSelector: vscode.DocumentSelector = supportedLanguages
      .filter(lang => lang !== '*')
      .map(lang => ({
        scheme: 'file',
        language: lang
      }));
    
    // Add wildcard selector if '*' is in supported languages
    if (supportedLanguages.includes('*')) {
      documentSelector = [...documentSelector, { scheme: 'file' }];
    }

    const codeActionProvider = vscode.languages.registerCodeActionsProvider(
      documentSelector,
      quickFixProvider,
      {
        providedCodeActionKinds: [
          vscode.CodeActionKind.QuickFix,      // Individual fixes
          vscode.CodeActionKind.Refactor,     // Code refactoring
          vscode.CodeActionKind.SourceFixAll  // Fix all issues
        ]
      }
    );
    
    context.subscriptions.push(codeActionProvider);
    logInfo(`代码操作提供者已注册 - 支持语言: ${supportedLanguages.join(', ')}`);
    
    // Register additional providers if needed in the future
    // (e.g., hover provider for security tips, completion provider for secure alternatives)
    
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

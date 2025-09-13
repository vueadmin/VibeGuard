/**
 * QuickFixProvider - 快速修复提供者
 * 
 * 实现 VSCode CodeActionProvider 接口，为安全问题提供一键修复功能。
 * 专为非技术用户设计，提供简单易懂的修复选项。
 */

import * as vscode from 'vscode';
import { 
  SecurityIssue, 
  SecurityCategory, 
  IQuickFixProvider,
  IssueSeverity 
} from '../types';

/**
 * 快速修复配置
 */
interface QuickFixConfig {
  /** 是否启用批量修复 */
  enableBatchFix: boolean;
  /** 最大批量修复数量 */
  maxBatchSize: number;
  /** 是否显示预览 */
  showPreview: boolean;
}

/**
 * 修复操作类型
 */
interface FixAction {
  /** 操作标题 */
  title: string;
  /** 操作类型 */
  kind: vscode.CodeActionKind;
  /** 工作区编辑 */
  edit: vscode.WorkspaceEdit;
  /** 是否为首选操作 */
  isPreferred: boolean;
  /** 操作描述 */
  description?: string;
}

/**
 * 快速修复提供者实现
 * 
 * 为各种安全问题提供自动修复功能，支持单个修复和批量修复
 */
export class QuickFixProvider implements IQuickFixProvider {
  private config: QuickFixConfig;
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor(
    diagnosticCollection: vscode.DiagnosticCollection,
    config?: Partial<QuickFixConfig>
  ) {
    this.diagnosticCollection = diagnosticCollection;
    this.config = {
      enableBatchFix: true,
      maxBatchSize: 10,
      showPreview: false,
      ...config
    };
  }

  /**
   * 提供代码操作
   * @param document 文档对象
   * @param range 选择范围
   * @param context 代码操作上下文
   * @param token 取消令牌
   * @returns 代码操作数组
   */
  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.CodeAction[]> {
    try {
      const actions: vscode.CodeAction[] = [];

      // 获取相关的诊断信息
      const relevantDiagnostics = context.diagnostics.filter(
        diagnostic => diagnostic.source === 'VibeGuard'
      );

      if (relevantDiagnostics.length === 0) {
        return actions;
      }

      // 为每个诊断创建修复操作
      for (const diagnostic of relevantDiagnostics) {
        const fixActions = this.createFixActionsForDiagnostic(
          document, 
          diagnostic, 
          range
        );
        actions.push(...fixActions);
      }

      // 如果有多个问题，添加批量修复选项
      if (relevantDiagnostics.length > 1 && this.config.enableBatchFix) {
        const batchActions = this.createBatchFixActions(
          document, 
          relevantDiagnostics
        );
        actions.push(...batchActions);
      }

      return actions;

    } catch (error) {
      console.error('VibeGuard: 创建快速修复操作失败', error);
      return [];
    }
  }

  /**
   * 为单个诊断创建修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @param range 选择范围
   * @returns 修复操作数组
   */
  private createFixActionsForDiagnostic(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    range: vscode.Range
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const code = diagnostic.code?.toString();

    if (!code) {
      return actions;
    }

    // 根据问题代码创建相应的修复操作
    switch (true) {
      case code.startsWith('API_KEY_'):
        actions.push(...this.createApiKeyFixActions(document, diagnostic));
        break;
      case code.startsWith('SQL_'):
        actions.push(...this.createSqlFixActions(document, diagnostic));
        break;
      case code.startsWith('CODE_INJECTION_'):
        actions.push(...this.createCodeInjectionFixActions(document, diagnostic));
        break;
      case code.startsWith('FRAMEWORK_'):
        actions.push(...this.createFrameworkFixActions(document, diagnostic));
        break;
      case code.startsWith('CONFIG_'):
        actions.push(...this.createConfigFixActions(document, diagnostic));
        break;
      default:
        // 通用修复操作
        actions.push(...this.createGenericFixActions(document, diagnostic));
        break;
    }

    return actions;
  }

  /**
   * 创建 API 密钥相关的修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createApiKeyFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const range = diagnostic.range;
    const text = document.getText(range);

    // 环境变量替换修复
    const envVarAction = this.createEnvironmentVariableReplacement(
      document,
      diagnostic,
      text
    );
    if (envVarAction) {
      actions.push(envVarAction);
    }

    // 配置文件移动修复
    const configAction = this.createConfigFileReplacement(
      document,
      diagnostic,
      text
    );
    if (configAction) {
      actions.push(configAction);
    }

    // 注释掉危险代码
    const commentAction = this.createCommentOutAction(
      document,
      diagnostic,
      '⚠️ 临时注释掉硬编码密钥'
    );
    if (commentAction) {
      actions.push(commentAction);
    }

    return actions;
  }

  /**
   * 创建环境变量替换操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @param originalText 原始文本
   * @returns 修复操作
   */
  private createEnvironmentVariableReplacement(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    originalText: string
  ): vscode.CodeAction | null {
    try {
      const code = diagnostic.code?.toString();
      let envVarName = 'API_KEY';
      let replacement = 'process.env.API_KEY';

      // 根据 API 密钥类型确定环境变量名
      switch (code) {
        case 'API_KEY_OPENAI':
          envVarName = 'OPENAI_API_KEY';
          replacement = 'process.env.OPENAI_API_KEY';
          break;
        case 'API_KEY_AWS':
          envVarName = 'AWS_ACCESS_KEY_ID';
          replacement = 'process.env.AWS_ACCESS_KEY_ID';
          break;
        case 'API_KEY_GITHUB':
          envVarName = 'GITHUB_TOKEN';
          replacement = 'process.env.GITHUB_TOKEN';
          break;
        default:
          // 尝试从原始文本推断
          if (originalText.toLowerCase().includes('openai')) {
            envVarName = 'OPENAI_API_KEY';
            replacement = 'process.env.OPENAI_API_KEY';
          } else if (originalText.toLowerCase().includes('github')) {
            envVarName = 'GITHUB_TOKEN';
            replacement = 'process.env.GITHUB_TOKEN';
          }
          break;
      }

      const action = new vscode.CodeAction(
        `🔧 使用环境变量 ${envVarName}`,
        vscode.CodeActionKind.QuickFix
      );

      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, replacement);
      
      action.isPreferred = true;
      action.diagnostics = [diagnostic];
      
      // 添加详细说明
      action.command = {
        command: 'vscode.executeCommand',
        title: '显示环境变量设置说明',
        arguments: ['workbench.action.openSettings', `@ext:vibeguard`]
      };

      return action;

    } catch (error) {
      console.error('VibeGuard: 创建环境变量替换操作失败', error);
      return null;
    }
  }

  /**
   * 创建配置文件替换操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @param originalText 原始文本
   * @returns 修复操作
   */
  private createConfigFileReplacement(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    originalText: string
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        '📁 移动到配置文件',
        vscode.CodeActionKind.Refactor
      );

      // 创建配置对象引用
      const configReplacement = 'config.apiKey';
      
      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, configReplacement);
      
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建配置文件替换操作失败', error);
      return null;
    }
  }

  /**
   * 创建注释操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @param title 操作标题
   * @returns 修复操作
   */
  private createCommentOutAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    title: string
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        title,
        vscode.CodeActionKind.QuickFix
      );

      const line = document.lineAt(diagnostic.range.start.line);
      const lineText = line.text;
      const indentation = lineText.match(/^\s*/)?.[0] || '';
      
      const commentedLine = `${indentation}// TODO: 移除硬编码密钥 - ${lineText.trim()}`;
      
      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(
        document.uri, 
        line.range, 
        commentedLine
      );
      
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建注释操作失败', error);
      return null;
    }
  }

  /**
   * 创建 SQL 相关的修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createSqlFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const code = diagnostic.code?.toString();
    const text = document.getText(diagnostic.range);

    switch (code) {
      case 'SQL_DELETE_NO_WHERE':
        const deleteAction = this.createSqlWhereClauseAction(document, diagnostic, 'DELETE');
        if (deleteAction) {
          actions.push(deleteAction);
        }
        break;
      case 'SQL_UPDATE_NO_WHERE':
        const updateAction = this.createSqlWhereClauseAction(document, diagnostic, 'UPDATE');
        if (updateAction) {
          actions.push(updateAction);
        }
        break;
      case 'SQL_DROP_TABLE':
        const safetyAction = this.createSqlSafetyCheckAction(document, diagnostic);
        if (safetyAction) {
          actions.push(safetyAction);
        }
        break;
    }

    return actions;
  }

  /**
   * 创建 SQL WHERE 子句添加操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @param sqlType SQL 类型
   * @returns 修复操作
   */
  private createSqlWhereClauseAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    sqlType: 'DELETE' | 'UPDATE'
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        `🛡️ 添加 WHERE 条件保护`,
        vscode.CodeActionKind.QuickFix
      );

      const originalText = document.getText(diagnostic.range);
      let replacement: string;

      if (sqlType === 'DELETE') {
        replacement = originalText.replace(/;?\s*$/, ' WHERE id = ?;');
      } else {
        replacement = originalText.replace(/;?\s*$/, ' WHERE id = ?;');
      }

      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, replacement);
      
      action.isPreferred = true;
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建 SQL WHERE 子句操作失败', error);
      return null;
    }
  }

  /**
   * 创建 SQL 安全检查操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作
   */
  private createSqlSafetyCheckAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        '🚨 添加安全确认',
        vscode.CodeActionKind.QuickFix
      );

      const originalText = document.getText(diagnostic.range);
      const replacement = `// 危险操作！请确认后取消注释\n// ${originalText}`;

      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, replacement);
      
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建 SQL 安全检查操作失败', error);
      return null;
    }
  }

  /**
   * 创建代码注入相关的修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createCodeInjectionFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const code = diagnostic.code?.toString();

    switch (code) {
      case 'CODE_INJECTION_EVAL':
        const evalAction = this.createEvalReplacementAction(document, diagnostic);
        if (evalAction) {
          actions.push(evalAction);
        }
        break;
      case 'CODE_INJECTION_INNERHTML':
        const htmlAction = this.createInnerHtmlReplacementAction(document, diagnostic);
        if (htmlAction) {
          actions.push(htmlAction);
        }
        break;
      case 'CODE_INJECTION_EXEC':
        const execAction = this.createExecReplacementAction(document, diagnostic);
        if (execAction) {
          actions.push(execAction);
        }
        break;
    }

    return actions;
  }

  /**
   * 创建 eval 替换操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作
   */
  private createEvalReplacementAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        '🔒 使用 JSON.parse 替代 eval',
        vscode.CodeActionKind.QuickFix
      );

      const originalText = document.getText(diagnostic.range);
      const replacement = originalText.replace(/eval\s*\(/g, 'JSON.parse(');

      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, replacement);
      
      action.isPreferred = true;
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建 eval 替换操作失败', error);
      return null;
    }
  }

  /**
   * 创建 innerHTML 替换操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作
   */
  private createInnerHtmlReplacementAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        '🔒 使用 textContent 替代 innerHTML',
        vscode.CodeActionKind.QuickFix
      );

      const originalText = document.getText(diagnostic.range);
      const replacement = originalText.replace(/\.innerHTML\s*=/g, '.textContent =');

      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, diagnostic.range, replacement);
      
      action.isPreferred = true;
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建 innerHTML 替换操作失败', error);
      return null;
    }
  }

  /**
   * 创建 exec 替换操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作
   */
  private createExecReplacementAction(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        '🔒 添加输入验证',
        vscode.CodeActionKind.QuickFix
      );

      const line = document.lineAt(diagnostic.range.start.line);
      const lineText = line.text;
      const indentation = lineText.match(/^\s*/)?.[0] || '';
      
      const safetyCheck = `${indentation}// 添加输入验证\n${indentation}if (!/^[a-zA-Z0-9\\s-_]+$/.test(userInput)) {\n${indentation}  throw new Error('无效输入');\n${indentation}}\n${lineText}`;
      
      action.edit = new vscode.WorkspaceEdit();
      action.edit.replace(document.uri, line.range, safetyCheck);
      
      action.diagnostics = [diagnostic];
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建 exec 替换操作失败', error);
      return null;
    }
  }

  /**
   * 创建框架相关的修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createFrameworkFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    // 框架特定修复将在后续任务中实现
    return actions;
  }

  /**
   * 创建配置相关的修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createConfigFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    // 配置错误修复将在后续任务中实现
    return actions;
  }

  /**
   * 创建通用修复操作
   * @param document 文档对象
   * @param diagnostic 诊断信息
   * @returns 修复操作数组
   */
  private createGenericFixActions(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    
    // 通用注释操作
    const commentAction = this.createCommentOutAction(
      document,
      diagnostic,
      '💬 注释掉问题代码'
    );
    
    if (commentAction) {
      actions.push(commentAction);
    }

    return actions;
  }

  /**
   * 创建批量修复操作
   * @param document 文档对象
   * @param diagnostics 诊断信息数组
   * @returns 批量修复操作数组
   */
  private createBatchFixActions(
    document: vscode.TextDocument,
    diagnostics: vscode.Diagnostic[]
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    // 限制批量修复数量
    const limitedDiagnostics = diagnostics.slice(0, this.config.maxBatchSize);

    // 按类型分组
    const groupedDiagnostics = this.groupDiagnosticsByType(limitedDiagnostics);

    // 为每个类型创建批量修复
    for (const [type, group] of groupedDiagnostics) {
      if (group.length > 1) {
        const batchAction = this.createBatchFixForType(document, type, group);
        if (batchAction) {
          actions.push(batchAction);
        }
      }
    }

    // 全部修复操作
    if (limitedDiagnostics.length > 1) {
      const fixAllAction = this.createFixAllAction(document, limitedDiagnostics);
      if (fixAllAction) {
        actions.push(fixAllAction);
      }
    }

    return actions;
  }

  /**
   * 按类型分组诊断信息
   * @param diagnostics 诊断信息数组
   * @returns 分组后的诊断信息
   */
  private groupDiagnosticsByType(
    diagnostics: vscode.Diagnostic[]
  ): Map<string, vscode.Diagnostic[]> {
    const groups = new Map<string, vscode.Diagnostic[]>();

    for (const diagnostic of diagnostics) {
      const code = diagnostic.code?.toString() || 'unknown';
      const type = code.split('_')[0]; // 取前缀作为类型
      
      if (!groups.has(type)) {
        groups.set(type, []);
      }
      groups.get(type)!.push(diagnostic);
    }

    return groups;
  }

  /**
   * 为特定类型创建批量修复
   * @param document 文档对象
   * @param type 问题类型
   * @param diagnostics 诊断信息数组
   * @returns 批量修复操作
   */
  private createBatchFixForType(
    document: vscode.TextDocument,
    type: string,
    diagnostics: vscode.Diagnostic[]
  ): vscode.CodeAction | null {
    try {
      const typeNames: { [key: string]: string } = {
        'API': 'API 密钥',
        'SQL': 'SQL 危险操作',
        'CODE': '代码注入',
        'FRAMEWORK': '框架风险',
        'CONFIG': '配置错误'
      };

      const typeName = typeNames[type] || type;
      const action = new vscode.CodeAction(
        `🔧 批量修复所有 ${typeName} 问题 (${diagnostics.length}个)`,
        vscode.CodeActionKind.QuickFix
      );

      action.edit = new vscode.WorkspaceEdit();

      // 为每个诊断应用修复
      for (const diagnostic of diagnostics) {
        const fixActions = this.createFixActionsForDiagnostic(
          document, 
          diagnostic, 
          diagnostic.range
        );
        
        // 使用首选修复
        const preferredFix = fixActions.find(fix => fix.isPreferred) || fixActions[0];
        if (preferredFix && preferredFix.edit) {
          // 合并编辑操作
          for (const [uri, edits] of preferredFix.edit.entries()) {
            for (const edit of edits) {
              action.edit.replace(uri, edit.range, edit.newText);
            }
          }
        }
      }

      action.diagnostics = diagnostics;
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建批量修复操作失败', error);
      return null;
    }
  }

  /**
   * 创建修复所有问题的操作
   * @param document 文档对象
   * @param diagnostics 诊断信息数组
   * @returns 修复所有操作
   */
  private createFixAllAction(
    document: vscode.TextDocument,
    diagnostics: vscode.Diagnostic[]
  ): vscode.CodeAction | null {
    try {
      const action = new vscode.CodeAction(
        `🚀 修复所有安全问题 (${diagnostics.length}个)`,
        vscode.CodeActionKind.SourceFixAll
      );

      action.edit = new vscode.WorkspaceEdit();

      // 按行号排序，从后往前修复避免位置偏移
      const sortedDiagnostics = diagnostics.sort((a, b) => 
        b.range.start.line - a.range.start.line ||
        b.range.start.character - a.range.start.character
      );

      for (const diagnostic of sortedDiagnostics) {
        const fixActions = this.createFixActionsForDiagnostic(
          document, 
          diagnostic, 
          diagnostic.range
        );
        
        const preferredFix = fixActions.find(fix => fix.isPreferred) || fixActions[0];
        if (preferredFix && preferredFix.edit) {
          for (const [uri, edits] of preferredFix.edit.entries()) {
            for (const edit of edits) {
              action.edit.replace(uri, edit.range, edit.newText);
            }
          }
        }
      }

      action.diagnostics = diagnostics;
      action.isPreferred = true;
      
      return action;

    } catch (error) {
      console.error('VibeGuard: 创建修复所有操作失败', error);
      return null;
    }
  }
}
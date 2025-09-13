/**
 * DiagnosticManager - 诊断管理器
 * 
 * 负责将 SecurityIssue 转换为 VSCode 诊断信息，并管理诊断的显示、更新和清除。
 * 专为非技术用户设计，使用中文错误信息，避免技术术语。
 */

import * as vscode from 'vscode';
import { 
  SecurityIssue, 
  IssueSeverity, 
  IDiagnosticManager,
  SecurityCategory 
} from '../types';

/**
 * 诊断管理器配置
 */
interface DiagnosticConfig {
  /** 诊断集合名称 */
  collectionName: string;
  /** 每个文件最大诊断数量 */
  maxDiagnosticsPerFile: number;
  /** 是否分组相似问题 */
  groupSimilarIssues: boolean;
}

/**
 * 诊断管理器实现
 * 
 * 将安全问题转换为 VSCode 诊断信息，提供用户友好的中文错误提示
 */
export class DiagnosticManager implements IDiagnosticManager {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private config: DiagnosticConfig;

  constructor(config?: Partial<DiagnosticConfig>) {
    this.config = {
      collectionName: 'vibeguard',
      maxDiagnosticsPerFile: 50,
      groupSimilarIssues: true,
      ...config
    };

    this.diagnosticCollection = vscode.languages.createDiagnosticCollection(
      this.config.collectionName
    );
  }

  /**
   * 更新文档的诊断信息
   * @param document 文档对象
   * @param issues 安全问题列表
   */
  public updateDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]): void {
    try {
      // 限制诊断数量，避免界面过于混乱
      const limitedIssues = issues.slice(0, this.config.maxDiagnosticsPerFile);
      
      // 转换为 VSCode 诊断对象
      const diagnostics = limitedIssues.map(issue => this.convertToDiagnostic(issue));
      
      // 如果启用分组，则合并相似问题
      const finalDiagnostics = this.config.groupSimilarIssues 
        ? this.groupSimilarDiagnostics(diagnostics)
        : diagnostics;

      // 更新诊断集合
      this.diagnosticCollection.set(document.uri, finalDiagnostics);
      
    } catch (error) {
      console.error('VibeGuard: 更新诊断信息失败', error);
      // 静默失败，不影响用户体验
    }
  }

  /**
   * 清除文档的诊断信息
   * @param document 文档对象
   */
  public clearDiagnostics(document: vscode.TextDocument): void {
    try {
      this.diagnosticCollection.delete(document.uri);
    } catch (error) {
      console.error('VibeGuard: 清除诊断信息失败', error);
    }
  }

  /**
   * 获取诊断集合
   * @returns VSCode 诊断集合
   */
  public getDiagnosticCollection(): vscode.DiagnosticCollection {
    return this.diagnosticCollection;
  }

  /**
   * 清除所有诊断信息
   */
  public clearAllDiagnostics(): void {
    try {
      this.diagnosticCollection.clear();
    } catch (error) {
      console.error('VibeGuard: 清除所有诊断信息失败', error);
    }
  }

  /**
   * 释放资源
   */
  public dispose(): void {
    try {
      this.diagnosticCollection.dispose();
    } catch (error) {
      console.error('VibeGuard: 释放诊断管理器资源失败', error);
    }
  }

  /**
   * 将 SecurityIssue 转换为 VSCode Diagnostic
   * @param issue 安全问题
   * @returns VSCode 诊断对象
   */
  private convertToDiagnostic(issue: SecurityIssue): vscode.Diagnostic {
    // 创建问题范围
    const range = new vscode.Range(
      issue.location.line,
      issue.location.column,
      issue.location.line,
      issue.location.column + issue.location.length
    );

    // 转换严重程度
    const severity = this.convertSeverity(issue.severity);

    // 创建诊断对象
    const diagnostic = new vscode.Diagnostic(
      range,
      this.enhanceMessage(issue),
      severity
    );

    // 设置诊断代码和来源
    diagnostic.code = issue.code;
    diagnostic.source = 'VibeGuard';
    
    // 添加相关信息
    diagnostic.relatedInformation = this.createRelatedInformation(issue);

    // 设置标签
    diagnostic.tags = this.getDiagnosticTags(issue);

    return diagnostic;
  }

  /**
   * 转换问题严重程度
   * @param severity 问题严重程度
   * @returns VSCode 诊断严重程度
   */
  private convertSeverity(severity: IssueSeverity): vscode.DiagnosticSeverity {
    switch (severity) {
      case IssueSeverity.ERROR:
        return vscode.DiagnosticSeverity.Error;
      case IssueSeverity.WARNING:
        return vscode.DiagnosticSeverity.Warning;
      case IssueSeverity.INFO:
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }

  /**
   * 增强错误信息，添加用户友好的提示
   * @param issue 安全问题
   * @returns 增强后的错误信息
   */
  private enhanceMessage(issue: SecurityIssue): string {
    let message = issue.message;

    // 根据问题类别添加特定的用户友好提示
    switch (issue.category) {
      case SecurityCategory.API_KEY:
        message += '\n💡 建议：使用环境变量存储密钥，避免泄露风险';
        break;
      case SecurityCategory.SQL_DANGER:
        message += '\n💡 建议：添加 WHERE 条件限制操作范围';
        break;
      case SecurityCategory.CODE_INJECTION:
        message += '\n💡 建议：使用安全的替代方法处理用户输入';
        break;
      case SecurityCategory.FRAMEWORK_RISK:
        message += '\n💡 建议：使用框架提供的安全方法';
        break;
      case SecurityCategory.CONFIG_ERROR:
        message += '\n💡 建议：检查生产环境配置';
        break;
    }

    // 添加修复难度提示
    if (issue.metadata.effort) {
      const effortText = this.getEffortText(issue.metadata.effort);
      message += `\n🔧 修复难度：${effortText}`;
    }

    return message;
  }

  /**
   * 获取修复难度的中文描述
   * @param effort 修复难度
   * @returns 中文描述
   */
  private getEffortText(effort: string): string {
    switch (effort) {
      case 'easy':
        return '简单（一键修复）';
      case 'medium':
        return '中等（需要少量修改）';
      case 'hard':
        return '困难（需要重构代码）';
      default:
        return '未知';
    }
  }

  /**
   * 创建相关信息
   * @param issue 安全问题
   * @returns 相关信息数组
   */
  private createRelatedInformation(issue: SecurityIssue): vscode.DiagnosticRelatedInformation[] {
    const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];

    // 添加详细描述
    if (issue.description && issue.description !== issue.message) {
      // 由于我们没有具体的位置信息，使用当前位置
      const location = new vscode.Location(
        vscode.Uri.parse(''), // 空 URI，表示当前文档
        new vscode.Range(issue.location.line, 0, issue.location.line, 0)
      );
      
      relatedInfo.push(new vscode.DiagnosticRelatedInformation(
        location,
        `详细说明：${issue.description}`
      ));
    }

    // 添加快速修复提示
    if (issue.quickFix) {
      const location = new vscode.Location(
        vscode.Uri.parse(''),
        new vscode.Range(issue.location.line, 0, issue.location.line, 0)
      );
      
      relatedInfo.push(new vscode.DiagnosticRelatedInformation(
        location,
        `快速修复：${issue.quickFix.title} - ${issue.quickFix.description}`
      ));
    }

    return relatedInfo;
  }

  /**
   * 获取诊断标签
   * @param issue 安全问题
   * @returns 诊断标签数组
   */
  private getDiagnosticTags(issue: SecurityIssue): vscode.DiagnosticTag[] {
    const tags: vscode.DiagnosticTag[] = [];

    // 根据问题类型添加标签
    if (issue.category === SecurityCategory.API_KEY && issue.severity === IssueSeverity.ERROR) {
      // 对于严重的安全问题，标记为不必要的代码（建议移除）
      tags.push(vscode.DiagnosticTag.Unnecessary);
    }

    return tags;
  }

  /**
   * 分组相似的诊断信息
   * @param diagnostics 诊断信息数组
   * @returns 分组后的诊断信息数组
   */
  private groupSimilarDiagnostics(diagnostics: vscode.Diagnostic[]): vscode.Diagnostic[] {
    if (diagnostics.length <= 1) {
      return diagnostics;
    }

    const grouped = new Map<string, vscode.Diagnostic[]>();
    
    // 按错误代码分组
    for (const diagnostic of diagnostics) {
      const key = diagnostic.code?.toString() || 'unknown';
      if (!grouped.has(key)) {
        grouped.set(key, []);
      }
      grouped.get(key)!.push(diagnostic);
    }

    const result: vscode.Diagnostic[] = [];
    
    // 处理每个分组
    for (const [code, group] of grouped) {
      if (group.length === 1) {
        result.push(group[0]);
      } else {
        // 创建合并的诊断信息
        const first = group[0];
        const count = group.length;
        
        const mergedDiagnostic = new vscode.Diagnostic(
          first.range,
          `${first.message}\n📊 在此文件中发现 ${count} 个相同问题`,
          first.severity
        );
        
        if (first.code) {
          mergedDiagnostic.code = first.code;
        }
        if (first.source) {
          mergedDiagnostic.source = first.source;
        }
        if (first.relatedInformation) {
          mergedDiagnostic.relatedInformation = first.relatedInformation;
        }
        if (first.tags) {
          mergedDiagnostic.tags = first.tags;
        }
        
        result.push(mergedDiagnostic);
      }
    }

    return result;
  }
}
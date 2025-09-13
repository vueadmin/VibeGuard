export type Severity = 'error' | 'warning' | 'info';

export interface Issue {
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    severity: Severity;
    message: string;
    code: string;
    quickFix?: QuickFix;
}

export interface QuickFix {
    title: string;
    replacement?: string;
    edit?: TextEdit;
}

export interface TextEdit {
    range: Range;
    newText: string;
}

export interface Range {
    start: Position;
    end: Position;
}

export interface Position {
    line: number;
    character: number;
}

export interface Rule {
    code: string;
    severity: Severity;
    message: string;
    pattern?: RegExp;
    astPattern?: ASTPattern;
    quickFix?: QuickFixTemplate;
    metadata?: RuleMetadata;
    check?: (text: string, languageId?: string) => Promise<RuleMatch[]> | RuleMatch[];
}

export interface RuleMatch {
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    matchedText?: string;
}

export interface QuickFixTemplate {
    title: string;
    replacement?: string;
    transform?: (match: string) => string;
}

export interface RuleMetadata {
    category: 'security' | 'performance' | 'quality' | 'style';
    tags: string[];
    docs?: string;
}

export interface ASTPattern {
    type: string;
    properties?: Record<string, any>;
}

export interface CacheEntry {
    value: any;
    timestamp: number;
}
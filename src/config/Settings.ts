import * as vscode from 'vscode';
import { Logger } from '../utils/logger';

export interface SeverityLevels {
    error: boolean;
    warning: boolean;
    info: boolean;
}

export interface VibeGuardSettings {
    enable: boolean;
    severityLevels: SeverityLevels;
    excludedFolders: string[];
    maxFileSize: number;
    debounceDelay: number;
}

export class Settings {
    private settings: VibeGuardSettings;

    constructor() {
        this.settings = this.loadSettings();
    }

    /**
     * \u52a0\u8f7d\u8bbe\u7f6e
     */
    private loadSettings(): VibeGuardSettings {
        const config = vscode.workspace.getConfiguration('vibeguard');
        
        return {
            enable: config.get<boolean>('enable', true),
            severityLevels: config.get<SeverityLevels>('severityLevels', {
                error: true,
                warning: true,
                info: false
            }),
            excludedFolders: config.get<string[]>('excludedFolders', [
                'node_modules',
                '.git',
                'dist',
                'build',
                '.vscode',
                'coverage',
                '.next',
                '.nuxt',
                'out'
            ]),
            maxFileSize: config.get<number>('maxFileSize', 500000),
            debounceDelay: config.get<number>('debounceDelay', 500)
        };
    }

    /**
     * \u91cd\u65b0\u52a0\u8f7d\u8bbe\u7f6e
     */
    reload(): void {
        this.settings = this.loadSettings();
        Logger.info('\u8bbe\u7f6e\u5df2\u91cd\u65b0\u52a0\u8f7d');
    }

    /**
     * \u83b7\u53d6\u662f\u5426\u542f\u7528
     */
    isEnabled(): boolean {
        return this.settings.enable;
    }

    /**
     * \u83b7\u53d6\u4e25\u91cd\u7ea7\u522b\u8fc7\u6ee4
     */
    getSeverityLevels(): SeverityLevels {
        return this.settings.severityLevels;
    }

    /**
     * \u83b7\u53d6\u6392\u9664\u6587\u4ef6\u5939
     */
    getExcludedFolders(): string[] {
        return this.settings.excludedFolders;
    }

    /**
     * \u83b7\u53d6\u6700\u5927\u6587\u4ef6\u5927\u5c0f
     */
    getMaxFileSize(): number {
        return this.settings.maxFileSize;
    }

    /**
     * \u83b7\u53d6\u9632\u6296\u5ef6\u8fdf
     */
    getDebounceDelay(): number {
        return this.settings.debounceDelay;
    }

    /**
     * \u68c0\u67e5\u8def\u5f84\u662f\u5426\u5e94\u88ab\u6392\u9664
     */
    isPathExcluded(path: string): boolean {
        const normalizedPath = path.replace(/\\/g, '/');
        
        for (const folder of this.settings.excludedFolders) {
            if (normalizedPath.includes(`/${folder}/`) || 
                normalizedPath.endsWith(`/${folder}`) ||
                normalizedPath.includes(`\\${folder}\\`) ||
                normalizedPath.endsWith(`\\${folder}`)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * \u68c0\u67e5\u6587\u4ef6\u5927\u5c0f\u662f\u5426\u8d85\u9650
     */
    isFileSizeExceeded(size: number): boolean {
        return size > this.settings.maxFileSize;
    }

    /**
     * \u66f4\u65b0\u8bbe\u7f6e
     */
    async updateSetting(key: string, value: any, global = false): Promise<void> {
        const config = vscode.workspace.getConfiguration('vibeguard');
        await config.update(key, value, global ? vscode.ConfigurationTarget.Global : vscode.ConfigurationTarget.Workspace);
        this.reload();
    }

    /**
     * \u83b7\u53d6\u6240\u6709\u8bbe\u7f6e
     */
    getAllSettings(): VibeGuardSettings {
        return { ...this.settings };
    }
}
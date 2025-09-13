import * as vscode from 'vscode';

export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3
}

export class Logger {
    private static outputChannel: vscode.OutputChannel | null = null;
    private static logLevel: LogLevel = LogLevel.INFO;

    /**
     * \u521d\u59cb\u5316\u65e5\u5fd7\u5668
     */
    private static init() {
        if (!this.outputChannel) {
            this.outputChannel = vscode.window.createOutputChannel('VibeGuard');
        }
    }

    /**
     * \u8bbe\u7f6e\u65e5\u5fd7\u7ea7\u522b
     */
    static setLogLevel(level: LogLevel) {
        this.logLevel = level;
    }

    /**
     * \u8c03\u8bd5\u65e5\u5fd7
     */
    static debug(message: string, ...args: any[]) {
        if (this.logLevel <= LogLevel.DEBUG) {
            this.log('DEBUG', message, ...args);
        }
    }

    /**
     * \u4fe1\u606f\u65e5\u5fd7
     */
    static info(message: string, ...args: any[]) {
        if (this.logLevel <= LogLevel.INFO) {
            this.log('INFO', message, ...args);
        }
    }

    /**
     * \u8b66\u544a\u65e5\u5fd7
     */
    static warning(message: string, ...args: any[]) {
        if (this.logLevel <= LogLevel.WARNING) {
            this.log('WARNING', message, ...args);
        }
    }

    /**
     * \u9519\u8bef\u65e5\u5fd7
     */
    static error(message: string, error?: any) {
        if (this.logLevel <= LogLevel.ERROR) {
            this.log('ERROR', message, error);
            
            // \u5982\u679c\u6709\u9519\u8bef\u5bf9\u8c61\uff0c\u8f93\u51fa\u5806\u6808\u4fe1\u606f
            if (error && error.stack) {
                this.log('ERROR', 'Stack trace:', error.stack);
            }
        }
    }

    /**
     * \u5199\u5165\u65e5\u5fd7
     */
    private static log(level: string, message: string, ...args: any[]) {
        this.init();
        
        const timestamp = new Date().toISOString();
        const formattedMessage = `[${timestamp}] [${level}] ${message}`;
        
        // \u8f93\u51fa\u5230\u63a7\u5236\u53f0\uff08\u5f00\u53d1\u65f6\uff09
        console.log(formattedMessage, ...args);
        
        // \u8f93\u51fa\u5230 VS Code \u8f93\u51fa\u9762\u677f
        if (this.outputChannel) {
            this.outputChannel.appendLine(formattedMessage);
            if (args.length > 0) {
                args.forEach(arg => {
                    if (typeof arg === 'object') {
                        this.outputChannel!.appendLine(JSON.stringify(arg, null, 2));
                    } else {
                        this.outputChannel!.appendLine(String(arg));
                    }
                });
            }
        }
    }

    /**
     * \u663e\u793a\u8f93\u51fa\u9762\u677f
     */
    static show() {
        this.init();
        this.outputChannel?.show();
    }

    /**
     * \u9690\u85cf\u8f93\u51fa\u9762\u677f
     */
    static hide() {
        this.outputChannel?.hide();
    }

    /**
     * \u6e05\u7a7a\u8f93\u51fa\u9762\u677f
     */
    static clear() {
        this.outputChannel?.clear();
    }

    /**
     * \u91ca\u653e\u8d44\u6e90
     */
    static dispose() {
        this.outputChannel?.dispose();
        this.outputChannel = null;
    }
}
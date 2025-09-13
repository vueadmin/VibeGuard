import { Rule, RuleMatch, Severity } from '../types';
import { Settings } from '../config/Settings';
import { sqlRules } from './definitions/sql-rules';
import { javascriptRules } from './definitions/javascript-rules';
import { typescriptRules } from './definitions/typescript-rules';
import { reactRules } from './definitions/react-rules';
import { vueRules } from './definitions/vue-rules';
import { nodejsRules } from './definitions/nodejs-rules';
import { pythonRules } from './definitions/python-rules';
import { configRules } from './definitions/config-rules';
import { Logger } from '../utils/logger';

export class RuleEngine {
    private rules: Map<string, Rule[]> = new Map();
    private allRules: Map<string, Rule> = new Map();

    constructor(private settings: Settings) {
        this.loadRules();
    }

    /**
     * \u52a0\u8f7d\u6240\u6709\u89c4\u5219
     */
    private loadRules() {
        Logger.debug('\u52a0\u8f7d\u89c4\u5219...');
        
        // \u52a0\u8f7d\u5404\u8bed\u8a00\u89c4\u5219
        this.rules.set('sql', sqlRules);
        this.rules.set('javascript', javascriptRules);
        this.rules.set('typescript', typescriptRules);
        this.rules.set('react', reactRules);
        this.rules.set('vue', vueRules);
        this.rules.set('nodejs', nodejsRules);
        this.rules.set('python', pythonRules);
        this.rules.set('config', configRules);

        // \u6784\u5efa\u89c4\u5219\u7d22\u5f15
        for (const [category, rules] of this.rules) {
            for (const rule of rules) {
                this.allRules.set(rule.code, rule);
            }
        }

        Logger.debug(`\u52a0\u8f7d\u5b8c\u6210 ${this.allRules.size} \u6761\u89c4\u5219`);
    }

    /**
     * \u83b7\u53d6\u6307\u5b9a\u8bed\u8a00\u7684\u89c4\u5219
     */
    getRulesForLanguage(languageId: string): Rule[] {
        const rules: Rule[] = [];
        const severityFilter = this.settings.getSeverityLevels();
        
        // \u8bed\u8a00\u6620\u5c04
        const languageMappings: Record<string, string[]> = {
            'javascript': ['javascript'],
            'typescript': ['javascript', 'typescript'],
            'javascriptreact': ['javascript', 'react'],
            'typescriptreact': ['javascript', 'typescript', 'react'],
            'vue': ['javascript', 'vue'],
            'python': ['python'],
            'sql': ['sql'],
            'json': ['config'],
            'jsonc': ['config'],
            'yaml': ['config'],
            'yml': ['config'],
            'dockerfile': ['config'],
            'plaintext': ['config'], // .env \u6587\u4ef6
            'dotenv': ['config'],
            'shellscript': ['config'],
            'sh': ['config'],
            'bash': ['config']
        };

        // \u83b7\u53d6\u6240\u6709\u9002\u7528\u7684\u89c4\u5219\u96c6
        let ruleSets = languageMappings[languageId] || [];
        
        // \u68c0\u6d4b Node.js \u73af\u5883(\u901a\u8fc7\u6587\u4ef6\u5185\u5bb9\u68c0\u6d4b)
        if (languageId.includes('javascript') || languageId.includes('typescript')) {
            ruleSets.push('nodejs');
        }
        
        // \u5408\u5e76\u6240\u6709\u89c4\u5219
        for (const ruleSet of ruleSets) {
            const ruleList = this.rules.get(ruleSet);
            if (ruleList) {
                for (const rule of ruleList) {
                    // \u6839\u636e\u4e25\u91cd\u7ea7\u522b\u8fc7\u6ee4
                    if (severityFilter[rule.severity]) {
                        rules.push(rule);
                    }
                }
            }
        }
        
        // \u53bb\u91cd(\u6839\u636e code)
        const uniqueRules = new Map<string, Rule>();
        for (const rule of rules) {
            uniqueRules.set(rule.code, rule);
        }
        
        return Array.from(uniqueRules.values());
    }

    /**
     * \u6839\u636e\u89c4\u5219\u4ee3\u7801\u83b7\u53d6\u89c4\u5219
     */
    getRuleByCode(code: string): Rule | undefined {
        return this.allRules.get(code);
    }

    /**
     * \u68c0\u67e5\u89c4\u5219
     */
    async checkRule(rule: Rule, text: string): Promise<RuleMatch[]> {
        if (rule.check) {
            return await rule.check(text);
        }
        
        if (rule.pattern) {
            return this.checkWithRegex(rule, text);
        }
        
        return [];
    }

    /**
     * \u4f7f\u7528\u6b63\u5219\u8868\u8fbe\u5f0f\u68c0\u67e5
     */
    private checkWithRegex(rule: Rule, text: string): RuleMatch[] {
        const matches: RuleMatch[] = [];
        const lines = text.split('\n');
        const regex = new RegExp(rule.pattern!.source, rule.pattern!.flags);
        
        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            regex.lastIndex = 0;
            
            let match;
            while ((match = regex.exec(line)) !== null) {
                matches.push({
                    line: lineIndex,
                    column: match.index,
                    endColumn: match.index + match[0].length,
                    matchedText: match[0]
                });
                
                if (!regex.global) break;
            }
        }
        
        return matches;
    }
}
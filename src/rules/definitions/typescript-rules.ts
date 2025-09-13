import { Rule } from '../../types';

export const typescriptRules: Rule[] = [
    {
        code: 'TS001',
        severity: 'warning',
        message: '\u26a0\ufe0f \u7c7b\u578b\u4e0d\u5b89\u5168\uff1a\u907f\u514d\u4f7f\u7528 any\uff0c\u5931\u53bb\u4e86 TypeScript \u7684\u610f\u4e49',
        pattern: /:\s*any\b/g,
        quickFix: {
            title: '\u4f7f\u7528\u5177\u4f53\u7c7b\u578b\u6216 unknown',
            replacement: ': unknown'
        },
        metadata: {
            category: 'quality',
            tags: ['type-safety', 'best-practice']
        }
    },
    {
        code: 'TS002',
        severity: 'warning',
        message: '\u26a0\ufe0f \u975e\u7a7a\u65ad\u8a00(!) \u53ef\u80fd\u5bfc\u81f4\u8fd0\u884c\u65f6\u9519\u8bef',
        pattern: /\w+!\./g,
        quickFix: {
            title: '\u6dfb\u52a0\u7a7a\u503c\u68c0\u67e5',
            replacement: '?.'
        },
        metadata: {
            category: 'quality',
            tags: ['null-safety', 'runtime-error']
        }
    },
    {
        code: 'TS003',
        severity: 'error',
        message: '\ud83d\udea8 @ts-ignore \u4f1a\u9690\u85cf\u7c7b\u578b\u9519\u8bef\uff0c\u751f\u4ea7\u73af\u5883\u7981\u7528',
        pattern: /@ts-ignore/g,
        metadata: {
            category: 'quality',
            tags: ['type-safety', 'production']
        }
    },
    {
        code: 'TS004',
        severity: 'warning',
        message: '\u26a0\ufe0f @ts-nocheck \u4f1a\u7981\u7528\u6574\u4e2a\u6587\u4ef6\u7684\u7c7b\u578b\u68c0\u67e5',
        pattern: /@ts-nocheck/g,
        metadata: {
            category: 'quality',
            tags: ['type-safety']
        }
    },
    {
        code: 'TS005',
        severity: 'warning',
        message: '\u26a0\ufe0f \u5f3a\u5236\u7c7b\u578b\u8f6c\u6362 (as) \u53ef\u80fd\u9690\u85cf\u9519\u8bef',
        pattern: /\bas\s+\w+/g,
        metadata: {
            category: 'quality',
            tags: ['type-safety', 'type-assertion']
        }
    },
    {
        code: 'TS006',
        severity: 'error',
        message: '\ud83d\udd34 \u4f7f\u7528 require() \u800c\u975e ES6 import',
        pattern: /\brequire\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 ES6 import',
            replacement: 'import'
        },
        metadata: {
            category: 'quality',
            tags: ['es6', 'module']
        }
    },
    {
        code: 'TS007',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u6307\u5b9a\u51fd\u6570\u8fd4\u56de\u7c7b\u578b',
        pattern: /function\s+\w+\s*\([^)]*\)\s*\{/g,
        metadata: {
            category: 'quality',
            tags: ['type-safety', 'function']
        }
    },
    {
        code: 'TS008',
        severity: 'warning',
        message: '\u26a0\ufe0f interface \u4e0e type \u6df7\u7528\uff0c\u5efa\u8bae\u7edf\u4e00\u98ce\u683c',
        pattern: /\b(interface|type)\s+\w+/g,
        metadata: {
            category: 'style',
            tags: ['consistency']
        }
    },
    {
        code: 'TS009',
        severity: 'error',
        message: '\ud83d\udd34 \u907f\u514d\u4f7f\u7528 Object \u7c7b\u578b\uff0c\u5e94\u4f7f\u7528 object',
        pattern: /:\s*Object\b/g,
        quickFix: {
            title: '\u4f7f\u7528\u5c0f\u5199 object',
            replacement: ': object'
        },
        metadata: {
            category: 'quality',
            tags: ['type-safety']
        }
    },
    {
        code: 'TS010',
        severity: 'warning',
        message: '\u26a0\ufe0f \u679a\u4e3e\u6210\u5458\u672a\u663e\u5f0f\u8d4b\u503c',
        pattern: /enum\s+\w+\s*\{[^}]*\w+\s*(?!=[^,}])[,}]/g,
        metadata: {
            category: 'quality',
            tags: ['enum', 'best-practice']
        }
    }
];
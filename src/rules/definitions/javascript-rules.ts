import { Rule } from '../../types';

export const javascriptRules: Rule[] = [
    {
        code: 'JS001',
        severity: 'error',
        message: '\ud83d\udd12 eval() \u4f1a\u6267\u884c\u4efb\u610f\u4ee3\u7801\uff0c\u9ed1\u5ba2\u6700\u7231\uff01',
        pattern: /\beval\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 JSON.parse() \u6216\u5176\u4ed6\u5b89\u5168\u65b9\u6cd5',
            replacement: 'JSON.parse'
        },
        metadata: {
            category: 'security',
            tags: ['code-injection', 'critical'],
            docs: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'
        }
    },
    {
        code: 'JS002',
        severity: 'warning',
        message: '\u26a0\ufe0f XSS \u98ce\u9669\uff1ainnerHTML \u53ef\u80fd\u5bfc\u81f4\u811a\u672c\u6ce8\u5165',
        pattern: /\.innerHTML\s*=/g,
        quickFix: {
            title: '\u4f7f\u7528 textContent \u6216 sanitize',
            replacement: '.textContent ='
        },
        metadata: {
            category: 'security',
            tags: ['xss', 'dom'],
            docs: 'https://owasp.org/www-community/attacks/xss/'
        }
    },
    {
        code: 'JS003',
        severity: 'error',
        message: '\ud83d\udd11 \u5bc6\u94a5\u6cc4\u9732\uff01\u4e0d\u8981\u5728\u4ee3\u7801\u4e2d\u786c\u7f16\u7801 API Key',
        pattern: /(api[_-]?key|secret|password|token|bearer|credentials?|auth)\s*[:=]\s*["'][^"']{8,}["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: 'process.env.API_KEY'
        },
        metadata: {
            category: 'security',
            tags: ['credentials', 'api-key', 'critical'],
            docs: 'https://12factor.net/config'
        }
    },
    {
        code: 'JS004',
        severity: 'error',
        message: '\u26a0\ufe0f \u5f02\u6b65\u9677\u9631\uff1aforEach \u4e2d\u7684 await \u4e0d\u4f1a\u7b49\u5f85',
        pattern: /\.forEach\s*\(\s*async/g,
        quickFix: {
            title: '\u4f7f\u7528 for...of \u6216 Promise.all',
            replacement: 'for (const item of items)'
        },
        metadata: {
            category: 'quality',
            tags: ['async', 'common-mistake']
        }
    },
    {
        code: 'JS005',
        severity: 'error',
        message: '\ud83d\udea8 \u751f\u4ea7\u73af\u5883\u914d\u7f6e\u9519\u8bef\uff1aCORS \u5141\u8bb8\u6240\u6709\u57df\u540d\uff01',
        pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"][^}]*\}/g,
        quickFix: {
            title: '\u9650\u5236\u5141\u8bb8\u7684\u57df\u540d',
            replacement: "cors({ origin: ['https://example.com'] })"
        },
        metadata: {
            category: 'security',
            tags: ['cors', 'configuration']
        }
    },
    {
        code: 'JS006',
        severity: 'warning',
        message: '\u26a0\ufe0f document.write \u53ef\u80fd\u5bfc\u81f4 XSS \u653b\u51fb',
        pattern: /document\.write\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 DOM API',
            replacement: 'document.createElement'
        },
        metadata: {
            category: 'security',
            tags: ['xss', 'dom']
        }
    },
    {
        code: 'JS007',
        severity: 'warning',
        message: '\u26a0\ufe0f == \u4f1a\u8fdb\u884c\u7c7b\u578b\u8f6c\u6362\uff0c\u53ef\u80fd\u5bfc\u81f4\u610f\u5916\u7ed3\u679c',
        pattern: /[^!=]==[^=]/g,
        quickFix: {
            title: '\u4f7f\u7528\u4e25\u683c\u76f8\u7b49 ===',
            replacement: '==='
        },
        metadata: {
            category: 'quality',
            tags: ['best-practice']
        }
    },
    {
        code: 'JS008',
        severity: 'error',
        message: '\ud83d\udd34 console.log \u5728\u751f\u4ea7\u73af\u5883\u4e2d\u4f1a\u6cc4\u9732\u654f\u611f\u4fe1\u606f',
        pattern: /console\.(log|info|debug|dir)\s*\(/g,
        quickFix: {
            title: '\u79fb\u9664 console \u8bed\u53e5',
            replacement: ''
        },
        metadata: {
            category: 'quality',
            tags: ['production', 'logging']
        }
    },
    {
        code: 'JS009',
        severity: 'error',
        message: '\u26a0\ufe0f setTimeout/setInterval \u4f20\u5165\u5b57\u7b26\u4e32\u4f1a\u50cf eval \u4e00\u6837\u6267\u884c',
        pattern: /set(Timeout|Interval)\s*\(\s*["']/g,
        quickFix: {
            title: '\u4f7f\u7528\u51fd\u6570\u800c\u975e\u5b57\u7b26\u4e32',
            replacement: 'setTimeout(() => {'
        },
        metadata: {
            category: 'security',
            tags: ['code-injection']
        }
    },
    {
        code: 'JS010',
        severity: 'warning',
        message: '\u26a0\ufe0f var \u58f0\u660e\u4f1a\u63d0\u5347\uff0c\u5efa\u8bae\u4f7f\u7528 let \u6216 const',
        pattern: /\bvar\s+\w+/g,
        quickFix: {
            title: '\u4f7f\u7528 let \u6216 const',
            replacement: 'let'
        },
        metadata: {
            category: 'quality',
            tags: ['es6', 'best-practice']
        }
    },
    {
        code: 'JS011',
        severity: 'error',
        message: '\ud83d\udd34 Function \u6784\u9020\u51fd\u6570\u76f8\u5f53\u4e8e eval\uff0c\u5b58\u5728\u5b89\u5168\u98ce\u9669',
        pattern: /new\s+Function\s*\(/g,
        metadata: {
            category: 'security',
            tags: ['code-injection']
        }
    },
    {
        code: 'JS012',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u58f0\u660e\u7684\u53d8\u91cf\u4f1a\u6210\u4e3a\u5168\u5c40\u53d8\u91cf',
        pattern: /^\s*(?!var|let|const|function|class|import|export)[a-zA-Z_$][a-zA-Z0-9_$]*\s*=/gm,
        quickFix: {
            title: '\u6dfb\u52a0\u53d8\u91cf\u58f0\u660e',
            replacement: 'let '
        },
        metadata: {
            category: 'quality',
            tags: ['scope', 'global']
        }
    },
    {
        code: 'JS013',
        severity: 'error',
        message: '\ud83d\udd25 with \u8bed\u53e5\u5df2\u88ab\u5f03\u7528\uff0c\u5b58\u5728\u6027\u80fd\u548c\u5b89\u5168\u95ee\u9898',
        pattern: /\bwith\s*\(/g,
        metadata: {
            category: 'quality',
            tags: ['deprecated', 'performance']
        }
    },
    {
        code: 'JS014',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u6355\u83b7\u7684 Promise \u9519\u8bef\u53ef\u80fd\u5bfc\u81f4\u7a0b\u5e8f\u5d29\u6e83',
        pattern: /\.then\s*\([^)]+\)(?!\s*\.catch)/g,
        quickFix: {
            title: '\u6dfb\u52a0 .catch \u5904\u7406',
            replacement: '.then().catch(err => console.error(err))'
        },
        metadata: {
            category: 'quality',
            tags: ['async', 'error-handling']
        }
    },
    {
        code: 'JS015',
        severity: 'warning',
        message: '\u26a0\ufe0f \u53ef\u80fd\u5b58\u5728\u5185\u5b58\u6cc4\u6f0f\uff1aaddEventListener \u672a\u6e05\u7406',
        pattern: /addEventListener\s*\([^)]+\)/g,
        metadata: {
            category: 'performance',
            tags: ['memory-leak', 'event-listener']
        }
    }
];
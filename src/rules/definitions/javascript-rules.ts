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
        message: '\u26a0\ufe0f \u5f02\u6b65\u9677\u9631\uff1aforEach \u4e2d\u7684 await \u4e0d\u4f1a\u7b49\u5f85\uff0c\u5c31\u50cf\u8ba9\u5458\u5de5\u5404\u81ea\u5e72\u6d3b\u4e0d\u7b49\u5f85\u5b8c\u6210',
        pattern: /\.forEach\s*\(\s*async/g,
        quickFix: {
            title: '\u4f7f\u7528 for...of \u6216 Promise.all',
            replacement: 'for (const item of items) {\n  await processItem(item);\n}'
        },
        metadata: {
            category: 'quality',
            tags: ['async', 'common-mistake'],
            docs: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for-await...of'
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
        message: '\u26a0\ufe0f \u672a\u58f0\u660e\u7684\u53d8\u91cf\u4f1a\u6210\u4e3a\u5168\u5c40\u53d8\u91cf\uff0c\u5c31\u50cf\u628a\u79c1\u4eba\u7269\u54c1\u653e\u5728\u516c\u5171\u573a\u6240',
        pattern: /(?<!\.)(?<![\w$])([\w$]+)\s*=\s*(?!.*\b(?:var|let|const)\s+\1\b)/g,
        quickFix: {
            title: '\u6dfb\u52a0\u53d8\u91cf\u58f0\u660e',
            replacement: 'let $1 = '
        },
        metadata: {
            category: 'quality',
            tags: ['scope', 'global', 'strict-mode']
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
    },
    {
        code: 'JS016',
        severity: 'error',
        message: '\ud83d\udd34 React \u5b89\u5168\u98ce\u9669\uff1adangerouslySetInnerHTML \u53ef\u80fd\u5bfc\u81f4 XSS \u653b\u51fb',
        pattern: /dangerouslySetInnerHTML\s*=\s*\{/g,
        quickFix: {
            title: '\u4f7f\u7528\u5b89\u5168\u7684 HTML \u6e32\u67d3\u65b9\u6cd5',
            replacement: '// \u8003\u8651\u4f7f\u7528 DOMPurify.sanitize() \u6216\u5176\u4ed6\u5b89\u5168\u65b9\u6cd5'
        },
        metadata: {
            category: 'security',
            tags: ['react', 'xss', 'dom'],
            docs: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
        }
    },
    {
        code: 'JS017',
        severity: 'warning',
        message: '\u26a0\ufe0f \u6b63\u5219\u8868\u8fbe\u5f0f\u53ef\u80fd\u5bfc\u81f4 ReDoS \u653b\u51fb\uff0c\u8ba9\u7f51\u7ad9\u5361\u6b7b',
        pattern: /\/(.*\+)+.*\|.*(\*)+.*\//g,
        quickFix: {
            title: '\u4f18\u5316\u6b63\u5219\u8868\u8fbe\u5f0f',
            replacement: '// \u907f\u514d\u5d4c\u5957\u91cf\u8bcd\u548c\u56de\u6eaf'
        },
        metadata: {
            category: 'security',
            tags: ['regex', 'dos', 'performance'],
            docs: 'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'
        }
    },
    {
        code: 'JS018',
        severity: 'error',
        message: '\ud83d\udd11 postMessage \u672a\u9a8c\u8bc1\u6765\u6e90\uff0c\u4efb\u4f55\u7f51\u7ad9\u90fd\u80fd\u53d1\u9001\u6d88\u606f',
        pattern: /addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\([^)]*\)\s*\{|[^{]*=>\s*\{)(?![^}]*origin)/g,
        quickFix: {
            title: '\u6dfb\u52a0 origin \u9a8c\u8bc1',
            replacement: 'if (event.origin !== "https://trusted-site.com") return;'
        },
        metadata: {
            category: 'security',
            tags: ['postMessage', 'cross-origin'],
            docs: 'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns'
        }
    },
    {
        code: 'JS019',
        severity: 'error',
        message: '\ud83d\udd12 localStorage \u5b58\u50a8\u654f\u611f\u4fe1\u606f\u4e0d\u5b89\u5168\uff0c\u5c31\u50cf\u628a\u5bc6\u7801\u8d34\u5728\u663e\u793a\u5668\u4e0a',
        pattern: /localStorage\.setItem\s*\([^,]*(?:password|token|secret|key|credential)[^,)]*,/gi,
        quickFix: {
            title: '\u4e0d\u8981\u5728 localStorage \u5b58\u50a8\u654f\u611f\u4fe1\u606f',
            replacement: '// \u8003\u8651\u4f7f\u7528 sessionStorage \u6216\u5185\u5b58\u5b58\u50a8'
        },
        metadata: {
            category: 'security',
            tags: ['storage', 'credentials'],
            docs: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage'
        }
    },
    {
        code: 'JS020',
        severity: 'warning',
        message: '\u26a0\ufe0f JSON.parse \u672a\u6355\u83b7\u5f02\u5e38\uff0c\u683c\u5f0f\u9519\u8bef\u4f1a\u8ba9\u7a0b\u5e8f\u5d29\u6e83',
        pattern: /JSON\.parse\s*\([^)]+\)(?!\s*\)?\s*\.?\s*catch|\s*}\s*catch)/g,
        quickFix: {
            title: '\u6dfb\u52a0 try-catch \u5904\u7406',
            replacement: 'try {\n  const data = JSON.parse(jsonString);\n} catch (e) {\n  console.error("Invalid JSON:", e);\n}'
        },
        metadata: {
            category: 'quality',
            tags: ['error-handling', 'json']
        }
    },
    {
        code: 'JS021',
        severity: 'error',
        message: '\ud83d\udd34 \u4e0d\u5b89\u5168\u7684\u52a8\u6001\u4ee3\u7801\u52a0\u8f7d\uff0c\u9ed1\u5ba2\u53ef\u4ee5\u6ce8\u5165\u6076\u610f\u811a\u672c',
        pattern: /(?:script\.src|import\s*\()\s*[^=]*=\s*[`'"]\$\{|(?:script\.src|import\s*\()\s*[^=]*=\s*[^'"`]+\+/g,
        quickFix: {
            title: '\u4f7f\u7528\u9759\u6001 URL \u6216\u767d\u540d\u5355\u9a8c\u8bc1',
            replacement: '// \u9a8c\u8bc1 URL \u662f\u5426\u5728\u5141\u8bb8\u5217\u8868\u4e2d'
        },
        metadata: {
            category: 'security',
            tags: ['code-injection', 'dynamic-import']
        }
    }
];
import { Rule } from '../../types';

export const pythonRules: Rule[] = [
    {
        code: 'PY001',
        severity: 'error',
        message: '\u26a0\ufe0f os.remove() \u4f1a\u6c38\u4e45\u5220\u9664\u6587\u4ef6',
        pattern: /os\.(remove|unlink|rmdir)\s*\(/g,
        quickFix: {
            title: '\u6dfb\u52a0\u6587\u4ef6\u5b58\u5728\u68c0\u67e5',
            replacement: 'if os.path.exists(file):\n    os.remove(file)'
        },
        metadata: {
            category: 'security',
            tags: ['file-system', 'destructive']
        }
    },
    {
        code: 'PY002',
        severity: 'error',
        message: '\ud83d\udd12 pickle.load \u53ef\u6267\u884c\u4efb\u610f\u4ee3\u7801\uff0c\u4e0d\u8981\u52a0\u8f7d\u4e0d\u53ef\u4fe1\u6570\u636e',
        pattern: /pickle\.(load|loads)\s*\(/g,
        metadata: {
            category: 'security',
            tags: ['deserialization', 'critical'],
            docs: 'https://docs.python.org/3/library/pickle.html#restricting-globals'
        }
    },
    {
        code: 'PY003',
        severity: 'error',
        message: '\ud83d\udc80 eval/exec \u4f1a\u6267\u884c\u4efb\u610f\u4ee3\u7801',
        pattern: /\b(eval|exec|compile)\s*\(/g,
        metadata: {
            category: 'security',
            tags: ['code-injection', 'critical']
        }
    },
    {
        code: 'PY004',
        severity: 'error',
        message: '\ud83d\udea8 \u547d\u4ee4\u6ce8\u5165\uff1aos.system \u6267\u884c shell \u547d\u4ee4',
        pattern: /os\.(system|popen)\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 subprocess.run',
            replacement: 'subprocess.run'
        },
        metadata: {
            category: 'security',
            tags: ['command-injection', 'shell']
        }
    },
    {
        code: 'PY005',
        severity: 'error',
        message: '\ud83d\udd34 Flask/Django debug=True \u5728\u751f\u4ea7\u73af\u5883\u4f1a\u6cc4\u9732\u654f\u611f\u4fe1\u606f',
        pattern: /debug\s*=\s*True/g,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: "debug=os.getenv('DEBUG', 'False') == 'True'"
        },
        metadata: {
            category: 'security',
            tags: ['production', 'configuration']
        }
    },
    {
        code: 'PY006',
        severity: 'warning',
        message: '\u26a0\ufe0f assert \u8bed\u53e5\u5728\u751f\u4ea7\u73af\u5883\u4f1a\u88ab\u5ffd\u7565',
        pattern: /assert\s+/g,
        metadata: {
            category: 'quality',
            tags: ['production', 'validation']
        }
    },
    {
        code: 'PY007',
        severity: 'error',
        message: '\ud83d\udd11 \u5bc6\u7801\u660e\u6587\u5b58\u50a8\u5728\u4ee3\u7801\u4e2d',
        pattern: /(password|secret|api[_-]?key|token)\s*=\s*["'][^"']+["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: "os.getenv('PASSWORD')"
        },
        metadata: {
            category: 'security',
            tags: ['credentials', 'hardcoded']
        }
    },
    {
        code: 'PY008',
        severity: 'error',
        message: '\u26a0\ufe0f SQL \u6ce8\u5165\u98ce\u9669\uff1a\u5b57\u7b26\u4e32\u683c\u5f0f\u5316\u6784\u9020 SQL',
        pattern: /\.\s*format\s*\([^)]*\).*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
        quickFix: {
            title: '\u4f7f\u7528\u53c2\u6570\u5316\u67e5\u8be2',
            replacement: 'cursor.execute(sql, params)'
        },
        metadata: {
            category: 'security',
            tags: ['sql-injection']
        }
    },
    {
        code: 'PY009',
        severity: 'warning',
        message: '\u26a0\ufe0f except: \u6355\u83b7\u6240\u6709\u5f02\u5e38\u4f1a\u9690\u85cf bug',
        pattern: /except\s*:/g,
        quickFix: {
            title: '\u6307\u5b9a\u5177\u4f53\u5f02\u5e38\u7c7b\u578b',
            replacement: 'except Exception:'
        },
        metadata: {
            category: 'quality',
            tags: ['error-handling']
        }
    },
    {
        code: 'PY010',
        severity: 'error',
        message: '\u26a0\ufe0f \u6ca1\u6709\u4f7f\u7528 with \u8bed\u53e5\u53ef\u80fd\u5bfc\u81f4\u8d44\u6e90\u6cc4\u6f0f',
        pattern: /open\s*\([^)]+\)(?!\s*as)/g,
        quickFix: {
            title: '\u4f7f\u7528 with \u8bed\u53e5',
            replacement: 'with open(file) as f:'
        },
        metadata: {
            category: 'quality',
            tags: ['resource-management']
        }
    },
    {
        code: 'PY011',
        severity: 'error',
        message: '\ud83d\udca3 shutil.rmtree \u4f1a\u9012\u5f52\u5220\u9664\u6574\u4e2a\u76ee\u5f55\u6811',
        pattern: /shutil\.rmtree\s*\(/g,
        metadata: {
            category: 'security',
            tags: ['destructive', 'file-system']
        }
    },
    {
        code: 'PY012',
        severity: 'warning',
        message: '\u26a0\ufe0f \u4f7f\u7528\u53ef\u53d8\u9ed8\u8ba4\u53c2\u6570\u4f1a\u5bfc\u81f4\u610f\u5916\u884c\u4e3a',
        pattern: /def\s+\w+\s*\([^)]*=\s*(\[|\{)/g,
        quickFix: {
            title: '\u4f7f\u7528 None \u4f5c\u4e3a\u9ed8\u8ba4\u503c',
            replacement: '=None'
        },
        metadata: {
            category: 'quality',
            tags: ['function', 'mutable-default']
        }
    }
];
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
        message: '\u26a0\ufe0f SQL \u6ce8\u5165\u98ce\u9669\uff1a\u5b57\u7b26\u4e32\u62fc\u63a5\u6784\u9020 SQL\uff0c\u5c31\u50cf\u628a\u5bb6\u95e8\u94a5\u5319\u653e\u5728\u95e8\u53e3\u8ba9\u5c0f\u5077\u968f\u4fbf\u8fdb',
        pattern: /(?:execute|executemany|executescript)\s*\([^)]*(?:\+|%|\.format|f["'])[^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/gi,
        quickFix: {
            title: '\u4f7f\u7528\u53c2\u6570\u5316\u67e5\u8be2',
            replacement: 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        },
        metadata: {
            category: 'security',
            tags: ['sql-injection', 'critical'],
            docs: 'https://realpython.com/prevent-python-sql-injection/'
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
    },
    {
        code: 'PY013',
        severity: 'error',
        message: '\ud83d\udea8 subprocess \u547d\u4ee4\u6ce8\u5165\uff1ashell=True \u8ba9\u9ed1\u5ba2\u53ef\u4ee5\u6267\u884c\u4efb\u610f\u547d\u4ee4',
        pattern: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/g,
        quickFix: {
            title: '\u4f7f\u7528\u5217\u8868\u53c2\u6570\u4ee3\u66ff shell=True',
            replacement: 'subprocess.run(["command", "arg1", "arg2"])'
        },
        metadata: {
            category: 'security',
            tags: ['command-injection', 'critical'],
            docs: 'https://docs.python.org/3/library/subprocess.html#security-considerations'
        }
    },
    {
        code: 'PY014',
        severity: 'error',
        message: '\ud83d\udc80 yaml.load() \u4e0d\u5b89\u5168\uff01\u53ef\u4ee5\u6267\u884c\u4efb\u610f Python \u4ee3\u7801',
        pattern: /yaml\.load\s*\([^,)]+(?:,\s*Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader))?\s*\)/g,
        quickFix: {
            title: '\u4f7f\u7528\u5b89\u5168\u7684 yaml.safe_load()',
            replacement: 'yaml.safe_load'
        },
        metadata: {
            category: 'security',
            tags: ['deserialization', 'critical'],
            docs: 'https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation'
        }
    },
    {
        code: 'PY015',
        severity: 'warning',
        message: '\u26a0\ufe0f requests \u672a\u9a8c\u8bc1 SSL \u8bc1\u4e66\uff0c\u5bb9\u6613\u88ab\u4e2d\u95f4\u4eba\u653b\u51fb',
        pattern: /requests\.\w+\s*\([^)]*verify\s*=\s*False/g,
        quickFix: {
            title: '\u5220\u9664 verify=False \u6216\u6539\u4e3a True',
            replacement: 'requests.get(url)'
        },
        metadata: {
            category: 'security',
            tags: ['ssl', 'network'],
            docs: 'https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification'
        }
    },
    {
        code: 'PY016',
        severity: 'error',
        message: '\ud83d\udd34 input() \u5728 Python 2 \u4e2d\u4f1a\u6267\u884c\u8f93\u5165\u7684\u4ee3\u7801\uff01',
        pattern: /\binput\s*\(/g,
        quickFix: {
            title: '\u5728 Python 2 \u4e2d\u4f7f\u7528 raw_input()',
            replacement: 'raw_input'
        },
        metadata: {
            category: 'security',
            tags: ['code-injection', 'python2']
        }
    },
    {
        code: 'PY017',
        severity: 'error',
        message: '\ud83d\udd11 \u786c\u7f16\u7801\u7684\u6570\u636e\u5e93\u8fde\u63a5\u4fe1\u606f\uff0c\u5305\u542b\u7528\u6237\u540d\u548c\u5bc6\u7801',
        pattern: /(?:mysql|postgresql|mongodb|redis|sqlite):\/\/[^:]+:[^@]+@/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: 'os.getenv("DATABASE_URL")'
        },
        metadata: {
            category: 'security',
            tags: ['credentials', 'database']
        }
    },
    {
        code: 'PY018',
        severity: 'error',
        message: '\ud83d\udd12 \u4e0d\u5b89\u5168\u7684\u968f\u673a\u6570\u751f\u6210\u5668\uff0c\u4e0d\u9002\u7528\u4e8e\u5bc6\u7801\u6216\u4ee4\u724c',
        pattern: /random\.(?:random|randint|choice|shuffle)\s*\([^)]*\).*(?:password|token|secret|key)/gi,
        quickFix: {
            title: '\u4f7f\u7528 secrets \u6a21\u5757',
            replacement: 'secrets.token_urlsafe(32)'
        },
        metadata: {
            category: 'security',
            tags: ['cryptography', 'random']
        }
    },
    {
        code: 'PY019',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u6307\u5b9a\u6587\u4ef6\u7f16\u7801\uff0c\u53ef\u80fd\u5bfc\u81f4\u4e2d\u6587\u4e71\u7801',
        pattern: /open\s*\([^,)]+\)(?!\s*\.read\(\)|\s*\.write\()/g,
        quickFix: {
            title: '\u6307\u5b9a UTF-8 \u7f16\u7801',
            replacement: 'open(file, encoding="utf-8")'
        },
        metadata: {
            category: 'quality',
            tags: ['encoding', 'i18n']
        }
    }
];
import { Rule } from '../../types';

export const nodejsRules: Rule[] = [
    {
        code: 'NODE001',
        severity: 'error',
        message: '\ud83d\udc80 \u547d\u4ee4\u6ce8\u5165\u98ce\u9669\uff1achild_process.exec \u6267\u884c\u4efb\u610f\u547d\u4ee4',
        pattern: /child_process\.(exec|spawn)\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 execFile \u6216\u53c2\u6570\u5316',
            replacement: 'child_process.execFile'
        },
        metadata: {
            category: 'security',
            tags: ['command-injection', 'critical'],
            docs: 'https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback'
        }
    },
    {
        code: 'NODE002',
        severity: 'error',
        message: '\ud83d\uddd1\ufe0f fs.unlink/rmdir \u4f1a\u6c38\u4e45\u5220\u9664\u6587\u4ef6',
        pattern: /fs\.(unlink|rmdir|rm|rmSync)\(/g,
        quickFix: {
            title: '\u6dfb\u52a0\u6587\u4ef6\u5b58\u5728\u68c0\u67e5',
            replacement: 'if (fs.existsSync(path)) fs.unlink(path)'
        },
        metadata: {
            category: 'security',
            tags: ['file-system', 'destructive']
        }
    },
    {
        code: 'NODE003',
        severity: 'warning',
        message: '\u26a0\ufe0f \u8def\u5f84\u904d\u5386\u6f0f\u6d1e\uff1a\u76f4\u63a5\u62fc\u63a5\u7528\u6237\u8f93\u5165\u7684\u8def\u5f84',
        pattern: /__dirname\s*\+[^)]*req\.(params|query|body)/g,
        quickFix: {
            title: '\u4f7f\u7528 path.join \u548c\u9a8c\u8bc1',
            replacement: 'path.join(__dirname, sanitize(userInput))'
        },
        metadata: {
            category: 'security',
            tags: ['path-traversal', 'input-validation']
        }
    },
    {
        code: 'NODE004',
        severity: 'error',
        message: '\ud83d\udea8 \u672a\u5904\u7406\u7684 Promise rejection \u4f1a\u5bfc\u81f4\u8fdb\u7a0b\u5d29\u6e83',
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
        code: 'NODE005',
        severity: 'error',
        message: '\ud83d\udca3 rm -rf \u68c0\u6d4b\u5230\uff01\u8fd9\u53ef\u80fd\u5220\u9664\u6574\u4e2a\u7cfb\u7edf\uff01',
        pattern: /rm\s+-rf\s+\//g,
        metadata: {
            category: 'security',
            tags: ['shell', 'destructive', 'critical']
        }
    },
    {
        code: 'NODE006',
        severity: 'error',
        message: '\u26a0\ufe0f process.env \u4e2d\u7684\u654f\u611f\u4fe1\u606f\u53ef\u80fd\u88ab\u66b4\u9732',
        pattern: /console\.(log|info)\s*\([^)]*process\.env/g,
        quickFix: {
            title: '\u79fb\u9664\u73af\u5883\u53d8\u91cf\u65e5\u5fd7',
            replacement: ''
        },
        metadata: {
            category: 'security',
            tags: ['environment', 'logging']
        }
    },
    {
        code: 'NODE007',
        severity: 'warning',
        message: '\u26a0\ufe0f Buffer() \u6784\u9020\u51fd\u6570\u5df2\u5f03\u7528\uff0c\u5b58\u5728\u5b89\u5168\u95ee\u9898',
        pattern: /new\s+Buffer\s*\(/g,
        quickFix: {
            title: '\u4f7f\u7528 Buffer.from()',
            replacement: 'Buffer.from('
        },
        metadata: {
            category: 'security',
            tags: ['deprecated', 'buffer']
        }
    },
    {
        code: 'NODE008',
        severity: 'error',
        message: '\ud83d\udd34 \u76d1\u542c 0.0.0.0 \u4f1a\u66b4\u9732\u670d\u52a1\u5230\u6240\u6709\u7f51\u7edc\u63a5\u53e3',
        pattern: /listen\s*\([^)]*['"]0\.0\.0\.0['"]/g,
        quickFix: {
            title: '\u4ec5\u76d1\u542c localhost',
            replacement: "listen(port, '127.0.0.1'"
        },
        metadata: {
            category: 'security',
            tags: ['network', 'exposure']
        }
    },
    {
        code: 'NODE009',
        severity: 'error',
        message: '\u26a0\ufe0f \u672a\u8bbe\u7f6e NODE_ENV \u53ef\u80fd\u5728\u751f\u4ea7\u73af\u5883\u542f\u7528\u8c03\u8bd5',
        pattern: /if\s*\(\s*!process\.env\.NODE_ENV/g,
        quickFix: {
            title: '\u8bbe\u7f6e\u9ed8\u8ba4\u503c',
            replacement: "if (process.env.NODE_ENV !== 'production'"
        },
        metadata: {
            category: 'quality',
            tags: ['environment', 'production']
        }
    },
    {
        code: 'NODE010',
        severity: 'warning',
        message: '\u26a0\ufe0f \u540c\u6b65\u6587\u4ef6\u64cd\u4f5c\u4f1a\u963b\u585e\u4e8b\u4ef6\u5faa\u73af',
        pattern: /fs\.(readFileSync|writeFileSync|existsSync)/g,
        quickFix: {
            title: '\u4f7f\u7528\u5f02\u6b65\u7248\u672c',
            replacement: 'fs.promises.readFile'
        },
        metadata: {
            category: 'performance',
            tags: ['async', 'blocking']
        }
    },
    {
        code: 'NODE011',
        severity: 'error',
        message: '\ud83d\udd11 JWT secret \u786c\u7f16\u7801\u5728\u4ee3\u7801\u4e2d',
        pattern: /jwt\.(sign|verify)\s*\([^,]+,\s*["'][^"']+["']/g,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: 'process.env.JWT_SECRET'
        },
        metadata: {
            category: 'security',
            tags: ['jwt', 'credentials']
        }
    },
    {
        code: 'NODE012',
        severity: 'error',
        message: '\u26a0\ufe0f Express \u672a\u4f7f\u7528 helmet \u4fdd\u62a4',
        pattern: /app\.use\s*\(\s*express/g,
        metadata: {
            category: 'security',
            tags: ['express', 'headers']
        }
    }
];
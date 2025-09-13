import { Rule } from '../../types';

export const sqlRules: Rule[] = [
    {
        code: 'SQL001',
        severity: 'error',
        message: '\ud83d\udc80 \u81f4\u547d\u9519\u8bef\uff1aDELETE \u6ca1\u6709 WHERE \u6761\u4ef6\u4f1a\u5220\u9664\u6574\u4e2a\u8868\uff01\u8fd9\u76f8\u5f53\u4e8e\u628a\u6574\u4e2a\u6570\u636e\u5e93\u6254\u8fdb\u5783\u573e\u6876\uff01',
        pattern: /DELETE\s+FROM\s+\w+\s*(?!WHERE|LIMIT|RETURNING)/gi,
        quickFix: {
            title: '\u6dfb\u52a0 WHERE \u6761\u4ef6',
            replacement: 'DELETE FROM table_name WHERE id = ?'
        },
        metadata: {
            category: 'security',
            tags: ['database', 'destructive', 'critical'],
            docs: 'https://dev.mysql.com/doc/refman/8.0/en/delete.html'
        }
    },
    {
        code: 'SQL002',
        severity: 'error',
        message: '\u26a0\ufe0f UPDATE \u8bed\u53e5\u6ca1\u6709 WHERE \u6761\u4ef6\uff0c\u4f1a\u66f4\u65b0\u6240\u6709\u8bb0\u5f55\uff01',
        pattern: /UPDATE\s+\w+\s+SET\s+[^;]+(?!WHERE|LIMIT)/gi,
        quickFix: {
            title: '\u6dfb\u52a0 WHERE \u6761\u4ef6',
            replacement: 'UPDATE table_name SET column = value WHERE id = ?'
        },
        metadata: {
            category: 'security',
            tags: ['database', 'destructive'],
            docs: 'https://dev.mysql.com/doc/refman/8.0/en/update.html'
        }
    },
    {
        code: 'SQL003',
        severity: 'error',
        message: '\ud83d\udca3 TRUNCATE \u4f1a\u7acb\u5373\u6e05\u7a7a\u6574\u4e2a\u8868\uff0c\u4e14\u65e0\u6cd5\u6062\u590d\uff01',
        pattern: /TRUNCATE\s+(TABLE\s+)?\w+/gi,
        metadata: {
            category: 'security',
            tags: ['database', 'destructive', 'critical'],
            docs: 'https://dev.mysql.com/doc/refman/8.0/en/truncate-table.html'
        }
    },
    {
        code: 'SQL004',
        severity: 'error',
        message: '\ud83d\udea8 DROP DATABASE \u68c0\u6d4b\u5230\uff01\u8fd9\u4f1a\u6c38\u4e45\u5220\u9664\u6574\u4e2a\u6570\u636e\u5e93\uff01',
        pattern: /DROP\s+(DATABASE|SCHEMA)\s+/gi,
        metadata: {
            category: 'security',
            tags: ['database', 'destructive', 'critical'],
            docs: 'https://dev.mysql.com/doc/refman/8.0/en/drop-database.html'
        }
    },
    {
        code: 'SQL005',
        severity: 'error',
        message: '\ud83d\udeab DROP TABLE \u4f1a\u6c38\u4e45\u5220\u9664\u8868\u548c\u6240\u6709\u6570\u636e\uff01',
        pattern: /DROP\s+TABLE\s+/gi,
        metadata: {
            category: 'security',
            tags: ['database', 'destructive', 'critical']
        }
    },
    {
        code: 'SQL006',
        severity: 'warning',
        message: '\u26a0\ufe0f SQL \u6ce8\u5165\u98ce\u9669\uff1a\u5b57\u7b26\u4e32\u62fc\u63a5\u53ef\u80fd\u5bfc\u81f4\u6ce8\u5165\u653b\u51fb',
        pattern: /(["'])\s*\+\s*\w+\s*\+\s*(["'])/g,
        quickFix: {
            title: '\u4f7f\u7528\u53c2\u6570\u5316\u67e5\u8be2',
            replacement: '?'
        },
        metadata: {
            category: 'security',
            tags: ['sql-injection', 'security'],
            docs: 'https://owasp.org/www-community/attacks/SQL_Injection'
        }
    },
    {
        code: 'SQL007',
        severity: 'warning',
        message: '\u26a0\ufe0f SELECT * \u53ef\u80fd\u67e5\u8be2\u8fc7\u591a\u6570\u636e\uff0c\u5f71\u54cd\u6027\u80fd',
        pattern: /SELECT\s+\*\s+FROM/gi,
        quickFix: {
            title: '\u6307\u5b9a\u9700\u8981\u7684\u5217',
            replacement: 'SELECT column1, column2 FROM'
        },
        metadata: {
            category: 'performance',
            tags: ['performance', 'optimization']
        }
    },
    {
        code: 'SQL008',
        severity: 'warning',
        message: '\u26a0\ufe0f \u6ca1\u6709 LIMIT \u7684\u67e5\u8be2\u53ef\u80fd\u8fd4\u56de\u5927\u91cf\u6570\u636e',
        pattern: /SELECT\s+[\s\S]+FROM\s+\w+(?![\s\S]*LIMIT)/gi,
        quickFix: {
            title: '\u6dfb\u52a0 LIMIT',
            replacement: 'SELECT ... FROM ... LIMIT 100'
        },
        metadata: {
            category: 'performance',
            tags: ['performance']
        }
    },
    {
        code: 'SQL009',
        severity: 'error',
        message: '\ud83d\udd12 \u5bc6\u7801\u660e\u6587\u5b58\u50a8\uff01\u5e94\u8be5\u4f7f\u7528\u52a0\u5bc6\u5b58\u50a8',
        pattern: /password\s*=\s*["'][^"']+["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u52a0\u5bc6\u51fd\u6570',
            replacement: 'password = SHA2(?, 256)'
        },
        metadata: {
            category: 'security',
            tags: ['security', 'password', 'encryption']
        }
    },
    {
        code: 'SQL010',
        severity: 'error',
        message: '\u26a0\ufe0f GRANT ALL PRIVILEGES \u6388\u4e88\u8fc7\u9ad8\u6743\u9650',
        pattern: /GRANT\s+ALL\s+PRIVILEGES/gi,
        quickFix: {
            title: '\u6307\u5b9a\u5177\u4f53\u6743\u9650',
            replacement: 'GRANT SELECT, INSERT, UPDATE ON'
        },
        metadata: {
            category: 'security',
            tags: ['security', 'permissions']
        }
    }
];
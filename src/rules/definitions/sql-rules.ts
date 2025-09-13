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
        message: '\u26a0\ufe0f \u6ca1\u6709 LIMIT \u7684\u67e5\u8be2\u53ef\u80fd\u8fd4\u56de\u5927\u91cf\u6570\u636e\uff0c\u5c31\u50cf\u4e00\u6b21\u6027\u628a\u6574\u4e2a\u4ed3\u5e93\u7684\u8d27\u7269\u90fd\u642c\u51fa\u6765',
        pattern: /SELECT\s+(?:(?!LIMIT|WHERE|TOP).)*FROM\s+\w+\s*(?:;|$)/gi,
        quickFix: {
            title: '\u6dfb\u52a0 LIMIT \u9650\u5236\u8fd4\u56de\u6570\u91cf',
            replacement: 'SELECT ... FROM ... LIMIT 100'
        },
        metadata: {
            category: 'performance',
            tags: ['performance', 'optimization']
        }
    },
    {
        code: 'SQL009',
        severity: 'error',
        message: '\ud83d\udd12 \u5bc6\u7801\u660e\u6587\u5b58\u50a8\uff01\u5c31\u50cf\u628a\u94f6\u884c\u5361\u5bc6\u7801\u8d34\u5728\u5361\u4e0a',
        pattern: /(?:password|pwd|pass)\s*=\s*["'][^"']+["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u4e13\u4e1a\u7684\u5bc6\u7801\u52a0\u5bc6\u51fd\u6570',
            replacement: '-- \u63a8\u8350\u4f7f\u7528 bcrypt\u3001PBKDF2 \u6216 Argon2'
        },
        metadata: {
            category: 'security',
            tags: ['security', 'password', 'encryption'],
            docs: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'
        }
    },
    {
        code: 'SQL010',
        severity: 'error',
        message: '\u26a0\ufe0f GRANT ALL PRIVILEGES \u6388\u4e88\u8fc7\u9ad8\u6743\u9650\uff0c\u5c31\u50cf\u628a\u5bb6\u91cc\u6240\u6709\u94a5\u5319\u90fd\u7ed9\u4e86\u964c\u751f\u4eba',
        pattern: /GRANT\s+ALL\s+PRIVILEGES/gi,
        quickFix: {
            title: '\u6307\u5b9a\u5177\u4f53\u6743\u9650',
            replacement: 'GRANT SELECT, INSERT, UPDATE ON database.table TO user'
        },
        metadata: {
            category: 'security',
            tags: ['security', 'permissions']
        }
    },
    {
        code: 'SQL011',
        severity: 'error',
        message: '\ud83d\udea8 \u52a8\u6001 SQL \u6784\u9020\u98ce\u9669\uff1a\u4f7f\u7528\u53d8\u91cf\u62fc\u63a5 SQL \u8bed\u53e5',
        pattern: /(?:EXEC|EXECUTE|sp_executesql)\s+(?:@\w+|\()/gi,
        quickFix: {
            title: '\u4f7f\u7528\u53c2\u6570\u5316\u5b58\u50a8\u8fc7\u7a0b',
            replacement: '-- \u4f7f\u7528\u53c2\u6570\u5316\u67e5\u8be2\u6216\u9884\u7f16\u8bd1\u8bed\u53e5'
        },
        metadata: {
            category: 'security',
            tags: ['sql-injection', 'dynamic-sql']
        }
    },
    {
        code: 'SQL012',
        severity: 'error',
        message: '\ud83d\udd34 ALTER TABLE DROP COLUMN \u4f1a\u6c38\u4e45\u5220\u9664\u5217\u548c\u6570\u636e',
        pattern: /ALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN/gi,
        quickFix: {
            title: '\u5148\u5907\u4efd\u6570\u636e',
            replacement: '-- \u5907\u4efd\u8868\uff1aCREATE TABLE backup_table AS SELECT * FROM original_table;'
        },
        metadata: {
            category: 'security',
            tags: ['destructive', 'schema-change']
        }
    },
    {
        code: 'SQL013',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u4f7f\u7528\u4e8b\u52a1\uff0c\u53ef\u80fd\u5bfc\u81f4\u6570\u636e\u4e0d\u4e00\u81f4',
        pattern: /(?:INSERT|UPDATE|DELETE)[\s\S]+(?:INSERT|UPDATE|DELETE)(?![\s\S]*(?:BEGIN|START)\s+TRANSACTION)/gi,
        quickFix: {
            title: '\u4f7f\u7528\u4e8b\u52a1\u4fdd\u8bc1\u4e00\u81f4\u6027',
            replacement: 'BEGIN TRANSACTION;\n-- SQL \u8bed\u53e5\nCOMMIT;'
        },
        metadata: {
            category: 'quality',
            tags: ['transaction', 'consistency']
        }
    },
    {
        code: 'SQL014',
        severity: 'error',
        message: '\ud83d\udd11 \u6570\u636e\u5e93\u8fde\u63a5\u5b57\u7b26\u4e32\u4e2d\u5305\u542b\u660e\u6587\u5bc6\u7801',
        pattern: /(?:Server|Data Source|User ID|Password|pwd)=[^;]+;.*Password=[^;]+/gi,
        quickFix: {
            title: '\u4f7f\u7528\u914d\u7f6e\u6587\u4ef6\u6216\u73af\u5883\u53d8\u91cf',
            replacement: '-- \u4ece\u5b89\u5168\u7684\u914d\u7f6e\u6e90\u8bfb\u53d6\u8fde\u63a5\u4fe1\u606f'
        },
        metadata: {
            category: 'security',
            tags: ['credentials', 'connection-string']
        }
    },
    {
        code: 'SQL015',
        severity: 'warning',
        message: '\u26a0\ufe0f LIKE \u67e5\u8be2\u4ee5 % \u5f00\u5934\u4f1a\u5bfc\u81f4\u5168\u8868\u626b\u63cf\uff0c\u6781\u5ea6\u5f71\u54cd\u6027\u80fd',
        pattern: /WHERE\s+\w+\s+LIKE\s+['"]%/gi,
        quickFix: {
            title: '\u4f18\u5316\u67e5\u8be2\u6216\u4f7f\u7528\u5168\u6587\u7d22\u5f15',
            replacement: '-- \u8003\u8651\u4f7f\u7528\u5168\u6587\u7d22\u5f15\u6216\u4f18\u5316\u67e5\u8be2\u6a21\u5f0f'
        },
        metadata: {
            category: 'performance',
            tags: ['performance', 'index']
        }
    },
    {
        code: 'SQL016',
        severity: 'error',
        message: '\ud83d\udea8 \u4f7f\u7528 sa \u6216 root \u8d26\u6237\u8fde\u63a5\u6570\u636e\u5e93\uff0c\u6743\u9650\u8fc7\u9ad8\u975e\u5e38\u5371\u9669',
        pattern: /(?:User\s*ID|uid|user)\s*=\s*['"]?(?:sa|root|admin)['"]?/gi,
        quickFix: {
            title: '\u521b\u5efa\u4e13\u7528\u6570\u636e\u5e93\u7528\u6237',
            replacement: '-- \u521b\u5efa\u6700\u5c0f\u6743\u9650\u7684\u4e13\u7528\u7528\u6237'
        },
        metadata: {
            category: 'security',
            tags: ['security', 'privileges']
        }
    }
];
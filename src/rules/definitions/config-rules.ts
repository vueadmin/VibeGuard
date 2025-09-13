import { Rule } from '../../types';

export const configRules: Rule[] = [
    {
        code: 'CFG001',
        severity: 'error',
        message: '\ud83d\udd10 \u6570\u636e\u5e93\u5bc6\u7801\u66b4\u9732\uff01\u4e0d\u8981\u5728\u914d\u7f6e\u6587\u4ef6\u4e2d\u660e\u6587\u5b58\u50a8',
        pattern: /(postgres|mysql|mongodb|redis|mssql|oracle):\/\/[^:]+:[^@]+@/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: '${DATABASE_URL}'
        },
        metadata: {
            category: 'security',
            tags: ['database', 'credentials', 'critical']
        }
    },
    {
        code: 'CFG002',
        severity: 'error',
        message: '\ud83d\udd11 AWS/Azure/GCP \u5bc6\u94a5\u6cc4\u9732',
        pattern: /(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|azure[_-]?storage[_-]?account[_-]?key|gcp[_-]?api[_-]?key)\s*[:=]\s*["'][^"']+["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf\u6216\u5bc6\u94a5\u7ba1\u7406\u670d\u52a1',
            replacement: 'process.env.AWS_ACCESS_KEY_ID'
        },
        metadata: {
            category: 'security',
            tags: ['cloud', 'credentials', 'critical']
        }
    },
    {
        code: 'CFG003',
        severity: 'warning',
        message: '\u26a0\ufe0f Redis \u672a\u8bbe\u7f6e\u5bc6\u7801',
        pattern: /redis:\/\/(?!:[^@]+@)[^/]+/g,
        metadata: {
            category: 'security',
            tags: ['redis', 'authentication']
        }
    },
    {
        code: 'CFG004',
        severity: 'error',
        message: '\ud83d\udea8 Docker \u66b4\u9732\u5371\u9669\u7aef\u53e3\uff08SSH/\u6570\u636e\u5e93\uff09',
        pattern: /EXPOSE\s+(22|3306|5432|27017|6379|1433|1521)\b/g,
        metadata: {
            category: 'security',
            tags: ['docker', 'ports', 'exposure']
        }
    },
    {
        code: 'CFG005',
        severity: 'error',
        message: '\ud83d\udc80 package.json \u4e2d\u5305\u542b\u6076\u610f\u811a\u672c',
        pattern: /"(preinstall|postinstall|preuninstall)"\s*:\s*"[^"]*\b(rm\s+-rf|curl|wget|eval|node\s+-e)/g,
        metadata: {
            category: 'security',
            tags: ['npm', 'malicious', 'critical']
        }
    },
    {
        code: 'CFG006',
        severity: 'error',
        message: '\ud83d\udd11 JWT secret \u786c\u7f16\u7801\u5728\u914d\u7f6e\u4e2d',
        pattern: /(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["'][^"']+["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: '${JWT_SECRET}'
        },
        metadata: {
            category: 'security',
            tags: ['jwt', 'credentials']
        }
    },
    {
        code: 'CFG007',
        severity: 'error',
        message: '\ud83d\udd34 API Key \u66b4\u9732\u5728\u914d\u7f6e\u6587\u4ef6\u4e2d',
        pattern: /(api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/gi,
        quickFix: {
            title: '\u4f7f\u7528\u73af\u5883\u53d8\u91cf',
            replacement: '${API_KEY}'
        },
        metadata: {
            category: 'security',
            tags: ['api', 'credentials']
        }
    },
    {
        code: 'CFG008',
        severity: 'error',
        message: '\u26a0\ufe0f Dockerfile \u4f7f\u7528 root \u7528\u6237\u8fd0\u884c',
        pattern: /USER\s+root/g,
        quickFix: {
            title: '\u4f7f\u7528\u975e root \u7528\u6237',
            replacement: 'USER node'
        },
        metadata: {
            category: 'security',
            tags: ['docker', 'privileges']
        }
    },
    {
        code: 'CFG009',
        severity: 'warning',
        message: '\u26a0\ufe0f npm \u4f7f\u7528\u4e0d\u5b89\u5168\u7684\u6ce8\u518c\u8868',
        pattern: /registry\s*=\s*["']?http:\/\//g,
        quickFix: {
            title: '\u4f7f\u7528 HTTPS',
            replacement: 'registry=https://'
        },
        metadata: {
            category: 'security',
            tags: ['npm', 'https']
        }
    },
    {
        code: 'CFG010',
        severity: 'error',
        message: '\ud83d\udd10 .env \u6587\u4ef6\u4e2d\u5305\u542b\u654f\u611f\u4fe1\u606f',
        pattern: /(PASSWORD|SECRET|PRIVATE[_-]?KEY|TOKEN|CREDENTIAL)\s*=\s*.+/gi,
        metadata: {
            category: 'security',
            tags: ['environment', 'credentials']
        }
    },
    {
        code: 'CFG011',
        severity: 'error',
        message: '\ud83d\udea8 CORS \u5141\u8bb8\u6240\u6709\u6765\u6e90',
        pattern: /(Access-Control-Allow-Origin|cors\.origin)\s*[:=]\s*["']?\*["']?/g,
        quickFix: {
            title: '\u6307\u5b9a\u5177\u4f53\u57df\u540d',
            replacement: 'https://example.com'
        },
        metadata: {
            category: 'security',
            tags: ['cors', 'configuration']
        }
    },
    {
        code: 'CFG012',
        severity: 'warning',
        message: '\u26a0\ufe0f SSL/TLS \u9a8c\u8bc1\u88ab\u7981\u7528',
        pattern: /(verify[_-]?ssl|ssl[_-]?verify|reject[_-]?unauthorized)\s*[:=]\s*(false|0|no)/gi,
        quickFix: {
            title: '\u542f\u7528 SSL \u9a8c\u8bc1',
            replacement: 'true'
        },
        metadata: {
            category: 'security',
            tags: ['ssl', 'tls', 'https']
        }
    }
];
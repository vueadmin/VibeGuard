import { Rule } from '../../types';

export const reactRules: Rule[] = [
    {
        code: 'REACT001',
        severity: 'error',
        message: '\ud83d\udc89 XSS \u98ce\u9669\uff1adangerouslySetInnerHTML \u76f4\u63a5\u6ce8\u5165 HTML',
        pattern: /dangerouslySetInnerHTML/g,
        metadata: {
            category: 'security',
            tags: ['xss', 'react', 'critical'],
            docs: 'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
        }
    },
    {
        code: 'REACT002',
        severity: 'error',
        message: '\u267e\ufe0f \u65e0\u9650\u5faa\u73af\u98ce\u9669\uff1auseEffect \u7f3a\u5c11\u4f9d\u8d56\u6570\u7ec4',
        pattern: /useEffect\s*\([^,)]+\)(?!\s*,)/g,
        quickFix: {
            title: '\u6dfb\u52a0\u4f9d\u8d56\u6570\u7ec4',
            replacement: 'useEffect(() => {}, [])'
        },
        metadata: {
            category: 'quality',
            tags: ['hooks', 'infinite-loop']
        }
    },
    {
        code: 'REACT003',
        severity: 'warning',
        message: '\u26a0\ufe0f \u5185\u5b58\u6cc4\u6f0f\uff1a\u7ec4\u4ef6\u5378\u8f7d\u65f6\u672a\u6e05\u7406\u4e8b\u4ef6\u76d1\u542c\u5668',
        pattern: /useEffect\s*\([^}]*addEventListener[^}]*\}(?!\s*,\s*\[[^\]]*\])/gs,
        metadata: {
            category: 'performance',
            tags: ['memory-leak', 'cleanup']
        }
    },
    {
        code: 'REACT004',
        severity: 'error',
        message: '\ud83d\udea8 \u76f4\u63a5\u64cd\u4f5c DOM \u8fdd\u53cd React \u539f\u5219',
        pattern: /document\.(getElementById|querySelector|getElementsBy)/g,
        quickFix: {
            title: '\u4f7f\u7528 useRef',
            replacement: 'useRef()'
        },
        metadata: {
            category: 'quality',
            tags: ['anti-pattern', 'dom']
        }
    },
    {
        code: 'REACT005',
        severity: 'warning',
        message: '\u26a0\ufe0f \u76f4\u63a5\u4fee\u6539 state \u4e0d\u4f1a\u89e6\u53d1\u91cd\u65b0\u6e32\u67d3',
        pattern: /state\.\w+\s*=/g,
        quickFix: {
            title: '\u4f7f\u7528 setState',
            replacement: 'setState'
        },
        metadata: {
            category: 'quality',
            tags: ['state', 'immutability']
        }
    },
    {
        code: 'REACT006',
        severity: 'error',
        message: '\u26a0\ufe0f \u5728\u6e32\u67d3\u65b9\u6cd5\u4e2d\u8c03\u7528 setState \u4f1a\u5bfc\u81f4\u65e0\u9650\u5faa\u73af',
        pattern: /render\s*\([^}]*setState[^}]*\}/gs,
        metadata: {
            category: 'quality',
            tags: ['infinite-loop', 'state']
        }
    },
    {
        code: 'REACT007',
        severity: 'warning',
        message: '\u26a0\ufe0f \u6570\u7ec4\u7d22\u5f15\u4f5c\u4e3a key \u53ef\u80fd\u5bfc\u81f4\u6e32\u67d3\u95ee\u9898',
        pattern: /key\s*=\s*\{?\s*index\s*\}?/g,
        quickFix: {
            title: '\u4f7f\u7528\u552f\u4e00 ID',
            replacement: 'key={item.id}'
        },
        metadata: {
            category: 'quality',
            tags: ['performance', 'key']
        }
    },
    {
        code: 'REACT008',
        severity: 'error',
        message: '\u26a0\ufe0f \u4f9d\u8d56\u6570\u7ec4\u7f3a\u5931\u4f9d\u8d56\u9879',
        pattern: /useEffect\s*\([^}]*\}\s*,\s*\[\s*\]\s*\)/gs,
        metadata: {
            category: 'quality',
            tags: ['hooks', 'dependencies']
        }
    },
    {
        code: 'REACT009',
        severity: 'warning',
        message: '\u26a0\ufe0f \u5728\u5faa\u73af\u4e2d\u8c03\u7528 Hook \u8fdd\u53cd Hook \u89c4\u5219',
        pattern: /(for|while|forEach|map)[^}]*use[A-Z]\w+\s*\(/gs,
        metadata: {
            category: 'quality',
            tags: ['hooks', 'rules-of-hooks']
        }
    },
    {
        code: 'REACT010',
        severity: 'error',
        message: '\ud83d\udd34 \u6761\u4ef6\u8bed\u53e5\u4e2d\u8c03\u7528 Hook \u8fdd\u53cd Hook \u89c4\u5219',
        pattern: /if\s*\([^}]*use[A-Z]\w+\s*\(/gs,
        metadata: {
            category: 'quality',
            tags: ['hooks', 'rules-of-hooks']
        }
    },
    {
        code: 'REACT011',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u4f7f\u7528 React.memo \u53ef\u80fd\u5bfc\u81f4\u4e0d\u5fc5\u8981\u7684\u91cd\u65b0\u6e32\u67d3',
        pattern: /export\s+(default\s+)?function\s+\w+\s*\(/g,
        metadata: {
            category: 'performance',
            tags: ['memo', 'optimization']
        }
    },
    {
        code: 'REACT012',
        severity: 'error',
        message: '\ud83d\udd25 \u4fee\u6539 props \u8fdd\u53cd React \u5355\u5411\u6570\u636e\u6d41',
        pattern: /props\.\w+\s*=/g,
        metadata: {
            category: 'quality',
            tags: ['props', 'immutability']
        }
    }
];
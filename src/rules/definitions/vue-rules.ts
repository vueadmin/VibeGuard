import { Rule } from '../../types';

export const vueRules: Rule[] = [
    {
        code: 'VUE001',
        severity: 'error',
        message: '\ud83d\udc89 XSS \u98ce\u9669\uff1av-html \u4f1a\u76f4\u63a5\u6e32\u67d3 HTML',
        pattern: /v-html/g,
        metadata: {
            category: 'security',
            tags: ['xss', 'vue', 'critical'],
            docs: 'https://vuejs.org/guide/best-practices/security.html#potential-dangers'
        }
    },
    {
        code: 'VUE002',
        severity: 'error',
        message: '\u26a0\ufe0f \u76f4\u63a5\u4fee\u6539 props \u8fdd\u53cd\u5355\u5411\u6570\u636e\u6d41',
        pattern: /this\.\$?props\.\w+\s*=/g,
        metadata: {
            category: 'quality',
            tags: ['props', 'data-flow']
        }
    },
    {
        code: 'VUE003',
        severity: 'warning',
        message: '\u26a0\ufe0f v-for \u7f3a\u5c11 key \u4f1a\u5bfc\u81f4\u6e32\u67d3\u95ee\u9898',
        pattern: /v-for(?!.*:key)/g,
        quickFix: {
            title: '\u6dfb\u52a0 key \u5c5e\u6027',
            replacement: 'v-for="item in items" :key="item.id"'
        },
        metadata: {
            category: 'quality',
            tags: ['performance', 'key']
        }
    },
    {
        code: 'VUE004',
        severity: 'error',
        message: '\u267e\ufe0f watch \u53ef\u80fd\u5bfc\u81f4\u65e0\u9650\u5faa\u73af',
        pattern: /watch\s*:\s*\{[^}]*deep\s*:\s*true/g,
        metadata: {
            category: 'quality',
            tags: ['watch', 'infinite-loop']
        }
    },
    {
        code: 'VUE005',
        severity: 'warning',
        message: '\u26a0\ufe0f \u4f7f\u7528\u6570\u7ec4\u7d22\u5f15\u4f5c\u4e3a key \u53ef\u80fd\u5f71\u54cd\u6027\u80fd',
        pattern: /:key\s*=\s*["']?\s*index\s*["']?/g,
        quickFix: {
            title: '\u4f7f\u7528\u552f\u4e00 ID',
            replacement: ':key="item.id"'
        },
        metadata: {
            category: 'performance',
            tags: ['key', 'v-for']
        }
    },
    {
        code: 'VUE006',
        severity: 'error',
        message: '\u26a0\ufe0f \u76f4\u63a5\u4fee\u6539\u6570\u7ec4\u7d22\u5f15\u4e0d\u4f1a\u89e6\u53d1\u54cd\u5e94\u5f0f\u66f4\u65b0',
        pattern: /this\.\w+\[\d+\]\s*=/g,
        quickFix: {
            title: '\u4f7f\u7528 Vue.set \u6216\u6570\u7ec4\u65b9\u6cd5',
            replacement: 'this.$set(this.array, index, value)'
        },
        metadata: {
            category: 'quality',
            tags: ['reactivity', 'array']
        }
    },
    {
        code: 'VUE007',
        severity: 'warning',
        message: '\u26a0\ufe0f v-if \u548c v-for \u540c\u65f6\u4f7f\u7528\u4f1a\u5f71\u54cd\u6027\u80fd',
        pattern: /v-if.*v-for|v-for.*v-if/g,
        quickFix: {
            title: '\u4f7f\u7528\u8ba1\u7b97\u5c5e\u6027\u8fc7\u6ee4',
            replacement: 'computed property'
        },
        metadata: {
            category: 'performance',
            tags: ['v-if', 'v-for']
        }
    },
    {
        code: 'VUE008',
        severity: 'error',
        message: '\ud83d\udd34 \u5728 created \u94a9\u5b50\u4e2d\u64cd\u4f5c DOM \u4f1a\u5931\u8d25',
        pattern: /created\s*\([^}]*document\.|created\s*\([^}]*\$refs/gs,
        metadata: {
            category: 'quality',
            tags: ['lifecycle', 'dom']
        }
    },
    {
        code: 'VUE009',
        severity: 'warning',
        message: '\u26a0\ufe0f \u672a\u5728 destroyed \u4e2d\u6e05\u7406\u5b9a\u65f6\u5668\u6216\u4e8b\u4ef6\u76d1\u542c',
        pattern: /mounted\s*\([^}]*addEventListener|mounted\s*\([^}]*setInterval/gs,
        metadata: {
            category: 'performance',
            tags: ['memory-leak', 'cleanup']
        }
    },
    {
        code: 'VUE010',
        severity: 'error',
        message: '\u26a0\ufe0f data \u5fc5\u987b\u662f\u51fd\u6570\u4ee5\u907f\u514d\u7ec4\u4ef6\u95f4\u6570\u636e\u5171\u4eab',
        pattern: /data\s*:\s*\{/g,
        quickFix: {
            title: '\u4f7f\u7528\u51fd\u6570\u8fd4\u56de\u6570\u636e',
            replacement: 'data() { return {'
        },
        metadata: {
            category: 'quality',
            tags: ['data', 'component']
        }
    },
    {
        code: 'VUE011',
        severity: 'warning',
        message: '\u26a0\ufe0f \u8ba1\u7b97\u5c5e\u6027\u4e0d\u5e94\u6709\u526f\u4f5c\u7528',
        pattern: /computed\s*:\s*\{[^}]*this\.\w+\s*=/gs,
        metadata: {
            category: 'quality',
            tags: ['computed', 'side-effect']
        }
    },
    {
        code: 'VUE012',
        severity: 'error',
        message: '\ud83d\udd34 v-model \u4e0d\u5e94\u7528\u4e8e props',
        pattern: /v-model\s*=\s*["']?\$props\./g,
        metadata: {
            category: 'quality',
            tags: ['v-model', 'props']
        }
    }
];
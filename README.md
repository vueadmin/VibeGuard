# VibeGuard 🛡️

> **一句话介绍**：实时检测代码中的致命错误，防止你删库跑路、泄露密钥、生产事故。

## 🚨 它能救你的命

想象一下这些场景：
- 你不小心写了 `DELETE FROM users` 没加 WHERE，整个用户表没了
- 你把 API Key 硬编码在代码里，推到 GitHub 被盗刷了 $5000
- 你在生产环境开了 `debug=True`，黑客看到了所有错误堆栈
- 你用了 `rm -rf /`，整个服务器没了

**VibeGuard 会在你敲下这些代码的瞬间发出警告！**

## 🎯 核心功能

### 1. 💀 致命操作检测
- SQL 无条件 DELETE/UPDATE/DROP DATABASE
- JavaScript eval() 执行任意代码
- React dangerouslySetInnerHTML XSS 漏洞
- Vue v-html 注入风险
- Node.js child_process 命令注入
- Python os.system/eval 危险调用

### 2. 🔑 密钥泄露防护
- API Key 硬编码检测（AWS, Azure, Google Cloud）
- 数据库密码明文存储
- JWT Token/OAuth Secret 泄露
- .env 文件中的敏感信息

### 3. 🐛 框架陷阱预警
- React useEffect 无限循环
- Vue props 直接修改
- async/await 在 forEach 中不生效
- 未处理的 Promise rejection
- 内存泄漏（未清理的事件监听器）

### 4. ⚙️ 生产环境配置检查
- Flask/Django debug=True
- CORS 允许所有域名
- Redis 未设置密码
- Docker 暴露危险端口

## 📦 支持的技术栈

- **前端**: JavaScript, TypeScript, React, Vue
- **后端**: Node.js, Python
- **数据库**: MySQL, PostgreSQL, MongoDB, Redis
- **配置文件**: JSON, YAML, .env, Dockerfile, package.json

## 🚀 快速开始

### 安装
1. 在 VS Code 扩展商店搜索 "VibeGuard"
2. 点击安装
3. 重启 VS Code

### 使用
插件会自动运行，当你写下危险代码时：
- 🔴 红色波浪线 = 致命错误（必须修复）
- 🟡 黄色波浪线 = 潜在风险（建议修复）

鼠标悬停查看详细说明，点击 💡 获取修复建议。

## 💡 示例

### SQL 删库警告
```sql
-- ❌ 危险！会删除整个表
DELETE FROM users;

-- ✅ 安全
DELETE FROM users WHERE id = 123;
```

### API Key 泄露检测
```javascript
// ❌ 危险！密钥泄露
const apiKey = "sk-1234567890abcdef";

// ✅ 安全
const apiKey = process.env.API_KEY;
```

### React XSS 防护
```jsx
// ❌ 危险！XSS 攻击
<div dangerouslySetInnerHTML={{__html: userInput}} />

// ✅ 安全
<div>{userInput}</div>
```

## 🏆 为什么选择 VibeGuard？

1. **实时检测** - 你写代码的同时就能发现问题
2. **新手友好** - 用通俗语言解释技术问题
3. **框架特定** - 深度理解 React/Vue/Node.js 特有陷阱
4. **零配置** - 安装即用，无需任何设置
5. **性能优异** - 增量检测，不影响编码体验

## 🤝 贡献

VibeGuard 是开源项目，欢迎贡献！

- 报告 Bug: [GitHub Issues](https://github.com/vibeguard/vibeguard/issues)
- 贡献代码: Fork 后提交 PR
- 添加规则: 在 `src/rules/` 目录添加新规则

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE)

---

**VibeGuard** - 让编码更安全，让新手少踩坑 💪

> 由 VibeHacks 24h 黑客松孵化，为全球开发者开源
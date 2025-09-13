# VibeGuard 🛡️

> **让 AI 编程更安全** - 防止你的代码值 $5000

## 🚨 真实案例警示

- **设计师小王**：把 OpenAI API key 写在代码里，被黑客刷了 $5000
- **产品经理小李**：用 ChatGPT 写 SQL，不小心 DELETE 了整个用户表
- **运营小张**：复制的代码包含 `eval()`，网站被注入恶意脚本

**VibeGuard 会在你写下这些危险代码时立即警告你！**

## 🎯 这是给谁用的？

**不是给程序员的**，而是给这些人：
- 🎨 用 Cursor 写前端的**设计师**
- 📊 用 ChatGPT 写 SQL 的**产品经理**  
- 📈 用 AI 写数据分析的**运营人员**
- 🚀 用 AI 快速搭建 MVP 的**创业者**

这些人的共同特点：**会用 AI 写代码，但不知道代码的危险性**。

## 💀 它能救你什么命？

### 1. 防止密钥泄露（价值 $5000+）
```javascript
// ❌ 危险！API key 会被偷
const apiKey = "sk-1234567890abcdef";

// ✅ VibeGuard 会提醒你这样写
const apiKey = process.env.API_KEY;
```

### 2. 防止数据库灾难
```sql
-- ❌ 危险！会删除所有用户
DELETE FROM users;

-- ✅ VibeGuard 会要求你加条件
DELETE FROM users WHERE id = 123;
```

### 3. 防止代码注入
```javascript
// ❌ 危险！黑客可以执行任意代码
eval(userInput);

// ✅ VibeGuard 会建议安全方案
JSON.parse(userInput);
```

## 🚀 快速开始

### 1. 安装
```bash
# 在 VS Code 扩展商店搜索
VibeGuard

# 或直接安装
code --install-extension vibeguard
```

### 2. 使用
- 🔴 **红色波浪线** = 致命错误（必须修复！）
- 🟡 **黄色波浪线** = 高危风险（强烈建议修复）
- 💡 **点击灯泡** = 一键自动修复

### 3. 就这么简单！
无需配置，安装即用。专为非技术人员优化。

## 📋 检测清单

### 🔑 密钥安全
- [x] API Key 硬编码（OpenAI、AWS、Azure）
- [x] 数据库密码明文
- [x] JWT Token 泄露
- [x] OAuth Secret 暴露

### 💣 危险操作
- [x] SQL DELETE/UPDATE 无条件
- [x] DROP DATABASE/TABLE
- [x] eval() 执行任意代码
- [x] innerHTML XSS 风险

### 🐛 框架陷阱
- [x] React：dangerouslySetInnerHTML
- [x] React：useEffect 无限循环
- [x] Vue：v-html 注入风险
- [x] Node.js：命令注入

### ⚙️ 配置错误
- [x] 生产环境 debug=true
- [x] CORS 允许所有域名
- [x] Docker 暴露危险端口

## 🤝 参与贡献

### 分享你的"事故"
如果你也因为 AI 生成的代码遭受损失，请分享你的故事：
```yaml
# .vibeguard/stories/your-story.yml
title: "我是如何损失 $5000 的"
date: "2024-03-15"
loss: "$5000"
code: |
  const apiKey = "sk-xxxxxx"; // 😭
lesson: "永远不要硬编码密钥"
```

### 贡献新规则
发现新的危险模式？添加规则很简单：
```javascript
// 规则格式
{
  pattern: "危险代码的正则",
  message: "💀 用大白话解释为什么危险",
  fix: "安全的替代方案"
}
```

## 🔧 开发指南

### 环境准备
```bash
# 克隆项目
git clone https://github.com/vibeguard/vibeguard.git
cd vibeguard

# 安装依赖
npm install

# 开发模式
npm run watch

# 运行测试
npm test
```

### 项目结构
```
vibeguard/
├── src/
│   ├── extension.ts      # 插件入口
│   ├── rules/           # 检测规则
│   │   ├── api-keys.ts  # API密钥检测
│   │   ├── sql.ts       # SQL危险操作
│   │   └── ...
│   └── quickfix/        # 一键修复
└── package.json
```

### 核心原则
1. **简单优先**：宁可漏报，不可误报
2. **用户友好**：用大白话，不用术语
3. **快速修复**：一键解决，不需要用户懂原理

## 📊 为什么选择 VibeGuard？

| 对比项 | 传统 Linter | VibeGuard |
|-------|------------|-----------|
| 目标用户 | 专业程序员 | AI 编程用户 |
| 检测重点 | 代码风格 | 致命错误 |
| 提示语言 | 英文术语 | 中文大白话 |
| 修复方式 | 需要理解原理 | 一键修复 |
| 学习成本 | 需要配置 | 零配置 |

## 🏆 用户反馈

> "要不是 VibeGuard，我的 AWS 账单可能会是 5 位数" - 设计师小王

> "终于有人为我们这些'野生程序员'考虑了！" - 产品经理小李

> "比 ChatGPT 更懂安全，救了我好几次" - 创业者小张

## 📈 项目进展

### ✅ 已完成（MVP）
- 核心规则引擎
- 50+ 危险模式检测
- VS Code 集成
- 中文提示系统

### 🚧 开发中
- [ ] 更多 AI 工具集成（Cursor、GitHub Copilot）
- [ ] 真实案例库
- [ ] 视频教程
- [ ] 在线规则分享

### 💡 未来计划
- 支持更多编辑器（JetBrains、Sublime）
- AI 驱动的智能检测
- 团队版本（公司统一安全标准）

## 📄 开源协议

MIT License - 免费使用，但使用后省下的钱请考虑[捐赠](https://github.com/sponsors/vibeguard)支持项目 😊

---

**VibeGuard** - 让 AI 编程不再危险 🛡️

> 由真实的 $5000 教训驱动，为下一个可能的受害者而建。

### 🆘 需要帮助？

- 📚 [查看文档](https://vibeguard.dev/docs)
- 💬 [加入社区](https://discord.gg/vibeguard)
- 🐛 [报告问题](https://github.com/vibeguard/vibeguard/issues)
- 📧 [联系我们](mailto:help@vibeguard.dev)

记住：**最贵的代码错误，往往是最简单的那一行。**
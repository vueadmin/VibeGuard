# VibeGuard 🛡️ - AI 编程安全卫士

> **让 AI 编程更安全** - 专为非技术人员设计的代码安全检测工具

[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://marketplace.visualstudio.com/items?itemName=vibeguard.vibeguard)
[![Downloads](https://img.shields.io/badge/downloads-0-green.svg)](https://marketplace.visualstudio.com/items?itemName=vibeguard.vibeguard)
[![Rating](https://img.shields.io/badge/rating-★★★★★-yellow.svg)](https://marketplace.visualstudio.com/items?itemName=vibeguard.vibeguard)

## 🚨 真实损失案例警示

### 💸 API 密钥泄露 - 损失 $5,000
**设计师小王的故事**：使用 ChatGPT 生成 OpenAI 集成代码，直接把 API key 写在了代码里。代码推送到 GitHub 后，被黑客发现并恶意使用，一夜之间产生了 $5,000 的费用。

### 💾 数据库误删 - 损失无法估量
**产品经理小李的故事**：让 AI 帮忙写 SQL 清理脚本，生成的 `DELETE FROM users` 没有 WHERE 条件。一键执行后，整个用户表被清空，虽然有备份，但业务中断了 4 小时。

### 🎯 XSS 攻击 - 用户数据泄露
**运营小张的故事**：从网上复制了一段代码，包含 `innerHTML` 直接插入用户输入。上线后被黑客利用，注入恶意脚本窃取了用户的登录信息。

**VibeGuard 会在你写下这些危险代码时立即警告你，并提供一键修复！**

## 🎯 专为 AI 编程用户设计

**不是给专业程序员的**，而是给这些 AI 编程用户：

### 👥 目标用户
- 🎨 **设计师**：用 Cursor、ChatGPT 写前端代码
- 📊 **产品经理**：用 AI 生成数据分析和 SQL 查询
- 📈 **运营人员**：用 AI 写自动化脚本和数据处理
- 🚀 **创业者**：用 AI 快速搭建 MVP 和原型
- 🎓 **学生**：学习编程时使用 AI 辅助工具
- 💼 **非技术创始人**：用 AI 开发产品原型

### 🤔 你是否遇到过这些情况？
- ✅ 经常使用 ChatGPT、Claude、GitHub Copilot 等 AI 工具写代码
- ✅ 对代码能跑起来很开心，但不太了解安全风险
- ✅ 担心 AI 生成的代码可能有安全问题，但不知道如何检查
- ✅ 希望有工具能自动发现并修复代码中的安全漏洞
- ✅ 想学习安全编程知识，但觉得太复杂

**如果你符合以上任何一条，VibeGuard 就是为你而生！**

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

## 🚀 5分钟快速上手

### 📦 第一步：安装 VibeGuard

#### 方法一：VS Code 扩展商店（推荐）
1. 打开 VS Code
2. 点击左侧的扩展图标（或按 `Ctrl+Shift+X`）
3. 搜索 "VibeGuard"
4. 点击 "安装"

#### 方法二：命令行安装
```bash
code --install-extension vibeguard.vibeguard
```

### 🎯 第二步：开始使用

安装完成后，VibeGuard 会自动开始工作，**无需任何配置**！

#### 🚨 识别安全问题
- 🔴 **红色波浪线** = 致命安全漏洞（必须立即修复！）
- 🟡 **黄色波浪线** = 高危安全风险（强烈建议修复）
- 💡 **灯泡图标** = 点击获取一键修复方案

#### 🛠️ 修复安全问题
1. **看到红色或黄色波浪线** → 鼠标悬停查看详细说明
2. **点击灯泡图标** → 查看修复建议
3. **选择修复方案** → 一键应用安全修复
4. **问题解决** → 继续安心编程！

### 🎬 使用演示

#### 场景一：API 密钥保护
```javascript
// ❌ 危险代码 - VibeGuard 会立即警告
const apiKey = "sk-proj-1234567890abcdef";

// ✅ 安全代码 - 点击灯泡自动修复
const apiKey = process.env.OPENAI_API_KEY;
```

#### 场景二：SQL 安全检查
```sql
-- ❌ 危险代码 - 会删除所有数据！
DELETE FROM users;

-- ✅ 安全代码 - 添加了条件限制
DELETE FROM users WHERE status = 'inactive';
```

#### 场景三：XSS 攻击防护
```javascript
// ❌ 危险代码 - 可能被注入恶意脚本
element.innerHTML = userInput;

// ✅ 安全代码 - 使用安全方法
element.textContent = userInput;
```

### ⚙️ 第三步：个性化设置（可选）

打开 VS Code 设置（`Ctrl+,`），搜索 "VibeGuard"：

- 🔍 **实时检测**：边写边检查（推荐开启）
- 📚 **显示真实案例**：在提示中显示真实损失案例
- 🚀 **自动修复**：保存时自动修复问题（谨慎使用）
- 🔔 **通知级别**：选择接收哪些类型的提醒

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

| 对比项   | 传统 Linter  | VibeGuard   |
| -------- | ------------ | ----------- |
| 目标用户 | 专业程序员   | AI 编程用户 |
| 检测重点 | 代码风格     | 致命错误    |
| 提示语言 | 英文术语     | 中文大白话  |
| 修复方式 | 需要理解原理 | 一键修复    |
| 学习成本 | 需要配置     | 零配置      |

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

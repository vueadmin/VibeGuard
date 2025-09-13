# VibeGuard 用户指南 📚

> 专为 AI 编程用户设计的完整使用指南

## 📖 目录

1. [快速入门](#快速入门)
2. [界面介绍](#界面介绍)
3. [安全检测详解](#安全检测详解)
4. [一键修复功能](#一键修复功能)
5. [常见问题解答](#常见问题解答)
6. [最佳实践](#最佳实践)
7. [真实案例学习](#真实案例学习)

## 🚀 快速入门

### 什么是 VibeGuard？

VibeGuard 是专为使用 AI 工具编程的非技术人员设计的安全检测工具。它能够：

- 🔍 **实时检测**：在你输入代码时立即发现安全问题
- 🚨 **智能警告**：用通俗易懂的语言解释安全风险
- 🛠️ **一键修复**：提供安全的代码替代方案
- 📚 **案例教学**：通过真实损失案例帮你理解风险

### 为什么需要 VibeGuard？

当你使用 ChatGPT、Claude、GitHub Copilot 等 AI 工具生成代码时，AI 可能会产生以下安全问题：

1. **API 密钥泄露** - 直接写在代码里，被黑客利用
2. **SQL 注入漏洞** - 危险的数据库操作
3. **XSS 攻击风险** - 恶意脚本注入
4. **配置错误** - 生产环境暴露敏感信息

VibeGuard 就像你的"安全顾问"，在这些问题造成损失之前就发现并修复它们。

## 🖥️ 界面介绍

### 主要界面元素

#### 1. 错误标识
- 🔴 **红色波浪线**：致命安全漏洞，必须立即修复
- 🟡 **黄色波浪线**：高危安全风险，强烈建议修复
- 💡 **灯泡图标**：点击查看修复建议

#### 2. 悬停提示
当鼠标悬停在问题代码上时，会显示：
- 🚨 **问题描述**：用简单语言解释什么地方有问题
- 💸 **真实案例**：类似问题造成的实际损失
- 🔧 **修复建议**：如何安全地修复这个问题

#### 3. 快速修复面板
点击灯泡图标后显示：
- 📝 **修复选项**：多种安全的修复方案
- 📖 **详细说明**：每个修复方案的解释
- ⚡ **一键应用**：直接应用修复到代码中

### 命令面板功能

按 `Ctrl+Shift+P` 打开命令面板，输入 "VibeGuard" 可以使用：

- 🔍 **检查当前文件的安全问题**：手动触发检测
- 🛡️ **扫描整个项目的安全风险**：全项目安全扫描
- 🚀 **一键修复所有安全问题**：批量修复功能
- 📊 **查看安全检测报告**：详细的安全报告
- 📚 **学习安全编程知识**：安全知识库

## 🔍 安全检测详解

### 1. API 密钥保护 🔑

#### 检测内容
- OpenAI API 密钥（sk-开头）
- AWS 访问密钥（AKIA开头）
- GitHub Token（ghp_开头）
- 数据库连接字符串
- JWT 密钥
- 通用 API 密钥模式

#### 真实案例
```javascript
// ❌ 危险：设计师小王因此损失 $5000
const openai = new OpenAI({
  apiKey: 'sk-proj-1234567890abcdef1234567890abcdef12345678'
});

// ✅ 安全：使用环境变量
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});
```

#### 为什么危险？
- 代码推送到 GitHub 时，密钥会被公开
- 黑客使用自动化工具扫描公开仓库中的密钥
- 一旦被发现，会立即被恶意使用

### 2. SQL 安全检查 💾

#### 检测内容
- DELETE 无 WHERE 条件
- UPDATE 无 WHERE 条件
- DROP TABLE/DATABASE
- TRUNCATE TABLE
- SQL 注入风险

#### 真实案例
```sql
-- ❌ 危险：产品经理小李因此删除了整个用户表
DELETE FROM users;

-- ✅ 安全：添加具体条件
DELETE FROM users WHERE created_at < '2023-01-01';
```

#### 为什么危险？
- 无条件的 DELETE/UPDATE 会影响整个表
- DROP 操作会永久删除数据
- SQL 注入可能导致数据泄露

### 3. 代码注入防护 💻

#### 检测内容
- eval() 函数使用
- innerHTML 直接赋值
- document.write() 使用
- 命令注入风险
- 动态脚本创建

#### 真实案例
```javascript
// ❌ 危险：运营小张的网站因此被攻击
element.innerHTML = userInput;

// ✅ 安全：使用安全方法
element.textContent = userInput;
// 或者使用 DOMPurify 清理
element.innerHTML = DOMPurify.sanitize(userInput);
```

#### 为什么危险？
- 恶意用户可以注入脚本代码
- 脚本会在其他用户浏览器中执行
- 可能窃取用户信息或执行恶意操作

### 4. 框架特定风险 ⚛️

#### React 风险检测
- dangerouslySetInnerHTML 使用
- useEffect 无限循环
- Props XSS 风险

#### Vue 风险检测
- v-html 指令风险
- 模板注入风险

#### Angular 风险检测
- bypassSecurityTrust* 方法
- 模板注入风险

### 5. 配置错误检测 ⚙️

#### 检测内容
- 生产环境 debug=true
- CORS 允许所有域名
- Docker 端口暴露
- 弱密码配置
- SSL/TLS 配置错误

## 🛠️ 一键修复功能

### 修复类型

#### 1. 自动替换修复
直接将危险代码替换为安全代码：
```javascript
// 修复前
const key = "sk-1234567890";

// 修复后
const key = process.env.API_KEY;
```

#### 2. 添加安全检查
在危险操作前添加安全措施：
```sql
-- 修复前
DELETE FROM users;

-- 修复后
DELETE FROM users WHERE id = ?; -- ⚠️ 请替换为具体条件
```

#### 3. 注释危险代码
将极度危险的代码注释掉并添加说明：
```javascript
// 修复前
eval(userInput);

// 修复后
// 🚨 危险函数已注释：eval() 存在严重安全风险！
// 🛡️ 安全替代方案：使用 JSON.parse() 或专门的表达式解析库
// eval(userInput);
```

### 批量修复功能

使用命令面板的"一键修复所有安全问题"可以：
- 🔍 扫描整个项目
- 📋 列出所有安全问题
- ✅ 让你选择要修复的问题
- 🚀 批量应用修复

## ❓ 常见问题解答

### Q1: VibeGuard 会影响编程性能吗？
**A:** 不会。VibeGuard 使用了防抖机制和增量分析，只在你停止输入 500ms 后才开始检测，并且只检测修改的部分。

### Q2: 误报怎么办？
**A:** VibeGuard 采用"宁可漏报，不可误报"的原则。如果遇到误报，可以：
- 添加注释说明这是安全的
- 在设置中调整检测规则
- 向我们反馈改进建议

### Q3: 支持哪些编程语言？
**A:** 目前支持：
- JavaScript/TypeScript
- Python
- SQL
- Java
- C#
- PHP
- JSON/YAML
- HTML/CSS

### Q4: 可以自定义检测规则吗？
**A:** 当前版本提供预设规则，未来版本会支持自定义规则。

### Q5: 如何学习更多安全知识？
**A:** 使用命令面板的"学习安全编程知识"功能，或查看我们的在线文档。

## 🏆 最佳实践

### 1. 开发流程建议

#### 编程前
- ✅ 确保 VibeGuard 已启用
- ✅ 了解你要使用的 AI 工具的特点
- ✅ 准备好环境变量配置

#### 编程中
- ✅ 注意红色和黄色波浪线
- ✅ 及时查看和修复安全问题
- ✅ 不要忽略任何安全警告

#### 编程后
- ✅ 运行全项目安全扫描
- ✅ 检查安全检测报告
- ✅ 确保所有问题都已修复

### 2. 环境变量管理

#### 创建 .env 文件
```bash
# .env 文件示例
OPENAI_API_KEY=your_actual_api_key_here
AWS_ACCESS_KEY_ID=your_aws_key_here
DATABASE_URL=your_database_connection_here
JWT_SECRET=your_jwt_secret_here
```

#### 添加到 .gitignore
```bash
# .gitignore 文件
.env
.env.local
.env.production
*.key
*.pem
```

#### 在代码中使用
```javascript
// 正确的使用方式
const apiKey = process.env.OPENAI_API_KEY;
const dbUrl = process.env.DATABASE_URL;
```

### 3. 团队协作建议

#### 项目设置
- 📋 在项目 README 中说明安全要求
- 🔧 统一团队的 VibeGuard 配置
- 📊 定期进行安全检查

#### 代码审查
- ✅ 确保所有 PR 都通过了安全检查
- ✅ 重点关注 API 密钥和数据库操作
- ✅ 教育团队成员安全编程知识

## 📚 真实案例学习

### 案例一：OpenAI API 密钥泄露

**背景**：设计师小王使用 ChatGPT 生成了一个聊天机器人的前端代码。

**问题代码**：
```javascript
const openai = new OpenAI({
  apiKey: 'sk-proj-abcd1234567890efgh1234567890ijkl12345678'
});
```

**发生的事情**：
1. 小王将代码推送到了公开的 GitHub 仓库
2. 黑客的自动化工具扫描到了这个 API 密钥
3. 黑客使用这个密钥大量调用 OpenAI API
4. 一夜之间产生了 $5,000 的费用

**VibeGuard 的保护**：
- 🚨 立即显示红色波浪线警告
- 💸 提示真实损失案例
- 🛠️ 提供一键修复：替换为环境变量

**正确做法**：
```javascript
// 1. 在 .env 文件中设置
OPENAI_API_KEY=sk-proj-abcd1234567890efgh1234567890ijkl12345678

// 2. 在代码中引用
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// 3. 将 .env 添加到 .gitignore
```

### 案例二：SQL 删除灾难

**背景**：产品经理小李需要清理测试数据，让 AI 帮忙写了一个清理脚本。

**问题代码**：
```sql
-- 清理无效用户
DELETE FROM users;
```

**发生的事情**：
1. 小李在生产数据库上执行了这个脚本
2. 整个用户表被清空，包括所有正常用户
3. 虽然有备份，但业务中断了 4 小时
4. 造成了巨大的业务损失和用户投诉

**VibeGuard 的保护**：
- 🚨 立即显示红色波浪线警告
- 💾 解释数据丢失的严重后果
- 🛠️ 提供修复：添加 WHERE 条件

**正确做法**：
```sql
-- 1. 先查询要删除的数据
SELECT * FROM users WHERE status = 'inactive' AND last_login < '2023-01-01';

-- 2. 确认无误后再删除
DELETE FROM users WHERE status = 'inactive' AND last_login < '2023-01-01';

-- 3. 或者使用更安全的软删除
UPDATE users SET deleted_at = NOW() WHERE status = 'inactive';
```

### 案例三：XSS 攻击事件

**背景**：运营小张从网上复制了一段代码，用于在页面上显示用户评论。

**问题代码**：
```javascript
// 显示用户评论
function showComment(comment) {
  document.getElementById('comment').innerHTML = comment;
}
```

**发生的事情**：
1. 恶意用户提交了包含脚本的评论
2. 脚本在其他用户浏览器中执行
3. 窃取了用户的登录 Cookie
4. 导致多个用户账户被盗

**VibeGuard 的保护**：
- ⚠️ 显示黄色波浪线警告
- 🎯 解释 XSS 攻击的危害
- 🛠️ 提供安全替代方案

**正确做法**：
```javascript
// 方法一：使用 textContent（纯文本）
function showComment(comment) {
  document.getElementById('comment').textContent = comment;
}

// 方法二：使用 DOMPurify 清理（支持 HTML）
function showComment(comment) {
  const clean = DOMPurify.sanitize(comment);
  document.getElementById('comment').innerHTML = clean;
}
```

## 🎓 进阶学习

### 安全编程原则

1. **最小权限原则**：只给必要的权限
2. **输入验证**：永远不要信任用户输入
3. **输出编码**：正确处理输出内容
4. **错误处理**：不要暴露敏感信息
5. **安全配置**：使用安全的默认设置

### 推荐资源

- 📖 [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- 📚 [安全编程指南](https://cheatsheetseries.owasp.org/)
- 🎥 [安全编程视频教程](https://www.youtube.com/results?search_query=secure+coding)
- 💬 [VibeGuard 社区](https://discord.gg/vibeguard)

---

## 🆘 需要帮助？

- 📧 **邮件支持**：help@vibeguard.dev
- 💬 **社区讨论**：[Discord 社区](https://discord.gg/vibeguard)
- 🐛 **问题反馈**：[GitHub Issues](https://github.com/vibeguard/vibeguard/issues)
- 📚 **在线文档**：[vibeguard.dev/docs](https://vibeguard.dev/docs)

记住：**最贵的代码错误，往往是最简单的那一行。让 VibeGuard 帮你避免这些代价高昂的错误！**
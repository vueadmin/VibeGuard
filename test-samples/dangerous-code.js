// 这个文件包含各种危险代码示例，用于测试 VibeGuard 插件

// 1. SQL 注入风险
const userId = req.params.id;
const query = "SELECT * FROM users WHERE id = " + userId; // SQL 注入！

// 2. 删库跑路
const deleteAllUsers = () => {
    const sql = "DELETE FROM users"; // 没有 WHERE 条件！
    db.execute(sql);
};

// 3. API Key 泄露
const apiKey = "sk-1234567890abcdef123456"; // 硬编码的 API Key
const awsKey = "AKIAIOSFODNN7EXAMPLE"; // AWS 密钥泄露

// 4. eval 执行任意代码
const userInput = req.body.code;
eval(userInput); // 极度危险！

// 5. XSS 攻击
document.getElementById('content').innerHTML = userInput; // XSS 风险

// 6. 异步陷阱
const items = [1, 2, 3, 4, 5];
items.forEach(async (item) => { // forEach 中的 await 不会等待
    await processItem(item);
});

// 7. 未处理的 Promise
fetch('/api/data')
    .then(res => res.json())
    .then(data => console.log(data)); // 缺少 .catch

// 8. console.log 在生产环境
console.log(password); // 密码泄露到控制台

// 9. == 而非 ===
if (status == "1") { // 应该使用 ===
    doSomething();
}

// 10. var 声明
var oldVariable = 123; // 应该使用 let 或 const
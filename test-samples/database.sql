-- 危险的 SQL 示例

-- 1. DELETE 没有 WHERE 条件
DELETE FROM users;

-- 2. UPDATE 没有 WHERE 条件  
UPDATE products SET price = 0;

-- 3. TRUNCATE 清空表
TRUNCATE TABLE orders;

-- 4. DROP DATABASE
DROP DATABASE production_db;

-- 5. DROP TABLE
DROP TABLE customers;

-- 6. 密码明文存储
INSERT INTO users (username, password) VALUES ('admin', 'password123');

-- 7. GRANT ALL 权限过高
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';

-- 8. SELECT * 性能问题
SELECT * FROM large_table;

-- 9. 没有 LIMIT 的查询
SELECT id, name, email FROM users;
/**
 * SQL Danger Detection Rules Tests
 * 
 * Comprehensive test suite for SQL danger detection rules based on real-world
 * scenarios where dangerous SQL operations could lead to data loss or security
 * vulnerabilities. These tests ensure the rules can detect dangerous SQL patterns
 * while avoiding false positives.
 */

import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { 
  SQL_DANGER_RULES, 
  registerSqlDangerRules,
  SQL_DELETE_NO_WHERE_RULE,
  SQL_UPDATE_NO_WHERE_RULE,
  SQL_DROP_TABLE_RULE,
  SQL_DROP_DATABASE_RULE,
  SQL_TRUNCATE_TABLE_RULE,
  SQL_INJECTION_CONCAT_RULE
} from '../../rules/definitions/sql-rules';
import { DetectionRule, IssueSeverity, SecurityCategory } from '../../types';

suite('SQL Danger Detection Rules Tests', () => {
  let ruleEngine: RuleEngine;

  setup(() => {
    ruleEngine = new RuleEngine();
    registerSqlDangerRules(ruleEngine);
  });

  teardown(() => {
    ruleEngine.clearRules();
  });

  suite('DELETE FROM without WHERE Detection', () => {
    test('should detect DELETE statements without WHERE clause', () => {
      const testCases = [
        {
          name: 'Simple DELETE without WHERE',
          code: 'DELETE FROM users;',
          shouldDetect: true
        },
        {
          name: 'DELETE with table name and semicolon',
          code: 'DELETE FROM products;',
          shouldDetect: true
        },
        {
          name: 'DELETE without semicolon',
          code: 'DELETE FROM orders',
          shouldDetect: true
        },
        {
          name: 'DELETE in JavaScript string',
          code: 'const query = "DELETE FROM customers;";',
          shouldDetect: true
        },
        {
          name: 'Multi-line DELETE',
          code: `DELETE FROM 
                 users;`,
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(deleteIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(deleteIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(deleteIssues[0].message.includes('DELETE'));
          assert.ok(deleteIssues[0].message.includes('WHERE'));
          assert.ok(deleteIssues[0].message.includes('致命错误'));
        } else {
          assert.strictEqual(deleteIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should NOT detect DELETE statements WITH WHERE clause', () => {
      const safeCases = [
        'DELETE FROM users WHERE id = 1;',
        'DELETE FROM products WHERE category = "old";',
        'DELETE FROM orders WHERE created_at < "2023-01-01";',
        'DELETE FROM customers WHERE status = "inactive" AND last_login < "2022-01-01";'
      ];

      safeCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
        assert.strictEqual(deleteIssues.length, 0, `Should not detect safe DELETE: ${code}`);
      });
    });

    test('should provide quick fix for DELETE without WHERE', () => {
      const code = 'DELETE FROM users;';
      const issues = ruleEngine.executeRules(code, 'sql');
      const deleteIssue = issues.find(issue => issue.code === 'SQL_DELETE_NO_WHERE');

      assert.ok(deleteIssue);
      assert.ok(deleteIssue.quickFix);
      assert.ok(deleteIssue.quickFix.replacement.includes('WHERE id = ?'));
      assert.ok(deleteIssue.quickFix.title.includes('WHERE 条件'));
    });

    test('should ignore whitelisted DELETE patterns', () => {
      const whitelistedCases = [
        '-- DELETE FROM users;',
        '/* DELETE FROM products; */',
        '// DELETE FROM orders;',
        '# DELETE FROM customers;',
        '"DELETE FROM users;"',
        "'DELETE FROM products;'",
        '`DELETE FROM orders;`',
        'DELETE FROM test;',
        'DELETE FROM example;',
        'DELETE FROM dummy;'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
        assert.strictEqual(deleteIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('UPDATE without WHERE Detection', () => {
    test('should detect UPDATE statements without WHERE clause', () => {
      const testCases = [
        {
          name: 'Simple UPDATE without WHERE',
          code: 'UPDATE users SET status = "inactive";',
          shouldDetect: true
        },
        {
          name: 'UPDATE with multiple columns',
          code: 'UPDATE products SET price = 0, stock = 0;',
          shouldDetect: true
        },
        {
          name: 'UPDATE without semicolon',
          code: 'UPDATE orders SET status = "cancelled"',
          shouldDetect: true
        },
        {
          name: 'UPDATE in JavaScript string',
          code: 'const query = "UPDATE customers SET active = false;";',
          shouldDetect: true
        },
        {
          name: 'Multi-line UPDATE',
          code: `UPDATE users 
                 SET status = "deleted", 
                     deleted_at = NOW();`,
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(updateIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(updateIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(updateIssues[0].message.includes('UPDATE'));
          assert.ok(updateIssues[0].message.includes('WHERE'));
          assert.ok(updateIssues[0].message.includes('致命错误'));
        } else {
          assert.strictEqual(updateIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should NOT detect UPDATE statements WITH WHERE clause', () => {
      const safeCases = [
        'UPDATE users SET status = "inactive" WHERE id = 1;',
        'UPDATE products SET price = 10.99 WHERE category = "sale";',
        'UPDATE orders SET status = "shipped" WHERE order_date > "2023-01-01";',
        'UPDATE customers SET last_login = NOW() WHERE active = true;'
      ];

      safeCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
        assert.strictEqual(updateIssues.length, 0, `Should not detect safe UPDATE: ${code}`);
      });
    });

    test('should provide quick fix for UPDATE without WHERE', () => {
      const code = 'UPDATE users SET status = "inactive";';
      const issues = ruleEngine.executeRules(code, 'sql');
      const updateIssue = issues.find(issue => issue.code === 'SQL_UPDATE_NO_WHERE');

      assert.ok(updateIssue);
      assert.ok(updateIssue.quickFix);
      assert.ok(updateIssue.quickFix.replacement.includes('WHERE id = ?'));
      assert.ok(updateIssue.quickFix.title.includes('WHERE 条件'));
    });

    test('should ignore whitelisted UPDATE patterns', () => {
      const whitelistedCases = [
        '-- UPDATE users SET status = "inactive";',
        '/* UPDATE products SET price = 0; */',
        '// UPDATE orders SET status = "cancelled";',
        '# UPDATE customers SET active = false;',
        '"UPDATE users SET status = \\"inactive\\""',
        "'UPDATE products SET price = 0'",
        'UPDATE test SET value = 1;',
        'UPDATE example SET name = "test";',
        'UPDATE dummy SET flag = true;'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
        assert.strictEqual(updateIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('DROP TABLE Detection', () => {
    test('should detect DROP TABLE statements', () => {
      const testCases = [
        {
          name: 'Simple DROP TABLE',
          code: 'DROP TABLE users;',
          shouldDetect: true
        },
        {
          name: 'DROP TABLE IF EXISTS',
          code: 'DROP TABLE IF EXISTS products;',
          shouldDetect: true
        },
        {
          name: 'DROP TABLE without semicolon',
          code: 'DROP TABLE orders',
          shouldDetect: true
        },
        {
          name: 'DROP TABLE in JavaScript',
          code: 'const query = "DROP TABLE customers";',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const dropIssues = issues.filter(issue => issue.code === 'SQL_DROP_TABLE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(dropIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(dropIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(dropIssues[0].message.includes('DROP TABLE'));
          assert.ok(dropIssues[0].message.includes('极度危险'));
        } else {
          assert.strictEqual(dropIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for DROP TABLE', () => {
      const code = 'DROP TABLE users;';
      const issues = ruleEngine.executeRules(code, 'sql');
      const dropIssue = issues.find(issue => issue.code === 'SQL_DROP_TABLE');

      assert.ok(dropIssue);
      assert.ok(dropIssue.quickFix);
      assert.ok(dropIssue.quickFix.replacement.includes('备份'));
      assert.ok(dropIssue.quickFix.replacement.includes('BACKUP'));
      assert.ok(dropIssue.quickFix.title.includes('备份提醒'));
    });

    test('should ignore whitelisted DROP TABLE patterns', () => {
      const whitelistedCases = [
        '-- DROP TABLE users;',
        '/* DROP TABLE products; */',
        '// DROP TABLE orders;',
        '# DROP TABLE customers;',
        '"DROP TABLE users"',
        "'DROP TABLE products'",
        'DROP TABLE test;',
        'DROP TABLE temp;',
        'DROP TABLE tmp;',
        'DROP TABLE example;',
        'DROP TABLE dummy;',
        'DROP TABLE users_temp;',
        'DROP TABLE products_backup;'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const dropIssues = issues.filter(issue => issue.code === 'SQL_DROP_TABLE');
        assert.strictEqual(dropIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('DROP DATABASE Detection', () => {
    test('should detect DROP DATABASE statements', () => {
      const testCases = [
        {
          name: 'DROP DATABASE',
          code: 'DROP DATABASE myapp;',
          shouldDetect: true
        },
        {
          name: 'DROP DATABASE IF EXISTS',
          code: 'DROP DATABASE IF EXISTS production;',
          shouldDetect: true
        },
        {
          name: 'DROP SCHEMA',
          code: 'DROP SCHEMA public;',
          shouldDetect: true
        },
        {
          name: 'DROP SCHEMA IF EXISTS',
          code: 'DROP SCHEMA IF EXISTS app_schema;',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const dropDbIssues = issues.filter(issue => issue.code === 'SQL_DROP_DATABASE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(dropDbIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(dropDbIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(dropDbIssues[0].message.includes('DROP DATABASE'));
          assert.ok(dropDbIssues[0].message.includes('毁灭性操作'));
        } else {
          assert.strictEqual(dropDbIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for DROP DATABASE', () => {
      const code = 'DROP DATABASE production;';
      const issues = ruleEngine.executeRules(code, 'sql');
      const dropDbIssue = issues.find(issue => issue.code === 'SQL_DROP_DATABASE');

      assert.ok(dropDbIssue);
      assert.ok(dropDbIssue.quickFix);
      assert.ok(dropDbIssue.quickFix.replacement.includes('危险操作警告'));
      assert.ok(dropDbIssue.quickFix.replacement.includes('--'));
      assert.ok(dropDbIssue.quickFix.title.includes('安全检查'));
    });

    test('should ignore whitelisted DROP DATABASE patterns', () => {
      const whitelistedCases = [
        '-- DROP DATABASE myapp;',
        '/* DROP DATABASE production; */',
        '// DROP SCHEMA public;',
        '# DROP DATABASE test_db;',
        '"DROP DATABASE myapp"',
        "'DROP SCHEMA public'",
        'DROP DATABASE test;',
        'DROP DATABASE temp;',
        'DROP DATABASE tmp;',
        'DROP DATABASE example;',
        'DROP DATABASE dummy;'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const dropDbIssues = issues.filter(issue => issue.code === 'SQL_DROP_DATABASE');
        assert.strictEqual(dropDbIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('TRUNCATE TABLE Detection', () => {
    test('should detect TRUNCATE statements', () => {
      const testCases = [
        {
          name: 'TRUNCATE TABLE',
          code: 'TRUNCATE TABLE users;',
          shouldDetect: true
        },
        {
          name: 'TRUNCATE without TABLE keyword',
          code: 'TRUNCATE products;',
          shouldDetect: true
        },
        {
          name: 'TRUNCATE in JavaScript',
          code: 'const query = "TRUNCATE TABLE orders";',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const truncateIssues = issues.filter(issue => issue.code === 'SQL_TRUNCATE_TABLE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(truncateIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(truncateIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(truncateIssues[0].message.includes('TRUNCATE'));
          assert.ok(truncateIssues[0].message.includes('危险操作'));
        } else {
          assert.strictEqual(truncateIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for TRUNCATE', () => {
      const code = 'TRUNCATE TABLE users;';
      const issues = ruleEngine.executeRules(code, 'sql');
      const truncateIssue = issues.find(issue => issue.code === 'SQL_TRUNCATE_TABLE');

      assert.ok(truncateIssue);
      assert.ok(truncateIssue.quickFix);
      assert.ok(truncateIssue.quickFix.replacement.includes('DELETE FROM'));
      assert.ok(truncateIssue.quickFix.title.includes('可回滚的 DELETE'));
    });

    test('should ignore whitelisted TRUNCATE patterns', () => {
      const whitelistedCases = [
        '-- TRUNCATE TABLE users;',
        '/* TRUNCATE products; */',
        '// TRUNCATE TABLE orders;',
        '# TRUNCATE customers;',
        '"TRUNCATE TABLE users"',
        "'TRUNCATE products'",
        'TRUNCATE test;',
        'TRUNCATE temp;',
        'TRUNCATE tmp;',
        'TRUNCATE example;',
        'TRUNCATE dummy;'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const truncateIssues = issues.filter(issue => issue.code === 'SQL_TRUNCATE_TABLE');
        assert.strictEqual(truncateIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('SQL Injection Detection', () => {
    test('should detect potential SQL injection via string concatenation', () => {
      const testCases = [
        {
          name: 'SELECT with user input concatenation',
          code: 'const query = "SELECT * FROM users WHERE name = " + userInput;',
          shouldDetect: true
        },
        {
          name: 'INSERT with form data concatenation',
          code: 'const sql = "INSERT INTO products (name) VALUES (" + formData.name + ")";',
          shouldDetect: true
        },
        {
          name: 'UPDATE with request parameter',
          code: 'const query = "UPDATE users SET email = " + request.body.email;',
          shouldDetect: true
        },
        {
          name: 'DELETE with user parameter',
          code: 'const sql = "DELETE FROM orders WHERE id = " + params.id;',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(injectionIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(injectionIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(injectionIssues[0].message.includes('SQL 注入'));
          assert.ok(injectionIssues[0].message.includes('攻击'));
        } else {
          assert.strictEqual(injectionIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for SQL injection', () => {
      const code = 'const query = "SELECT * FROM users WHERE id = " + userId;';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const injectionIssue = issues.find(issue => issue.code === 'SQL_INJECTION_CONCAT');

      assert.ok(injectionIssue);
      assert.ok(injectionIssue.quickFix);
      assert.ok(injectionIssue.quickFix.replacement.includes('参数化查询'));
      assert.ok(injectionIssue.quickFix.replacement.includes('?'));
      assert.ok(injectionIssue.quickFix.title.includes('参数化查询'));
    });

    test('should ignore whitelisted SQL injection patterns', () => {
      const whitelistedCases = [
        '-- SELECT * FROM users WHERE id = " + userId;',
        '/* INSERT INTO products VALUES (" + data + ") */',
        '// const query = "UPDATE users SET name = " + input;',
        '# DELETE FROM orders WHERE id = " + param;',
        '"SELECT * FROM users WHERE id = \\" + userId"',
        "'INSERT INTO products VALUES (' + data + ')'",
        'console.log("SELECT * FROM users WHERE id = " + userId);',
        'print("UPDATE users SET name = " + input);',
        'echo "DELETE FROM orders WHERE id = " + param;',
        'log("INSERT INTO products VALUES (" + data + ")");'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
        assert.strictEqual(injectionIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('Real-World AI Generated Code Scenarios', () => {
    test('should detect issues in ChatGPT generated database cleanup script', () => {
      const chatgptCode = `
        // Clean up old user data
        const mysql = require('mysql2');
        
        const connection = mysql.createConnection({
          host: 'localhost',
          user: 'root',
          password: 'password',
          database: 'myapp'
        });
        
        // Remove inactive users
        connection.query('DELETE FROM users;', (error, results) => {
          if (error) throw error;
          console.log('Deleted ' + results.affectedRows + ' users');
        });
        
        // Reset product prices
        connection.query('UPDATE products SET price = 0;', (error, results) => {
          if (error) throw error;
          console.log('Updated ' + results.affectedRows + ' products');
        });
      `;

      const issues = ruleEngine.executeRules(chatgptCode, 'javascript');
      const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
      const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
      
      assert.strictEqual(deleteIssues.length, 1);
      assert.strictEqual(updateIssues.length, 1);
      assert.ok(deleteIssues[0].message.includes('致命错误'));
      assert.ok(updateIssues[0].message.includes('致命错误'));
    });

    test('should detect issues in Claude generated database migration', () => {
      const claudeCode = `
        -- Database migration script
        -- WARNING: This will remove all existing data
        
        DROP DATABASE IF EXISTS old_app;
        DROP TABLE users;
        DROP TABLE products;
        DROP TABLE orders;
        
        -- Recreate tables
        CREATE DATABASE new_app;
        USE new_app;
        
        CREATE TABLE users (
          id INT PRIMARY KEY,
          name VARCHAR(255),
          email VARCHAR(255)
        );
      `;

      const issues = ruleEngine.executeRules(claudeCode, 'sql');
      const dropDbIssues = issues.filter(issue => issue.code === 'SQL_DROP_DATABASE');
      const dropTableIssues = issues.filter(issue => issue.code === 'SQL_DROP_TABLE');
      
      assert.strictEqual(dropDbIssues.length, 1);
      assert.strictEqual(dropTableIssues.length, 3); // users, products, orders
      assert.ok(dropDbIssues[0].message.includes('毁灭性操作'));
    });

    test('should detect issues in AI generated data cleanup utility', () => {
      const aiCode = `
        const { Pool } = require('pg');
        
        const pool = new Pool({
          user: 'admin',
          host: 'localhost',
          database: 'production',
          password: 'secret123',
          port: 5432,
        });
        
        async function cleanupData() {
          // Remove all test data
          await pool.query('TRUNCATE TABLE test_users;');
          
          // Clear all logs
          await pool.query('DELETE FROM logs;');
          
          // Reset counters
          await pool.query('UPDATE counters SET value = 0;');
          
          console.log('Data cleanup completed');
        }
        
        cleanupData();
      `;

      const issues = ruleEngine.executeRules(aiCode, 'javascript');
      const truncateIssues = issues.filter(issue => issue.code === 'SQL_TRUNCATE_TABLE');
      const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
      const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
      
      assert.strictEqual(truncateIssues.length, 1);
      assert.strictEqual(deleteIssues.length, 1);
      assert.strictEqual(updateIssues.length, 1);
    });

    test('should detect SQL injection in AI generated search function', () => {
      const searchCode = `
        function searchUsers(searchTerm) {
          const query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
          return db.query(query);
        }
        
        function getUserById(userId) {
          const sql = "SELECT * FROM users WHERE id = " + userId;
          return database.execute(sql);
        }
        
        function updateUserEmail(userId, email) {
          const updateQuery = "UPDATE users SET email = '" + email + "' WHERE id = " + userId;
          return db.run(updateQuery);
        }
      `;

      const issues = ruleEngine.executeRules(searchCode, 'javascript');
      const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
      
      assert.ok(injectionIssues.length >= 3); // Should detect multiple injection points
      injectionIssues.forEach(issue => {
        assert.ok(issue.message.includes('SQL 注入'));
      });
    });

    test('should handle mixed SQL dangers in one file', () => {
      const mixedCode = `
        -- Dangerous database operations
        DELETE FROM users;
        UPDATE products SET price = 0;
        DROP TABLE old_data;
        DROP DATABASE backup_db;
        TRUNCATE TABLE logs;
        
        -- Dynamic queries with injection risks
        const userQuery = "SELECT * FROM users WHERE name = " + userName;
        const deleteQuery = "DELETE FROM orders WHERE status = " + statusInput;
      `;

      const issues = ruleEngine.executeRules(mixedCode, 'sql');
      
      // Should detect multiple different types of issues
      const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
      const updateIssues = issues.filter(issue => issue.code === 'SQL_UPDATE_NO_WHERE');
      const dropTableIssues = issues.filter(issue => issue.code === 'SQL_DROP_TABLE');
      const dropDbIssues = issues.filter(issue => issue.code === 'SQL_DROP_DATABASE');
      const truncateIssues = issues.filter(issue => issue.code === 'SQL_TRUNCATE_TABLE');
      const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
      
      assert.strictEqual(deleteIssues.length, 1);
      assert.strictEqual(updateIssues.length, 1);
      assert.strictEqual(dropTableIssues.length, 1);
      assert.strictEqual(dropDbIssues.length, 1);
      assert.strictEqual(truncateIssues.length, 1);
      assert.strictEqual(injectionIssues.length, 2);
      
      // All should be errors or warnings
      issues.forEach(issue => {
        assert.ok(issue.severity === IssueSeverity.ERROR || issue.severity === IssueSeverity.WARNING);
        assert.ok(issue.quickFix);
      });
    });
  });

  suite('Whitelist and False Positive Prevention', () => {
    test('should ignore SQL statements in comments', () => {
      const commentCases = [
        '-- DELETE FROM users;',
        '/* UPDATE products SET price = 0; */',
        '// DROP TABLE old_data;',
        '# TRUNCATE TABLE logs;',
        '* DELETE FROM orders WHERE status = "old"'
      ];

      commentCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        assert.strictEqual(issues.length, 0, `Should ignore comment: ${code}`);
      });
    });

    test('should ignore SQL statements in string literals', () => {
      const stringCases = [
        '"DELETE FROM users;"',
        "'UPDATE products SET price = 0;'",
        '`DROP TABLE old_data;`',
        '"TRUNCATE TABLE logs"',
        "'SELECT * FROM users WHERE id = ' + userId"
      ];

      stringCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const sqlIssues = issues.filter(issue => 
          issue.code.startsWith('SQL_') && 
          issue.code !== 'SQL_INJECTION_CONCAT'
        );
        assert.strictEqual(sqlIssues.length, 0, `Should ignore string literal: ${code}`);
      });
    });

    test('should ignore test and example table names', () => {
      const testCases = [
        'DELETE FROM test;',
        'UPDATE example SET value = 1;',
        'DROP TABLE dummy;',
        'TRUNCATE temp;',
        'DELETE FROM test_users;',
        'DROP TABLE users_temp;',
        'DROP TABLE products_backup;'
      ];

      testCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'sql');
        const sqlIssues = issues.filter(issue => issue.code.startsWith('SQL_'));
        assert.strictEqual(sqlIssues.length, 0, `Should ignore test table: ${code}`);
      });
    });

    test('should ignore logging and debugging contexts for injection detection', () => {
      const loggingCases = [
        'console.log("SELECT * FROM users WHERE id = " + userId);',
        'print("UPDATE users SET name = " + input);',
        'echo "DELETE FROM orders WHERE id = " + param;',
        'log("INSERT INTO products VALUES (" + data + ")");',
        'debug("Query: SELECT * FROM users WHERE name = " + name);'
      ];

      loggingCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
        assert.strictEqual(injectionIssues.length, 0, `Should ignore logging: ${code}`);
      });
    });
  });

  suite('Quick Fix Generation', () => {
    test('should generate appropriate quick fixes for all SQL rule types', () => {
      const testCases = [
        {
          code: 'DELETE FROM users;',
          ruleId: 'SQL_DELETE_NO_WHERE',
          expectedInFix: 'WHERE id = ?'
        },
        {
          code: 'UPDATE products SET price = 0;',
          ruleId: 'SQL_UPDATE_NO_WHERE',
          expectedInFix: 'WHERE id = ?'
        },
        {
          code: 'DROP TABLE old_data;',
          ruleId: 'SQL_DROP_TABLE',
          expectedInFix: '备份'
        },
        {
          code: 'DROP DATABASE myapp;',
          ruleId: 'SQL_DROP_DATABASE',
          expectedInFix: '危险操作警告'
        },
        {
          code: 'TRUNCATE TABLE logs;',
          ruleId: 'SQL_TRUNCATE_TABLE',
          expectedInFix: 'DELETE FROM'
        },
        {
          code: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          ruleId: 'SQL_INJECTION_CONCAT',
          expectedInFix: '参数化查询'
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'sql');
        const issue = issues.find(issue => issue.code === testCase.ruleId);
        
        assert.ok(issue, `Should detect issue for: ${testCase.code}`);
        assert.ok(issue.quickFix, 'Should have quick fix');
        assert.ok(issue.quickFix.replacement.includes(testCase.expectedInFix), 
          `Quick fix should contain "${testCase.expectedInFix}"`);
      });
    });

    test('should generate dynamic quick fixes with proper table names', () => {
      const code = 'DELETE FROM customers;';
      const issues = ruleEngine.executeRules(code, 'sql');
      const deleteIssue = issues.find(issue => issue.code === 'SQL_DELETE_NO_WHERE');

      assert.ok(deleteIssue);
      assert.ok(deleteIssue.quickFix);
      assert.ok(deleteIssue.quickFix.replacement.includes('customers WHERE id = ?'));
    });
  });

  suite('Rule Registration and Management', () => {
    test('should register all SQL danger rules successfully', () => {
      const freshEngine = new RuleEngine();
      registerSqlDangerRules(freshEngine);

      const stats = freshEngine.getStatistics();
      assert.strictEqual(stats.totalRules, SQL_DANGER_RULES.length);
      assert.strictEqual(stats.enabledRules, SQL_DANGER_RULES.length);
      
      // Check that all rules are in the SQL_DANGER category
      assert.strictEqual(stats.rulesByCategory[SecurityCategory.SQL_DANGER], SQL_DANGER_RULES.length);
    });

    test('should handle rule registration errors gracefully', () => {
      const mockEngine = {
        registerRule: (rule: DetectionRule) => {
          if (rule.id === 'SQL_DELETE_NO_WHERE') {
            throw new Error('Mock registration error');
          }
        }
      };

      // Should not throw, but log error
      assert.doesNotThrow(() => {
        registerSqlDangerRules(mockEngine);
      });
    });

    test('should retrieve rules by category', () => {
      const sqlRules = ruleEngine.getRulesByCategory(SecurityCategory.SQL_DANGER);
      assert.strictEqual(sqlRules.length, SQL_DANGER_RULES.length);
      
      sqlRules.forEach(rule => {
        assert.strictEqual(rule.category, SecurityCategory.SQL_DANGER);
        assert.strictEqual(rule.enabled, true);
      });
    });
  });

  suite('Multi-language Support', () => {
    test('should detect SQL dangers in different programming languages', () => {
      const languageTests = [
        {
          language: 'python',
          code: 'cursor.execute("DELETE FROM users;")'
        },
        {
          language: 'php',
          code: '$query = "UPDATE products SET price = 0;";'
        },
        {
          language: 'java',
          code: 'String sql = "DROP TABLE old_data;";'
        },
        {
          language: 'csharp',
          code: 'var command = "TRUNCATE TABLE logs;";'
        }
      ];

      languageTests.forEach(test => {
        const issues = ruleEngine.executeRules(test.code, test.language);
        const sqlIssues = issues.filter(issue => issue.code.startsWith('SQL_'));
        assert.ok(sqlIssues.length > 0, `Should detect SQL danger in ${test.language}`);
      });
    });
  });

  suite('Performance and Edge Cases', () => {
    test('should handle large SQL files efficiently', () => {
      const largeSqlFile = Array(1000).fill('SELECT * FROM users WHERE id = 1;').join('\n') + 
                          '\nDELETE FROM users;'; // One dangerous statement at the end

      const startTime = Date.now();
      const issues = ruleEngine.executeRules(largeSqlFile, 'sql');
      const duration = Date.now() - startTime;

      assert.ok(duration < 1000, 'Should process large file quickly'); // Less than 1 second
      assert.strictEqual(issues.length, 1); // Should find the one dangerous statement
      assert.strictEqual(issues[0].code, 'SQL_DELETE_NO_WHERE');
    });

    test('should handle malformed SQL gracefully', () => {
      const malformedCases = [
        'DELETE FROM;', // Missing table name
        'UPDATE SET value = 1;', // Missing table name
        'DROP;', // Incomplete statement
        'TRUNCATE;', // Missing table
        'SELECT * FROM users WHERE id = " +;' // Incomplete injection pattern
      ];

      malformedCases.forEach(code => {
        assert.doesNotThrow(() => {
          const issues = ruleEngine.executeRules(code, 'sql');
          // Should not crash, may or may not detect issues
        }, `Should handle malformed SQL: ${code}`);
      });
    });

    test('should handle mixed content files', () => {
      const mixedContent = `
        // JavaScript code
        function connectToDatabase() {
          const connection = mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'password'
          });
          
          // Dangerous SQL operation
          connection.query('DELETE FROM users;');
          
          return connection;
        }
        
        /* SQL comments and code */
        -- This is a comment
        SELECT * FROM products WHERE active = 1;
        
        // More JavaScript
        const userInput = req.body.username;
        const query = "SELECT * FROM users WHERE name = " + userInput;
      `;

      const issues = ruleEngine.executeRules(mixedContent, 'javascript');
      const deleteIssues = issues.filter(issue => issue.code === 'SQL_DELETE_NO_WHERE');
      const injectionIssues = issues.filter(issue => issue.code === 'SQL_INJECTION_CONCAT');
      
      assert.strictEqual(deleteIssues.length, 1);
      assert.strictEqual(injectionIssues.length, 1);
    });
  });
});
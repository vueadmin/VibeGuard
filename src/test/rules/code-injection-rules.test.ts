/**
 * Code Injection Detection Rules Tests
 * 
 * Comprehensive test suite for code injection detection rules based on real-world
 * attack scenarios and AI-generated code patterns. These tests ensure the rules
 * can detect dangerous code injection vulnerabilities while avoiding false positives.
 */

import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { 
  CODE_INJECTION_RULES, 
  registerCodeInjectionRules,
  EVAL_USAGE_RULE,
  INNERHTML_ASSIGNMENT_RULE,
  CHILD_PROCESS_EXEC_RULE,
  DOCUMENT_WRITE_RULE,
  FUNCTION_CONSTRUCTOR_RULE,
  SETTIMEOUT_STRING_RULE,
  SCRIPT_TAG_INJECTION_RULE
} from '../../rules/definitions/code-injection-rules';
import { DetectionRule, IssueSeverity, SecurityCategory } from '../../types';

suite('Code Injection Detection Rules Tests', () => {
  let ruleEngine: RuleEngine;

  setup(() => {
    ruleEngine = new RuleEngine();
    registerCodeInjectionRules(ruleEngine);
  });

  teardown(() => {
    ruleEngine.clearRules();
  });

  suite('eval() Function Detection', () => {
    test('should detect dangerous eval() usage', () => {
      const testCases = [
        {
          name: 'Basic eval usage',
          code: 'eval("alert(\'hello\')");',
          shouldDetect: true
        },
        {
          name: 'eval with user input',
          code: 'eval(userInput);',
          shouldDetect: true
        },
        {
          name: 'eval in function',
          code: 'function dangerous() { eval(code); }',
          shouldDetect: true
        },
        {
          name: 'eval with variable',
          code: 'const result = eval(dynamicCode);',
          shouldDetect: true
        },
        {
          name: 'eval with spacing',
          code: 'eval (someCode)',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const evalIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_EVAL');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(evalIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(evalIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(evalIssues[0].message.includes('eval'));
          assert.ok(evalIssues[0].message.includes('极度危险'));
        } else {
          assert.strictEqual(evalIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for eval() usage', () => {
      const code = 'eval("console.log(\'test\')");';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const evalIssue = issues.find(issue => issue.code === 'CODE_INJECTION_EVAL');

      assert.ok(evalIssue);
      assert.ok(evalIssue.quickFix);
      assert.ok(evalIssue.quickFix.replacement.includes('JSON.parse'));
      assert.ok(evalIssue.quickFix.title.includes('安全替代'));
    });

    test('should ignore whitelisted eval patterns', () => {
      const whitelistedCases = [
        '// This is dangerous: eval(userInput)',
        '/* Never use eval() in production */',
        'console.log("eval is dangerous");',
        'const warning = "Don\'t use eval()";'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const evalIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_EVAL');
        assert.strictEqual(evalIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('innerHTML Assignment Detection', () => {
    test('should detect dangerous innerHTML assignments', () => {
      const testCases = [
        {
          name: 'innerHTML with user input',
          code: 'element.innerHTML = userInput;',
          shouldDetect: true
        },
        {
          name: 'innerHTML with form data',
          code: 'div.innerHTML = formData.content;',
          shouldDetect: true
        },
        {
          name: 'innerHTML with request parameter',
          code: 'container.innerHTML = request.body.html;',
          shouldDetect: true
        },
        {
          name: 'innerHTML with query parameter',
          code: 'element.innerHTML = queryParams.message;',
          shouldDetect: true
        },
        {
          name: 'innerHTML with concatenation',
          code: 'div.innerHTML = "<p>" + userInput + "</p>";',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const innerHTMLIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_INNERHTML');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(innerHTMLIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(innerHTMLIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(innerHTMLIssues[0].message.includes('XSS'));
          assert.ok(innerHTMLIssues[0].message.includes('innerHTML'));
        } else {
          assert.strictEqual(innerHTMLIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for innerHTML assignments', () => {
      const code = 'element.innerHTML = userInput;';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const innerHTMLIssue = issues.find(issue => issue.code === 'CODE_INJECTION_INNERHTML');

      assert.ok(innerHTMLIssue);
      assert.ok(innerHTMLIssue.quickFix);
      assert.ok(innerHTMLIssue.quickFix.replacement.includes('textContent'));
      assert.ok(innerHTMLIssue.quickFix.title.includes('安全'));
    });

    test('should ignore safe innerHTML patterns', () => {
      const safePatterns = [
        'element.innerHTML = "<p>Static content</p>";',
        'div.innerHTML = `<span>Safe template</span>`;',
        'container.innerHTML = "";',
        '// element.innerHTML = userInput;',
        '/* element.innerHTML = dangerous */'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const innerHTMLIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_INNERHTML');
        assert.strictEqual(innerHTMLIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('child_process.exec Command Injection Detection', () => {
    test('should detect command injection in child_process.exec', () => {
      const testCases = [
        {
          name: 'exec with user input',
          code: 'exec("ls " + userInput);',
          shouldDetect: true
        },
        {
          name: 'exec with form parameter',
          code: 'child_process.exec(`rm ${formData.filename}`);',
          shouldDetect: true
        },
        {
          name: 'exec with request body',
          code: 'exec("cat " + request.body.file);',
          shouldDetect: true
        },
        {
          name: 'exec with query parameter',
          code: 'child_process.exec("echo " + queryParams.message);',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const execIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_CHILD_PROCESS');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(execIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(execIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(execIssues[0].message.includes('命令注入'));
          assert.ok(execIssues[0].message.includes('系统命令'));
        } else {
          assert.strictEqual(execIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for command injection', () => {
      const code = 'exec("ls " + userInput);';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const execIssue = issues.find(issue => issue.code === 'CODE_INJECTION_CHILD_PROCESS');

      assert.ok(execIssue);
      assert.ok(execIssue.quickFix);
      assert.ok(execIssue.quickFix.replacement.includes('execFile'));
      assert.ok(execIssue.quickFix.title.includes('参数化'));
    });

    test('should ignore safe exec patterns', () => {
      const safePatterns = [
        'exec("ls -la");',
        'child_process.exec("pwd");',
        '// exec("dangerous " + userInput);',
        'require("child_process");',
        'console.log("exec command");'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const execIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_CHILD_PROCESS');
        assert.strictEqual(execIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('document.write() Detection', () => {
    test('should detect document.write() usage', () => {
      const testCases = [
        {
          name: 'Basic document.write',
          code: 'document.write("<p>Hello</p>");',
          shouldDetect: true
        },
        {
          name: 'document.write with variable',
          code: 'document.write(content);',
          shouldDetect: true
        },
        {
          name: 'document.write with spacing',
          code: 'document.write ("<script>alert(1)</script>");',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const writeIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_DOCUMENT_WRITE');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(writeIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(writeIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(writeIssues[0].message.includes('document.write'));
          assert.ok(writeIssues[0].message.includes('XSS'));
        } else {
          assert.strictEqual(writeIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for document.write', () => {
      const code = 'document.write("<p>Content</p>");';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const writeIssue = issues.find(issue => issue.code === 'CODE_INJECTION_DOCUMENT_WRITE');

      assert.ok(writeIssue);
      assert.ok(writeIssue.quickFix);
      assert.ok(writeIssue.quickFix.replacement.includes('DOM'));
      assert.ok(writeIssue.quickFix.title.includes('现代'));
    });

    test('should ignore whitelisted document.write patterns', () => {
      const whitelistedCases = [
        '// document.write is deprecated',
        '/* document.write("<p>test</p>") */',
        'console.log("document.write");'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const writeIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_DOCUMENT_WRITE');
        assert.strictEqual(writeIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('Function Constructor Detection', () => {
    test('should detect Function constructor usage', () => {
      const testCases = [
        {
          name: 'Basic Function constructor',
          code: 'new Function("return 1 + 1");',
          shouldDetect: true
        },
        {
          name: 'Function constructor with parameters',
          code: 'new Function("a", "b", "return a + b");',
          shouldDetect: true
        },
        {
          name: 'Function constructor with spacing',
          code: 'new Function ("alert(1)");',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const functionIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_FUNCTION_CONSTRUCTOR');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(functionIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(functionIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(functionIssues[0].message.includes('Function'));
          assert.ok(functionIssues[0].message.includes('代码注入'));
        } else {
          assert.strictEqual(functionIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for Function constructor', () => {
      const code = 'new Function("return 42");';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const functionIssue = issues.find(issue => issue.code === 'CODE_INJECTION_FUNCTION_CONSTRUCTOR');

      assert.ok(functionIssue);
      assert.ok(functionIssue.quickFix);
      assert.ok(functionIssue.quickFix.replacement.includes('验证'));
      assert.ok(functionIssue.quickFix.title.includes('验证'));
    });

    test('should ignore whitelisted Function patterns', () => {
      const whitelistedCases = [
        '// new Function("code")',
        '/* new Function() is dangerous */',
        'console.log("Function constructor");'
      ];

      whitelistedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const functionIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_FUNCTION_CONSTRUCTOR');
        assert.strictEqual(functionIssues.length, 0, `Should ignore: ${code}`);
      });
    });
  });

  suite('setTimeout/setInterval String Detection', () => {
    test('should detect setTimeout with string containing user input', () => {
      const testCases = [
        {
          name: 'setTimeout with user input',
          code: 'setTimeout("alert(\'" + userInput + "\')", 1000);',
          shouldDetect: true
        },
        {
          name: 'setInterval with form data',
          code: 'setInterval("console.log(\'" + formData.message + "\')", 500);',
          shouldDetect: true
        },
        {
          name: 'setTimeout with request parameter',
          code: 'setTimeout(`eval("${requestParam}")`, 100);',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        const timeoutIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_SETTIMEOUT_STRING');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(timeoutIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(timeoutIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(timeoutIssues[0].message.includes('setTimeout'));
          assert.ok(timeoutIssues[0].message.includes('代码注入'));
        } else {
          assert.strictEqual(timeoutIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for setTimeout string', () => {
      const code = 'setTimeout("alert(\'" + userInput + "\')", 1000);';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const timeoutIssue = issues.find(issue => issue.code === 'CODE_INJECTION_SETTIMEOUT_STRING');

      assert.ok(timeoutIssue);
      assert.ok(timeoutIssue.quickFix);
      assert.ok(timeoutIssue.quickFix.replacement.includes('函数'));
      assert.ok(timeoutIssue.quickFix.title.includes('函数'));
    });

    test('should ignore safe setTimeout patterns', () => {
      const safePatterns = [
        'setTimeout(() => { console.log("safe"); }, 1000);',
        'setTimeout("console.log(\'static\')", 1000);',
        '// setTimeout("dangerous " + userInput, 1000);'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        const timeoutIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_SETTIMEOUT_STRING');
        assert.strictEqual(timeoutIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Script Tag Injection Detection', () => {
    test('should detect script tag injection', () => {
      const testCases = [
        {
          name: 'Script tag with user input',
          code: '<script>alert(userInput);</script>',
          shouldDetect: true
        },
        {
          name: 'Script tag with form data',
          code: '<script>console.log(formData.message);</script>',
          shouldDetect: true
        },
        {
          name: 'Script tag with request parameter',
          code: '<script>eval(requestParam);</script>',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'html');
        const scriptIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_SCRIPT_TAG');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(scriptIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(scriptIssues[0].severity, IssueSeverity.ERROR);
          assert.ok(scriptIssues[0].message.includes('script'));
          assert.ok(scriptIssues[0].message.includes('XSS'));
        } else {
          assert.strictEqual(scriptIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide quick fix for script tag injection', () => {
      const code = '<script>alert(userInput);</script>';
      const issues = ruleEngine.executeRules(code, 'html');
      const scriptIssue = issues.find(issue => issue.code === 'CODE_INJECTION_SCRIPT_TAG');

      assert.ok(scriptIssue);
      assert.ok(scriptIssue.quickFix);
      assert.ok(scriptIssue.quickFix.replacement.includes('<!--'));
      assert.ok(scriptIssue.quickFix.title.includes('移除'));
    });

    test('should ignore commented script tags', () => {
      const commentedCases = [
        '<!-- <script>alert(userInput);</script> -->',
        '// <script>dangerous</script>',
        '/* <script>code</script> */'
      ];

      commentedCases.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'html');
        const scriptIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_SCRIPT_TAG');
        assert.strictEqual(scriptIssues.length, 0, `Should ignore commented: ${code}`);
      });
    });
  });

  suite('Real-World Attack Scenarios', () => {
    test('should detect XSS in AI-generated form handling code', () => {
      const xssCode = `
        function handleFormSubmit(event) {
          const userMessage = event.target.message.value;
          const output = document.getElementById('output');
          
          // Dangerous: Direct innerHTML assignment with user input
          output.innerHTML = '<p>You said: ' + userMessage + '</p>';
        }
      `;

      const issues = ruleEngine.executeRules(xssCode, 'javascript');
      const xssIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_INNERHTML');
      
      assert.strictEqual(xssIssues.length, 1);
      assert.ok(xssIssues[0].message.includes('XSS'));
    });

    test('should detect command injection in file processing code', () => {
      const cmdInjectionCode = `
        const { exec } = require('child_process');
        
        function processFile(filename) {
          // Dangerous: User input directly in command
          exec('convert ' + filename + ' output.jpg', (error, stdout, stderr) => {
            if (error) {
              console.error('Error:', error);
              return;
            }
            console.log('File processed successfully');
          });
        }
      `;

      const issues = ruleEngine.executeRules(cmdInjectionCode, 'javascript');
      const cmdIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_CHILD_PROCESS');
      
      assert.strictEqual(cmdIssues.length, 1);
      assert.ok(cmdIssues[0].message.includes('命令注入'));
    });

    test('should detect eval injection in calculator code', () => {
      const evalCode = `
        function calculate(expression) {
          try {
            // Extremely dangerous: eval with user input
            const result = eval(expression);
            return result;
          } catch (error) {
            return 'Error in calculation';
          }
        }
        
        // Usage: calculate(userInput) - can execute any JavaScript!
      `;

      const issues = ruleEngine.executeRules(evalCode, 'javascript');
      const evalIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_EVAL');
      
      assert.strictEqual(evalIssues.length, 1);
      assert.ok(evalIssues[0].message.includes('极度危险'));
    });

    test('should detect multiple injection types in complex code', () => {
      const complexCode = `
        function dangerousHandler(userInput, filename, htmlContent) {
          // Multiple injection vulnerabilities
          eval('var result = ' + userInput);
          exec('rm ' + filename);
          document.getElementById('content').innerHTML = htmlContent;
          document.write('<script>alert("' + userInput + '")</script>');
          setTimeout('console.log("' + userInput + '")', 1000);
        }
      `;

      const issues = ruleEngine.executeRules(complexCode, 'javascript');
      
      // Should detect multiple different injection types
      const evalIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_EVAL');
      const execIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_CHILD_PROCESS');
      const innerHTMLIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_INNERHTML');
      const writeIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_DOCUMENT_WRITE');
      const timeoutIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_SETTIMEOUT_STRING');
      
      assert.strictEqual(evalIssues.length, 1);
      assert.strictEqual(execIssues.length, 1);
      assert.strictEqual(innerHTMLIssues.length, 1);
      assert.strictEqual(writeIssues.length, 1);
      assert.strictEqual(timeoutIssues.length, 1);
      
      // All should have appropriate severity
      evalIssues.forEach(issue => assert.strictEqual(issue.severity, IssueSeverity.ERROR));
      execIssues.forEach(issue => assert.strictEqual(issue.severity, IssueSeverity.ERROR));
      innerHTMLIssues.forEach(issue => assert.strictEqual(issue.severity, IssueSeverity.ERROR));
      writeIssues.forEach(issue => assert.strictEqual(issue.severity, IssueSeverity.WARNING));
      timeoutIssues.forEach(issue => assert.strictEqual(issue.severity, IssueSeverity.WARNING));
    });

    test('should detect DOM-based XSS in URL parameter handling', () => {
      const domXssCode = `
        function displayWelcomeMessage() {
          const urlParams = new URLSearchParams(window.location.search);
          const userName = urlParams.get('name');
          
          // Dangerous: Direct DOM manipulation with URL parameter
          document.getElementById('welcome').innerHTML = 
            '<h1>Welcome, ' + userName + '!</h1>';
        }
      `;

      const issues = ruleEngine.executeRules(domXssCode, 'javascript');
      const domXssIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_INNERHTML');
      
      assert.strictEqual(domXssIssues.length, 1);
      assert.ok(domXssIssues[0].message.includes('XSS'));
    });

    test('should detect server-side template injection patterns', () => {
      const templateCode = `
        function renderTemplate(userTemplate) {
          // Dangerous: Dynamic template evaluation
          const template = new Function('data', 'return "' + userTemplate + '"');
          return template({ user: 'admin' });
        }
      `;

      const issues = ruleEngine.executeRules(templateCode, 'javascript');
      const templateIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_FUNCTION_CONSTRUCTOR');
      
      assert.strictEqual(templateIssues.length, 1);
      assert.ok(templateIssues[0].message.includes('代码注入'));
    });
  });

  suite('False Positive Prevention', () => {
    test('should ignore safe coding patterns', () => {
      const safeCodes = [
        // Safe DOM manipulation
        'element.textContent = userInput;',
        'element.setAttribute("data-value", userInput);',
        
        // Safe command execution
        'execFile("convert", [filename, "output.jpg"]);',
        'spawn("ls", ["-la", directory]);',
        
        // Safe function usage
        'setTimeout(() => { console.log("safe"); }, 1000);',
        'setInterval(function() { update(); }, 500);',
        
        // Safe HTML generation
        'element.innerHTML = "<p>Static content</p>";',
        'document.write("<script src=\\"safe.js\\"></script>");',
        
        // Comments and documentation
        '// Never use eval() with user input',
        '/* innerHTML can be dangerous with user data */',
        '# Avoid: exec("rm " + userFile)',
        
        // Safe JSON parsing
        'JSON.parse(jsonString);',
        'JSON.stringify(data);'
      ];

      safeCodes.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore safe code: ${code}`);
      });
    });

    test('should ignore test and example code patterns', () => {
      const testPatterns = [
        'eval("1 + 1"); // test case',
        'element.innerHTML = testData;',
        'exec("echo test");',
        'document.write("<!-- test -->");'
      ];

      testPatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        // Should either ignore or have reduced severity for test patterns
        const errorIssues = issues.filter(issue => issue.severity === IssueSeverity.ERROR);
        assert.ok(errorIssues.length <= 1, `Should have minimal errors for test code: ${code}`);
      });
    });

    test('should ignore logging and debugging code', () => {
      const debugCodes = [
        'console.log("eval result:", result);',
        'console.error("innerHTML error");',
        'logger.debug("exec command completed");'
      ];

      debugCodes.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'javascript');
        assert.strictEqual(issues.length, 0, `Should ignore debug code: ${code}`);
      });
    });
  });

  suite('Quick Fix Quality', () => {
    test('should provide actionable quick fixes for all injection types', () => {
      const testCases = [
        {
          code: 'eval(userCode);',
          expectedFixKeywords: ['JSON.parse', 'Function']
        },
        {
          code: 'element.innerHTML = userInput;',
          expectedFixKeywords: ['textContent', 'DOMPurify']
        },
        {
          code: 'exec("rm " + filename);',
          expectedFixKeywords: ['execFile', 'spawn']
        },
        {
          code: 'document.write(content);',
          expectedFixKeywords: ['createElement', 'appendChild']
        },
        {
          code: 'new Function(userCode);',
          expectedFixKeywords: ['验证', '清理']
        },
        {
          code: 'setTimeout("alert(\'" + userInput + "\')", 1000);',
          expectedFixKeywords: ['函数', '() =>']
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'javascript');
        assert.ok(issues.length > 0, `Should detect issue in: ${testCase.code}`);
        
        const issue = issues[0];
        assert.ok(issue.quickFix, 'Should have quick fix');
        
        // Check that fix contains expected keywords
        const fixText = issue.quickFix.replacement + ' ' + issue.quickFix.description;
        const hasExpectedKeywords = testCase.expectedFixKeywords.some(keyword => 
          fixText.includes(keyword)
        );
        assert.ok(hasExpectedKeywords, 
          `Quick fix should contain one of: ${testCase.expectedFixKeywords.join(', ')}`);
      });
    });

    test('should provide educational quick fixes', () => {
      const code = 'eval(dynamicCode);';
      const issues = ruleEngine.executeRules(code, 'javascript');
      const evalIssue = issues.find(issue => issue.code === 'CODE_INJECTION_EVAL');

      assert.ok(evalIssue);
      assert.ok(evalIssue.quickFix);
      
      // Should explain why it's dangerous and provide alternatives
      assert.ok(evalIssue.quickFix.description.includes('JSON.parse'));
      assert.ok(evalIssue.quickFix.replacement.includes('危险'));
    });
  });

  suite('Rule Registration and Management', () => {
    test('should register all code injection rules successfully', () => {
      const freshEngine = new RuleEngine();
      registerCodeInjectionRules(freshEngine);

      const stats = freshEngine.getStatistics();
      assert.strictEqual(stats.totalRules, CODE_INJECTION_RULES.length);
      assert.strictEqual(stats.enabledRules, CODE_INJECTION_RULES.length);
      
      // Check that all rules are in the CODE_INJECTION category
      assert.strictEqual(stats.rulesByCategory[SecurityCategory.CODE_INJECTION], CODE_INJECTION_RULES.length);
    });

    test('should handle rule registration errors gracefully', () => {
      const mockEngine = {
        registerRule: (rule: DetectionRule) => {
          if (rule.id === 'CODE_INJECTION_EVAL') {
            throw new Error('Mock registration error');
          }
        }
      };

      // Should not throw, but log error
      assert.doesNotThrow(() => {
        registerCodeInjectionRules(mockEngine);
      });
    });

    test('should retrieve rules by category', () => {
      const codeInjectionRules = ruleEngine.getRulesByCategory(SecurityCategory.CODE_INJECTION);
      assert.strictEqual(codeInjectionRules.length, CODE_INJECTION_RULES.length);
      
      codeInjectionRules.forEach(rule => {
        assert.strictEqual(rule.category, SecurityCategory.CODE_INJECTION);
        assert.strictEqual(rule.enabled, true);
      });
    });
  });

  suite('Multi-language Support', () => {
    test('should detect code injection in different programming languages', () => {
      const languageTests = [
        {
          language: 'javascript',
          code: 'eval(userInput);'
        },
        {
          language: 'typescript',
          code: 'element.innerHTML = userContent;'
        },
        {
          language: 'html',
          code: '<script>alert(userInput);</script>'
        }
      ];

      languageTests.forEach(test => {
        const issues = ruleEngine.executeRules(test.code, test.language);
        assert.ok(issues.length > 0, `Should detect injection in ${test.language}`);
        
        const injectionIssues = issues.filter(issue => 
          issue.category === SecurityCategory.CODE_INJECTION
        );
        assert.ok(injectionIssues.length > 0, `Should detect code injection in ${test.language}`);
      });
    });
  });

  suite('Performance and Edge Cases', () => {
    test('should handle large code blocks efficiently', () => {
      const largeCode = 'const safe = "normal code";\n'.repeat(1000) + 
                      'eval(userInput);' + 
                      '\nconst moreSafe = "more normal code";\n'.repeat(1000);

      const startTime = Date.now();
      const issues = ruleEngine.executeRules(largeCode, 'javascript');
      const duration = Date.now() - startTime;

      // Should complete within reasonable time (less than 1 second)
      assert.ok(duration < 1000, 'Should analyze large code quickly');
      
      // Should still detect the injection
      const evalIssues = issues.filter(issue => issue.code === 'CODE_INJECTION_EVAL');
      assert.strictEqual(evalIssues.length, 1);
    });

    test('should handle edge cases and malformed code', () => {
      const edgeCases = [
        'eval(',  // Incomplete
        'eval();', // Empty
        'eval(;', // Malformed
        'innerHTML =', // Incomplete
        '<script>', // Unclosed tag
        'exec(', // Incomplete command
      ];

      edgeCases.forEach(code => {
        // Should not throw errors on malformed code
        assert.doesNotThrow(() => {
          const issues = ruleEngine.executeRules(code, 'javascript');
          // May or may not detect issues, but should not crash
        }, `Should handle edge case: ${code}`);
      });
    });
  });
});
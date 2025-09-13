/**
 * Framework-Specific Risk Detection Rules Tests
 * 
 * Comprehensive test suite for framework-specific security risk detection rules.
 * These tests cover React, Vue, and Angular specific vulnerabilities based on
 * real-world framework code patterns and AI-generated code scenarios.
 */

import * as assert from 'assert';
import { RuleEngine } from '../../rules/RuleEngine';
import { 
  FRAMEWORK_RISK_RULES, 
  registerFrameworkRiskRules,
  REACT_DANGEROUS_INNERHTML_RULE,
  VUE_V_HTML_RULE,
  REACT_USEEFFECT_INFINITE_LOOP_RULE,
  ANGULAR_BYPASS_SECURITY_RULE,
  REACT_PROPS_XSS_RULE,
  VUE_TEMPLATE_INJECTION_RULE,
  ANGULAR_TEMPLATE_INJECTION_RULE
} from '../../rules/definitions/framework-rules';
import { DetectionRule, IssueSeverity, SecurityCategory } from '../../types';

suite('Framework Risk Detection Rules Tests', () => {
  let ruleEngine: RuleEngine;

  setup(() => {
    ruleEngine = new RuleEngine();
    registerFrameworkRiskRules(ruleEngine);
  });

  teardown(() => {
    ruleEngine.clearRules();
  });

  suite('React dangerouslySetInnerHTML Detection', () => {
    test('should detect dangerous dangerouslySetInnerHTML usage with user data', () => {
      const testCases = [
        {
          name: 'dangerouslySetInnerHTML with props',
          code: '<div dangerouslySetInnerHTML={{ __html: props.content }} />',
          shouldDetect: true
        },
        {
          name: 'dangerouslySetInnerHTML with state',
          code: '<span dangerouslySetInnerHTML={{ __html: state.htmlContent }} />',
          shouldDetect: true
        },
        {
          name: 'dangerouslySetInnerHTML with user input',
          code: '<p dangerouslySetInnerHTML={{ __html: userInput }} />',
          shouldDetect: true
        },
        {
          name: 'dangerouslySetInnerHTML with form data',
          code: '<div dangerouslySetInnerHTML={{ __html: formData.message }} />',
          shouldDetect: true
        },
        {
          name: 'dangerouslySetInnerHTML with request data',
          code: '<article dangerouslySetInnerHTML={{ __html: request.body.content }} />',
          shouldDetect: true
        },
        {
          name: 'dangerouslySetInnerHTML with query params',
          code: '<section dangerouslySetInnerHTML={{ __html: queryParams.html }} />',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'jsx');
        const dangerousIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(dangerousIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(dangerousIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(dangerousIssues[0].message.includes('React XSS'));
          assert.ok(dangerousIssues[0].message.includes('dangerouslySetInnerHTML'));
        } else {
          assert.strictEqual(dangerousIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide DOMPurify quick fix for dangerouslySetInnerHTML', () => {
      const code = '<div dangerouslySetInnerHTML={{ __html: props.content }} />';
      const issues = ruleEngine.executeRules(code, 'jsx');
      const dangerousIssue = issues.find(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');

      assert.ok(dangerousIssue);
      assert.ok(dangerousIssue.quickFix);
      assert.ok(dangerousIssue.quickFix.replacement.includes('DOMPurify.sanitize'));
      assert.ok(dangerousIssue.quickFix.title.includes('DOMPurify'));
    });

    test('should ignore safe dangerouslySetInnerHTML patterns', () => {
      const safePatterns = [
        '<div dangerouslySetInnerHTML={{ __html: "<p>Static content</p>" }} />',
        '<span dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
        '<p dangerouslySetInnerHTML={{ __html: sanitizeHtml(userInput) }} />',
        '// <div dangerouslySetInnerHTML={{ __html: props.content }} />',
        '/* dangerouslySetInnerHTML with user data is dangerous */'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const dangerousIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');
        assert.strictEqual(dangerousIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Vue v-html Directive Detection', () => {
    test('should detect dangerous v-html usage with user data', () => {
      const testCases = [
        {
          name: 'v-html with user input',
          code: '<div v-html="userInput"></div>',
          shouldDetect: true
        },
        {
          name: 'v-html with form data',
          code: '<p v-html="formData.content"></p>',
          shouldDetect: true
        },
        {
          name: 'v-html with props',
          code: '<span v-html="props.htmlContent"></span>',
          shouldDetect: true
        },
        {
          name: 'v-html with $data',
          code: '<article v-html="$data.content"></article>',
          shouldDetect: true
        },
        {
          name: 'v-html with request parameter',
          code: '<section v-html="request.body.html"></section>',
          shouldDetect: true
        },
        {
          name: 'v-html with query parameter',
          code: '<div v-html="queryParams.message"></div>',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'vue');
        const vHtmlIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_V_HTML');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(vHtmlIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(vHtmlIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(vHtmlIssues[0].message.includes('Vue XSS'));
          assert.ok(vHtmlIssues[0].message.includes('v-html'));
        } else {
          assert.strictEqual(vHtmlIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide v-text quick fix for v-html', () => {
      const code = '<div v-html="userInput"></div>';
      const issues = ruleEngine.executeRules(code, 'vue');
      const vHtmlIssue = issues.find(issue => issue.code === 'FRAMEWORK_VUE_V_HTML');

      assert.ok(vHtmlIssue);
      assert.ok(vHtmlIssue.quickFix);
      assert.ok(vHtmlIssue.quickFix.replacement.includes('v-text'));
      assert.ok(vHtmlIssue.quickFix.title.includes('v-text'));
    });

    test('should ignore safe v-html patterns', () => {
      const safePatterns = [
        '<div v-html="staticContent"></div>',
        '<p v-html="sanitize(userInput)"></p>',
        '<span v-html="DOMPurify.sanitize(content)"></span>',
        '<!-- <div v-html="userInput"></div> -->',
        '// v-html can be dangerous'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'vue');
        const vHtmlIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_V_HTML');
        assert.strictEqual(vHtmlIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('React useEffect Infinite Loop Detection', () => {
    test('should detect potential infinite loops in useEffect', () => {
      const testCases = [
        {
          name: 'useEffect with setState and empty deps',
          code: 'useEffect(() => { setState(newValue); }, []);',
          shouldDetect: true
        },
        {
          name: 'useEffect with setCount and empty deps',
          code: 'useEffect(() => { setCount(count + 1); }, []);',
          shouldDetect: true
        },
        {
          name: 'useEffect with dispatch and empty deps',
          code: 'useEffect(() => { dispatch(action); }, []);',
          shouldDetect: true
        },
        {
          name: 'useEffect with multiple state updates',
          code: 'useEffect(() => { setName("test"); setAge(25); }, []);',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'jsx');
        const loopIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_USEEFFECT_LOOP');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(loopIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(loopIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(loopIssues[0].message.includes('useEffect'));
          assert.ok(loopIssues[0].message.includes('无限循环'));
        } else {
          assert.strictEqual(loopIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide dependency array quick fix for useEffect', () => {
      const code = 'useEffect(() => { setState(newValue); }, []);';
      const issues = ruleEngine.executeRules(code, 'jsx');
      const loopIssue = issues.find(issue => issue.code === 'FRAMEWORK_REACT_USEEFFECT_LOOP');

      assert.ok(loopIssue);
      assert.ok(loopIssue.quickFix);
      assert.ok(loopIssue.quickFix.replacement.includes('依赖数组'));
      assert.ok(loopIssue.quickFix.title.includes('依赖项'));
    });

    test('should ignore safe useEffect patterns', () => {
      const safePatterns = [
        'useEffect(() => { fetchData(); }, [id]);',
        'useEffect(() => { setState(value); }, [value]);',
        'useEffect(() => { console.log("mounted"); }, []); // once',
        '// useEffect(() => { setState(x); }, []);',
        'useEffect(() => { /* setup */ }, []); /* run once */'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const loopIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_USEEFFECT_LOOP');
        assert.strictEqual(loopIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Angular bypassSecurityTrust* Detection', () => {
    test('should detect dangerous bypassSecurityTrust* usage with user data', () => {
      const testCases = [
        {
          name: 'bypassSecurityTrustHtml with user input',
          code: 'this.sanitizer.bypassSecurityTrustHtml(userInput)',
          shouldDetect: true
        },
        {
          name: 'bypassSecurityTrustScript with form data',
          code: 'bypassSecurityTrustScript(formData.script)',
          shouldDetect: true
        },
        {
          name: 'bypassSecurityTrustUrl with request parameter',
          code: 'this.sanitizer.bypassSecurityTrustUrl(request.query.url)',
          shouldDetect: true
        },
        {
          name: 'bypassSecurityTrustResourceUrl with user data',
          code: 'bypassSecurityTrustResourceUrl(userData.resourceUrl)',
          shouldDetect: true
        },
        {
          name: 'bypassSecurityTrustStyle with input',
          code: 'this.sanitizer.bypassSecurityTrustStyle(inputData.css)',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'typescript');
        const bypassIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_BYPASS_SECURITY');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(bypassIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(bypassIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(bypassIssues[0].message.includes('Angular 安全风险'));
          assert.ok(bypassIssues[0].message.includes('绕过安全'));
        } else {
          assert.strictEqual(bypassIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide sanitization quick fix for bypassSecurityTrust*', () => {
      const code = 'this.sanitizer.bypassSecurityTrustHtml(userInput)';
      const issues = ruleEngine.executeRules(code, 'typescript');
      const bypassIssue = issues.find(issue => issue.code === 'FRAMEWORK_ANGULAR_BYPASS_SECURITY');

      assert.ok(bypassIssue);
      assert.ok(bypassIssue.quickFix);
      assert.ok(bypassIssue.quickFix.replacement.includes('DOMPurify'));
      assert.ok(bypassIssue.quickFix.title.includes('清理'));
    });

    test('should ignore safe bypassSecurityTrust* patterns', () => {
      const safePatterns = [
        'bypassSecurityTrustHtml("<p>Static content</p>")',
        'this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(content))',
        'bypassSecurityTrustUrl("https://trusted-domain.com")',
        '// bypassSecurityTrustHtml(userInput)',
        '/* bypassSecurityTrust* methods are dangerous */'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'typescript');
        const bypassIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_BYPASS_SECURITY');
        assert.strictEqual(bypassIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('React Props XSS Detection', () => {
    test('should detect dangerous prop usage in href/src attributes', () => {
      const testCases = [
        {
          name: 'href with props',
          code: '<a href={props.url}>Link</a>',
          shouldDetect: true
        },
        {
          name: 'src with user input',
          code: '<img src={userInput} alt="image" />',
          shouldDetect: true
        },
        {
          name: 'action with form data',
          code: '<form action={formData.submitUrl}>',
          shouldDetect: true
        },
        {
          name: 'formAction with request parameter',
          code: '<button formAction={request.body.action}>Submit</button>',
          shouldDetect: true
        },
        {
          name: 'href with state',
          code: '<a href={state.redirectUrl}>Go</a>',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'jsx');
        const xssIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_PROPS_XSS');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(xssIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(xssIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(xssIssues[0].message.includes('React XSS'));
          assert.ok(xssIssues[0].message.includes('href') || xssIssues[0].message.includes('src'));
        } else {
          assert.strictEqual(xssIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide URL validation quick fix for props XSS', () => {
      const code = '<a href={props.url}>Link</a>';
      const issues = ruleEngine.executeRules(code, 'jsx');
      const xssIssue = issues.find(issue => issue.code === 'FRAMEWORK_REACT_PROPS_XSS');

      assert.ok(xssIssue);
      assert.ok(xssIssue.quickFix);
      assert.ok(xssIssue.quickFix.replacement.includes('验证'));
      assert.ok(xssIssue.quickFix.title.includes('验证'));
    });

    test('should ignore safe prop patterns', () => {
      const safePatterns = [
        '<a href="/static/page">Link</a>',
        '<img src="#placeholder" alt="image" />',
        '<a href="mailto:test@example.com">Email</a>',
        '{/* <a href={props.url}>Link</a> */}',
        '// href with user data can be dangerous'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const xssIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_PROPS_XSS');
        assert.strictEqual(xssIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Vue Template Injection Detection', () => {
    test('should detect potential template injection in Vue templates', () => {
      const testCases = [
        {
          name: 'template interpolation with user input',
          code: '{{ userInput }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with form data',
          code: '{{ formData.message }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with $data',
          code: '{{ $data.content }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with props',
          code: '{{ $props.htmlContent }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with request parameter',
          code: '{{ request.query.text }}',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'vue');
        const injectionIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_TEMPLATE_INJECTION');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(injectionIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(injectionIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(injectionIssues[0].message.includes('Vue 模板注入'));
          assert.ok(injectionIssues[0].message.includes('用户数据'));
        } else {
          assert.strictEqual(injectionIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide filter quick fix for template injection', () => {
      const code = '{{ userInput }}';
      const issues = ruleEngine.executeRules(code, 'vue');
      const injectionIssue = issues.find(issue => issue.code === 'FRAMEWORK_VUE_TEMPLATE_INJECTION');

      assert.ok(injectionIssue);
      assert.ok(injectionIssue.quickFix);
      assert.ok(injectionIssue.quickFix.replacement.includes('过滤器'));
      assert.ok(injectionIssue.quickFix.title.includes('过滤器'));
    });

    test('should ignore safe template patterns', () => {
      const safePatterns = [
        '{{ item.id }}',
        '{{ count }}',
        '{{ true }}',
        '{{ message | sanitize }}',
        '<!-- {{ userInput }} -->',
        '// {{ dangerous template }}'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'vue');
        const injectionIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_TEMPLATE_INJECTION');
        assert.strictEqual(injectionIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Angular Template Injection Detection', () => {
    test('should detect potential template injection in Angular templates', () => {
      const testCases = [
        {
          name: 'template interpolation with user input',
          code: '{{ userInput }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with form data',
          code: '{{ formData.content }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with request parameter',
          code: '{{ request.body.message }}',
          shouldDetect: true
        },
        {
          name: 'template interpolation with data property',
          code: '{{ data.htmlContent }}',
          shouldDetect: true
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'html');
        const injectionIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_TEMPLATE_INJECTION');
        
        if (testCase.shouldDetect) {
          assert.strictEqual(injectionIssues.length, 1, `Should detect: ${testCase.name}`);
          assert.strictEqual(injectionIssues[0].severity, IssueSeverity.WARNING);
          assert.ok(injectionIssues[0].message.includes('Angular 模板注入'));
          assert.ok(injectionIssues[0].message.includes('用户数据'));
        } else {
          assert.strictEqual(injectionIssues.length, 0, `Should not detect: ${testCase.name}`);
        }
      });
    });

    test('should provide pipe quick fix for template injection', () => {
      const code = '{{ userInput }}';
      const issues = ruleEngine.executeRules(code, 'html');
      const injectionIssue = issues.find(issue => issue.code === 'FRAMEWORK_ANGULAR_TEMPLATE_INJECTION');

      assert.ok(injectionIssue);
      assert.ok(injectionIssue.quickFix);
      assert.ok(injectionIssue.quickFix.replacement.includes('管道'));
      assert.ok(injectionIssue.quickFix.title.includes('管道'));
    });

    test('should ignore safe Angular template patterns', () => {
      const safePatterns = [
        '{{ item.id }}',
        '{{ count }}',
        '{{ false }}',
        '{{ message | sanitize }}',
        '<!-- {{ userInput }} -->',
        '// {{ dangerous template }}'
      ];

      safePatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'html');
        const injectionIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_TEMPLATE_INJECTION');
        assert.strictEqual(injectionIssues.length, 0, `Should ignore safe pattern: ${code}`);
      });
    });
  });

  suite('Real-World Framework Scenarios', () => {
    test('should detect XSS in React comment component', () => {
      const reactCode = `
        function CommentComponent({ comment }) {
          return (
            <div className="comment">
              <h4>{comment.author}</h4>
              <div dangerouslySetInnerHTML={{ __html: comment.content }} />
              <a href={comment.website}>Visit Website</a>
            </div>
          );
        }
      `;

      const issues = ruleEngine.executeRules(reactCode, 'jsx');
      const dangerousIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');
      const xssIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_PROPS_XSS');
      
      assert.strictEqual(dangerousIssues.length, 1);
      assert.strictEqual(xssIssues.length, 1);
    });

    test('should detect XSS in Vue blog post component', () => {
      const vueCode = `
        <template>
          <article>
            <h2>{{ post.title }}</h2>
            <div v-html="post.content"></div>
            <p>By: {{ post.author }}</p>
          </article>
        </template>
      `;

      const issues = ruleEngine.executeRules(vueCode, 'vue');
      const vHtmlIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_V_HTML');
      const templateIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_TEMPLATE_INJECTION');
      
      assert.strictEqual(vHtmlIssues.length, 1);
      // Should detect template injection in post.title and post.author
      assert.ok(templateIssues.length >= 1);
    });

    test('should detect security bypass in Angular content sanitizer', () => {
      const angularCode = `
        @Component({
          template: \`
            <div [innerHTML]="trustedHtml"></div>
            <p>{{ userMessage }}</p>
          \`
        })
        export class ContentComponent {
          trustedHtml: SafeHtml;
          
          constructor(private sanitizer: DomSanitizer) {}
          
          setContent(userContent: string) {
            this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userContent);
          }
        }
      `;

      const issues = ruleEngine.executeRules(angularCode, 'typescript');
      const bypassIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_BYPASS_SECURITY');
      const templateIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_TEMPLATE_INJECTION');
      
      assert.strictEqual(bypassIssues.length, 1);
      assert.ok(templateIssues.length >= 1);
    });

    test('should detect infinite loop in React data fetching', () => {
      const reactCode = `
        function UserProfile({ userId }) {
          const [user, setUser] = useState(null);
          const [loading, setLoading] = useState(false);
          
          useEffect(() => {
            setLoading(true);
            fetchUser(userId).then(userData => {
              setUser(userData);
              setLoading(false);
            });
          }, []); // Missing userId dependency!
          
          return loading ? <div>Loading...</div> : <div>{user?.name}</div>;
        }
      `;

      const issues = ruleEngine.executeRules(reactCode, 'jsx');
      const loopIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_USEEFFECT_LOOP');
      
      assert.strictEqual(loopIssues.length, 1);
    });

    test('should detect multiple framework risks in mixed code', () => {
      const mixedCode = `
        // React component with multiple issues
        function DangerousComponent({ userContent, userUrl, userScript }) {
          const [html, setHtml] = useState('');
          
          useEffect(() => {
            setHtml(userContent); // State update without dependency
          }, []);
          
          return (
            <div>
              <div dangerouslySetInnerHTML={{ __html: userContent }} />
              <a href={userUrl}>Click here</a>
              <script dangerouslySetInnerHTML={{ __html: userScript }} />
            </div>
          );
        }
      `;

      const issues = ruleEngine.executeRules(mixedCode, 'jsx');
      
      const dangerousIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');
      const xssIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_PROPS_XSS');
      const loopIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_USEEFFECT_LOOP');
      
      assert.ok(dangerousIssues.length >= 1);
      assert.ok(xssIssues.length >= 1);
      assert.strictEqual(loopIssues.length, 1);
    });
  });

  suite('AI-Generated Code Scenarios', () => {
    test('should detect XSS in ChatGPT-generated React form', () => {
      const chatGptCode = `
        // ChatGPT generated form handler
        function ContactForm() {
          const [message, setMessage] = useState('');
          const [preview, setPreview] = useState('');
          
          const handlePreview = () => {
            setPreview(message);
          };
          
          return (
            <form>
              <textarea 
                value={message} 
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter your message"
              />
              <button type="button" onClick={handlePreview}>Preview</button>
              <div dangerouslySetInnerHTML={{ __html: preview }} />
            </form>
          );
        }
      `;

      const issues = ruleEngine.executeRules(chatGptCode, 'jsx');
      const dangerousIssues = issues.filter(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');
      
      assert.strictEqual(dangerousIssues.length, 1);
      assert.ok(dangerousIssues[0].message.includes('XSS'));
    });

    test('should detect XSS in Claude-generated Vue component', () => {
      const claudeCode = `
        <!-- Claude generated user profile component -->
        <template>
          <div class="user-profile">
            <h1>{{ user.name }}</h1>
            <div class="bio" v-html="user.bio"></div>
            <div class="social-links">
              <a v-for="link in user.socialLinks" 
                 :key="link.platform" 
                 :href="link.url">
                {{ link.platform }}
              </a>
            </div>
          </div>
        </template>
      `;

      const issues = ruleEngine.executeRules(claudeCode, 'vue');
      const vHtmlIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_V_HTML');
      const templateIssues = issues.filter(issue => issue.code === 'FRAMEWORK_VUE_TEMPLATE_INJECTION');
      
      assert.strictEqual(vHtmlIssues.length, 1);
      assert.ok(templateIssues.length >= 1);
    });

    test('should detect security bypass in Copilot-generated Angular service', () => {
      const copilotCode = `
        // GitHub Copilot generated content service
        @Injectable()
        export class ContentService {
          constructor(private sanitizer: DomSanitizer) {}
          
          renderUserContent(htmlContent: string): SafeHtml {
            // Bypass security for user-generated content
            return this.sanitizer.bypassSecurityTrustHtml(htmlContent);
          }
          
          createDynamicComponent(template: string) {
            return this.sanitizer.bypassSecurityTrustHtml(template);
          }
        }
      `;

      const issues = ruleEngine.executeRules(copilotCode, 'typescript');
      const bypassIssues = issues.filter(issue => issue.code === 'FRAMEWORK_ANGULAR_BYPASS_SECURITY');
      
      assert.strictEqual(bypassIssues.length, 2);
    });
  });

  suite('False Positive Prevention', () => {
    test('should ignore safe framework patterns', () => {
      const safeCodes = [
        // Safe React patterns
        '<div>{userInput}</div>', // Text content is safe
        '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />',
        'useEffect(() => { fetchData(); }, [id]);',
        '<a href="/static/page">Link</a>',
        
        // Safe Vue patterns
        '<div>{{ userInput }}</div>', // Text interpolation is safe
        '<div v-text="userInput"></div>',
        '<div v-html="sanitizeHtml(content)"></div>',
        
        // Safe Angular patterns
        'bypassSecurityTrustHtml(DOMPurify.sanitize(content))',
        '<div [textContent]="userInput"></div>',
        '{{ item.id }}',
        
        // Comments and documentation
        '// dangerouslySetInnerHTML is dangerous',
        '/* v-html can cause XSS */',
        '<!-- {{ userInput }} -->',
        
        // Test files
        'dangerouslySetInnerHTML={{ __html: testData }}',
        'v-html="mockContent"'
      ];

      safeCodes.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const frameworkIssues = issues.filter(issue => 
          issue.category === SecurityCategory.FRAMEWORK_RISK
        );
        assert.strictEqual(frameworkIssues.length, 0, `Should ignore safe code: ${code}`);
      });
    });

    test('should ignore static content in framework directives', () => {
      const staticPatterns = [
        '<div dangerouslySetInnerHTML={{ __html: "<p>Static HTML</p>" }} />',
        '<div v-html="\'<span>Static content</span>\'"></div>',
        'bypassSecurityTrustHtml("<div>Static</div>")',
        '<a href="https://example.com">Static link</a>'
      ];

      staticPatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const frameworkIssues = issues.filter(issue => 
          issue.category === SecurityCategory.FRAMEWORK_RISK
        );
        assert.strictEqual(frameworkIssues.length, 0, `Should ignore static content: ${code}`);
      });
    });

    test('should ignore already sanitized content', () => {
      const sanitizedPatterns = [
        '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />',
        '<div v-html="sanitize(userContent)"></div>',
        'bypassSecurityTrustHtml(xss(userInput))',
        '<div dangerouslySetInnerHTML={{ __html: sanitizeHtml(content) }} />'
      ];

      sanitizedPatterns.forEach(code => {
        const issues = ruleEngine.executeRules(code, 'jsx');
        const frameworkIssues = issues.filter(issue => 
          issue.category === SecurityCategory.FRAMEWORK_RISK
        );
        assert.strictEqual(frameworkIssues.length, 0, `Should ignore sanitized content: ${code}`);
      });
    });
  });

  suite('Quick Fix Quality', () => {
    test('should provide actionable quick fixes for all framework risks', () => {
      const testCases = [
        {
          code: '<div dangerouslySetInnerHTML={{ __html: props.content }} />',
          expectedFixKeywords: ['DOMPurify', 'sanitize']
        },
        {
          code: '<div v-html="userInput"></div>',
          expectedFixKeywords: ['v-text', 'DOMPurify']
        },
        {
          code: 'useEffect(() => { setState(value); }, []);',
          expectedFixKeywords: ['依赖', '数组']
        },
        {
          code: 'bypassSecurityTrustHtml(userContent)',
          expectedFixKeywords: ['DOMPurify', '清理']
        },
        {
          code: '<a href={props.url}>Link</a>',
          expectedFixKeywords: ['验证', 'URL']
        }
      ];

      testCases.forEach(testCase => {
        const issues = ruleEngine.executeRules(testCase.code, 'jsx');
        const frameworkIssues = issues.filter(issue => 
          issue.category === SecurityCategory.FRAMEWORK_RISK
        );
        
        assert.ok(frameworkIssues.length > 0, `Should detect issue in: ${testCase.code}`);
        
        const issue = frameworkIssues[0];
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
      const code = '<div dangerouslySetInnerHTML={{ __html: props.content }} />';
      const issues = ruleEngine.executeRules(code, 'jsx');
      const dangerousIssue = issues.find(issue => issue.code === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML');

      assert.ok(dangerousIssue);
      assert.ok(dangerousIssue.quickFix);
      
      // Should explain the security risk and provide safe alternatives
      assert.ok(dangerousIssue.quickFix.description.includes('DOMPurify'));
      assert.ok(dangerousIssue.quickFix.replacement.includes('DOMPurify.sanitize'));
    });
  });

  suite('Rule Registration and Management', () => {
    test('should register all framework risk rules successfully', () => {
      const freshEngine = new RuleEngine();
      registerFrameworkRiskRules(freshEngine);

      const stats = freshEngine.getStatistics();
      assert.strictEqual(stats.totalRules, FRAMEWORK_RISK_RULES.length);
      assert.strictEqual(stats.enabledRules, FRAMEWORK_RISK_RULES.length);
      
      // Check that all rules are in the FRAMEWORK_RISK category
      assert.strictEqual(stats.rulesByCategory[SecurityCategory.FRAMEWORK_RISK], FRAMEWORK_RISK_RULES.length);
    });

    test('should handle rule registration errors gracefully', () => {
      const mockEngine = {
        registerRule: (rule: DetectionRule) => {
          if (rule.id === 'FRAMEWORK_REACT_DANGEROUS_INNERHTML') {
            throw new Error('Mock registration error');
          }
        }
      };

      // Should not throw, but log error
      assert.doesNotThrow(() => {
        registerFrameworkRiskRules(mockEngine);
      });
    });

    test('should retrieve rules by category', () => {
      const frameworkRules = ruleEngine.getRulesByCategory(SecurityCategory.FRAMEWORK_RISK);
      assert.strictEqual(frameworkRules.length, FRAMEWORK_RISK_RULES.length);
      
      frameworkRules.forEach(rule => {
        assert.strictEqual(rule.category, SecurityCategory.FRAMEWORK_RISK);
        assert.ok(rule.enabled);
      });
    });

    test('should have appropriate severity levels', () => {
      const stats = ruleEngine.getStatistics();
      
      // Most framework risks should be warnings (not errors)
      // since they often require context to determine if they're truly dangerous
      assert.ok(stats.rulesBySeverity[IssueSeverity.WARNING] >= 5);
    });

    test('should support multiple programming languages', () => {
      const allLanguages = new Set<string>();
      
      FRAMEWORK_RISK_RULES.forEach(rule => {
        rule.languages.forEach(lang => allLanguages.add(lang));
      });
      
      // Should support framework-specific languages
      assert.ok(allLanguages.has('jsx') || allLanguages.has('tsx'));
      assert.ok(allLanguages.has('vue'));
      assert.ok(allLanguages.has('typescript'));
      assert.ok(allLanguages.has('html'));
    });
  });
});
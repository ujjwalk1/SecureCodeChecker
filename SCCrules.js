 // Security patterns and rules
        const securityRules = {
            javascript: [
                {
                    pattern: /eval\s*\(/gi,
                    severity: 'high',
                    title: 'Use of eval() function',
                    description: 'The eval() function executes arbitrary JavaScript code, which can lead to code injection attacks.',
                    fix: 'Use JSON.parse() for parsing JSON, or safer alternatives like Function constructor with limited scope.'
                },
                {
                    pattern: /innerHTML\s*=.*\+|innerHTML\s*\+=|outerHTML\s*=/gi,
                    severity: 'high',
                    title: 'XSS vulnerability via innerHTML',
                    description: 'Setting innerHTML with user input can lead to Cross-Site Scripting (XSS) attacks.',
                    fix: 'Use textContent, createTextNode(), or properly sanitize input before setting innerHTML.'
                },
                {
                    pattern: /document\.write\s*\(/gi,
                    severity: 'medium',
                    title: 'Use of document.write()',
                    description: 'document.write() can be exploited for XSS attacks and affects page performance.',
                    fix: 'Use DOM manipulation methods like appendChild() or modern frameworks.'
                },
                {
                    pattern: /window\.location\s*=.*\+|location\.href\s*=.*\+/gi,
                    severity: 'high',
                    title: 'Open redirect vulnerability',
                    description: 'Directly setting location with user input can lead to open redirect attacks.',
                    fix: 'Validate and whitelist allowed redirect URLs.'
                },
                {
                    pattern: /localStorage\.setItem|sessionStorage\.setItem/gi,
                    severity: 'low',
                    title: 'Sensitive data in browser storage',
                    description: 'Storing sensitive data in localStorage/sessionStorage is accessible to XSS attacks.',
                    fix: 'Avoid storing sensitive data client-side. Use secure, httpOnly cookies for sensitive data.'
                }
            ],
            python: [
                {
                    pattern: /exec\s*\(|eval\s*\(/gi,
                    severity: 'high',
                    title: 'Code injection via exec/eval',
                    description: 'Using exec() or eval() with user input can lead to arbitrary code execution.',
                    fix: 'Use ast.literal_eval() for safe evaluation or avoid dynamic code execution.'
                },
                {
                    pattern: /subprocess\.call\(.*shell\s*=\s*True|os\.system\(/gi,
                    severity: 'high',
                    title: 'Command injection vulnerability',
                    description: 'Using shell=True or os.system() with user input can lead to command injection.',
                    fix: 'Use subprocess with shell=False and pass arguments as a list.'
                },
                {
                    pattern: /pickle\.loads?\(/gi,
                    severity: 'high',
                    title: 'Insecure deserialization',
                    description: 'pickle.load() can execute arbitrary code during deserialization.',
                    fix: 'Use json module for data serialization or implement secure deserialization.'
                },
                {
                    pattern: /random\.random\(\)|random\.choice\(/gi,
                    severity: 'medium',
                    title: 'Weak random number generation',
                    description: 'The random module is not cryptographically secure.',
                    fix: 'Use secrets module for cryptographic operations: secrets.choice(), secrets.token_hex().'
                },
                {
                    pattern: /password\s*=\s*['"][^'"]+['"]|secret\s*=\s*['"][^'"]+['"]/gi,
                    severity: 'high',
                    title: 'Hardcoded credentials',
                    description: 'Hardcoded passwords and secrets in source code are security risks.',
                    fix: 'Use environment variables, configuration files, or secure credential management.'
                }
            ],
            java: [
                {
                    pattern: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder.*\.start\(\)/gi,
                    severity: 'high',
                    title: 'Command injection risk',
                    description: 'Executing system commands with user input can lead to command injection.',
                    fix: 'Validate and sanitize input, use ProcessBuilder with separate arguments.'
                },
                {
                    pattern: /MessageDigest\.getInstance\s*\(\s*["']MD5["']|MessageDigest\.getInstance\s*\(\s*["']SHA1["']/gi,
                    severity: 'medium',
                    title: 'Weak cryptographic algorithm',
                    description: 'MD5 and SHA1 are cryptographically weak and should not be used.',
                    fix: 'Use SHA-256 or stronger algorithms: MessageDigest.getInstance("SHA-256").'
                },
                {
                    pattern: /new\s+Random\s*\(\)|Math\.random\(\)/gi,
                    severity: 'medium',
                    title: 'Weak random number generation',
                    description: 'Standard Random class is not cryptographically secure.',
                    fix: 'Use SecureRandom for cryptographic operations: new SecureRandom().'
                },
                {
                    pattern: /Class\.forName\(.*\+|\.newInstance\(\)/gi,
                    severity: 'high',
                    title: 'Unsafe reflection',
                    description: 'Dynamic class loading with user input can lead to code injection.',
                    fix: 'Validate class names against a whitelist before using reflection.'
                }
            ],
            sql: [
                {
                    pattern: /['"].*\+.*['"]|EXEC\s*\(|EXECUTE\s*\(/gi,
                    severity: 'high',
                    title: 'SQL injection vulnerability',
                    description: 'String concatenation in SQL queries can lead to SQL injection attacks.',
                    fix: 'Use parameterized queries or prepared statements instead of string concatenation.'
                },
                {
                    pattern: /xp_cmdshell|sp_OACreate|sp_OAMethod/gi,
                    severity: 'high',
                    title: 'Dangerous stored procedures',
                    description: 'These stored procedures can execute system commands and pose security risks.',
                    fix: 'Avoid using dangerous stored procedures, implement application-level solutions.'
                }
            ],
            php: [
                {
                    pattern: /eval\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(/gi,
                    severity: 'high',
                    title: 'Code/Command injection risk',
                    description: 'These functions can execute arbitrary code/commands with user input.',
                    fix: 'Avoid these functions with user input. Use safer alternatives and input validation.'
                },
                {
                    pattern: /\$_GET\[|\$_POST\[|\$_REQUEST\[/gi,
                    severity: 'medium',
                    title: 'Direct use of superglobals',
                    description: 'Direct use of $_GET, $_POST, $_REQUEST without validation can lead to various attacks.',
                    fix: 'Always validate and sanitize user input before use.'
                },
                {
                    pattern: /mysql_query\(|mysql_connect\(/gi,
                    severity: 'medium',
                    title: 'Deprecated MySQL functions',
                    description: 'Old MySQL functions are deprecated and may be vulnerable to SQL injection.',
                    fix: 'Use PDO or MySQLi with prepared statements.'
                }
            ],
            html: [
                {
                    pattern: /javascript\s*:|vbscript\s*:|data\s*:/gi,
                    severity: 'high',
                    title: 'Dangerous URL schemes',
                    description: 'javascript:, vbscript:, and data: URLs can be used for XSS attacks.',
                    fix: 'Validate URLs and avoid dangerous schemes in href attributes.'
                },
                {
                    pattern: /onclick\s*=|onload\s*=|onerror\s*=/gi,
                    severity: 'medium',
                    title: 'Inline event handlers',
                    description: 'Inline event handlers can be exploited for XSS attacks.',
                    fix: 'Use addEventListener() in JavaScript instead of inline event handlers.'
                }
            ]
        };
  function detectLanguage(code) {
            const indicators = {
                javascript: [/function\s+\w+\s*\(/, /var\s+\w+\s*=/, /console\.log/, /document\./, /window\./],
                python: [/def\s+\w+\s*\(/, /import\s+\w+/, /print\s*\(/, /if\s+__name__\s*==/, /:\s*$/m],
                java: [/public\s+class/, /public\s+static\s+void\s+main/, /System\.out\./, /import\s+java\./],
                php: [/<\?php/, /\$\w+\s*=/, /echo\s+/, /function\s+\w+\s*\(/],
                sql: [/SELECT\s+.*FROM/i, /INSERT\s+INTO/i, /UPDATE\s+.*SET/i, /DELETE\s+FROM/i],
                html: [/<html/i, /<head/i, /<body/i, /<div/i, /<script/i]
            };

            for (const [lang, patterns] of Object.entries(indicators)) {
                const matches = patterns.filter(pattern => pattern.test(code)).length;
                if (matches >= 2) return lang;
            }

            return 'javascript'; // default
        }

        function analyzeCode() {
            const code = document.getElementById('codeInput').value.trim();
            const selectedLang = document.getElementById('languageSelect').value;
            
            if (!code) {
                alert('Please enter some code to analyze.');
                return;
            }

            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            const btn = document.querySelector('.analyze-btn');

            loading.classList.add('show');
            results.style.display = 'none';
            btn.disabled = true;

            // Simulate analysis delay
            setTimeout(() => {
                const language = selectedLang === 'auto' ? detectLanguage(code) : selectedLang;
                const vulnerabilities = findVulnerabilities(code, language);
                
                displayResults(vulnerabilities);
                
                loading.classList.remove('show');
                results.style.display = 'block';
                btn.disabled = false;
            }, 1500);
        }

        function findVulnerabilities(code, language) {
            const rules = securityRules[language] || [];
            const vulnerabilities = [];
            const lines = code.split('\n');

            rules.forEach(rule => {
                lines.forEach((line, index) => {
                    const matches = line.match(rule.pattern);
                    if (matches) {
                        vulnerabilities.push({
                            ...rule,
                            line: index + 1,
                            code: line.trim(),
                            match: matches[0]
                        });
                    }
                });
            });

            return vulnerabilities;
        }

        function displayResults(vulnerabilities) {
            const statsContainer = document.getElementById('stats');
            const vulnContainer = document.getElementById('vulnerabilities');

            // Calculate statistics
            const stats = {
                total: vulnerabilities.length,
                high: vulnerabilities.filter(v => v.severity === 'high').length,
                medium: vulnerabilities.filter(v => v.severity === 'medium').length,
                low: vulnerabilities.filter(v => v.severity === 'low').length
            };

            // Display statistics
            statsContainer.innerHTML = `
                <div class="stat-item">
                    <div class="stat-number">${stats.total}</div>
                    <div class="stat-label">Total Issues</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number high">${stats.high}</div>
                    <div class="stat-label">High Risk</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number medium">${stats.medium}</div>
                    <div class="stat-label">Medium Risk</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number low">${stats.low}</div>
                    <div class="stat-label">Low Risk</div>
                </div>
            `;

            // Display vulnerabilities
            if (vulnerabilities.length === 0) {
                vulnContainer.innerHTML = `
                    <div class="empty-state">
                        <h3>✅ No security issues found!</h3>
                        <p>Your code appears to follow secure coding practices.</p>
                    </div>
                `;
            } else {
                vulnContainer.innerHTML = vulnerabilities
                    .sort((a, b) => {
                        const severityOrder = { high: 3, medium: 2, low: 1 };
                        return severityOrder[b.severity] - severityOrder[a.severity];
                    })
                    .map(vuln => `
                        <div class="vulnerability severity-${vuln.severity}">
                            <div class="vuln-header">
                                <div class="vuln-title">
                                    ${vuln.title}
                                    <span class="vuln-severity">${vuln.severity}</span>
                                </div>
                            </div>
                            <div class="vuln-description">${vuln.description}</div>
                            <div class="vuln-code">
                                <strong>Line ${vuln.line}:</strong> ${vuln.code}
                            </div>
                            <div class="vuln-fix">
                                <strong>Fix:</strong> ${vuln.fix}
                            </div>
                        </div>
                    `).join('');
            }
        }

        // Add sample code button functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Pre-populate with the SQL injection example
            document.getElementById('codeInput').value = `query = "SELECT * FROM products WHERE category = '" + product_category + "'"`;
            document.getElementById('languageSelect').value = 'sql';
            
            // Add keyboard shortcut
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey && e.key === 'Enter') {
                    analyzeCode();
                }
            });
        });

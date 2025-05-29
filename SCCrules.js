import { javascriptVulnerabilityRules } from './Rules/JavaScriptRules.js';
import { pythonVulnerabilityRules } from './Rules/PythonRules.js';
import { javaVulnerabilityRules } from './Rules/JavaRules.js';
import { sqlVulnerabilityRules } from './Rules/SQLRules.js';
import { phpVulnerabilityRules } from './Rules/PHPRules.js';
import { htmlVulnerabilityRules } from './Rules/HTMLRules.js';

const securityRules = {
    javascript: javascriptVulnerabilityRules,
    python: pythonVulnerabilityRules,
    java: javaVulnerabilityRules,
    sql: sqlVulnerabilityRules,
    php: phpVulnerabilityRules,
    html: htmlVulnerabilityRules
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

            return 'javascript';
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

            setTimeout(() => {
                const language = selectedLang === 'auto' ? detectLanguage(code) : selectedLang;
                const vulnerabilities = findVulnerabilities(code, language);
                
                displayResults(vulnerabilities);
                
                loading.classList.remove('show');
                results.style.display = 'block';
                btn.disabled = false;
            }, 1500);
        }

    window.analyzeCode = analyzeCode;

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

            const stats = {
                total: vulnerabilities.length,
                high: vulnerabilities.filter(v => v.severity === 'high').length,
                medium: vulnerabilities.filter(v => v.severity === 'medium').length,
                low: vulnerabilities.filter(v => v.severity === 'low').length
            };

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

    
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('codeInput').value = `query = "SELECT * FROM products WHERE category = '" + product_category + "'"`;
            document.getElementById('languageSelect').value = 'sql';
            
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey && e.key === 'Enter') {
                    analyzeCode();
                }
            });
        });

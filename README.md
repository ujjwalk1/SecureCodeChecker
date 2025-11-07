# Secure Coding Guidelines Checker

A powerful, client-side web application for identifying security vulnerabilities and anti-patterns in your code across multiple programming languages. This tool helps developers write more secure code by detecting common security issues and providing actionable remediation advice.

## Live Demo

**Try it now**: [https://ujjwalk1.github.io/SecureCodeChecker/](https://ujjwalk1.github.io/SecureCodeChecker/)

The application is hosted live on GitHub Pages - no installation required! Simply visit the link above to start analyzing your code for security vulnerabilities.

## Features

### Multi-Language Support
- **JavaScript** - XSS, eval usage, DOM manipulation vulnerabilities
- **Python** - Code injection, deserialization, path traversal issues
- **Java** - Command injection, weak cryptography, unsafe reflection
- **SQL** - Injection vulnerabilities, dangerous procedures, DDL risks
- **PHP** - Code execution, file inclusion, session security
- **HTML** - XSS vectors, CSP issues, unsafe attributes

### Security Analysis Capabilities
-  **Pattern-Based Detection** - Uses regex patterns to identify vulnerable code constructs
-  **Risk Categorization** - Classifies vulnerabilities as High, Medium, or Low severity
-  **Line-Level Analysis** - Pinpoints exact locations of security issues
-  **Fix Recommendations** - Provides specific remediation guidance for each vulnerability
-  **Security Statistics** - Visual dashboard showing vulnerability distribution

### User Experience
-  **Instant Analysis** - Client-side processing for fast results
-  **Modern UI** - Clean, responsive design with gradient backgrounds
-  **Auto-Detection** - Automatically identifies programming language
-  **Keyboard Shortcuts** - Ctrl+Enter to analyze code quickly
-  **Mobile Friendly** - Responsive design works on all devices

##  Getting Started

### Quick Start (Recommended)
**No setup required!** Visit the live application:
- **Live Demo**: [https://ujjwalk1.github.io/SecureCodeChecker/](https://ujjwalk1.github.io/SecureCodeChecker/)
- Works in any modern web browser
- No installation or configuration needed
- Start analyzing code immediately

### Local Development Setup

#### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- No server setup required - runs entirely in the browser

#### Installation
1. Clone the repository:
```bash
git clone https://github.com/ujjwalk1/secure-coding-checker.git
cd secure-coding-checker
```

2. Open `index.html` in your web browser or serve it using a local web server:
```bash
# Using Python
python -m http.server 8000

# Using Node.js
npx serve .

# Using PHP
php -S localhost:8000
```

3. Navigate to `http://localhost:8000` and start analyzing your code!

##  Usage

### Online Usage (Recommended)
1. Visit [https://ujjwalk1.github.io/SecureCodeChecker/](https://ujjwalk1.github.io/SecureCodeChecker/)
2. **Paste Your Code** - Copy and paste your code into the text area
3. **Select Language** - Choose your programming language or use auto-detection
4. **Analyze** - Click "Analyze Code Security" or press Ctrl+Enter
5. **Review Results** - Examine the security vulnerabilities found
6. **Apply Fixes** - Follow the provided remediation guidance

### Example Analysis
The tool will identify issues like:
- SQL injection vulnerabilities in database queries
- XSS risks in JavaScript DOM manipulation
- Command injection in system calls
- Hardcoded credentials in source code
- Weak cryptographic implementations

##  Architecture

### File Structure
```
secure-coding-checker/
├── index.html              # Main application interface
├── SCCrules.js            # Core analysis engine
└── Rules/
    ├── JavaScriptRules.js # JavaScript security patterns
    ├── PythonRules.js     # Python security patterns
    ├── JavaRules.js       # Java security patterns
    ├── SQLRules.js        # SQL security patterns
    ├── PHPRules.js        # PHP security patterns
    └── HTMLRules.js       # HTML security patterns
```

### Technology Stack
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Architecture**: Modular ES6 imports for rule definitions
- **Processing**: Client-side regex pattern matching
- **Styling**: Custom CSS with modern design principles
- **Hosting**: GitHub Pages for live deployment

##  Security Rule Categories

### High Severity Issues
- Code/Command injection vulnerabilities
- SQL injection patterns
- Insecure deserialization
- Hardcoded credentials
- Dangerous file operations

### Medium Severity Issues
- Weak cryptographic algorithms
- Session security issues
- Open redirect vulnerabilities
- Missing security headers
- Unsafe random number generation

### Low Severity Issues
- Information disclosure risks
- Configuration weaknesses
- Development/debugging code in production
- Minor security anti-patterns

##  Current Capabilities

### Supported Vulnerability Types
- **Injection Attacks**: SQL, NoSQL, Command, Code injection
- **Cross-Site Scripting (XSS)**: Reflected, Stored, DOM-based
- **Cryptographic Issues**: Weak algorithms, poor key management
- **Authentication/Session**: Session fixation, weak authentication
- **File Security**: Path traversal, unsafe file operations
- **Configuration**: Missing security headers, verbose errors
- **Deserialization**: Unsafe object deserialization
- **Input Validation**: Missing sanitization, weak validation

### Language-Specific Detections
- **JavaScript**: DOM manipulation, eval usage, postMessage issues
- **Python**: Pickle deserialization, subprocess vulnerabilities
- **Java**: Reflection abuse, weak SSL/TLS configuration
- **SQL**: Union attacks, time-based blind injection
- **PHP**: Include vulnerabilities, superglobal usage
- **HTML**: Unsafe attributes, missing CSP headers

##  Known Issues

### Auto-Detection Limitations
- **Language Auto-Detection is Glitchy**: The automatic language detection feature may incorrectly identify the programming language, especially for:
  - Mixed-language code files
  - Short code snippets
  - Code with minimal language-specific syntax
  - Files with similar syntax patterns across languages
- **Recommendation**: Manually select the correct language from the dropdown for more accurate analysis

### Analysis Limitations
- **False Positives**: Some secure code patterns may be flagged as vulnerabilities due to regex-based detection
- **False Negatives**: Complex, context-dependent vulnerabilities may not be detected
- **Multi-line Patterns**: Some vulnerabilities spanning multiple lines may be missed
- **Comments vs Code**: The tool may flag vulnerability patterns in code comments as actual issues

### Browser Compatibility Issues
- **Older Browsers**: ES6+ features may not work in Internet Explorer or very old browser versions
- **Memory Limitations**: Very large code files (>10MB) may cause performance issues
- **Mobile Keyboards**: Some mobile browsers may have issues with keyboard shortcuts

### UI/UX Issues
- **Long Code Analysis**: No progress indicator for large file analysis
- **Copy-Paste Formatting**: Some formatted code may lose indentation when pasted
- **Results Overflow**: Very long vulnerability descriptions may not display properly on small screens

##  Future Work & Roadmap

### Short-term Improvements (v2.0)
- [ ] **Enhanced Pattern Matching**
  - Context-aware analysis beyond simple regex
  - Multi-line vulnerability detection
  - Function call flow analysis

- [ ] **Additional Language Support**
  - C/C++ security patterns
  - C# .NET vulnerabilities
  - Go security anti-patterns
  - Rust safety violations
  - TypeScript-specific issues

- [ ] **Improved User Experience**
  - Syntax highlighting in code editor
  - Export reports (PDF, JSON, CSV)
  - Vulnerability severity customization
  - Code snippet sharing functionality

### Medium-term Enhancements (v3.0)
- [ ] **Advanced Analysis Engine**
  - Abstract Syntax Tree (AST) parsing
  - Data flow analysis for complex vulnerabilities
  - Inter-procedural analysis
  - False positive reduction algorithms

- [ ] **Integration Capabilities**
  - GitHub Actions integration
  - CI/CD pipeline plugins
  - IDE extensions (VS Code, IntelliJ)
  - API endpoints for automated scanning

- [ ] **Collaborative Features**
  - Team workspaces
  - Vulnerability tracking and management
  - Security policy templates
  - Custom rule creation interface

### Long-term Vision (v4.0+)
- [ ] **AI-Powered Analysis**
  - Machine learning vulnerability detection
  - Natural language fix suggestions
  - Contextual security recommendations
  - Automated patch generation

- [ ] **Enterprise Features**
  - SAML/SSO authentication
  - Compliance reporting (OWASP, NIST)
  - Custom rule management
  - Audit trails and logging

- [ ] **Cloud Platform**
  - SaaS deployment option
  - Real-time collaborative editing
  - Centralized rule updates
  - Usage analytics and insights

##  Contributing

We welcome contributions! Here's how you can help:

### Adding New Security Rules
1. Create a new rule file in the `Rules/` directory
2. Follow the existing pattern structure:
```javascript
export const languageVulnerabilityRules = [
    {
        pattern: /vulnerable-pattern/gi,
        severity: 'high|medium|low',
        title: 'Vulnerability Name',
        description: 'Detailed explanation of the security risk',
        fix: 'Specific remediation steps'
    }
];
```

### Improving Detection Accuracy
- Submit issues for false positives/negatives
- Enhance existing regex patterns
- Add test cases for edge scenarios
- Improve language detection algorithms

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly across different browsers
5. Submit a pull request with detailed description

##  Statistics & Performance

### Current Rule Coverage
- **JavaScript**: 11 vulnerability patterns
- **Python**: 11 vulnerability patterns  
- **Java**: 10 vulnerability patterns
- **SQL**: 11 vulnerability patterns
- **PHP**: 10 vulnerability patterns
- **HTML**: 9 vulnerability patterns

### Performance Metrics
- Analysis time: <2 seconds for typical code files
- Browser compatibility: 95%+ modern browsers
- Memory usage: <50MB for large code files
- Offline capability: Fully functional without internet

##  License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- Security patterns inspired by OWASP Top 10
- Rule definitions based on CWE (Common Weakness Enumeration)
- UI design influenced by modern security tools
- Community contributions and feedback

##  Support & Contact

- 🌐 **Live Demo**: [https://ujjwalk1.github.io/SecureCodeChecker/](https://ujjwalk1.github.io/SecureCodeChecker/)
- 🐛 **Bug Reports**: [Create an issue](https://github.com/ujjwalk1/secure-coding-checker/issues)
- 📧 **Email**: kaulujjwal1@gmail.com

---

** Important Note**: This tool is designed to assist developers in identifying potential security issues but should not be considered a complete security audit solution. Always conduct thorough security testing and consider professional security assessments for production applications.

**🔍 Happy Secure Coding!** 🛡️

# SecureCodeChecker
A very basic Secure Coding Guidelines Checker that can analyze code for common security anti-patterns. Scans for various security vulnerabilities across multiple programming languages. 

# Key Features
1. Multi-Language Support - JavaScript, Python, Java, C#, PHP, SQL, and HTML.
2. Auto-detection of programming language
3. Language-specific security rules

# Security Vulnerability Detection
1. High Risk: Code injection, XSS, command injection, hardcoded credentials.
2. Medium Risk: Weak cryptography, deprecated functions, unsafe practices.
3. Low Risk: Best practice violations, minor security concerns.

# Comprehensive Reporting 
1. Visual statistics dashboard
2. Severity-based categorization
3. Line-by-line vulnerability identification
4. Specific fix recommendations

# Security Anti-Patterns Detected
1. JavaScript: eval() usage, innerHTML XSS, document.write(), open redirects, insecure storage
2. Python: exec/eval injection, command injection, pickle deserialization, weak random, hardcoded secrets (updated with Directory Traversal, XXE, Unsafe Temporary File Creation, ReDoS, CORS Misconfiguration, SSRF, Weak Hashing Algorithms)
3. Java: Command injection, weak algorithms (MD5/SHA1), unsafe reflection, weak random
4. SQL: SQL injection, dangerous stored procedures
5. PHP: Code injection, direct superglobal usage, deprecated MySQL functions
6. HTML: Dangerous URL schemes, inline event handlers



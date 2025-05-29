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
1. JavaScript: eval() usage, innerHTML XSS, document.write(), open redirects, insecure storage (updated with Weak Random Number Generation, Hardcoded Credentials/API Keys, Insecure XMLHttpRequest/fetch usage, postMessage without origin validation, window.open without noopener/noreferrer)
   
2. Python: exec/eval injection, command injection, pickle deserialization, weak random, hardcoded secrets (updated with Directory Traversal, XXE, Unsafe Temporary File Creation, ReDoS, CORS Misconfiguration, SSRF, Weak Hashing Algorithms)
   
3. Java: Command injection, weak algorithms (MD5/SHA1), unsafe reflection, weak random
   
4. SQL: SQL injection, dangerous stored procedures (updated with  SQL Injection via UNION/Type Conversion, Blind SQL Injection (Time-Based/Benchmark), Blind SQL Injection (Boolean-Based Indicators), SQL Injection in Data Modification Statements, Dangerous DDL Statements, Error-Based SQL Injection Indicators in Application Code, Oracle Specific Dangerous Packages, MySQL Specific File Operations)
   
5. PHP: Code injection, direct superglobal usage, deprecated MySQL functions
    
6. HTML: Dangerous URL schemes, inline event handlers



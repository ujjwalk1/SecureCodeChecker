export const JavaVulnerabilityRules = [

[
    {
        pattern: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder.*\.start\(\)/gi,
        severity: 'high',
        title: 'Command Injection Risk',
        description: 'Executing system commands with unvalidated user input can lead to arbitrary command injection, allowing attackers to run malicious commands on the server.',
        fix: 'Always validate and sanitize all user input before using it in system commands. Prefer `ProcessBuilder` with separate arguments instead of a single command string to avoid shell interpretation issues.'
    },
    {
        pattern: /MessageDigest\.getInstance\s*\(\s*["']MD5["']|MessageDigest\.getInstance\s*\(\s*["']SHA1["']/gi,
        severity: 'medium',
        title: 'Weak Cryptographic Algorithm Usage',
        description: 'MD5 and SHA1 are cryptographically weak and are vulnerable to collision attacks, making them unsuitable for security-sensitive operations like password hashing or digital signatures.',
        fix: 'Use stronger, modern hashing algorithms such as SHA-256 or SHA-512 (e.g., `MessageDigest.getInstance("SHA-256")`). For password storage, use dedicated password hashing functions like BCrypt or Argon2.'
    },
    {
        pattern: /new\s+Random\s*\(\)|Math\.random\(\)/gi,
        severity: 'medium',
        title: 'Weak Random Number Generation',
        description: 'The standard `java.util.Random` class (and `Math.random()`) provides pseudorandom numbers that are predictable and not cryptographically secure. They should not be used for security-sensitive operations like generating session IDs, tokens, or encryption keys.',
        fix: 'For all cryptographic operations or security-sensitive data generation, use `java.security.SecureRandom` (e.g., `new SecureRandom()`) to ensure strong, unpredictable randomness.'
    },
    {
        pattern: /Class\.forName\(.*\+|\.newInstance\(\)/gi,
        severity: 'high',
        title: 'Unsafe Reflection / Dynamic Class Loading',
        description: 'Dynamically loading classes or invoking methods using reflection (e.g., `Class.forName()`, `newInstance()`) with unvalidated user-supplied input can lead to arbitrary code execution or denial of service attacks.',
        fix: 'Always validate any class names or method names derived from user input against a strict whitelist of allowed values before using reflection. Minimize the use of reflection where possible.'
    },
    {
        pattern: /ObjectInputStream\.readObject\(\)/gi,
        severity: 'high',
        title: 'Insecure Deserialization (Java)',
        description: 'Deserializing untrusted data with `java.io.ObjectInputStream.readObject()` can lead to arbitrary code execution, denial of service, or other severe impacts if an attacker can control the serialized input.',
        fix: 'Avoid deserializing untrusted data entirely. If deserialization is unavoidable, use safer data formats like JSON or XML with secure, validated parsers. Implement strict deserialization filters or whitelisting mechanisms (Java 9+ `ObjectInputFilter`).'
    },
    {
        pattern: /(new\s+File\(.*[+]|\b(FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\([^)]*\+[^\)]*\))/gi,
        severity: 'high',
        title: 'Path Traversal / Directory Traversal',
        description: 'Constructing file or directory paths directly by concatenating unvalidated user input can allow attackers to access, read, or write to arbitrary files outside the intended directories (e.g., `../../../../etc/passwd`).',
        fix: 'Always validate and sanitize all user-provided file paths. Use `java.nio.file.Path.normalize()` and resolve the path against a secure base directory using `toRealPath()` or similar, ensuring the final path stays within the allowed boundaries.'
    },
    {
        pattern: /(String\s+(password|secret|apiKey|api_key|token)\s*=\s*["'][^"']{8,}["'])/gi,
        severity: 'high',
        title: 'Hardcoded Credentials',
        description: 'Hardcoding sensitive information like passwords, API keys, or security tokens directly in the source code exposes them to anyone with access to the code. This is a severe security risk.',
        fix: 'Never hardcode credentials. Use environment variables, secure configuration files that are not committed to version control, or dedicated secure credential management systems (e.g., HashiCorp Vault, AWS Secrets Manager).'
    },
    {
        pattern: /(new\s+URL\(.*[+]|\b(HttpURLConnection|HttpsURLConnection|URLConnection)\.openConnection\(\))/gi,
        severity: 'high',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'Allowing unvalidated user input to control parts of a URL used in server-side requests (e.g., with `URL`, `HttpURLConnection`, `fetch` libraries) can enable attackers to make the server request internal resources, scan internal networks, or interact with cloud metadata services.',
        fix: 'Validate and sanitize all user-provided URLs rigorously. Implement a strict whitelist of allowed domains/IPs, and block requests to private IP ranges. Be cautious with redirects and ensure they don\'t lead to unauthorized internal resources.'
    },
    {
        pattern: /(TrustAllCerts|HostnameVerifier\.ALLOW_ALL_HOSTNAME_VERIFIER|SSLContext\.getInstance\(\s*['"]TLS['"]\s*\)\.init\(null,.*?TrustManager\[\]\{new\s+X509TrustManager\(\)\{.*?\}\},null\))/gi,
        severity: 'high',
        title: 'Insecure SSL/TLS Configuration (Trusting All Certificates)',
        description: 'Disabling SSL/TLS certificate validation or hostname verification (e.g., by trusting all certificates or hostnames) severely compromises the security of encrypted connections, making your application vulnerable to man-in-the-middle attacks.',
        fix: 'Always verify SSL/TLS certificates and hostnames. Use proper certificate validation with trusted certificate authorities. Never disable certificate or hostname verification in production environments.'
    },
    {
        pattern: /(Statement\.executeQuery\(.*?\+.*?\)|Statement\.executeUpdate\(.*?\+.*?\)|Statement\.execute\(.*?\+.*?\))/gi,
        severity: 'high',
        title: 'SQL Injection via java.sql.Statement',
        description: 'Building SQL queries by concatenating unvalidated user input directly into `java.sql.Statement` methods (like `executeQuery`, `executeUpdate`, `execute`) is a classic SQL Injection vulnerability.',
        fix: 'Always use `java.sql.PreparedStatement` with parameterized queries. Never concatenate user input directly into SQL query strings, as this is the most common way to introduce SQL injection flaws.'
    }
]
]

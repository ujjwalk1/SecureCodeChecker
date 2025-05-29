export const pythonVulnerabilityRules = [

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
    },
    {
        pattern: /os\.path\.(join|abspath|normpath)\(.*user_input.*\)|open\(user_path.*\)/gi,
        severity: 'high',
        title: 'Directory Traversal / Path Manipulation',
        description: 'Constructing file paths directly with unvalidated user input can allow attackers to access or modify arbitrary files outside the intended directory.',
        fix: 'Use `os.path.abspath()` and `os.path.commonprefix()` to ensure the final path is within an allowed directory. Better yet, map user input to a predefined set of safe file names or use a whitelist approach.'
    },
    {
        pattern: /xml\.etree\.ElementTree\.parse\(|lxml\.etree\.parse\(/gi,
        severity: 'high',
        title: 'XML External Entity (XXE) Injection',
        description: 'Parsing XML from untrusted sources without disabling DTDs or external entity resolution can lead to information disclosure, DoS, or SSRF.',
        fix: 'For `xml.etree.ElementTree`, use `defusedxml.ElementTree` or configure the parser to disallow DTDs and external entities. For `lxml`, use `etree.parse(..., resolve_entities=False)` and `etree.XMLParser(resolve_entities=False, no_network=True)`.'
    },
    {
        pattern: /tempfile\.mktemp\(\)/gi,
        severity: 'high',
        title: 'Unsafe Temporary File Creation',
        description: '`tempfile.mktemp()` is vulnerable to race conditions, as it creates a file name but not the file itself, allowing another process to create a file with the same name before your application does.',
        fix: 'Use `tempfile.mkstemp()` or `tempfile.TemporaryFile()` which create and open the file atomically, preventing race conditions.'
    },
    {
        pattern: /requests\.(get|post|put|delete)\(.*url=user_input.*\)|urllib\.request\.urlopen\(user_input.*\)/gi,
        severity: 'high',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'Allowing users to control the URL in server-side requests can enable attackers to make the server request internal resources, scan internal networks, or interact with cloud metadata services.',
        fix: 'Validate and sanitize all user-provided URLs. Implement a whitelist of allowed domains/IPs, or use a proxy to filter requests.'
    },
    {
        pattern: /hashlib\.(md5|sha1)\(/gi,
        severity: 'medium',
        title: 'Use of Weak Hashing Algorithms',
        description: 'MD5 and SHA1 are cryptographically weak and are susceptible to collision attacks, making them unsuitable for sensitive data like passwords or digital signatures.',
        fix: 'Use stronger, modern hashing algorithms like SHA256, SHA512, or bcrypt/scrypt for password hashing. Always use salts when hashing passwords.'
    },
    {
        pattern: /re\.compile\(user_input\)|re\.search\(user_input\)|re\.match\(user_input\)/gi,
        severity: 'medium',
        title: 'Regular Expression Denial of Service (ReDoS)',
        description: 'Using complex or inefficient regular expressions with untrusted user input can lead to catastrophic backtracking, causing the application to consume excessive CPU and become unresponsive.',
        fix: 'Avoid overly complex regex patterns. Use simpler regexes or alternative parsing methods. Consider using a regex engine that mitigates ReDoS (e.g., `re2`) if available, or set a timeout for regex operations.'
    }
]

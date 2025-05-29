export const phpVulnerabilityRules = [

    {
        pattern: /eval\s*\(|assert\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|popen\s*\(/gi,
        severity: 'high',
        title: 'Code/Command Injection Risk',
        description: 'These functions (`eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`) can execute arbitrary code or commands if their arguments are derived from unvalidated user input.',
        fix: 'Avoid using these functions with user-supplied data. If external command execution is necessary, use `escapeshellarg()` and `escapeshellcmd()` to properly escape arguments, and prefer `proc_open` or `Symfony Process` component for more control and security.'
    },
    {
        pattern: /\$_GET\[|\$_POST\[|\$_REQUEST\[|\$_COOKIE\[|\$_FILES\[|\$_SERVER\[/gi,
        severity: 'medium',
        title: 'Direct Use of Superglobals Without Validation',
        description: 'Directly using data from superglobal arrays (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`) without proper validation and sanitization can lead to various vulnerabilities like XSS, SQL Injection, or file inclusion.',
        fix: 'Always validate and sanitize all user input from superglobals using functions like `filter_var()`, `htmlspecialchars()`, or dedicated validation libraries/frameworks. Never trust user input implicitly.'
    },
    {
        pattern: /mysql_query\(|mysql_connect\(|mysql_real_escape_string\(/gi,
        severity: 'medium',
        title: 'Deprecated and Insecure MySQL Functions',
        description: 'The `mysql_*` functions are deprecated and lack support for prepared statements, making them highly susceptible to SQL injection attacks. `mysql_real_escape_string` alone is insufficient defense.',
        fix: 'Migrate to **PDO** (PHP Data Objects) or **MySQLi** with **prepared statements**. These modern extensions provide robust security features against SQL injection by separating query logic from data.'
    },
    {
        pattern: /include\s*\(|\s*require\s*\(|\s*include_once\s*\(|\s*require_once\s*\(/gi,
        severity: 'high',
        title: 'Local/Remote File Inclusion (LFI/RFI)',
        description: 'Using `include`, `require`, `include_once`, or `require_once` with unvalidated user input can allow attackers to include arbitrary local files (LFI) or even remote files (RFI) from external servers, leading to code execution or information disclosure.',
        fix: 'Never include files based on user input directly. Use a whitelist of allowed files, or map user input to predefined, safe file paths. Disable `allow_url_include` in `php.ini` to prevent RFI.'
    },
    {
        pattern: /unserialize\s*\(/gi,
        severity: 'high',
        title: 'Insecure Deserialization',
        description: 'Deserializing untrusted data with `unserialize()` can lead to arbitrary code execution (PHP Object Injection), denial of service, or other severe impacts if an attacker can control the serialized input.',
        fix: 'Avoid deserializing untrusted data. If deserialization is unavoidable, use safer data formats like JSON or XML. Implement a robust deserialization whitelist or validation mechanism to ensure only expected classes and properties are deserialized.'
    },
    {
        pattern: /(md5\s*\(|sha1\s*\(|crypt\s*\([^,]+,\s*['"][^$]{1,2}['"]\))/gi,
        severity: 'medium',
        title: 'Weak Hashing Algorithms for Passwords',
        description: 'Using MD5, SHA1, or `crypt()` with weak salts for password hashing is insecure. These algorithms are fast and susceptible to brute-force attacks and rainbow table attacks.',
        fix: 'Use modern, strong, and slow password hashing functions like `password_hash()` with `PASSWORD_DEFAULT` (which currently uses Bcrypt) or `password_hash()` with `PASSWORD_ARGON2ID` for new applications. Always use unique salts for each password.'
    },
    {
        pattern: /(header\s*\(\s*['"]Location:\s*.*\$_GET\[|header\s*\(\s*['"]Location:\s*.*\$_POST\[)/gi,
        severity: 'high',
        title: 'Open Redirect Vulnerability',
        description: 'Constructing redirect URLs (`Location` header) directly from unvalidated user input can allow attackers to redirect users to malicious external sites, facilitating phishing attacks.',
        fix: 'Always validate and whitelist allowed redirect URLs. Only redirect to internal, predefined paths, or validate the full URL against a strict list of trusted domains before issuing the redirect.'
    },
    {
        pattern: /(file_put_contents\s*\(.*,\s*\$_FILES\[.*\]\['tmp_name'\]\)|move_uploaded_file\s*\([^,]+,\s*.*[\$_GET|\$_POST].*\))/gi,
        severity: 'high',
        title: 'Unrestricted File Upload',
        description: 'Allowing users to upload files without proper validation of file type, size, and content, or storing them in an executable directory, can lead to arbitrary code execution (web shell upload).',
        fix: 'Strictly validate file types (using both MIME type and file extension), sanitize filenames, and store uploaded files outside the web root or in a non-executable directory. Consider renaming files to prevent execution. Scan for malicious content.'
    },
    {
        pattern: /(session_start\s*\(\)\s*;\s*session_id\s*\(\s*\$_GET\[|session_start\s*\(\)\s*;\s*session_id\s*\(\s*\$_POST\[)/gi,
        severity: 'medium',
        title: 'Session Fixation Vulnerability',
        description: 'Accepting a session ID from user input (e.g., via GET/POST parameters) can allow attackers to fixate a session ID, making it possible to hijack a user\'s session after they log in.',
        fix: 'Never accept session IDs from user input. PHP handles session IDs securely by default. Regenerate the session ID after successful login (`session_regenerate_id(true);`) to prevent fixation.'
    },
    {
        pattern: /(ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]1['"]\s*\)|error_reporting\s*\(\s*E_ALL\s*\))/gi,
        severity: 'low',
        title: 'Verbose Error Reporting in Production',
        description: 'Displaying detailed PHP error messages (`display_errors = On`, `error_reporting = E_ALL`) in a production environment can expose sensitive information about the application\'s internals, file paths, or database queries to attackers.',
        fix: 'In production, set `display_errors = Off` and `log_errors = On` in `php.ini`. Configure `error_reporting` to a less verbose level (e.g., `E_ALL & ~E_NOTICE & ~E_DEPRECATED`) and ensure errors are logged securely to a file, not displayed to users.'
    }
]

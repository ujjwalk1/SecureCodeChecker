export const sqlVulnerabilityRules = [

[
    {
        pattern: /['"].*\+.*['"]|EXEC\s*\(|EXECUTE\s*\(/gi,
        severity: 'high',
        title: 'SQL Injection Vulnerability (String Concatenation/EXEC)',
        description: 'Building SQL queries through string concatenation with unvalidated user input or using `EXEC`/`EXECUTE` with dynamic SQL can lead to severe SQL injection attacks.',
        fix: 'Always use **parameterized queries** or **prepared statements** for all dynamic SQL. Never concatenate user input directly into SQL strings. If dynamic SQL is unavoidable, rigorously validate and escape all inputs.'
    },
    {
        pattern: /xp_cmdshell|sp_OACreate|sp_OAMethod/gi,
        severity: 'high',
        title: 'Dangerous Extended Stored Procedures (SQL Server)',
        description: 'These SQL Server extended stored procedures (`xp_cmdshell`, `sp_OACreate`, `sp_OAMethod`) allow database users to execute operating system commands or interact with COM objects, posing significant security risks if exploited.',
        fix: 'Disable these dangerous extended stored procedures if they are not strictly necessary for your application. Implement the **Principle of Least Privilege**, ensuring database users have only the minimum permissions required.'
    },
    {
        pattern: /(SELECT\s+\*\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*['"].*?['"]\s*OR\s*['"]1['"]\s*=\s*['"]1['"]|(--\s*.*|#\s*.*|\/\*.*\*\/\s*['"]))/gi,
        severity: 'high',
        title: 'Common SQL Injection Patterns (Bypasses/Comments)',
        description: 'Detects classic SQL injection bypass techniques like "OR 1=1" conditions or the use of SQL comments (`--`, `#`, `/* */`) to truncate or modify queries, often revealing underlying vulnerabilities.',
        fix: 'The fundamental fix is **parameterized queries**. Additionally, ensure strict input validation and input sanitization for all user-supplied data that interacts with database queries.'
    },
    {
        pattern: /(UNION\s+SELECT\s+.*|CAST\(.*AS\s+VARCHAR\)|CONVERT\(.*,\s*NVARCHAR\))/gi,
        severity: 'high',
        title: 'SQL Injection via UNION/Type Conversion',
        description: 'Identifies patterns associated with `UNION SELECT` attacks used to extract data from other tables, or the use of type conversion functions (`CAST`, `CONVERT`) commonly employed in error-based SQL injection techniques to extract data through database error messages.',
        fix: 'Enforce **parameterized queries** for all SQL statements. Restrict database user permissions to the absolute minimum necessary (Principle of Least Privilege) to prevent unauthorized data access.'
    },
    {
        pattern: /(SLEEP\(\d+\)|WAITFOR\s+DELAY\s+['"]\d+:\d+:\d+['"]|BENCHMARK\(\d+,\s*MD5\('?\w+'?\)\)|PG_SLEEP\(\d+\))/gi,
        severity: 'high',
        title: 'Blind SQL Injection (Time-Based/Benchmark)',
        description: 'Detects SQL functions designed to introduce delays (`SLEEP`, `WAITFOR DELAY`, `PG_SLEEP`) or CPU-intensive operations (`BENCHMARK`) in queries. These are indicative of time-based or benchmark-based blind SQL injection attempts, where attackers infer data based on response times.',
        fix: 'The primary defense is **parameterized queries**. Beyond that, implement robust logging and monitoring of unusual database query patterns, execution times, and resource consumption to detect such attacks.'
    },
    {
        pattern: /(IF\(\w+,\s*.*,\s*.*\)|CASE\s+WHEN\s+.*THEN\s+.*END)/gi,
        severity: 'medium',
        title: 'Blind SQL Injection (Boolean-Based Indicators)',
        description: 'Detects conditional statements (`IF`, `CASE WHEN`) within SQL queries that are frequently used in boolean-based blind SQL injection attacks. Attackers use these to infer data bit-by-bit based on true/false conditions in query responses.',
        fix: 'Ensure all dynamic SQL uses **parameterized queries**. Implement strict input validation and sanitization for any user input that could influence conditional logic in database queries.'
    },
    {
        pattern: /(INSERT\s+INTO\s+.*VALUES\s*\(.*?,?\s*['"]\s*['"]\s*--|UPDATE\s+.*SET\s+.*=\s*['"]\s*['"]\s*--|DELETE\s+FROM\s+.*WHERE\s+.*=\s*['"]\s*['"]\s*--)/gi,
        severity: 'high',
        title: 'SQL Injection in Data Modification Statements',
        description: 'Identifies patterns typically used in SQL injection attempts against `INSERT`, `UPDATE`, or `DELETE` statements. Attackers often use comments (`--`) to bypass security controls or modify query logic, potentially leading to data corruption or unauthorized deletion.',
        fix: 'Crucially, always use **parameterized queries** for all `INSERT`, `UPDATE`, and `DELETE` operations. Implement comprehensive input validation for all data being submitted or used in these statements.'
    },
    {
        pattern: /(ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+TABLE|TRUNCATE\s+TABLE|ALTER\s+DATABASE|DROP\s+DATABASE|CREATE\s+DATABASE)/gi,
        severity: 'high',
        title: 'Dangerous DDL Statements',
        description: 'Detects Data Definition Language (DDL) statements (`ALTER`, `DROP`, `CREATE`, `TRUNCATE` for tables or databases). If these can be injected via user input, attackers could severely damage or compromise your database schema and data.',
        fix: 'Database users should operate under the **Principle of Least Privilege**, meaning they have only the permissions absolutely necessary. Never allow user input to directly or indirectly influence DDL statements. Database schema changes should only be performed by trusted administrators.'
    },
    {
        pattern: /(SQL\s+INJECTION|ERROR\s+IN\s+SYNTAX|WARNING:\s*)/gi,
        severity: 'low',
        title: 'Error-Based SQL Injection Indicators in Application Code',
        description: 'Detects patterns that might indicate an application is printing database error messages directly or indirectly. This can help attackers exploit error-based SQL injection vulnerabilities to gain information about the database structure.',
        fix: 'Never display raw database error messages to users. Implement custom error handling that provides generic, user-friendly messages while logging detailed errors securely on the server-side for debugging.'
    },
    {
        pattern: /(DBMS_PIPE|DBMS_OUTPUT|UTL_HTTP|UTL_INADDR|UTL_FILE)/gi,
        severity: 'high',
        title: 'Oracle Specific Dangerous Packages',
        description: 'Detects common Oracle database packages (`DBMS_PIPE`, `DBMS_OUTPUT`, `UTL_HTTP`, `UTL_INADDR`, `UTL_FILE`) that can be abused for information disclosure, network access, or file system operations if SQL injection is possible.',
        fix: 'Restrict execution privileges on these packages to only necessary and trusted database users. Monitor for unusual activity related to these packages.'
    },
    {
        pattern: /(LOAD_FILE|INTO\s+OUTFILE|DUMPFILE)/gi,
        severity: 'high',
        title: 'MySQL Specific File Operations',
        description: 'Detects MySQL functions (`LOAD_FILE`, `INTO OUTFILE`, `DUMPFILE`) that can be used to read or write files on the database server, potentially leading to arbitrary file access or RCE.',
        fix: 'Ensure the MySQL user has minimal file system privileges. Avoid using these functions with user-controlled input. Configure `secure_file_priv` to a restricted directory or `NULL`.'
    }
]
]

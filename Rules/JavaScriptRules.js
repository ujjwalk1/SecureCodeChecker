export const javascriptVulnerabilityRules = [

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
    },
    {
        pattern: /setTimeout\s*\(\s*['"].*['"]\s*,|setInterval\s*\(\s*['"].*['"]\s*,/gi,
        severity: 'high',
        title: 'Code injection via setTimeout/setInterval with string',
        description: 'Passing a string as the first argument to setTimeout or setInterval can execute arbitrary code, similar to eval().',
        fix: 'Pass a function reference instead of a string to setTimeout/setInterval.'
    },
    {
        pattern: /Math\.random\(\)/gi,
        severity: 'medium',
        title: 'Weak random number generation',
        description: 'Math.random() is not cryptographically secure and should not be used for generating sensitive values like session tokens, passwords, or cryptographic keys.',
        fix: 'Use `window.crypto.getRandomValues()` for generating cryptographically strong random numbers in a browser environment.'
    },
    {
        pattern: /(api_key|token|secret|password)\s*:\s*['"][^'"]{10,}['"]|const\s+(API_KEY|TOKEN|SECRET|PASSWORD)\s*=\s*['"][^'"]{10,}['"]/gi,
        severity: 'high',
        title: 'Hardcoded sensitive information',
        description: 'Storing API keys, tokens, or other sensitive credentials directly in client-side JavaScript exposes them to attackers who can inspect the source code.',
        fix: 'Avoid exposing sensitive data in client-side code. Use server-side proxies, environment variables, or secure credential management systems. Fetch sensitive data from the server only when needed and never store it persistently client-side.'
    },
    {
        pattern: /postMessage\s*\(.*,\s*['"]\*['"]\s*\)/gi,
        severity: 'high',
        title: 'Insecure window.postMessage() usage',
        description: 'Using `*` as the targetOrigin in `window.postMessage()` allows any window to receive the message, potentially leading to information disclosure or Cross-Site Scripting (XSS) if sensitive data is sent.',
        fix: 'Always specify a precise target origin (e.g., `https://example.com`) instead of `*`. When receiving messages, always validate `event.origin` to ensure the message comes from a trusted source.'
    },
    {
        pattern: /window\.open\s*\([^,]+,[^,]+,(?!.*\b(noopener|noreferrer)\b).*?\)/gi,
        severity: 'medium',
        title: 'Tabnabbing vulnerability via window.open()',
        description: 'Opening new windows without `rel="noopener"` or `rel="noreferrer"` in the link, or without these options in `window.open()`, allows the opened page to control the opener window (`window.opener`), leading to phishing attacks (tabnabbing).',
        fix: 'Always include `noopener` and `noreferrer` in the `window.open()` features string (e.g., `window.open(url, "_blank", "noopener,noreferrer")`) or use `rel="noopener noreferrer"` on `<a>` tags.'
    },
    {
        pattern: /xhr\.withCredentials\s*=\s*true|fetch\s*\(.*,\s*{[^}]*credentials\s*:\s*['"]include['"][^}]*}\)/gi,
        severity: 'medium',
        title: 'Cross-origin requests with credentials',
        description: 'Sending credentials (like cookies or HTTP authentication headers) with cross-origin requests can expose them to unintended domains or make your application vulnerable to Cross-Site Request Forgery (CSRF) if the target domain is not properly secured.',
        fix: 'Only send credentials to trusted, same-origin domains. Be cautious with `xhr.withCredentials = true` or `credentials: "include"` for cross-origin requests, and ensure proper CSRF protection is in place on the server-side.'
    }
]

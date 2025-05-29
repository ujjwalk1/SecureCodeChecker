export const htmlVulnerabilityRules = [

[
    {
        pattern: /javascript\s*:|vbscript\s*:|data\s*:/gi,
        severity: 'high',
        title: 'Dangerous URL Schemes in Attributes',
        description: 'Using `javascript:`, `vbscript:`, or `data:` URLs in attributes like `href`, `src`, or `formaction` can be exploited for Cross-Site Scripting (XSS) attacks if user input is not properly sanitized.',
        fix: 'Validate and sanitize all URLs derived from user input. Strictly whitelist allowed URL schemes (e.g., `http`, `https`) and avoid dangerous schemes in HTML attributes.'
    },
    {
        pattern: /on(click|load|error|submit|mouseover|mouseout|keydown|keyup|keypress|focus|blur|change|input|select)\s*=/gi,
        severity: 'medium',
        title: 'Inline Event Handlers',
        description: 'Using inline event handlers (e.g., `onclick="alert(1)"`) mixes JavaScript with HTML, making Content Security Policy (CSP) implementation difficult and potentially exposing XSS vulnerabilities if user input is reflected unsafely.',
        fix: 'Separate JavaScript from HTML. Use `addEventListener()` in external JavaScript files to attach event listeners dynamically. This improves maintainability and security.'
    },
    {
        pattern: /<meta\s+http-equiv=["']Content-Security-Policy["']\s+content=["'](.*?)["']/gi,
        severity: 'low', 
        title: 'Missing or Weak Content Security Policy (CSP)',
        description: 'A missing or overly permissive Content Security Policy (CSP) header or meta tag fails to mitigate various attacks like XSS, clickjacking, and data injection by restricting the sources of content that a browser can load.',
        fix: 'Implement a strong CSP. Define strict `default-src`, `script-src`, `style-src`, `img-src`, `connect-src`, etc., directives to allow only trusted sources. Regularly review and refine your CSP.'
    },
    {
        pattern: /<meta\s+http-equiv=["']X-Frame-Options["']\s+content=["'](DENY|SAMEORIGIN)["']/gi,
        severity: 'medium', 
        title: 'Missing X-Frame-Options Header/Meta Tag',
        description: 'Lack of `X-Frame-Options` header or meta tag allows your page to be embedded in an `<iframe>` on any domain, making it vulnerable to Clickjacking attacks where attackers overlay malicious content on your site.',
        fix: 'Implement `X-Frame-Options: DENY` (to prevent framing by anyone) or `X-Frame-Options: SAMEORIGIN` (to allow framing only by your own domain) in your HTTP response headers or as a meta tag.'
    },
    {
        pattern: /<input[^>]*type=["']password["'][^>]*autocomplete=["']on["']/gi,
        severity: 'medium',
        title: 'Insecure Autocomplete for Sensitive Input Fields',
        description: 'Using `autocomplete="on"` or not specifying `autocomplete` for sensitive input fields (like passwords, credit card numbers) can lead to sensitive data being stored and auto-filled by browsers, increasing the risk of information disclosure if the user\'s device is compromised.',
        fix: 'Set `autocomplete="off"` or `autocomplete="new-password"` for sensitive input fields, especially passwords and personal information, to prevent browsers from storing and auto-filling these values.'
    },
    {
        pattern: /<iframe[^>]*srcdoc\s*=/gi,
        severity: 'high',
        title: 'XSS via srcdoc in Iframes',
        description: 'The `srcdoc` attribute of an `<iframe>` allows embedding HTML content directly. If this content is derived from unvalidated user input, it can lead to XSS attacks within the iframe\'s context.',
        fix: 'Avoid using `srcdoc` with untrusted user input. If it must be used, ensure all user-supplied content is rigorously sanitized and HTML-escaped before being embedded.'
    },
    {
        pattern: /<a[^>]*target=["']_blank["'][^>]*rel=["'](?!.*(noopener|noreferrer)).*?["']/gi,
        severity: 'medium',
        title: 'Tabnabbing Vulnerability (Missing rel="noopener noreferrer")',
        description: 'Links with `target="_blank"` that open in a new tab without `rel="noopener"` or `rel="noreferrer"` allow the newly opened page to control the `window.opener` object of the original page, potentially redirecting it to a phishing site (tabnabbing).',
        fix: 'Always include `rel="noopener noreferrer"` for all `<a>` tags that use `target="_blank"` to prevent the new tab from accessing the `window.opener` object.'
    },
    {
        pattern: /||/gi,
        severity: 'low',
        title: 'Sensitive Information in HTML Comments',
        description: 'Embedding sensitive information like passwords, API keys, or internal system details within HTML comments makes them easily discoverable by attackers who can view the page source.',
        fix: 'Never store sensitive data in HTML comments. Remove any comments containing credentials, internal logic, or other confidential information from production code.'
    },
    {
        pattern: /<input[^>]*type=["']hidden["'][^>]*value=["']([^"']*)["']/gi,
        severity: 'low',
        title: 'Sensitive Data in Hidden Input Fields',
        description: 'Storing sensitive data (e.g., user IDs, prices, statuses) in hidden HTML input fields makes it visible to users inspecting the source code and easily modifiable by attackers, potentially leading to data manipulation.',
        fix: 'Avoid storing sensitive or critical application state data in hidden input fields. Instead, manage such data server-side using sessions, or use secure tokens/hashes to verify client-side data on the server.'
    }
]
]

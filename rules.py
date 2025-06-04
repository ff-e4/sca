from typing import Dict, List, Iterable

def ruleset(language="cf"):
    Rule = Dict[str, object]

    def _p(regex: str,
           reason: str,
           recommendation: str,
           severity: str = "medium") -> Rule:
        """Helper to build a pattern dict"""
        return {
            "regex": regex,
            "reason": reason,
            "recommendation": recommendation,
            "severity": severity
        }
    if language == "cf":
        RULES: List[Dict] = [
            {
                "id": "A01",
                "name": "Broken Access Control",
                "patterns": [
                    _p(
                        r"<cffile\s+action\s*=\s*\"?write\"?",
                        "File‑write operation without explicit authorization guard.",
                        "Ensure user is authorized; validate and sanitise path.",
                        "high"
                    ),
                    _p(
                        r"<cfcomponent[^>]*\baccess\s*=",
                        "Component declares broad access level; may expose methods.",
                        "Restrict access attribute (remote/public/package) as narrowly as possible."
                    )
                ]
            },
            {
                "id": "A02",
                "name": "Cryptographic Failures",
                "patterns": [
                    _p(
                        r"\bencrypt\s*\([^)]*(DES|RC4|MD5)\b",
                        "Weak or legacy cipher/hash used in encrypt().",
                        "Switch to AES‑256/CFCRYPT with strong key & CBC or GCM mode.",
                        "high"
                    ),
                    _p(
                        r"\bhash\s*\([^)]*\bMD5\b",
                        "MD5 is broken and collision‑prone.",
                        "Use SHA‑256/512 or bcrypt/Argon2 for password hashing.",
                        "high"
                    ),
                ],
            },
            {
                "id": "A03",
                "name": "Injection",
                "patterns": [
                    # ── SQL injection ───────────────────────────────────────────────────
                    _p(
                        r"\bqueryExecute\s*\(.*[#&]\w+",
                        "Dynamic query string built with #variable# in queryExecute() — possible SQL injection.",
                        "Use named/positional parameters instead of string concatenation.",
                        "high",
                    ),
                    # ── OS‑command injection ────────────────────────────────────────────
                    _p(
                        r"<cfexecute[^>]*>(?:(?!</cfexecute>).)*#\s*[\w.]+\s*#",
                        "Variable inserted into OS command (<cfexecute>) — OS command injection risk.",
                        "Validate/allow‑list args or avoid dynamic shell execution.",
                        "high"
                    ),
                    _p(
                        r"<cflocation[^>]*>(?:(?!</cflocation>).)*#\s*[\w.]+\s*#",
                        "Dynamic input in cflocation tag.",
                        "Replace #variable# with <cfqueryparam> (or bind parameters in queryExecute.",
                        "high"
                    ),
                    # ToDo: try and find a better regex to filter out too much data.
                    # we only need: a) dynamic input #something# that is b) outside a cfqueryparam tag
                    # _p(
                    #     # Match only #form.var# that is NOT inside a line with <cfqueryparam>
                    #     r'(?i)(?!.*<cfqueryparam\b).*#\s*form\.[a-zA-Z0-9_]+\s*#',
                    #     "Unescaped #form.# input used directly in SQL or output outside of <cfqueryparam>; this poses a SQL injection risk.",
                    #     "Use <cfqueryparam> to safely bind #form.# values inside <cfquery> blocks and avoid injection vulnerabilities.",
                    #     "high"
                    # ),
                ],
            },
            {
                "id": "A04",
                "name": "Insecure Design",
                "patterns": [
                    _p(
                        r"<cfinclude\s+template\s*=\s*#\s*[\w.]+",
                        "Dynamic template include; may allow path traversal or LFI.",
                        "Sanitise include path or switch to static includes.",
                        "medium"
                    )
                ],
            },
            {
                "id": "A05",
                "name": "Security Misconfiguration",
                "patterns": [
                    _p(
                        r"<cfapplication[^>]*\bsetclientcookies\s*=\s*\"?\s*yes",
                        "ColdFusion default client cookies enable session fixation.",
                        "Disable client cookies or set secure/httponly/SameSite flags.",
                        "medium"
                    ),
                ],
            },
            {
                "id": "A06",
                "name": "Vulnerable & Outdated Components",
                "patterns": [
                    _p(
                        r"<!---?.*ColdFusion\s+11\b",
                        "Project comment mentions ColdFusion 11 (end‑of‑life).",
                        "Upgrade to supported version or Lucee LTS.",
                        "high"
                    )
                ],
            },
            {
                "id": "A07",
                "name": "Identification & Authentication Failures",
                "patterns": [
                    _p(
                        r"<cfform[^>]*(passwordfield|type\s*=\s*\"?password)",
                        "Password field rendered without TLS enforced in code.",
                        "Enforce HTTPS and set secure flag in CFIDE.",
                        "high"
                    )
                ],
            },
            {
                "id": "A08",
                "name": "Software & Data Integrity Failures",
                "patterns": [
                    _p(
                        r"<cffile\s+action\s*=\s*\"?upload\"?",
                        "File upload endpoint detected — risk of unrestricted file upload.",
                        "Validate MIME type, extension and store outside web root.",
                        "high"
                    )
                ],
            },
            {
                "id": "A09",
                "name": "Security Logging & Monitoring Failures",
                "patterns": [
                    #ToDo: This rule alerts on all catch w/o log. I'm not sure it's relevant as most empty catch will not relate to areas of interest.
                    _p(
                        r"(?is)<cfcatch\b[^>]*>\s*</cfcatch>",  # match cfcatch tags with nothing between them
                        "Empty <cfcatch> block suppresses errors without logging, notifying, or handling them.",
                        "Handle exceptions explicitly — log the error, rethrow it, or return a secure fallback.",
                        "medium"
                    )
                ],
            },
            {
                "id": "A10",
                "name": "Server‑Side Request Forgery",
                # Details: https://foundeo.com/security/guide/server-side-request-forgery/
                "patterns": [
                    _p(
                        r"\b(cfhttp|http(?:Get|Post))\b",
                        "Outbound HTTP request; may be abused for SSRF.",
                        "Validate target host/IP against allow‑list. See: https://foundeo.com/security/guide/server-side-request-forgery/.",
                        "medium"
                    )
                ],
            },
            # ─────────────────────────────────────────────────────────────────────────────
            # JS01  Unsafe JavaScript eval()
            # ─────────────────────────────────────────────────────────────────────────────
            {
                "id": "JS01",
                "name": "Unsafe JavaScript eval()",
                "patterns": [
                    # eval() fed by any ColdFusion scope that may contain user input
                    _p(
                        r"(?i)eval\s*\(\s*['\"]?\s*#?.*?(form|url|cgi|cookie|request|session)\.[A-Za-z0-9_]+",
                        "JavaScript eval() receives user-controlled input — extremely dangerous (XSS / arbitrary code execution).",
                        "Refactor to eliminate eval(); if unavoidable, strictly validate input or use JSON.parse / secure APIs.",
                        "high"
                    ),
                    # generic eval() with string concatenation (catch-all heuristic)
                    _p(
                        r"(?i)eval\s*\(\s*[^)]+(\+[^)]+)+\)",
                        "Dynamic string concatenation inside eval() — unsafe runtime code generation.",
                        "Rewrite logic to avoid eval(); never build code from strings.",
                        "high"
                    ),
                ],
            },
            # ─────────────────────────────────────────────────────────────────────────────
            # SQL01  Unsafe SQL Construction
            # ─────────────────────────────────────────────────────────────────────────────
            {
                "id": "SQL01",
                "name": "Unsafe SQL Construction",
                "patterns": [
                    # Un-parameterised user scope in cfquery / queryExecute
                    _p(
                        r"(?i)<cfquery[^>]*>[^<]*#\s*(form|url|cgi|cookie|request|session)\.[A-Za-z0-9_]+\s*#[^<]*(?!<cfqueryparam)",
                        "User-controlled input appears in SQL without cfqueryparam — classic SQL injection vector.",
                        "Replace the #variable# with <cfqueryparam> (or named parameters in queryExecute).",
                        "high",
                    ),
                    # SQL built in CFScript via string concat
                    _p(
                        r"(?i)\bqueryExecute\s*\(\s*['\"][^'\"]*\+\s*(form|url|cgi|cookie|request|session)\.[A-Za-z0-9_]+",
                        "CFScript queryExecute() call concatenates user input into SQL.",
                        "Pass parameters separately to queryExecute() rather than concatenating strings.",
                        "high",
                    ),
                    # Generic wildcard select with dynamic variable
                    _p(
                        r"(?i)select\s+\*\s+from\s+\w+\s+where\s+\w+\s*=\s*#",
                        "Wildcard SELECT with dynamic variable suggests unparameterised query.",
                        "Specify columns and bind variables using cfqueryparam.",
                        "medium",
                    ),
                ],
            },
        ]
        return RULES

    if language == "grails":
        RULES: List[Dict] = [
            # ────────────────────────────────────────────────────────────────────────
            # A01 Broken Access Control
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A01",
                "name": "Broken Access Control",
                "patterns": [
                    _p(
                        r"(?i)class\s+(\w+)Controller\b(?!.*?@Secured)",
                        "Controller class without @Secured annotation. "
                        "Endpoints may be exposed without authentication.",
                        "Add @Secured / @PreAuthorize annotations or configure Spring Security.",
                        "high",
                    ),
                    _p(
                        r"(?i)def\s+\w+\s*\(\s*\)\s*\{[^@]*render\s*\(",
                        "Render method with no explicit allowedMethods / security guard.",
                        "Define allowedMethods OR apply @Secured / @RoleAllowed.",
                        "medium",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A02 Cryptographic Failures
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A02",
                "name": "Cryptographic Failures",
                "patterns": [
                    _p(
                        r'(?i)new\s+MessageDigest\.getInstance\(\s*"(MD5|SHA-1)"\s*\)',
                        "Use of weak hash function (MD5 or SHA‑1).",
                        "Use SHA‑256/512 or BCrypt/SCrypt/Argon2 for passwords.",
                        "high",
                    ),
                    _p(
                        r"(?i)\bencodeAsMD5\b|\bDigestUtils\.md5",
                        "Deprecated MD5 encoding helper found.",
                        "Switch to stronger algorithms (SHA‑256) or password encoders.",
                        "high",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A03 Injection
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A03",
                "name": "Injection",
                "patterns": [
                    _p(
                        r'\b(executeQuery|executeUpdate|find|findAll)\s*\(\s*".*"\s*\+\s*\w+',
                        "Dynamic query string concatenation detected "
                        "(possible SQL/HQL injection).",
                        "Use named parameters (e.g., where {...}), positional params or "
                        "GORM criteria instead of string concatenation.",
                        "high",
                    ),
                    _p(
                        r'(?s)<%=\s*\$\{.*request\..*?\}\s*%>',
                        "EL‑style variable rendered directly in GSP; may lead to XSS.",
                        "HTML‑encode output with encodeAsHTML() or use the double‑$ syntax (${raw(...)}) cautiously.",
                        "high",
                    ),
                    _p(
                        r'\b(executeQuery|executeUpdate|find|findAll)\s*\(\s*".*"\s*\+\s*\w+',
                        "Dynamic query string concatenation detected (possible SQL/HQL injection).",
                        "Use named parameters, positional params, or GORM criteria instead of string concatenation.",
                        "high",
                    ),
                    _p(
                        r'(?s)<%=\s*\$\{.*request\..*?\}\s*%>',
                        "EL‑style variable rendered directly in GSP; may lead to XSS.",
                        "HTML‑encode output with encodeAsHTML() or use safe render syntax like <g:message>.",
                        "high",
                    ),
                    _p(
                        r'\$\{(?:params|request|session|flash)\.\w+\}',
                        "Direct output of user-controlled input without encoding — possible XSS vulnerability.",
                        "Escape output using encodeAsHTML(), encodeAsJavaScript(), or use built-in escaping in GSP with <g:message>.",
                        "high",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A04 Insecure Design
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A04",
                "name": "Insecure Design",
                "patterns": [
                    _p(
                        r'\binclude\s+template\s*:\s*["\']\$\{.*\}',
                        "Template include path built from user data; could allow LFI.",
                        "Sanitize template path or switch to static includes.",
                        "medium",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A05 Security Misconfiguration
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A05",
                "name": "Security Misconfiguration",
                "patterns": [
                    _p(
                        r'(?i)grails\.serverURL\s*=\s*["\']http://',
                        "Application base URL set to plain HTTP.",
                        "Serve over HTTPS and update grails.serverURL.",
                        "medium",
                    ),
                    _p(
                        r'(?i)cors\.enabled\s*=\s*true\s*[\r\n].*?cors\.allowAll\s*=\s*true',
                        "Global CORS allowAll enabled — broad cross‑origin access.",
                        "Restrict allowedOrigins or disable allowAll.",
                        "medium",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A06 Vulnerable & Outdated Components
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A06",
                "name": "Vulnerable and Outdated Components",
                "patterns": [
                    _p(
                        r"org\.grails\.grails-core:.*:2\.[0-4]\.",
                        "Legacy Grails 2.x dependency detected (EOL, known CVEs).",
                        "Upgrade to Grails 5+ or patch the framework.",
                        "high",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A07 Identification & Authentication Failures
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A07",
                "name": "Identification and Authentication Failures",
                "patterns": [
                    _p(
                        r'(?i)passwordEncoder\s*=\s*["\'](none|plain)',
                        "Plain‑text password encoder configured.",
                        "Use BCryptPasswordEncoder or Argon2PasswordEncoder.",
                        "high",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A08 Software & Data Integrity Failures
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A08",
                "name": "Software and Data Integrity Failures",
                "patterns": [
                    _p(
                        r"(?i)File\.copyFrom|File\.write|new\s+FileOutputStream",
                        "Raw file write operation — check that upload paths are validated.",
                        "Validate file paths and use whitelist of locations.",
                        "medium",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A09 Security Logging & Monitoring Failures
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A09",
                "name": "Security Logging and Monitoring Failures",
                "patterns": [
                    _p(
                        r'(?i)catch\s*\([^)]+\)\s*\{\s*\}',
                        "Empty catch block — swallowed exception, no logging.",
                        "Log the exception (log.error) or rethrow.",
                        "low",
                    ),
                ],
            },
            # ────────────────────────────────────────────────────────────────────────
            # A10 Server‑Side Request Forgery (SSRF)
            # ────────────────────────────────────────────────────────────────────────
            {
                "id": "A10",
                "name": "Server‑Side Request Forgery",
                "patterns": [
                    _p(
                        r'new\s+URL\(\s*\w+\s*\)',
                        "Dynamic URL object built from variable; may allow SSRF.",
                        "Validate host against allow‑list before issuing requests.",
                        "medium",
                    ),
                ],
            },
        ]
        return RULES

    if language == "qt":
        RULES: List[Dict] = [
            # ──────────────────────────────────────────────────────────────────────
            # A01  Broken Access Control  (heuristic: TODO / FIXME markers)
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A01",
                "name": "Broken Access Control",
                "patterns": [
                    _p(
                        r"//\s*(TODO|FIXME).*access\s*control",
                        "Source contains TODO/FIXME regarding access control — may be incomplete.",
                        "Complete and test access-control checks; remove TODO before shipping.",
                        "low",
                    )
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A02  Cryptographic Failures
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A02",
                "name": "Cryptographic Failures",
                "patterns": [
                    _p(
                        r'\b(md5|sha1)_crypt\b|\bMD5\b',
                        "Use of weak hash (MD5/SHA-1) for cryptographic purpose.",
                        "Replace with SHA-256/512 or a KDF like Argon2/Bcrypt.",
                        "high",
                    ),
                    _p(
                        r'\bsrand\s*\(\s*time\s*\(\s*0\s*\)\s*\)',
                        "Predictable RNG seeding with time(0).",
                        "Use a cryptographically secure RNG (e.g., std::random_device or QtRandomGenerator::global()).",
                        "high",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A03  Injection (SQL / Command)
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A03",
                "name": "Injection",
                "patterns": [
                    _p(
                        r'QSqlQuery\s+\w+\s*\(\s*".*"\s*\+\s*\w+',
                        "SQL built by concatenating variable into QSqlQuery — SQL injection risk.",
                        "Use prepared statements with bound values (QSqlQuery::bindValue).",
                        "high",
                    ),
                    _p(
                        r'\b(system|popen|QProcess::startDetached)\s*\([^"]*"\s*\+\s*\w+',
                        "User data concatenated into shell/OS command — command injection risk.",
                        "Avoid string concatenation; pass args separately or validate/escape.",
                        "high",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A04  Insecure Design
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A04",
                "name": "Insecure Design",
                "patterns": [
                    _p(
                        r'\bQSettings\b.*\.setValue\s*\(\s*"(password|secret|token)"',
                        "Sensitive data stored in clear text using QSettings.",
                        "Encrypt the data at rest or use OS-provided secure storage.",
                        "medium",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A05  Security Misconfiguration
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A05",
                "name": "Security Misconfiguration",
                "patterns": [
                    _p(
                        r'\bQT_SSL_USE_TEMPORARY_KEY\b',
                        "Use of deprecated Qt SSL setting — may weaken TLS.",
                        "Use current QSslConfiguration defaults and enable modern ciphers.",
                        "medium",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A06  Vulnerable & Outdated Components
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A06",
                "name": "Vulnerable and Outdated Components",
                "patterns": [
                    _p(
                        r'Qt\s*=\s*4\.[0-9]+',
                        "Project references Qt 4 which is End of Life.",
                        "Upgrade to a maintained Qt version (≥ 5.15 LTS or Qt 6).",
                        "high",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A07  Identification & Authentication Failures
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A07",
                "name": "Identification and Authentication Failures",
                "patterns": [
                    _p(
                        r'QString\s+password\s*=\s*".{0,20}"',
                        "Hard-coded password in source code.",
                        "Remove hard-coded secrets; load from secure vault / env var.",
                        "high",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A08  Software & Data Integrity Failures
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A08",
                "name": "Software and Data Integrity Failures",
                "patterns": [
                    _p(
                        r'\bstrcpy\s*\(',
                        "Use of strcpy (no bounds check) — buffer-overflow risk.",
                        "Use strncpy, strlcpy, std::copy, or safer C++ string APIs.",
                        "high",
                    ),
                    _p(
                        r'\bsprintf\s*\([^n]',
                        "Use of sprintf without size limit — buffer-overflow risk.",
                        "Use snprintf or std::format.",
                        "high",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A09  Security Logging & Monitoring Failures
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A09",
                "name": "Security Logging and Monitoring Failures",
                "patterns": [
                    _p(
                        r'catch\s*\([^)]*\)\s*\{\s*\}',
                        "Empty catch block suppresses exceptions / errors.",
                        "Log or rethrow exceptions; never leave catch blocks empty.",
                        "low",
                    ),
                ],
            },
            # ──────────────────────────────────────────────────────────────────────
            # A10  Server-Side Request Forgery (SSRF)
            # ──────────────────────────────────────────────────────────────────────
            {
                "id": "A10",
                "name": "Server-Side Request Forgery",
                "patterns": [
                    _p(
                        r'QNetworkRequest\s+\w+\s*\(\s*QUrl\s*\(\s*\w+\s*\+\s*\w+',
                        "Dynamic URL built from variables for outbound request — possible SSRF.",
                        "Validate hostname or use a whitelist before making network requests.",
                        "medium",
                    ),
                ],
            },
        ]
        return RULES
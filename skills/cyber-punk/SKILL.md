---
name: cyber-punk
description: >
  Use when analyzing project security, checking for CVE/CWE vulnerabilities,
  scanning for insecure code patterns, generating exploit PoCs, or hardening
  a codebase. Triggers on: "security audit", "vulnerability scan", "CVE",
  "CWE", "penetration test", "security check", "harden", "exploit",
  "insecure code", "security review", "OWASP", "find vulnerabilities"
user-invocable: true
argument-hint: "[project-path]"
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Agent
  - Edit
  - Write
  - TodoWrite
---

# Security Vulnerability Scanner

Automated security vulnerability analysis for any project. Fetches CVE/CWE data from NVD (NIST), scans code for vulnerable patterns, generates proof-of-concept exploit scripts, and applies fixes inline.

**Scope**: Authorized security testing, defensive security, CTF challenges, and educational contexts only.

## Prerequisites

Before starting, verify:

1. **Python 3.8+**: Run `python3 --version`. If missing, inform user.
2. **requests library**: Run `python3 -c "import requests"`. If ImportError, tell user: `pip install requests`
3. **NVD API Key** (optional but recommended):
   - Check `echo $NVD_API_KEY`
   - Without key: 5 requests per 30 seconds (slow for large projects)
   - With key: 50 requests per 30 seconds
   - Get free key at: https://nvd.nist.gov/developers/request-an-api-key
   - If no key is set, inform user about rate limits and proceed

## Checklist

You MUST create a TodoWrite task for each phase and complete them in order:

1. Phase 1: DETECT — Auto-detect project stack
2. Phase 2: FETCH — Query NVD API for CVE/CWE data
3. Phase 3: ANALYZE — Scan code with 3 parallel subagents
4. Phase 4: INPUT VALIDATION — Analyze all user input fields, verify sanitization and validation
5. Phase 5: POC — Generate exploit scripts (requires user confirmation)
6. Phase 6: REPORT — Generate security report (report only, no code changes)

---

## Phase 1: DETECT (Stack Detection)

**Goal**: Identify every language, framework, and dependency in the project.

### Steps

1. Use Glob to search for manifest files in the project root and subdirectories:
   ```
   Glob: **/package.json, **/yarn.lock, **/pnpm-lock.yaml
   Glob: **/requirements.txt, **/Pipfile, **/pyproject.toml, **/setup.py, **/setup.cfg
   Glob: **/go.mod, **/go.sum
   Glob: **/Cargo.toml, **/Cargo.lock
   Glob: **/pom.xml, **/build.gradle, **/build.gradle.kts
   Glob: **/composer.json, **/composer.lock
   Glob: **/Gemfile, **/Gemfile.lock
   Glob: **/CMakeLists.txt, **/Makefile, **/meson.build
   ```

2. For each manifest found, use Read to extract dependencies with versions:
   - **package.json**: Parse `dependencies` and `devDependencies` objects
   - **requirements.txt**: Parse each line as `package==version` or `package>=version`
   - **pyproject.toml**: Parse `[project.dependencies]` and `[project.optional-dependencies]`
   - **go.mod**: Parse `require` block entries
   - **Cargo.toml**: Parse `[dependencies]` section
   - **pom.xml**: Parse `<dependency>` elements for groupId, artifactId, version
   - **build.gradle**: Parse `implementation`, `api`, `compile` dependency declarations
   - **composer.json**: Parse `require` and `require-dev` objects
   - **Gemfile**: Parse `gem` declarations

3. Also detect configuration files:
   ```
   Glob: **/.env, **/.env.*, **/Dockerfile, **/docker-compose.yml
   Glob: **/.github/workflows/*.yml, **/.gitlab-ci.yml
   Glob: **/nginx.conf, **/apache.conf, **/httpd.conf
   ```

4. Build the detection result as a structured summary:
   ```
   Detected Stack:
   - Languages: [javascript, python]
   - Frameworks: [express@4.18.0, django@4.2.0]
   - Dependencies: [{name: "lodash", version: "4.17.20"}, ...]
   - Config files: [Dockerfile, .env, .github/workflows/ci.yml]
   ```

### Multi-Language Projects

If multiple manifest files are found (e.g., package.json AND requirements.txt), treat each as a separate stack. Run Phase 2 and Phase 3 for EACH stack independently.

### Output

Present the detection results to the user and proceed to Phase 2.

---

## Phase 2: FETCH (NVD API Query)

**Goal**: Retrieve CVE and CWE data relevant to the detected dependencies.

### Steps

1. Construct the dependencies JSON from Phase 1 output:
   ```json
   {"express": "4.17.1", "lodash": "4.17.20"}
   ```

2. Determine the skill's asset path. The nvd-fetcher.py script is at:
   ```
   ${CLAUDE_PLUGIN_ROOT}/skills/cyber-punk/assets/nvd-fetcher.py
   ```

3. Run the NVD fetcher via Bash:
   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/skills/cyber-punk/assets/nvd-fetcher.py \
     --dependencies '{"express": "4.17.1", "lodash": "4.17.20"}' \
     --language javascript \
     --output /tmp/nvd-scan-results.json
   ```
   If user has an API key:
   ```bash
   python3 ${CLAUDE_PLUGIN_ROOT}/skills/cyber-punk/assets/nvd-fetcher.py \
     --dependencies '...' \
     --language javascript \
     --api-key "$NVD_API_KEY" \
     --output /tmp/nvd-scan-results.json
   ```

4. For multi-language projects, run the fetcher once per language stack.

5. Read the output JSON file to get the CVE/CWE results.

### Error Handling

- **Python not found**: Report error, suggest installation, skip to Phase 3 (code-only scan)
- **requests not installed**: Report error, suggest `pip install requests`, skip to Phase 3
- **NVD API unreachable**: Report network error, skip dependency CVE check, proceed with Phase 3 code pattern scan only
- **Rate limited (403/429)**: The script handles this internally with backoff. If it still fails, report partial results.
- **No dependencies detected**: Skip Phase 2 entirely, proceed to Phase 3

### Output

Present CVE findings summary to user:
```
NVD Results:
- X CVEs found across Y dependencies
- Critical: N | High: N | Medium: N | Low: N
```

---

## Phase 3: ANALYZE (Parallel Code Scanning)

**Goal**: Scan the project source code for actual vulnerabilities. Launch 3 subagents in parallel.

### IMPORTANT: Launch all 3 subagents in a SINGLE message using the Agent tool

Use the Agent tool to spawn all 3 subagents in ONE message (parallel execution). Each subagent must receive ALL context it needs — subagents have no access to the parent conversation.

#### Subagent 1: Dependency Vulnerability Matcher

```
Agent({
  description: "Dependency CVE analysis",
  prompt: "You are a dependency vulnerability analyst. Analyze this project for known CVE vulnerabilities in its dependencies.

  PROJECT PATH: {project_path}
  LANGUAGE: {language}
  
  DEPENDENCY CVEs TO VERIFY:
  {paste the dependency_cves array from Phase 2 output}

  For each CVE in the list:
  1. Use Grep to search for imports/requires of the affected package in the codebase
  2. Determine if the vulnerable function or feature is actually USED (not just imported)
  3. Rate the exposure: is this in a public-facing API, internal tool, or test code?
  4. Check if the installed version is truly in the affected range

  OUTPUT: A structured report with this format for each confirmed vulnerability:
  - CVE ID
  - Package name and installed version
  - Affected version range
  - CVSS score and severity
  - Files where the vulnerable package is used (with line numbers)
  - Exposure level (public/internal/test)
  - Whether the vulnerable function is actually called
  - Confidence: HIGH (function called in prod code) / MEDIUM (package imported but usage unclear) / LOW (only in tests/dev)
  
  If no CVEs were provided or none are confirmed, report that clearly."
})
```

#### Subagent 2: CWE Code Pattern Scanner

```
Agent({
  description: "CWE code pattern scan",
  prompt: "You are a code security pattern scanner. Scan this project's source code for vulnerable patterns matching known CWEs.

  PROJECT PATH: {project_path}
  LANGUAGE: {language}

  First, Read the CWE pattern database at:
  ${CLAUDE_PLUGIN_ROOT}/skills/cyber-punk/assets/cwe-patterns.json

  Then, for each CWE relevant to {language}:
  1. Use Grep with each regex pattern from the 'patterns' array
  2. For each match, read the surrounding context (5 lines before/after)
  3. Check if any 'false_positive_signals' patterns are present in the context
  4. If false positive signals found, skip this match
  5. If the pattern is confirmed vulnerable, record it

  OUTPUT: A structured report with this format for each confirmed vulnerability:
  - CWE ID and name
  - Severity
  - File path and line number
  - The vulnerable code snippet (3-5 lines)
  - Why it's vulnerable (reference the CWE description)
  - Suggested fix (from safe_alternatives)
  - Confidence: HIGH (clearly vulnerable) / MEDIUM (likely vulnerable but context unclear) / LOW (possible but needs manual review)
  
  Do NOT report matches where false positive signals clearly indicate safe code.
  Be thorough — scan the entire codebase, not just a few files."
})
```

#### Subagent 3: Configuration & Infrastructure Scanner

```
Agent({
  description: "Config security scan",
  prompt: "You are a configuration and infrastructure security scanner. Analyze this project for insecure configurations.

  PROJECT PATH: {project_path}
  LANGUAGE: {language}
  CONFIG FILES DETECTED: {list from Phase 1}

  Scan for ALL of the following:

  1. SECURITY HEADERS: Search for HTTP response configuration. Check for missing:
     - Content-Security-Policy (CSP)
     - Strict-Transport-Security (HSTS)
     - X-Frame-Options / X-Content-Type-Options / X-XSS-Protection
     - Referrer-Policy
     Use Grep to find header configuration in server setup files.

  2. DEBUG MODE: Search for debug/development mode enabled:
     - Grep for: DEBUG\s*=\s*True, NODE_ENV.*development, app.debug
     - Check if these are in production config files

  3. CORS: Search for CORS configuration:
     - Grep for: Access-Control-Allow-Origin.*\*, cors\(\{.*origin.*\*
     - Wildcard CORS origins are a vulnerability

  4. COOKIES: Search for cookie configuration:
     - Missing Secure flag, HttpOnly flag, SameSite attribute
     - Grep for: cookie, session, Set-Cookie

  5. SECRETS IN CODE: Search for hardcoded secrets:
     - Grep for: password\s*=\s*['\"], api_key\s*=\s*['\"], secret\s*=\s*['\"], token\s*=\s*['\"]
     - Check .env files tracked in git (use: git ls-files .env)
     - Look for AWS keys, private keys, database connection strings

  6. DOCKER: If Dockerfile exists:
     - Running as root (no USER directive)
     - Exposed unnecessary ports
     - Using latest tag instead of pinned versions
     - Secrets in build args

  7. CI/CD: If workflow files exist:
     - Secrets in plain text
     - Unpinned action versions
     - Overly permissive permissions

  8. TLS/SSL: Check for:
     - HTTP URLs in production config (should be HTTPS)
     - Disabled certificate verification (verify=False, NODE_TLS_REJECT_UNAUTHORIZED=0)

  9. FILE PERMISSIONS: Check for:
     - chmod 777, chmod 666, world-readable/writable settings
     - Permissive umask values

  OUTPUT: A structured report with this format for each issue:
  - Category (from the list above)
  - Severity (CRITICAL/HIGH/MEDIUM/LOW)
  - File path and line number
  - Current insecure value/configuration
  - Recommended secure value/configuration
  - Explanation of the risk"
})
```

### After Subagents Complete

1. Collect all findings from the 3 subagents
2. Merge into a single vulnerability list
3. De-duplicate (same file:line found by multiple subagents)
4. Sort by severity (CRITICAL first)
5. Present summary to user:
   ```
   Analysis Complete:
   - Dependency vulnerabilities: X
   - Code pattern vulnerabilities: Y
   - Configuration issues: Z
   - Total: N findings
   ```

### Decision Gate

If total findings = 0:
- Report clean scan, proceed to Phase 4 (input validation is always performed)

If total findings > 0:
- Present the findings summary and proceed to Phase 4

---

## Phase 4: INPUT VALIDATION (User Input Sanitization & Validation Audit)

**Goal**: Find every point where user input enters the application and verify that it is properly sanitized AND validated before being used.

Sanitization and validation are different and BOTH are required:
- **Sanitization**: cleaning/escaping input to prevent injection (e.g., HTML encoding, SQL escaping)
- **Validation**: verifying input meets expected constraints (e.g., type, length, format, range, allowed values)

### Steps

1. **Identify all input entry points** — Use Grep to find every place where external/user input enters the application:

   **HTTP/API inputs**:
   ```
   Grep: req\.body, req\.query, req\.params, req\.headers, req\.cookies
   Grep: request\.form, request\.args, request\.json, request\.data, request\.files
   Grep: r\.FormValue, r\.URL\.Query, r\.Header, r\.Body
   Grep: @RequestParam, @RequestBody, @PathVariable, @RequestHeader
   Grep: \$_GET, \$_POST, \$_REQUEST, \$_COOKIE, \$_FILES, \$_SERVER
   Grep: params\[, params\.require, params\.permit
   ```

   **Form/UI inputs**:
   ```
   Grep: getElementById|querySelector|getElementsByName|FormData
   Grep: <input|<textarea|<select|contenteditable
   Grep: onChange|onSubmit|onInput|handleChange|handleSubmit
   Grep: v-model|ng-model|\[ngModel\]|bind:value
   ```

   **File system inputs**:
   ```
   Grep: upload|multer|formidable|busboy|multipart
   Grep: readFile.*req|readFile.*param|open.*request
   ```

   **Database/external inputs**:
   ```
   Grep: process\.env|os\.environ|env\.|getenv
   Grep: argv|sys\.argv|os\.Args|args\[
   Grep: stdin|readline|input\(|Scanner\(System\.in
   ```

   **WebSocket/real-time inputs**:
   ```
   Grep: socket\.on|ws\.on|message.*event\.data
   ```

2. **For each input entry point found, trace the data flow** — Read the surrounding code (20-30 lines) to determine:

   a) **Is the input VALIDATED?** Check for:
   - Type checking (is it a string, number, boolean, etc.?)
   - Length/size limits (max length, max file size)
   - Format validation (regex for email, phone, UUID, date, etc.)
   - Range validation (min/max for numbers, allowed values for enums)
   - Required field checks (null/undefined/empty checks)
   - Schema validation (Joi, Zod, Yup, Pydantic, marshmallow, JSON Schema, etc.)

   b) **Is the input SANITIZED?** Check for:
   - HTML encoding/escaping (DOMPurify, escape(), htmlspecialchars, bleach)
   - SQL parameterization (prepared statements, bound parameters, ORM usage)
   - Shell escaping (shlex.quote, escapeshellarg)
   - Path sanitization (path.normalize, realpath, preventing ../ traversal)
   - URL encoding (encodeURIComponent, urllib.parse.quote)
   - Trim/strip of whitespace and control characters

3. **Classify each input field** into one of these categories:

   | Status | Meaning |
   |--------|---------|
   | SAFE | Both validated AND sanitized appropriately for its usage context |
   | PARTIAL | Has validation OR sanitization, but not both |
   | UNSAFE | Neither validated nor sanitized — raw user input used directly |
   | UNKNOWN | Could not determine from static analysis — needs manual review |

4. **Build the input validation report** — For each input field, record:
   - File and line number
   - Input source (HTTP body, query param, file upload, CLI arg, etc.)
   - What the input is used for (database query, file path, HTML render, shell command, API call, etc.)
   - Validation status (what checks exist, what's missing)
   - Sanitization status (what escaping exists, what's missing)
   - Risk level: CRITICAL (used in SQL/shell/HTML without any protection), HIGH (partial protection), MEDIUM (mostly protected, minor gaps), LOW (well protected)
   - Specific recommendation for what validation/sanitization to add

### Language-Specific Patterns

**JavaScript/TypeScript**:
- Good: Joi, Zod, Yup, express-validator, class-validator, DOMPurify, helmet
- Bad: direct `req.body.xxx` usage without validation middleware, `innerHTML = userInput`

**Python**:
- Good: Pydantic, marshmallow, WTForms, Django Forms, bleach, markupsafe
- Bad: `request.form['x']` used directly in f-strings, `eval(input)`, `os.system(request.data)`

**Go**:
- Good: go-playground/validator, custom validation functions, html/template (auto-escapes)
- Bad: `r.FormValue()` used directly in `fmt.Sprintf` for SQL, `template.HTML()` with user data

**Java**:
- Good: Bean Validation (JSR 380), Hibernate Validator, OWASP Java Encoder, PreparedStatement
- Bad: `@RequestParam` without `@Valid`, string concatenation in JPQL/HQL

**PHP**:
- Good: filter_input(), filter_var(), htmlspecialchars(), prepared statements (PDO)
- Bad: `$_GET['x']` directly in `echo` or `mysql_query()`

**Ruby**:
- Good: Strong Parameters, ActiveModel validations, ERB auto-escaping, sanitize helper
- Bad: `params[:x]` without permit, `raw` helper with user data, string interpolation in SQL

### Output

Present input validation findings as a table:
```
Input Validation Audit:
Found N input entry points across M files

| # | File:Line | Source | Used For | Validated | Sanitized | Status | Risk |
|---|-----------|--------|----------|-----------|-----------|--------|------|
| 1 | src/api/users.js:15 | req.body.email | DB query | No | No | UNSAFE | CRITICAL |
| 2 | src/api/users.js:22 | req.body.name | HTML render | Length only | No | PARTIAL | HIGH |
| 3 | src/auth/login.js:8 | req.body.password | bcrypt hash | Yes (Joi) | Yes (trim) | SAFE | LOW |
```

Add these findings to the vulnerability list for Phase 5 (POC) and Phase 6 (REPORT).

---

## Phase 5: POC (Proof-of-Concept Generation)

**Goal**: Generate executable exploit scripts for each confirmed vulnerability.

### Safety Constraints — NON-NEGOTIABLE

- PoCs target ONLY the local project instance
- NO network-facing exploits or remote targets
- NO destructive payloads (no data deletion, no file system damage outside project dir)
- Every PoC includes a prominent safety warning in the header
- Every PoC includes a `--dry-run` flag that explains the exploit without executing

### Steps

1. Create the `security-pocs/` directory in the project root:
   ```bash
   mkdir -p security-pocs
   ```

2. For each confirmed vulnerability, generate a PoC script:
   - **Language**: Same as the target project
   - **Naming**: `poc-{cve-or-cwe-id}-{short-description}.{ext}`
   - **Example**: `poc-cwe-89-sql-injection.js`, `poc-cve-2021-23337-lodash-command-injection.js`

3. Each PoC MUST include:
   ```
   /**
    * ============================================================
    * SECURITY PROOF-OF-CONCEPT — FOR AUTHORIZED TESTING ONLY
    * ============================================================
    * 
    * Vulnerability: {CWE/CVE ID} - {name}
    * Location: {file_path}:{line_number}
    * Severity: {severity} (CVSS {score})
    * 
    * Description: {what the vulnerability is}
    * 
    * Usage:
    *   node poc-cwe-89-sql-injection.js              # Execute exploit
    *   node poc-cwe-89-sql-injection.js --dry-run     # Show what would happen
    * 
    * Expected Result: {what successful exploitation looks like}
    * 
    * WARNING: This script is for authorized security testing only.
    * Do not use against systems you do not own or have permission to test.
    * ============================================================
    */
   ```

4. The PoC body should:
   - Set up minimal required context (mock server, test data, etc.)
   - Demonstrate the exploit with a clear payload
   - Show the vulnerable behavior
   - In `--dry-run` mode: print the explanation without executing the exploit

5. Use Write tool to create each PoC file.

---

## Phase 6: REPORT (Security Report Generation)

**Goal**: Generate a comprehensive, human-readable security report. This phase produces ONLY the report — no code modifications, no inline fixes. The report includes findings from Phase 3 (code/dependency/config analysis), Phase 4 (input validation audit), and Phase 5 (PoC scripts).

### Report Language

The report MUST be written in the user's language. To determine the language:
1. Check the user's memory files at `~/.claude/projects/*/memory/` for language preferences
2. If no memory available, detect the language from the user's messages in the current conversation
3. If still unclear, default to English

All section titles, descriptions, explanations, and recommendations must be in the detected language. Only CVE/CWE IDs, code snippets, and technical identifiers stay in English.

### Steps

1. Read the report template:
   ```
   Read: ${CLAUDE_PLUGIN_ROOT}/skills/cyber-punk/assets/report-template.md
   ```

2. Generate the report in the user's language by filling in all sections with actual data from Phases 1-5. Sort findings by severity (CRITICAL first). Include a dedicated "Input Validation Audit" section with the table from Phase 4.

3. **For EACH vulnerability, include these three mandatory sections:**

   #### a) WHY it happens (Root Cause)
   Explain the underlying programming mistake or design flaw that introduces the vulnerability. Be specific to the actual code found — don't give generic textbook definitions. Reference the exact file, line, and code pattern.
   
   Example: "This happens because the function at `src/api/users.js:42` builds the SQL query by concatenating the `userId` parameter directly into the query string instead of using parameterized placeholders. The developer likely did this for simplicity, but it means any string passed as `userId` becomes part of the SQL command."

   #### b) HOW it happens (Attack Vector)
   Describe step-by-step how an attacker would exploit this vulnerability. Be concrete: what request they send, what payload they craft, what endpoint they target. Reference the PoC script if one was generated.
   
   Example: "An attacker sends a GET request to `/api/users?id=1 OR 1=1 --`. The application passes this value directly into the query: `SELECT * FROM users WHERE id = 1 OR 1=1 --`. The `OR 1=1` condition makes the WHERE clause always true, returning every user record. The `--` comments out the rest of the query, bypassing any additional filters."

   #### c) WHAT could happen (Impact & Consequences)
   Describe the realistic worst-case scenario if this vulnerability is exploited in production. Cover data exposure, system compromise, business impact, legal/compliance implications.
   
   Example: "An attacker could extract the entire user database including emails, hashed passwords, and personal data. With this data they could perform credential stuffing attacks on other services, sell the data on the dark web, or use the information for targeted phishing. Under GDPR, this breach could result in fines up to 4% of annual revenue. Additionally, the attacker could modify or delete database records, potentially corrupting critical business data."

4. Write the report:
   ```
   Write: security-report-YYYY-MM-DD.md (in project root)
   ```

5. Present final summary to user (in their language):
   ```
   Security Scan Complete!
   
   Report: security-report-YYYY-MM-DD.md
   PoC scripts: security-pocs/ (N scripts)
   
   Findings:
   - Critical: X | High: Y | Medium: Z | Low: W
   - Dependency vulnerabilities: N
   - Code pattern vulnerabilities: M  
   - Configuration issues: K
   - Input fields audited: J (UNSAFE: A | PARTIAL: B | SAFE: C)
   
   Next steps:
   - Review the report for detailed analysis of each vulnerability
   - Prioritize fixes based on severity and exposure
   - Run the PoC scripts (with --dry-run) to verify findings
   ```

### IMPORTANT: Phase 5 does NOT modify any project files. It only creates the report.

---

## Red Flags

These rationalizations mean STOP — you're cutting corners:

| Thought | Reality |
|---------|---------|
| "This pattern is probably fine" | VERIFY it. Check context, check sanitization. |
| "This dependency isn't directly exposed" | Transitive vulnerabilities are real. Check usage. |
| "This is just a dev dependency" | Dev deps can be exploited in CI/CD and build pipelines. |
| "The version might not be affected" | Check the version range precisely. Don't guess. |
| "This is just test code" | Report it with LOW confidence, but still report it. |
| "I'll skip this CWE, it's unlikely" | Scan ALL relevant CWEs. That's the point of the tool. |
| "The false positive rate is too high" | Tune patterns, don't skip the scan. |
| "I don't need to check config files" | Config vulnerabilities are among the most common. Always check. |

## Error Recovery

| Error | Action |
|-------|--------|
| Python not installed | Report, suggest installation, proceed with Phase 3 only (no NVD API) |
| requests library missing | Report, suggest `pip install requests`, proceed with Phase 3 only |
| NVD API unreachable | Report, skip Phase 2 dependency CVEs, proceed with code scan |
| NVD rate limited after retries | Report partial results, continue with what was fetched |
| No manifest files found | Skip Phase 2, proceed with Phase 3 code/config scan only |
| Subagent fails | Proceed with results from other subagents, report partial scan |
| No vulnerabilities found | Generate clean report, congratulate user |

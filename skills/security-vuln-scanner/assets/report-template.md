# Security Vulnerability Report

<!-- LANGUAGE: This entire report must be written in the user's language.
     Detect the language from the user's messages or memory.
     Only CVE/CWE IDs, code snippets, and technical identifiers stay in English.
     All titles, descriptions, explanations, and recommendations: user's language. -->

**Project**: {{project_name}}
**Date**: {{date}}
**Stack**: {{languages_and_frameworks}}
**Scan Duration**: {{scan_duration}}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {{critical_count}} |
| HIGH     | {{high_count}} |
| MEDIUM   | {{medium_count}} |
| LOW      | {{low_count}} |
| **Total**| **{{total_count}}** |

**Breakdown**:
- Dependencies with known CVEs: {{dep_cve_count}}
- Code patterns matching CWEs: {{code_cwe_count}}
- Configuration/infrastructure issues: {{config_issue_count}}

---

## Dependency Vulnerabilities

<!-- For each dependency CVE found, add a row to this table.
     Sort by severity (CRITICAL first), then by CVSS score descending. -->

| Package | Installed Version | CVE | CVSS | Severity | Fix Version |
|---------|-------------------|-----|------|----------|-------------|

### Dependency Update Commands

<!-- For each affected dependency, provide the exact command to update it.
     Example:
     ```bash
     npm install lodash@4.17.21
     ``` -->

---

## Code Vulnerabilities

<!-- For each code vulnerability found, create a subsection using this format.
     Group by CWE ID. Sort by severity descending within each group.
     
     MANDATORY: Each vulnerability MUST include the three sections below:
     1. WHY it happens (Root Cause)
     2. HOW it happens (Attack Vector)
     3. WHAT could happen (Impact & Consequences)
     
     Be specific to the ACTUAL code found. No generic textbook definitions. -->

### [CWE-XXX] Vulnerability Name

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW (CVSS X.X)
- **File**: `path/to/file.ext:line_number`
- **PoC Script**: `security-pocs/poc-cwe-xxx-short-description.ext`

**Vulnerable Code**:
```
// The vulnerable code snippet with surrounding context
```

#### WHY it happens (Root Cause)

<!-- Explain the specific programming mistake or design flaw in THIS code.
     Reference the exact file, line, and code pattern.
     Be concrete: what did the developer do wrong and why it creates a weakness.
     
     Example: "This happens because the function at `src/api/users.js:42` builds
     the SQL query by concatenating the `userId` parameter directly into the query
     string instead of using parameterized placeholders. The developer likely did
     this for simplicity, but it means any string passed as `userId` becomes part
     of the SQL command." -->

#### HOW it happens (Attack Vector)

<!-- Describe step-by-step how an attacker would exploit this vulnerability.
     Be concrete: what request they send, what payload they craft, what endpoint
     they target. Reference the PoC script if one was generated.
     
     Example: "An attacker sends a GET request to `/api/users?id=1 OR 1=1 --`.
     The application passes this value directly into the query:
     `SELECT * FROM users WHERE id = 1 OR 1=1 --`. The `OR 1=1` condition makes
     the WHERE clause always true, returning every user record. The `--` comments
     out the rest of the query, bypassing any additional filters." -->

#### WHAT could happen (Impact & Consequences)

<!-- Describe the realistic worst-case scenario if exploited in production.
     Cover ALL applicable areas:
     - Data exposure (what data leaks, how sensitive)
     - System compromise (can the attacker gain further access?)
     - Business impact (downtime, reputation, customer trust)
     - Legal/compliance (GDPR, PCI-DSS, HIPAA implications)
     - Lateral movement (can this be chained with other vulnerabilities?)
     
     Example: "An attacker could extract the entire user database including emails,
     hashed passwords, and personal data. With this data they could perform
     credential stuffing attacks on other services. Under GDPR, this breach could
     result in fines up to 4% of annual revenue. Additionally, the attacker could
     modify or delete database records, corrupting critical business data." -->

---

## Configuration & Infrastructure Issues

<!-- For each configuration issue, create a subsection. Sort by severity.
     Same three mandatory sections (WHY/HOW/WHAT) apply here. -->

### Issue: Issue Title

- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **File**: `path/to/config/file`
- **Category**: Security Headers / CORS / Cookies / Secrets / Docker / TLS / Permissions / Debug Mode

**Current Configuration**:
```
// Show the current insecure configuration
```

**Recommended Configuration**:
```
// Show the secure configuration
```

#### WHY it happens
<!-- Why this misconfiguration exists -->

#### HOW it happens
<!-- How an attacker would exploit it -->

#### WHAT could happen
<!-- Realistic impact if exploited -->

---

## Recommendations

### Priority Actions

<!-- Rank all findings by:
     1. Severity (CRITICAL first)
     2. Exploitability (easily exploitable first)
     3. Exposure (public-facing first)
     
     Present as a numbered checklist with concrete fix instructions. -->

1. [ ] **[CRITICAL]** Fix description — `file:line`
2. [ ] **[HIGH]** Fix description — `file:line`
3. [ ] **[MEDIUM]** Fix description — `file:line`

### Best Practices for {{language}}

<!-- Include 3-5 stack-specific security best practices that are relevant
     to the vulnerabilities found. Only actionable recommendations
     that apply to this specific project. -->

---

## Appendix: Scan Details

- **Scanner**: Claude Code Security Vulnerability Scanner
- **NVD API**: {{api_key_used}} (key used: yes/no)
- **CWE Patterns Checked**: {{cwe_count}} CWEs
- **Files Scanned**: {{files_scanned_count}}
- **Dependencies Checked**: {{deps_checked_count}}

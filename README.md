# Cyber Punk (Security Vulnerability Scanner)

A Claude Code plugin that automates security vulnerability analysis for any project.

## Example Use Cases

- **Pre-deploy audit**: Run a full scan before shipping to production to catch SQL injections, XSS, hardcoded secrets, and misconfigurations
- **Dependency check**: Discover which of your npm/pip/cargo packages have known CVEs and what versions fix them
- **Code review security pass**: Scan a PR branch for insecure patterns — command injection, path traversal, weak crypto — before merging
- **Legacy codebase hardening**: Point it at an inherited project to get a prioritized list of vulnerabilities with root cause analysis
- **Compliance preparation**: Generate a detailed security report (with WHY/HOW/WHAT analysis) for GDPR, PCI-DSS, or SOC 2 audits
- **Security training**: Use the generated PoC scripts (with `--dry-run`) to understand how real exploits work on your own code
- **CI/CD pipeline gate**: Integrate the scan into your workflow to block deploys when critical vulnerabilities are found

## What it does

1. **Detects** your project's tech stack, languages, and dependencies
2. **Fetches** known CVE/CWE data from the NIST National Vulnerability Database
3. **Scans** your code for vulnerable patterns using 576 regex rules across 20 CWEs
4. **Generates** proof-of-concept exploit scripts for confirmed vulnerabilities
5. **Reports** a detailed security analysis with root cause, attack vector, and impact for each finding

## Supported Languages

JavaScript/TypeScript, Python, Go, Java, Rust, PHP, Ruby, C/C++

## Prerequisites

- Python 3.8+
- `requests` library: `pip install requests`
- NVD API key (optional, recommended): [Request one here](https://nvd.nist.gov/developers/request-an-api-key)

Set your API key:
```bash
export NVD_API_KEY="your-key-here"
```

## Installation

```bash
claude plugin install security-vuln-scanner
```

Or test locally:
```bash
claude --plugin-dir /path/to/SkillCyberPunk
```

## Usage

Invoke the skill in any project:

```
/security-vuln-scanner
```

Or ask naturally:

```
"Scan this project for security vulnerabilities"
"Check for CVEs in my dependencies"
"Run a security audit"
"Find insecure code patterns"
```

## Output

- `security-report-YYYY-MM-DD.md` — Full vulnerability report with WHY/HOW/WHAT analysis, severity scores, and fix recommendations
- `security-pocs/` — Proof-of-concept exploit scripts (with `--dry-run` safety mode)

## CWE Coverage

| Category | CWEs |
|----------|------|
| Injection | CWE-89 (SQL), CWE-78 (OS Command), CWE-79 (XSS) |
| Traversal & SSRF | CWE-22 (Path Traversal), CWE-918 (SSRF) |
| Auth & Access | CWE-287, CWE-306, CWE-862 |
| Data Exposure | CWE-200, CWE-798 (Hardcoded Creds) |
| Deserialization | CWE-502 |
| Crypto | CWE-327 (Weak Crypto) |
| Web | CWE-352 (CSRF), CWE-434 (File Upload), CWE-611 (XXE) |
| Memory Safety | CWE-119 (Buffer Overflow), CWE-416 (Use After Free), CWE-190 (Integer Overflow) |
| Config | CWE-732 (Permissions), CWE-400 (Resource Consumption) |

## License

MIT

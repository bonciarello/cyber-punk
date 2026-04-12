# Changelog

## [1.0.0] - 2026-04-11

### Added
- Initial release of cyber-punk skill
- NVD API integration for CVE/CWE fetching (nvd-fetcher.py)
- CWE pattern database with 20 CWEs across 9 languages (576 regex patterns)
- 5-phase analysis pipeline: DETECT, FETCH, ANALYZE, POC, REMEDIATE
- Parallel code scanning with 3 subagents (dependency CVEs, code patterns, config issues)
- Proof-of-concept exploit script generation with --dry-run safety flag
- Markdown security report generation with Before/After code diffs
- Inline code fix application
- Support for: JavaScript/TypeScript, Python, Go, Java, Rust, PHP, Ruby, C/C++

"""Vulnerability Analyzer - Detects common security vulnerability patterns in code."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.models.schemas import Severity, VulnerabilityFinding, VulnerabilityReport


# ── Vulnerability pattern definitions ──────────────────────────────────────

VULNERABILITY_PATTERNS: list[dict[str, str | Severity | list[str]]] = [
    # SQL Injection
    {
        "name": "SQL Injection",
        "type": "SQL Injection",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-89",
        "patterns": [
            # Python
            r"""(?:execute|cursor\.execute)\s*\(\s*f['"]\s*SELECT.*\{""",
            r"""(?:execute|cursor\.execute)\s*\(\s*['"].*%s.*['"]\s*%""",
            r"""(?:execute|cursor\.execute)\s*\(\s*['"].*\+.*\+.*['"]""",
            r"""(?:execute|cursor\.execute)\s*\(\s*['"].*\+\s*\w+""",
            # JavaScript / TypeScript
            r"""(?:query|execute)\s*\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE).*\$\{""",
            r"""(?:query|execute)\s*\(\s*`.*\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)""",
            r"""\.query\s*\(\s*['"].*\+\s*\w+""",
            # F-string con SQL interpolado, incluso cuando la query se arma
            # en una variable y se ejecuta después (patrón muy común).
            r"""(?i)f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)\s[^'"]*\{""",
            r"""(?i)f['"][^'"]*\{[^}]+\}[^'"]*(?:SELECT|INSERT|UPDATE|DELETE)\s""",
            # Generic
            r"""(?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\+\s*\w+""",
            r"""(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\$\{""",
        ],
        "description": "User input is concatenated directly into a SQL query, allowing SQL injection attacks.",
        "recommendation": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
    },
    # XSS (Cross-Site Scripting)
    {
        "name": "Cross-Site Scripting (XSS)",
        "type": "XSS",
        "severity": Severity.HIGH,
        "cwe": "CWE-79",
        "patterns": [
            # React (dangerouslySetInnerHTML)
            r"""dangerouslySetInnerHTML\s*=\s*\{""",
            # Raw HTML insertion
            r"""\.innerHTML\s*=\s*""",
            r"""\.outerHTML\s*=\s*""",
            r"""document\.write\s*\(""",
            # Template injection
            r"""\{\{.*\|.*safe.*\}\}""",
            r"""\{\{.*!\s*html\s*.*\}\}""",
            # Python
            r"""mark_safe\s*\(""",
            r"""SafeString\s*\(""",
        ],
        "description": "Untrusted content is rendered as raw HTML, enabling XSS attacks.",
        "recommendation": "Use text content instead of HTML. If HTML is necessary, sanitize with DOMPurify or similar.",
    },
    # Command Injection
    {
        "name": "Command Injection",
        "type": "Command Injection",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-78",
        "patterns": [
            # Python
            r"""os\.system\s*\(""",
            r"""os\.popen\s*\(""",
            r"""subprocess\.call\s*\(\s*['"].*\+""",
            r"""subprocess\.Popen\s*\(\s*['"].*\+""",
            r"""subprocess\.run\s*\(\s*[^)]*\bshell\s*=\s*True""",
            # Node.js
            r"""exec\s*\(\s*['"`].*\$\{""",
            r"""execSync\s*\(\s*['"`].*\$\{""",
            r"""spawn\s*\(\s*[^,]+,\s*[^,]*\+""",
            # Shell
            r"""/bin/(?:ba)?sh\s+-c\s*.*\$\{""",
        ],
        "description": "User input is passed to a system shell command, allowing arbitrary command execution.",
        "recommendation": "Use subprocess with a list of arguments (no shell=True). Validate and sanitize all inputs.",
    },
    # Path Traversal
    {
        "name": "Path Traversal",
        "type": "Path Traversal",
        "severity": Severity.HIGH,
        "cwe": "CWE-22",
        "patterns": [
            r"""open\s*\(\s*(?:request\.|req\.|input).*\+""",
            r"""open\s*\(\s*.*\.\.(?:\/|\\\\)""",
            r"""\.readFile\s*\(.*\+""",
            r"""\.readFileSync\s*\(.*\+""",
            r"""path\.join\s*\([^)]*(?:request|req|params|query|input)""",
            r"""os\.path\.join\s*\([^)]*(?:request|req)""",
        ],
        "description": "User-controlled input is used to construct file paths, potentially allowing access to arbitrary files.",
        "recommendation": "Validate paths against a whitelist. Use os.path.realpath() and verify the resolved path is within expected directory.",
    },
    # SSRF (Server-Side Request Forgery)
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "type": "SSRF",
        "severity": Severity.HIGH,
        "cwe": "CWE-918",
        "patterns": [
            r"""requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|req\.|params|input|query)""",
            r"""http\.get\s*\(\s*(?:request\.|req\.|params)""",
            r"""fetch\s*\(\s*(?:request\.|req\.|params|query)""",
            r"""axios\.(?:get|post)\s*\(\s*(?:request\.|req\.|params)""",
            r"""urllib\.request\.urlopen\s*\(\s*(?:request\.|req\.|input)""",
        ],
        "description": "User-controlled URL is used for server-side HTTP requests, potentially accessing internal services.",
        "recommendation": "Validate and whitelist target URLs. Block requests to internal/private IP ranges.",
    },
    # Insecure Deserialization
    {
        "name": "Insecure Deserialization",
        "type": "Deserialization",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-502",
        "patterns": [
            r"""pickle\.loads?\s*\(""",
            r"""yaml\.load\s*\([^)]*(?:\bLoader\s*=\s*yaml\.FullLoader)?\s*\)""",
            r"""yaml\.unsafe_load\s*\(""",
            r"""marshal\.loads?\s*\(""",
            r"""unserialize\s*\(""",
            r"""JSON\.parse\s*\(.*(?:req|request)\.body""",
        ],
        "description": "Untrusted data is deserialized without proper validation, potentially leading to remote code execution.",
        "recommendation": "Avoid deserializing untrusted data. Use safe formats like JSON. If pickle is needed, validate input first.",
    },
    # Insecure Use of eval
    {
        "name": "Use of eval()",
        "type": "Code Injection",
        "severity": Severity.HIGH,
        "cwe": "CWE-95",
        "patterns": [
            r"""\beval\s*\(\s*(?:request|req|params|input|query|body)""",
            r"""\bexec\s*\(\s*(?:request|req|params|input|query)""",
            r"""\bnew\s+Function\s*\(\s*(?:request|req|params)""",
            r"""\bcompile\s*\(\s*(?:request|req|input).*['"]\s*exec\s*['"]""",
        ],
        "description": "User input is passed to eval/exec, allowing arbitrary code execution.",
        "recommendation": "Never use eval() with user input. Use safer alternatives like ast.literal_eval() for data parsing.",
    },
    # Weak Cryptography
    {
        "name": "Weak Cryptography",
        "type": "Weak Crypto",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-327",
        "patterns": [
            r"""(?:hashlib\.)?md5\s*\(""",
            r"""(?:hashlib\.)?sha1\s*\(""",
            r"""MD5\.Create\s*\(""",
            r"""SHA1\.Create\s*\(""",
            r"""DES\.Create\s*\(""",
            r"""RC4""",
        ],
        "description": "Weak or deprecated cryptographic algorithms are used.",
        "recommendation": "Use modern algorithms: SHA-256+ for hashing, AES-256 for encryption. Never use MD5 or SHA1 for security purposes.",
    },
    # Hardcoded IV / salt
    {
        "name": "Hardcoded Encryption Key",
        "type": "Hardcoded Key",
        "severity": Severity.HIGH,
        "cwe": "CWE-321",
        "patterns": [
            r"""(?i)(?:key|secret|salt|iv)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
            r"""AES\.new\s*\(\s*['"][^'"]{16,}['"]""",
            r"""cipher\s*=\s*\w+\.(?:new|new_from_password)\s*\(\s*['"][^'"]{8,}['"]""",
        ],
        "description": "Encryption keys or initialization vectors are hardcoded in source code.",
        "recommendation": "Store encryption keys in environment variables or a secrets manager, never in source code.",
    },
    # Open Redirect
    {
        "name": "Open Redirect",
        "type": "Open Redirect",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-601",
        "patterns": [
            r"""redirect\s*\(\s*(?:request\.|req\.|params|query|input)""",
            r"""window\.location\s*=\s*(?:request|req|params|query)""",
            r"""window\.location\.href\s*=\s*(?:request|req|params|query)""",
        ],
        "description": "User-controlled input is used in a redirect, potentially redirecting users to malicious sites.",
        "recommendation": "Validate redirect targets against a whitelist of allowed domains.",
    },
    # CORS Misconfiguration
    {
        "name": "CORS Wildcard",
        "type": "CORS",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-942",
        "patterns": [
            r"""Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]""",
            r"""cors\(\s*\)""",
            r"""allow_origins\s*=\s*\[?\s*['"]\*['"]""",
        ],
        "description": "CORS is configured to allow all origins, which may expose the API to cross-origin attacks.",
        "recommendation": "Restrict CORS to specific trusted origins. Never use wildcard (*) in production.",
    },
]


# ── Files to skip ─────────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "bin", "obj",
    ".idea", ".vscode",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
    ".jar", ".exe", ".dll", ".so", ".dylib", ".min.js", ".min.css",
}


class VulnerabilityAnalyzer:
    """Scans source code for common vulnerability patterns."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._compiled = self._compile_patterns()

    def analyze(self) -> VulnerabilityReport:
        """Run full vulnerability analysis."""
        findings = self._scan_code()

        report = VulnerabilityReport(
            findings=findings,
            total_count=len(findings),
        )

        for f in findings:
            if f.severity == Severity.CRITICAL:
                report.critical_count += 1
            elif f.severity == Severity.HIGH:
                report.high_count += 1
            elif f.severity == Severity.MEDIUM:
                report.medium_count += 1
            elif f.severity == Severity.LOW:
                report.low_count += 1

        report.summary = self._generate_summary(report)
        return report

    def _compile_patterns(self) -> list[dict]:
        """Pre-compile all vulnerability patterns."""
        compiled = []
        for vuln in VULNERABILITY_PATTERNS:
            compiled_vulns = []
            for pattern in vuln["patterns"]:
                try:
                    compiled_vulns.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    pass
            compiled.append({
                "name": vuln["name"],
                "type": vuln["type"],
                "severity": vuln["severity"],
                "cwe": vuln["cwe"],
                "description": vuln["description"],
                "recommendation": vuln["recommendation"],
                "regexes": compiled_vulns,
            })
        return compiled

    def _scan_code(self) -> list[VulnerabilityFinding]:
        """Scan all source files for vulnerability patterns."""
        findings: list[VulnerabilityFinding] = []
        seen: set[str] = set()

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in SKIP_EXTENSIONS or ".min." in fname:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except (OSError, UnicodeDecodeError):
                    continue

                if len(content) > 500_000:
                    continue

                rel_path = str(fpath.relative_to(self.root))
                lines = content.splitlines()

                for vuln_info in self._compiled:
                    for line_num, line in enumerate(lines, 1):
                        for regex in vuln_info["regexes"]:
                            if regex.search(line):
                                key = f"{rel_path}:{line_num}:{vuln_info['type']}"
                                if key in seen:
                                    continue
                                seen.add(key)

                                # Get snippet context
                                start = max(0, line_num - 2)
                                end = min(len(lines), line_num + 1)
                                snippet = "\n".join(lines[start:end])

                                findings.append(VulnerabilityFinding(
                                    file_path=rel_path,
                                    line_number=line_num,
                                    vulnerability_type=vuln_info["type"],
                                    severity=vuln_info["severity"],
                                    description=vuln_info["description"],
                                    code_snippet=snippet,
                                    recommendation=vuln_info["recommendation"],
                                    cwe_id=vuln_info["cwe"],
                                ))

        return findings

    def _generate_summary(self, report: VulnerabilityReport) -> str:
        """Generate a human-readable summary."""
        if report.total_count == 0:
            return "✅ No vulnerability patterns detected in the codebase."

        parts = [f"🔴 Found {report.total_count} potential vulnerability pattern(s):"]

        if report.critical_count:
            parts.append(f"  🚨 CRITICAL: {report.critical_count}")
        if report.high_count:
            parts.append(f"  ⚠️  HIGH: {report.high_count}")
        if report.medium_count:
            parts.append(f"  📋 MEDIUM: {report.medium_count}")
        if report.low_count:
            parts.append(f"  ℹ️  LOW: {report.low_count}")

        # Group by type
        by_type: dict[str, int] = {}
        for f in report.findings:
            by_type[f.vulnerability_type] = by_type.get(f.vulnerability_type, 0) + 1

        parts.append("\nBy type:")
        for vtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            parts.append(f"  • {vtype}: {count}")

        return "\n".join(parts)

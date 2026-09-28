"""Security Analyzer - Detects leaked secrets, credentials, API keys, and sensitive data."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.models.schemas import SecretFinding, SecurityReport, Severity


# ── Secret detection patterns ──────────────────────────────────────────────

SECRET_PATTERNS: list[dict[str, str | Severity | list[str]]] = [
    # API Keys
    {
        "name": "API Key",
        "pattern": r"""(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([^'"]{8,})['"]""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "OpenAI API Key",
        "pattern": r"""sk-[a-zA-Z0-9]{20,}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    {
        "name": "Anthropic API Key",
        "pattern": r"""sk-ant-[a-zA-Z0-9-]{20,}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    # AWS
    {
        "name": "AWS Access Key",
        "pattern": r"""(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"""(?i)(aws[_-]?secret[_-]?access[_-]?key|aws_secret)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    # GCP
    {
        "name": "GCP Service Account Key",
        "pattern": r"""-----BEGIN PRIVATE KEY-----""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    # Azure
    {
        "name": "Azure Connection String",
        "pattern": r"""(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    # Generic secrets
    {
        "name": "Secret Key / Token",
        "pattern": r"""(?i)(secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "Bearer Token",
        "pattern": r"""(?i)(bearer|authorization)\s*[:=]\s*['"]?Bearer\s+[A-Za-z0-9._-]{20,}['"]?""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "JWT Token",
        "pattern": r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "Password Assignment",
        "pattern": r"""(?i)(password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]""",
        "severity": Severity.HIGH,
        "cwe": "CWE-259",
    },
    {
        "name": "Database Connection String",
        "pattern": r"""(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'"]{10,}""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "GitHub Token",
        "pattern": r"""ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    {
        "name": "Slack Token",
        "pattern": r"""xox[baprs]-[0-9a-zA-Z-]{10,}""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "Stripe API Key",
        "pattern": r"""(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    {
        "name": "Firebase Key",
        "pattern": r"""(?i)firebase[_-]?key\s*[:=]\s*['"]([^'"]{10,})['"]""",
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    {
        "name": "Private Key Block",
        "pattern": r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-321",
    },
    {
        "name": "SSH Private Key",
        "pattern": r"""-----BEGIN OPENSSH PRIVATE KEY-----""",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-321",
    },
]

# ── Sensitive file patterns ────────────────────────────────────────────────

SENSITIVE_FILE_PATTERNS: list[str] = [
    r"(?i)\.env$",
    # .env.example / .sample / .template son plantillas versionables:
    # reportarlas como fuga sería un falso positivo en casi todo repo.
    r"(?i)\.env\.(?!example$|sample$|template$)\w+$",
    r"(?i)\.env\.local$",
    r"(?i)\.env\.production$",
    r"(?i)\.env\.development$",
    r"(?i)firebase\.json$",
    r"(?i)service[_-]?account\.json$",
    r"(?i)credentials\.json$",
    r"(?i)\.htpasswd$",
    r"(?i)\.netrc$",
    r"(?i)\.ssh/id_[a-z]+$",
    r"(?i)\.pem$",
    r"(?i)\.key$",
    r"(?i)\.cert$",
    r"(?i)\.p12$",
    r"(?i)\.pfx$",
    r"(?i)\.jks$",
    r"(?i)keystore\.jks$",
    r"(?i)docker-compose\.ya?ml$",  # often has passwords
]

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "bin", "obj",
    ".idea", ".vscode",
}


class SecurityAnalyzer:
    """Scans for leaked secrets, credentials, and sensitive files."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._compiled_patterns = self._compile_patterns()

    def analyze(self) -> SecurityReport:
        """Run full security scan."""
        secrets = self._scan_for_secrets()
        env_files = self._find_sensitive_files()
        cert_files = self._find_certificate_files()

        report = SecurityReport(
            secrets_found=secrets,
            secrets_count=len(secrets),
            exposed_env_files=env_files,
            exposed_certificates=cert_files,
            exposed_credentials=[s.file_path for s in secrets if "key" in s.secret_type.lower() or "password" in s.secret_type.lower()],
        )

        report.summary = self._generate_summary(report)
        return report

    # ── Private ────────────────────────────────────────────────────────

    def _compile_patterns(self) -> list[re.Pattern]:
        """Pre-compile all regex patterns."""
        compiled = []
        for p in SECRET_PATTERNS:
            try:
                compiled.append({
                    "regex": re.compile(p["pattern"]),
                    "name": p["name"],
                    "severity": p["severity"],
                    "cwe": p.get("cwe", ""),
                })
            except re.error:
                pass
        return compiled  # type: ignore

    def _scan_for_secrets(self) -> list[SecretFinding]:
        """Walk the project and scan all text files for secrets."""
        findings: list[SecretFinding] = []
        seen: set[str] = set()

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname

                # Skip binary-like files
                if fpath.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".jar", ".exe", ".dll", ".so", ".dylib"):
                    continue

                # Skip minified files
                if ".min." in fname:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except (OSError, UnicodeDecodeError):
                    continue

                # Limit file size to 500KB for performance
                if len(content) > 500_000:
                    continue

                rel_path = str(fpath.relative_to(self.root))

                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern_info in self._compiled_patterns:
                        regex = pattern_info["regex"]
                        matches = regex.finditer(line)

                        for match in matches:
                            # Deduplicate by file + line + pattern
                            key = f"{rel_path}:{line_num}:{pattern_info['name']}"
                            if key in seen:
                                continue
                            seen.add(key)

                            # Get context (surrounding lines)
                            lines = content.splitlines()
                            start = max(0, line_num - 2)
                            end = min(len(lines), line_num + 1)
                            context = "\n".join(lines[start:end])

                            findings.append(SecretFinding(
                                file_path=rel_path,
                                line_number=line_num,
                                secret_type=pattern_info["name"],
                                severity=pattern_info["severity"],
                                context=context,
                                recommendation=f"Remove the {pattern_info['name']} from source code. Use environment variables or a secrets manager instead.",
                            ))

        return findings

    def _find_sensitive_files(self) -> list[str]:
        """Find files that typically contain secrets."""
        sensitive_files = []

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.relative_to(self.root))

                for pattern in SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, fname):
                        sensitive_files.append(rel_path)
                        break

        return sensitive_files

    def _find_certificate_files(self) -> list[str]:
        """Find certificate and key files."""
        cert_extensions = {".pem", ".key", ".cert", ".p12", ".pfx", ".jks", ".crt"}
        certs = []

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in cert_extensions:
                    certs.append(str(fpath.relative_to(self.root)))

        return certs

    def _generate_summary(self, report: SecurityReport) -> str:
        """Generate a human-readable security summary."""
        parts = []

        if report.secrets_count == 0:
            parts.append("✅ No secrets or credentials detected in source code.")
        else:
            parts.append(f"🔴 Found {report.secrets_count} potential secret(s) exposed in source code!")

            # Group by severity
            by_severity: dict[str, int] = {}
            for s in report.secrets_found:
                by_severity[s.severity.value] = by_severity.get(s.severity.value, 0) + 1

            for sev, count in sorted(by_severity.items()):
                parts.append(f"  • {sev.upper()}: {count}")

        if report.exposed_env_files:
            parts.append(f"⚠️  Found {len(report.exposed_env_files)} sensitive file(s) (e.g., .env, firebase.json).")
            parts.append("   Make sure these are in .gitignore!")

        if report.exposed_certificates:
            parts.append(f"🔑 Found {len(report.exposed_certificates)} certificate/key file(s).")
            parts.append("   Ensure they are not committed to version control.")

        return "\n".join(parts)

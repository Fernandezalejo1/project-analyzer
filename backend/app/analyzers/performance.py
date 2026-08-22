"""Performance Analyzer - Detects performance anti-patterns and issues."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.models.schemas import PerformanceFinding, PerformanceReport, Severity


# ── Performance anti-patterns ──────────────────────────────────────────────

PERF_PATTERNS: list[dict[str, str | Severity | list[str]]] = [
    # N+1 Query (ORM patterns)
    {
        "name": "N+1 Query Pattern",
        "type": "N+1 Query",
        "severity": Severity.HIGH,
        "patterns": [
            # Django N+1
            r"""for\s+\w+\s+in\s+\w+\.objects\.\w+\(\).*:\s*$""",
            r"""\.all\(\).*for\s+""",
            # SQLAlchemy N+1
            r"""for\s+\w+\s+in\s+session\.query\(""",
            r"""\.relationship.*lazy\s*=\s*['"]select['"]""",
            # Prisma / TypeORM
            r"""findMany.*include""",
            # Generic: accessing .something inside a loop over a query
            r"""for\s+\w+\s+in\s+.*(?:select|query|find).*\n.*\.(?:related|association|foreign)""",
        ],
        "description": "Pattern suggests N+1 query problem — data is fetched one-by-one inside a loop instead of using joins or eager loading.",
        "recommendation": "Use select_related/prefetch_related (Django), joinedload (SQLAlchemy), or include (Prisma) to fetch related data in bulk.",
    },
    # Expensive Loop
    {
        "name": "Expensive Loop",
        "type": "Expensive Loop",
        "severity": Severity.MEDIUM,
        "patterns": [
            r"""for\s+\w+\s+in\s+.*\n\s+.*(?:request|http|fetch|query|execute|send)""",
            r"""while\s+.*\n\s+.*(?:request|http|fetch|query|execute)""",
            r"""for\s+\w+\s+in\s+range\(.*\)\s*:\s*\n\s+.*(?:sleep|time\.sleep)""",
        ],
        "description": "Network requests or I/O operations inside a loop. This is usually slow and can be parallelized.",
        "recommendation": "Batch requests, use connection pooling, or parallelize with async/concurrent execution.",
    },
    # Synchronous I/O in async context
    {
        "name": "Blocking I/O in Async Context",
        "type": "Blocking I/O",
        "severity": Severity.MEDIUM,
        "patterns": [
            r"""async\s+def\s+\w+.*\n(?:.*\n)*?.*time\.sleep\s*\(""",
            r"""async\s+def\s+\w+.*\n(?:.*\n)*?.*requests\.\w+\s*\(""",
            r"""async\s+def\s+\w+.*\n(?:.*\n)*?.*open\s*\(""",
            r"""async\s+def\s+\w+.*\n(?:.*\n)*?.*urllib""",
        ],
        "description": "Synchronous blocking call inside an async function, which blocks the event loop.",
        "recommendation": "Use aiohttp instead of requests, aiofiles for file I/O, asyncio.sleep instead of time.sleep.",
    },
    # Unbounded Collection
    {
        "name": "Unbounded Collection",
        "type": "Memory Issue",
        "severity": Severity.MEDIUM,
        "patterns": [
            r"""\.all\(\)(?!.*(?:limit|slice|\[:|\[0:\d+\]))""",
            r"""select\s+\*\s+from(?!.*where)""",
            r"""SELECT\s+\*\s+FROM(?!.*WHERE)""",
            r"""\.find\(\{\}\)(?!.*\.limit)""",
        ],
        "description": "Query or collection fetch without limits, potentially loading entire datasets into memory.",
        "recommendation": "Add pagination, use .limit()/.offset(), or stream results instead of loading everything at once.",
    },
    # String Concatenation in Loop
    {
        "name": "String Concatenation in Loop",
        "type": "Performance",
        "severity": Severity.LOW,
        "patterns": [
            r"""for\s+\w+\s+in\s+.*\n\s+.*\+=\s*['"]""",
            r"""for\s+\w+\s+in\s+.*\n\s+.*\+=\s*\w+""",
        ],
        "description": "String concatenation in a loop creates new string objects each iteration. Use join() or a list accumulator instead.",
        "recommendation": "Use ''.join(list) or io.StringIO for string building in loops.",
    },
    # Missing Database Index
    {
        "name": "Potential Missing Index",
        "type": "Database",
        "severity": Severity.LOW,
        "patterns": [
            r"""\.filter\(\w+__icontains=""",
            r"""WHERE\s+.*LIKE\s+['"]%""",
            r"""\.order_by\((?!.*index)""",
        ],
        "description": "Queries on fields that may not be indexed, potentially causing full table scans.",
        "recommendation": "Add database indexes on frequently queried/filtered/sorted columns.",
    },
    # Excessive Logging
    {
        "name": "Excessive Logging",
        "type": "Performance",
        "severity": Severity.LOW,
        "patterns": [
            r"""(?:logger|logging|console|log)\.\w+\(.*\b(?:dump|str\(.*request)|repr\(.*request)""",
        ],
        "description": "Logging full request/response objects can be very slow in high-throughput applications.",
        "recommendation": "Log only essential fields. Avoid logging large objects or full request bodies in production.",
    },
]


SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "bin", "obj",
    ".idea", ".vscode",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
    ".jar", ".exe", ".dll", ".so", ".dylib", ".lock", ".min.js",
}


class PerformanceAnalyzer:
    """Analyzes code for performance issues and anti-patterns."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._compiled = self._compile_patterns()

    def analyze(self) -> PerformanceReport:
        """Run full performance analysis."""
        findings = self._scan_code()
        large_files = self._find_large_files()
        heavy_files = self._find_heavy_files()

        report = PerformanceReport(
            findings=findings,
            large_files=large_files,
            heavy_images=heavy_files,
        )

        report.summary = self._generate_summary(report)
        return report

    def _compile_patterns(self) -> list[dict]:
        """Pre-compile performance patterns."""
        compiled = []
        for perf in PERF_PATTERNS:
            regexes = []
            for pattern in perf["patterns"]:
                try:
                    regexes.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
                except re.error:
                    pass
            compiled.append({
                "name": perf["name"],
                "type": perf["type"],
                "severity": perf["severity"],
                "description": perf["description"],
                "recommendation": perf["recommendation"],
                "regexes": regexes,
            })
        return compiled

    def _scan_code(self) -> list[PerformanceFinding]:
        """Scan source code for performance anti-patterns."""
        findings: list[PerformanceFinding] = []
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

                for perf_info in self._compiled:
                    for line_num, line in enumerate(lines, 1):
                        for regex in perf_info["regexes"]:
                            if regex.search(line):
                                key = f"{rel_path}:{line_num}:{perf_info['type']}"
                                if key in seen:
                                    continue
                                seen.add(key)

                                start = max(0, line_num - 2)
                                end = min(len(lines), line_num + 2)
                                snippet = "\n".join(lines[start:end])

                                findings.append(PerformanceFinding(
                                    file_path=rel_path,
                                    line_number=line_num,
                                    issue_type=perf_info["type"],
                                    severity=perf_info["severity"],
                                    description=perf_info["description"],
                                    recommendation=perf_info["recommendation"],
                                ))

        return findings

    def _find_large_files(self) -> list[dict[str, Any]]:
        """Find abnormally large source files."""
        large = []
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                try:
                    size = fpath.stat().st_size
                    if size > 100_000:  # >100KB
                        large.append({
                            "file": str(fpath.relative_to(self.root)),
                            "size_kb": round(size / 1024, 1),
                        })
                except OSError:
                    pass

        large.sort(key=lambda x: -x["size_kb"])
        return large[:20]

    def _find_heavy_files(self) -> list[dict[str, Any]]:
        """Find heavy binary/image files."""
        heavy = []
        image_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff"}
        video_exts = {".mp4", ".avi", ".mov", ".wmv", ".mkv"}

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in image_exts or ext in video_exts:
                    try:
                        size = fpath.stat().st_size
                        if size > 500_000:  # >500KB for images, any size for video
                            heavy.append({
                                "file": str(fpath.relative_to(self.root)),
                                "size_kb": round(size / 1024, 1),
                                "type": "image" if ext in image_exts else "video",
                            })
                    except OSError:
                        pass

        heavy.sort(key=lambda x: -x["size_kb"])
        return heavy[:20]

    def _generate_summary(self, report: PerformanceReport) -> str:
        """Generate a human-readable summary."""
        parts = []

        if not report.findings:
            parts.append("✅ No obvious performance anti-patterns detected.")
        else:
            parts.append(f"⚡ Found {len(report.findings)} potential performance issue(s):")

            by_type: dict[str, int] = {}
            for f in report.findings:
                by_type[f.issue_type] = by_type.get(f.issue_type, 0) + 1

            for itype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                parts.append(f"  • {itype}: {count}")

        if report.large_files:
            parts.append(f"📁 {len(report.large_files)} large source file(s) (>100KB).")
            for f in report.large_files[:3]:
                parts.append(f"  • {f['file']}: {f['size_kb']}KB")

        if report.heavy_images:
            parts.append(f"🖼️  {len(report.heavy_images)} heavy media file(s).")

        return "\n".join(parts)


# Fix the import for dict/Any
from typing import Any

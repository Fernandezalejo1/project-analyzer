"""Code Quality Analyzer - Measures complexity, duplication, dead code, and maintainability."""

from __future__ import annotations

import ast
import os
import re
from collections import Counter
from pathlib import Path

from app.models.schemas import CodeQualityReport, FileMetrics


# ── Files to skip ─────────────────────────────────────────────────────────

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "target", "bin", "obj",
    ".idea", ".vscode", ".tox", ".mypy_cache", "coverage",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz",
    ".jar", ".exe", ".dll", ".so", ".dylib", ".lock",
}


class CodeQualityAnalyzer:
    """Analyzes code quality metrics across the project."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._all_source_files: list[Path] = []

    def analyze(self) -> CodeQualityReport:
        """Run full code quality analysis."""
        self._collect_files()

        file_metrics: list[FileMetrics] = []
        all_lines = 0
        complexities: list[float] = []
        maintainabilities: list[float] = []
        dead_code_files: list[str] = []
        large_functions: list[dict] = []
        large_classes: list[dict] = []
        unused_imports_total = 0

        for fpath in self._all_source_files:
            rel_path = str(fpath.relative_to(self.root))

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            lines = content.splitlines()
            loc = len([l for l in lines if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("//") and not l.strip().startswith("*")])
            all_lines += loc

            # Complexity analysis
            complexity = self._calculate_complexity(content, fpath.suffix)
            if complexity > 0:
                complexities.append(complexity)

            # Maintainability index (simplified)
            maintainability = self._calculate_maintainability(loc, complexity)
            maintainabilities.append(maintainability)

            issues = []

            # Check for large functions/methods (Python)
            if fpath.suffix == ".py":
                funcs, classes, unused_imp = self._analyze_python(content, fpath)
                large_functions.extend(funcs)
                large_classes.extend(classes)
                unused_imports_total += unused_imp

                if unused_imp > 0:
                    issues.append(f"{unused_imp} unused import(s)")

            # Check for large functions (JavaScript/TypeScript)
            elif fpath.suffix in (".js", ".ts", ".jsx", ".tsx"):
                funcs = self._analyze_javascript(content, fpath)
                large_functions.extend(funcs)

            # Check for large files
            if loc > 500:
                issues.append(f"Large file ({loc} lines of code)")
                dead_code_files.append(rel_path)  # Not necessarily dead, but flagged

            metrics = FileMetrics(
                file_path=rel_path,
                lines_of_code=loc,
                complexity=complexity,
                maintainability_index=maintainability,
                issues=issues,
            )
            file_metrics.append(metrics)

        # Calculate duplication (basic line-level dedup)
        duplication_pct = self._calculate_duplication()

        report = CodeQualityReport(
            total_files=len(self._all_source_files),
            total_lines=all_lines,
            average_complexity=round(sum(complexities) / len(complexities), 2) if complexities else 0,
            average_maintainability=round(sum(maintainabilities) / len(maintainabilities), 2) if maintainabilities else 0,
            duplicated_percentage=round(duplication_pct, 1),
            dead_code_files=dead_code_files[:20],
            large_functions=large_functions[:20],
            large_classes=large_classes[:20],
            unused_imports_count=unused_imports_total,
            technical_debt_hours=self._estimate_technical_debt(report=None, metrics=file_metrics),
            file_metrics=file_metrics[:50],  # Top 50
        )

        report.summary = self._generate_summary(report)
        return report

    # ── Private ────────────────────────────────────────────────────────

    def _collect_files(self):
        """Collect all source files."""
        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()

                if ext in SKIP_EXTENSIONS or ".min." in fname:
                    continue

                # Source files only
                if ext in (
                    ".py", ".js", ".ts", ".jsx", ".tsx", ".java",
                    ".go", ".rs", ".cs", ".cpp", ".cc", ".h",
                    ".rb", ".php", ".swift", ".kt", ".dart",
                ):
                    # Skip very large files (>10KB for analysis)
                    try:
                        if fpath.stat().st_size < 100_000:
                            self._all_source_files.append(fpath)
                    except OSError:
                        pass

    def _calculate_complexity(self, content: str, ext: str) -> float:
        """Calculate cyclomatic complexity (simplified)."""
        if ext == ".py":
            return self._python_complexity(content)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            return self._javascript_complexity(content)
        return 0

    def _python_complexity(self, content: str) -> float:
        """Calculate cyclomatic complexity for Python."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return 0

        complexity = 1  # Base

        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
            elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                complexity += 1
            elif isinstance(node, ast.Lambda):
                complexity += 1
            elif isinstance(node, ast.comprehension):
                complexity += 1

        return float(complexity)

    def _javascript_complexity(self, content: str) -> float:
        """Estimate cyclomatic complexity for JavaScript/TypeScript."""
        complexity = 1

        # Count branching keywords
        keywords = re.findall(
            r'\b(?:if|else\s+if|elif|while|for|case|catch|&&|\|\||\?)\b',
            content,
        )
        complexity += len(keywords)

        return float(complexity)

    def _calculate_maintainability(self, loc: int, complexity: float) -> float:
        """Calculate a simplified maintainability index (0-100)."""
        # Simplified MI formula
        # High LOC + high complexity = low maintainability
        if loc == 0:
            return 100

        mi = max(0, 171 - 5.2 * (complexity ** 0.5) - 0.23 * loc - 16.2 * (loc ** 0.5) + 50)
        return round(min(100, max(0, mi)), 1)

    def _analyze_python(self, content: str, fpath: Path) -> tuple[list[dict], list[dict], int]:
        """Analyze Python file for functions, classes, and unused imports."""
        large_functions = []
        large_classes = []
        unused_imports = 0
        rel_path = str(fpath.relative_to(self.root))

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return large_functions, large_classes, 0

        # Check imports vs usage
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    imports.add(name)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imports.add(name)

        # Check usage (rough: just search for the name in content)
        for imp in imports:
            # Count occurrences beyond import statements
            pattern = re.compile(rf'\b{re.escape(imp)}\b')
            matches = pattern.findall(content)
            # Remove import line occurrences
            if len(matches) <= 1:
                unused_imports += 1

        # Find large functions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, "end_lineno") and node.end_lineno:
                    func_lines = node.end_lineno - node.lineno
                    if func_lines > 50:
                        large_functions.append({
                            "file": rel_path,
                            "name": node.name,
                            "line": node.lineno,
                            "lines": func_lines,
                            "type": "function",
                        })

            elif isinstance(node, ast.ClassDef):
                if hasattr(node, "end_lineno") and node.end_lineno:
                    class_lines = node.end_lineno - node.lineno
                    if class_lines > 200:
                        large_classes.append({
                            "file": rel_path,
                            "name": node.name,
                            "line": node.lineno,
                            "lines": class_lines,
                            "type": "class",
                        })

        return large_functions, large_classes, unused_imports

    def _analyze_javascript(self, content: str, fpath: Path) -> list[dict]:
        """Analyze JavaScript/TypeScript for large functions."""
        large_functions = []
        rel_path = str(fpath.relative_to(self.root))

        # Simple heuristic: find function/arrow function definitions and count lines
        func_pattern = re.compile(
            r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|'
            r'(?:async\s+)?function\s*\*?\s*\([^)]*\))',
            re.MULTILINE,
        )

        lines = content.splitlines()
        for match in func_pattern.finditer(content):
            start_line = content[:match.start()].count("\n") + 1
            name = match.group(1) or match.group(2) or "anonymous"

            # Find matching closing brace (rough)
            depth = 0
            end_line = start_line
            for i, line in enumerate(lines[start_line - 1:], start_line):
                depth += line.count("{") - line.count("}")
                if depth <= 0 and i > start_line:
                    end_line = i
                    break

            func_lines = end_line - start_line
            if func_lines > 50:
                large_functions.append({
                    "file": rel_path,
                    "name": name,
                    "line": start_line,
                    "lines": func_lines,
                    "type": "function",
                })

        return large_functions

    def _calculate_duplication(self) -> float:
        """Calculate basic code duplication percentage using line hashing."""
        all_lines: list[str] = []
        line_hashes: Counter[str] = Counter()

        for fpath in self._all_source_files[:100]:  # Sample
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            for line in content.splitlines():
                stripped = line.strip()
                # Skip empty, short, or comment lines
                if len(stripped) < 10:
                    continue
                if stripped.startswith(("#", "//", "*", "/*", "import", "from")):
                    continue
                line_hashes[stripped] += 1
                all_lines.append(stripped)

        total = len(all_lines)
        if total == 0:
            return 0.0

        duplicated = sum(count - 1 for count in line_hashes.values() if count > 1)
        return (duplicated / total) * 100

    def _estimate_technical_debt(self, report: None, metrics: list[FileMetrics]) -> float:
        """Estimate technical debt in hours based on code quality metrics."""
        debt_minutes = 0.0

        for m in metrics:
            # High complexity adds debt
            if m.complexity > 15:
                debt_minutes += (m.complexity - 15) * 5
            elif m.complexity > 10:
                debt_minutes += (m.complexity - 10) * 2

            # Large files add debt
            if m.lines_of_code > 500:
                debt_minutes += (m.lines_of_code - 500) * 0.1

            # Each issue adds ~5 minutes
            debt_minutes += len(m.issues) * 5

        return round(debt_minutes / 60, 1)

    def _generate_summary(self, report: CodeQualityReport) -> str:
        """Generate a human-readable summary."""
        parts = [
            f"📊 Analyzed {report.total_files} files ({report.total_lines:,} lines of code).",
            f"Average complexity: {report.average_complexity:.1f}",
            f"Average maintainability: {report.average_maintainability:.1f}/100",
            f"Code duplication: {report.duplicated_percentage:.1f}%",
        ]

        if report.unused_imports_count:
            parts.append(f"🗑️  {report.unused_imports_count} unused import(s) detected.")
        if report.large_functions:
            parts.append(f"📏 {len(report.large_functions)} oversized function(s) (>50 lines).")
        if report.large_classes:
            parts.append(f"📦 {len(report.large_classes)} oversized class(es) (>200 lines).")
        if report.technical_debt_hours > 0:
            parts.append(f"⏳ Estimated technical debt: {report.technical_debt_hours:.1f} hours.")

        return "\n".join(parts)

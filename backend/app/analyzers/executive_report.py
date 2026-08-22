"""Executive Report Generator - Produces the final scored report."""

from __future__ import annotations

from app.models.schemas import (
    AIAnalysisReport,
    ArchitectureAnalysis,
    CategoryScore,
    CodeQualityReport,
    DependencyReport,
    DocumentationReport,
    ExecutiveReport,
    FullAnalysisResult,
    GitReport,
    PerformanceReport,
    Priority,
    SecurityReport,
    Severity,
    VulnerabilityReport,
)


class ExecutiveReportGenerator:
    """Generates the final executive report with scores and priorities."""

    def generate(
        self,
        architecture: ArchitectureAnalysis,
        dependencies: DependencyReport,
        security: SecurityReport,
        vulnerabilities: VulnerabilityReport,
        code_quality: CodeQualityReport,
        git: GitReport,
        performance: PerformanceReport,
        ai_analysis: AIAnalysisReport,
        documentation: DocumentationReport,
    ) -> ExecutiveReport:
        """Generate the executive report."""

        # Calculate category scores
        arch_score = self._score_architecture(architecture, code_quality)
        sec_score = self._score_security(security, vulnerabilities)
        quality_score = self._score_quality(code_quality)
        perf_score = self._score_performance(performance)
        dep_score = self._score_dependencies(dependencies)
        doc_score = self._score_documentation(documentation)

        categories = [
            arch_score,
            sec_score,
            quality_score,
            perf_score,
            dep_score,
            doc_score,
        ]

        # Calculate overall score (weighted average)
        weights = {
            "Architecture": 0.20,
            "Security": 0.25,
            "Code Quality": 0.20,
            "Performance": 0.15,
            "Dependencies": 0.10,
            "Documentation": 0.10,
        }

        overall = 0.0
        for cat in categories:
            w = weights.get(cat.name, 0.15)
            overall += cat.score * w * 10  # Scale to 0-100

        overall = round(min(100, max(0, overall)), 1)

        # Build priority lists
        critical, important, recommendations = self._build_priorities(
            security, vulnerabilities, code_quality, dependencies, git, performance, ai_analysis
        )

        return ExecutiveReport(
            overall_score=overall,
            categories=categories,
            priorities_critical=critical,
            priorities_important=important,
            priorities_recommendations=recommendations,
            summary=self._generate_summary(overall, categories, critical, important, recommendations),
        )

    # ── Scoring methods ───────────────────────────────────────────────

    def _score_architecture(self, arch: ArchitectureAnalysis, quality: CodeQualityReport) -> CategoryScore:
        """Score architecture quality (0-10)."""
        score = 8.0  # Base

        # Deduct for too many languages
        if len(arch.languages_detected) > 5:
            score -= 1.5
        elif len(arch.languages_detected) > 3:
            score -= 0.5

        # Deduct for very large codebase without structure
        if quality.total_lines > 100_000 and not arch.architecture_map.layers:
            score -= 2.0

        # Bonus for detected frameworks (structure)
        if arch.frameworks:
            score += 0.5

        # Deduct for high complexity
        if quality.average_complexity > 15:
            score -= 1.0

        score = round(min(10, max(0, score)), 1)

        details = f"Languages: {len(arch.languages_detected)}, Frameworks: {len(arch.frameworks)}, Type: {arch.project_type.value}"

        return CategoryScore(name="Architecture", score=score, details=details)

    def _score_security(self, sec: SecurityReport, vulns: VulnerabilityReport) -> CategoryScore:
        """Score security (0-10)."""
        score = 10.0

        # Deductions for secrets
        score -= min(5.0, sec.secrets_count * 1.0)

        # Deductions for vulnerable files
        score -= min(2.0, len(sec.exposed_env_files) * 0.5)
        score -= min(2.0, len(sec.exposed_certificates) * 0.5)

        # Deductions for vulnerability patterns
        score -= min(3.0, vulns.critical_count * 1.5)
        score -= min(2.0, vulns.high_count * 0.5)
        score -= min(1.0, vulns.medium_count * 0.2)

        score = round(min(10, max(0, score)), 1)

        details = f"Secrets: {sec.secrets_count}, Vulnerabilities: {vulns.total_count}, Critical: {vulns.critical_count}"

        return CategoryScore(name="Security", score=score, details=details)

    def _score_quality(self, quality: CodeQualityReport) -> CategoryScore:
        """Score code quality (0-10)."""
        score = 8.0

        # Complexity penalty
        if quality.average_complexity > 20:
            score -= 2.0
        elif quality.average_complexity > 15:
            score -= 1.0
        elif quality.average_complexity > 10:
            score -= 0.5

        # Duplication penalty
        if quality.duplicated_percentage > 20:
            score -= 2.0
        elif quality.duplicated_percentage > 10:
            score -= 1.0

        # Large functions/classes penalty
        if len(quality.large_functions) > 10:
            score -= 1.5
        elif len(quality.large_functions) > 5:
            score -= 0.5

        # Maintainability bonus
        if quality.average_maintainability > 60:
            score += 0.5

        score = round(min(10, max(0, score)), 1)

        details = f"Complexity: {quality.average_complexity:.1f}, Maintainability: {quality.average_maintainability:.1f}, Duplication: {quality.duplicated_percentage:.1f}%"

        return CategoryScore(name="Code Quality", score=score, details=details)

    def _score_performance(self, perf: PerformanceReport) -> CategoryScore:
        """Score performance (0-10)."""
        score = 9.0

        # Deductions for each finding type
        by_type: dict[str, int] = {}
        for f in perf.findings:
            by_type[f.issue_type] = by_type.get(f.issue_type, 0) + 1

        score -= min(3.0, by_type.get("N+1 Query", 0) * 1.0)
        score -= min(2.0, by_type.get("Blocking I/O", 0) * 0.5)
        score -= min(2.0, by_type.get("Expensive Loop", 0) * 0.5)
        score -= min(1.0, by_type.get("Memory Issue", 0) * 0.5)

        # Large files penalty
        if len(perf.large_files) > 5:
            score -= 0.5

        score = round(min(10, max(0, score)), 1)

        details = f"Issues: {len(perf.findings)}, Large files: {len(perf.large_files)}, Heavy media: {len(perf.heavy_images)}"

        return CategoryScore(name="Performance", score=score, details=details)

    def _score_dependencies(self, deps: DependencyReport) -> CategoryScore:
        """Score dependency health (0-10)."""
        score = 9.0

        if deps.vulnerable_count > 0:
            score -= min(4.0, deps.vulnerable_count * 2.0)

        if deps.deprecated_count > 0:
            score -= min(2.0, deps.deprecated_count * 0.5)

        if deps.outdated_count > 0:
            ratio = deps.outdated_count / max(1, deps.total_count)
            if ratio > 0.3:
                score -= 1.5
            elif ratio > 0.1:
                score -= 0.5

        score = round(min(10, max(0, score)), 1)

        details = f"Total: {deps.total_count}, Vulnerable: {deps.vulnerable_count}, Outdated: {deps.outdated_count}"

        return CategoryScore(name="Dependencies", score=score, details=details)

    def _score_documentation(self, doc: DocumentationReport) -> CategoryScore:
        """Score documentation (0-10)."""
        score = 4.0  # Low base — most projects lack docs

        if doc.has_existing_readme:
            score += 2.0
        if doc.has_existing_docs:
            score += 2.0
        if doc.readme_generated:
            score += 1.0
        if doc.architecture_diagram:
            score += 1.0

        score = round(min(10, max(0, score)), 1)

        details_parts = []
        if doc.has_existing_readme:
            details_parts.append("Has README")
        else:
            details_parts.append("No README")
        if doc.has_existing_docs:
            details_parts.append("Has docs/")

        return CategoryScore(name="Documentation", score=score, details=", ".join(details_parts) or "Minimal documentation")

    # ── Priority builder ──────────────────────────────────────────────

    def _build_priorities(
        self,
        security: SecurityReport,
        vulns: VulnerabilityReport,
        quality: CodeQualityReport,
        deps: DependencyReport,
        git: GitReport,
        perf: PerformanceReport,
        ai_analysis: AIAnalysisReport,
    ) -> tuple[list[Priority], list[Priority], list[Priority]]:
        """Build prioritized action items."""
        critical: list[Priority] = []
        important: list[Priority] = []
        recommendations: list[Priority] = []

        # Critical: secrets + critical vulnerabilities
        if security.secrets_count > 0:
            critical.append(Priority(
                level="critical",
                title=f"{security.secrets_count} leaked secret(s) in source code",
                description="Immediately rotate all exposed credentials and move them to a secrets manager.",
            ))

        if git.secrets_in_history:
            critical.append(Priority(
                level="critical",
                title=f"{len(git.secrets_in_history)} secret(s) in git history",
                description="Rotate credentials and consider cleaning git history with git-filter-repo.",
            ))

        sql_findings = [f for f in vulns.findings if f.vulnerability_type == "SQL Injection"]
        if sql_findings:
            critical.append(Priority(
                level="critical",
                title=f"{len(sql_findings)} SQL injection(s) detected",
                description="Fix immediately — use parameterized queries or ORM.",
            ))

        if deps.vulnerable_count > 0:
            critical.append(Priority(
                level="critical",
                title=f"{deps.vulnerable_count} vulnerable dependency/dependencies",
                description="Update or replace vulnerable dependencies ASAP.",
            ))

        # Important: high vulns, security concerns
        if security.exposed_env_files:
            important.append(Priority(
                level="important",
                title=f"{len(security.exposed_env_files)} sensitive file(s) exposed",
                description="Add .env and similar files to .gitignore. Remove from version control if committed.",
            ))

        if vulns.high_count > 0:
            important.append(Priority(
                level="important",
                title=f"{vulns.high_count} high-severity vulnerability pattern(s)",
                description="Review and fix high-severity patterns (XSS, command injection, etc.).",
            ))

        if quality.average_complexity > 15:
            important.append(Priority(
                level="important",
                title="High code complexity",
                description="Refactor complex functions to reduce cyclomatic complexity.",
            ))

        if quality.duplicated_percentage > 10:
            important.append(Priority(
                level="important",
                title=f"{quality.duplicated_percentage:.1f}% code duplication",
                description="Extract duplicated logic into shared utilities.",
            ))

        # Recommendations
        if not quality.large_functions:
            pass  # Good
        else:
            recommendations.append(Priority(
                level="recommendation",
                title="Break down large functions",
                description=f"{len(quality.large_functions)} function(s) exceed 50 lines. Consider splitting them.",
            ))

        if quality.unused_imports_count > 0:
            recommendations.append(Priority(
                level="recommendation",
                title=f"Clean up {quality.unused_imports_count} unused import(s)",
                description="Remove unused imports to improve readability.",
            ))

        if deps.outdated_count > 5:
            recommendations.append(Priority(
                level="recommendation",
                title=f"Update {deps.outdated_count} outdated dependencies",
                description="Keep dependencies up to date for security and compatibility.",
            ))

        if git.abandoned_branches:
            recommendations.append(Priority(
                level="recommendation",
                title=f"Clean up {len(git.abandoned_branches)} abandoned branch(es)",
                description="Delete stale branches to keep the repository organized.",
            ))

        if perf.findings:
            recommendations.append(Priority(
                level="recommendation",
                title="Address performance anti-patterns",
                description=f"{len(perf.findings)} performance issue(s) detected. Review for optimization opportunities.",
            ))

        # Use AI analysis priorities
        for rec in ai_analysis.recommendations:
            if rec.priority == Severity.CRITICAL and not any(c.title.startswith(str(rec.title[:20])) for c in critical):
                critical.append(Priority(level="critical", title=rec.title, description=rec.description))
            elif rec.priority == Severity.HIGH and not any(i.title[:20] in rec.title for i in important):
                important.append(Priority(level="important", title=rec.title, description=rec.description))

        return critical, important, recommendations

    def _generate_summary(
        self,
        overall: float,
        categories: list[CategoryScore],
        critical: list[Priority],
        important: list[Priority],
        recommendations: list[Priority],
    ) -> str:
        """Generate the overall summary text."""
        # Rating
        if overall >= 90:
            rating = "EXCELLENT"
        elif overall >= 75:
            rating = "GOOD"
        elif overall >= 60:
            rating = "FAIR"
        elif overall >= 40:
            rating = "POOR"
        else:
            rating = "CRITICAL"

        parts = [
            f"Overall Score: {overall}/100 ({rating})",
            "",
            "Category Breakdown:",
        ]

        for cat in categories:
            bar = "█" * int(cat.score) + "░" * (10 - int(cat.score))
            parts.append(f"  {cat.name:15s} {bar} {cat.score}/10  ({cat.details})")

        parts.append("")

        if critical:
            parts.append(f"🔴 {len(critical)} CRITICAL item(s) requiring immediate action.")
        if important:
            parts.append(f"🟠 {len(important)} important item(s) to address.")
        if recommendations:
            parts.append(f"🟢 {len(recommendations)} recommendation(s) for improvement.")

        return "\n".join(parts)

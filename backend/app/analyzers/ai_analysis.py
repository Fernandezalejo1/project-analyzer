"""AI Analysis Engine - Generates intelligent recommendations based on all analysis results."""

from __future__ import annotations

from pathlib import Path

from app.models.schemas import (
    AIAnalysisReport,
    AIRecommendation,
    ArchitectureAnalysis,
    CodeQualityReport,
    DependencyReport,
    FullAnalysisResult,
    GitReport,
    PerformanceReport,
    SecurityReport,
    Severity,
    VulnerabilityReport,
)


class AIAnalyzer:
    """Generates intelligent architectural and code recommendations."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)

    def analyze(
        self,
        architecture: ArchitectureAnalysis,
        dependencies: DependencyReport,
        security: SecurityReport,
        vulnerabilities: VulnerabilityReport,
        code_quality: CodeQualityReport,
        git: GitReport,
        performance: PerformanceReport,
    ) -> AIAnalysisReport:
        """Generate AI-powered analysis and recommendations."""
        recommendations: list[AIRecommendation] = []
        arch_suggestions: list[str] = []
        scalability: list[str] = []

        # ── Architecture Recommendations ────────────────────────────
        self._analyze_architecture(architecture, code_quality, recommendations, arch_suggestions)

        # ── Security Recommendations ────────────────────────────────
        self._analyze_security(security, vulnerabilities, recommendations)

        # ── Dependency Recommendations ──────────────────────────────
        self._analyze_dependencies(dependencies, recommendations)

        # ── Code Quality Recommendations ────────────────────────────
        self._analyze_code_quality(code_quality, recommendations)

        # ── Performance Recommendations ─────────────────────────────
        self._analyze_performance(performance, recommendations)

        # ── Git Recommendations ─────────────────────────────────────
        self._analyze_git(git, recommendations)

        # ── Scalability Concerns ────────────────────────────────────
        self._analyze_scalability(architecture, code_quality, performance, scalability)

        # Sort recommendations by severity
        recommendations.sort(key=lambda r: {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }.get(r.priority, 5))

        return AIAnalysisReport(
            recommendations=recommendations,
            architecture_suggestions=arch_suggestions,
            scalability_concerns=scalability,
            summary=self._generate_summary(recommendations, arch_suggestions, scalability),
        )

    # ── Analysis methods ──────────────────────────────────────────────

    def _analyze_architecture(
        self,
        arch: ArchitectureAnalysis,
        quality: CodeQualityReport,
        recs: list[AIRecommendation],
        suggestions: list[str],
    ):
        """Analyze architecture and suggest improvements."""

        # Monolith that's getting large
        from app.models.schemas import ProjectType
        if arch.project_type == ProjectType.MONOLITH and quality.total_lines > 50_000:
            recs.append(AIRecommendation(
                category="architecture",
                priority=Severity.MEDIUM,
                title="Consider breaking up the monolith",
                description=(
                    f"This is a monolith with {quality.total_lines:,} lines of code. "
                    "As the project grows, consider splitting into modules or microservices "
                    "to improve maintainability and deployment flexibility."
                ),
                impact="Improved maintainability, independent deployments, team autonomy",
            ))
            suggestions.append(
                "The monolith is large. Consider identifying bounded contexts "
                "and splitting into domain-driven modules or services."
            )

        # Too many languages
        if len(arch.languages_detected) > 4:
            suggestions.append(
                f"The project uses {len(arch.languages_detected)} languages. "
                "This increases cognitive load and build complexity. Consider standardizing "
                "on fewer languages where possible."
            )

        # Check if React is doing backend work
        framework_names = {f.name for f in arch.frameworks}
        if "React" in framework_names and "Express" in framework_names:
            suggestions.append(
                "React and Express detected — make sure the frontend doesn't mix "
                "business logic that belongs in the backend."
            )

        # No test framework detected
        if not framework_names.intersection({"Jest", "Pytest", "Mocha", "Vitest", "PHPUnit"}):
            recs.append(AIRecommendation(
                category="architecture",
                priority=Severity.HIGH,
                title="No test framework detected",
                description="No testing framework was detected in the project. Tests are crucial for maintaining code quality.",
                impact="Prevents regressions, improves confidence in deployments, enables refactoring",
            ))

    def _analyze_security(
        self,
        security: SecurityReport,
        vulns: VulnerabilityReport,
        recs: list[AIRecommendation],
    ):
        """Analyze security findings."""
        if security.secrets_count > 0:
            recs.append(AIRecommendation(
                category="security",
                priority=Severity.CRITICAL,
                title=f"{security.secrets_count} secret(s) exposed in source code",
                description=(
                    "Hardcoded secrets found. These could be extracted by anyone with "
                    "repository access. Immediately rotate all exposed credentials and "
                    "move them to environment variables or a secrets manager."
                ),
                impact="Prevents unauthorized access, data breaches, and service compromise",
            ))

        if security.exposed_env_files:
            recs.append(AIRecommendation(
                category="security",
                priority=Severity.HIGH,
                title="Sensitive files may be committed",
                description=(
                    f"{len(security.exposed_env_files)} sensitive file(s) like .env or firebase.json "
                    "were found. Ensure they are in .gitignore and never committed."
                ),
                impact="Prevents accidental exposure of API keys and database credentials",
            ))

        # SQL injection is the most critical
        sql_findings = [f for f in vulns.findings if f.vulnerability_type == "SQL Injection"]
        if sql_findings:
            recs.append(AIRecommendation(
                category="security",
                priority=Severity.CRITICAL,
                title=f"{len(sql_findings)} potential SQL injection(s)",
                description="SQL injection allows attackers to read, modify, or delete your entire database.",
                impact="Prevents data breach, data loss, and potential system compromise",
            ))

    def _analyze_dependencies(
        self,
        deps: DependencyReport,
        recs: list[AIRecommendation],
    ):
        """Analyze dependency health."""
        if deps.vulnerable_count > 0:
            recs.append(AIRecommendation(
                category="dependencies",
                priority=Severity.CRITICAL,
                title=f"{deps.vulnerable_count} vulnerable dependency/dependencies",
                description="Known vulnerabilities exist in current dependencies. Update them immediately.",
                impact="Prevents exploitation of known vulnerabilities (CVEs)",
            ))

        if deps.outdated_count > 10:
            recs.append(AIRecommendation(
                category="dependencies",
                priority=Severity.MEDIUM,
                title=f"{deps.outdated_count} outdated dependencies",
                description=(
                    "Many dependencies are outdated. This increases the risk of "
                    "vulnerabilities and incompatibilities with newer tools."
                ),
                impact="Improved security, access to new features, better compatibility",
            ))

    def _analyze_code_quality(
        self,
        quality: CodeQualityReport,
        recs: list[AIRecommendation],
    ):
        """Analyze code quality."""
        if quality.average_complexity > 15:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.HIGH,
                title="High average cyclomatic complexity",
                description=(
                    f"Average complexity is {quality.average_complexity:.1f}. High complexity "
                    "makes code harder to test, maintain, and debug. Consider refactoring "
                    "complex functions into smaller, focused ones."
                ),
                impact="Reduced bug rate, easier testing, improved maintainability",
            ))

        if quality.duplicated_percentage > 10:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.MEDIUM,
                title=f"{quality.duplicated_percentage:.1f}% code duplication",
                description=(
                    "Significant code duplication increases maintenance burden. "
                    "Extract common logic into shared utilities or base classes."
                ),
                impact="DRYer code, fewer bugs from inconsistent fixes",
            ))

        if quality.large_functions:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.MEDIUM,
                title=f"{len(quality.large_functions)} oversized functions",
                description=(
                    "Functions over 50 lines are hard to understand and test. "
                    "Break them into smaller, focused functions."
                ),
                impact="Better readability, testability, and reusability",
            ))

        if quality.technical_debt_hours > 40:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.MEDIUM,
                title=f"Estimated {quality.technical_debt_hours:.0f}h of technical debt",
                description=(
                    "The accumulated technical debt is significant. Plan regular "
                    "refactoring sprints to keep the codebase healthy."
                ),
                impact="Long-term productivity gains, reduced bug rates",
            ))

    def _analyze_performance(
        self,
        perf: PerformanceReport,
        recs: list[AIRecommendation],
    ):
        """Analyze performance issues."""
        n_plus_one = [f for f in perf.findings if f.issue_type == "N+1 Query"]
        if n_plus_one:
            recs.append(AIRecommendation(
                category="performance",
                priority=Severity.HIGH,
                title=f"{len(n_plus_one)} potential N+1 query pattern(s)",
                description=(
                    "N+1 queries are one of the most common performance killers in "
                    "web applications. Use eager loading or joins."
                ),
                impact="Can reduce database queries by 10-100x, dramatically improving response times",
            ))

        blocking = [f for f in perf.findings if f.issue_type == "Blocking I/O"]
        if blocking:
            recs.append(AIRecommendation(
                category="performance",
                priority=Severity.MEDIUM,
                title=f"{len(blocking)} blocking I/O call(s) in async context",
                description="Blocking I/O in async functions defeats the purpose of async and can stall the entire event loop.",
                impact="Improved throughput and responsiveness under load",
            ))

    def _analyze_git(
        self,
        git: GitReport,
        recs: list[AIRecommendation],
    ):
        """Analyze git practices."""
        if git.secrets_in_history:
            recs.append(AIRecommendation(
                category="security",
                priority=Severity.CRITICAL,
                title=f"{len(git.secrets_in_history)} commit(s) with secrets in history",
                description=(
                    "Even if secrets were removed in later commits, they remain in "
                    "git history. Rotate all exposed credentials and consider using "
                    "git-filter-repo to clean history."
                ),
                impact="Prevents credential theft from repository history",
            ))

        if len(git.abandoned_branches) > 3:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.LOW,
                title=f"{len(git.abandoned_branches)} abandoned branches",
                description="Clean up stale branches to reduce confusion and keep the repository organized.",
                impact="Cleaner repository, easier navigation",
            ))

        if git.large_commits:
            recs.append(AIRecommendation(
                category="quality",
                priority=Severity.LOW,
                title=f"{len(git.large_commits)} unusually large commit(s)",
                description=(
                    "Large commits are hard to review and understand. Consider breaking "
                    "them into smaller, focused commits."
                ),
                impact="Better code review, easier debugging with git bisect",
            ))

    def _analyze_scalability(
        self,
        arch: ArchitectureAnalysis,
        quality: CodeQualityReport,
        perf: PerformanceReport,
        scalability: list[str],
    ):
        """Analyze scalability concerns."""
        if quality.total_lines > 100_000:
            scalability.append(
                f"With {quality.total_lines:,} lines of code, the project will benefit from "
                "modular architecture. Consider domain-driven design boundaries."
            )

        if quality.average_complexity > 12:
            scalability.append(
                "High complexity makes it harder for new developers to contribute "
                "and for teams to work in parallel."
            )

        n_plus_one = [f for f in perf.findings if f.issue_type == "N+1 Query"]
        if n_plus_one:
            scalability.append(
                "N+1 queries will become increasingly painful as data grows. "
                "Optimize before the dataset becomes large."
            )

        from app.models.schemas import ProjectType
        if arch.project_type == ProjectType.MONOLITH:
            scalability.append(
                "As a monolith, deployment and scaling are all-or-nothing. "
                "Consider extracting critical services for independent scaling."
            )

    def _generate_summary(
        self,
        recs: list[AIRecommendation],
        arch_suggestions: list[str],
        scalability: list[str],
    ) -> str:
        """Generate a summary of the AI analysis."""
        critical = sum(1 for r in recs if r.priority == Severity.CRITICAL)
        high = sum(1 for r in recs if r.priority == Severity.HIGH)

        parts = [f"🤖 AI Analysis: {len(recs)} recommendation(s) generated."]

        if critical:
            parts.insert(0, f"🚨 {critical} CRITICAL finding(s) require immediate attention!")

        if arch_suggestions:
            parts.append(f"\n📋 Architecture Insights ({len(arch_suggestions)}):")
            for s in arch_suggestions[:3]:
                parts.append(f"  • {s}")

        if scalability:
            parts.append(f"\n📈 Scalability Concerns ({len(scalability)}):")
            for s in scalability[:3]:
                parts.append(f"  • {s}")

        return "\n".join(parts)

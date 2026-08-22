"""Main Orchestrator - Runs all analyzers and produces the final report."""

from __future__ import annotations

import time
from pathlib import Path

from app.analyzers import (
    AIAnalyzer,
    ArchitectureAnalyzer,
    CodeQualityAnalyzer,
    DependencyAnalyzer,
    DocumentationGenerator,
    ExecutiveReportGenerator,
    GitAnalyzer,
    PerformanceAnalyzer,
    SecurityAnalyzer,
    VulnerabilityAnalyzer,
)
from app.models.schemas import FullAnalysisResult


class ProjectAnalyzer:
    """Orchestrates all analysis modules and produces the final report."""

    def __init__(self, project_path: str):
        self.project_path = Path(project_path).resolve()

        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")

    def analyze(self) -> FullAnalysisResult:
        """Run the complete analysis pipeline."""
        start_time = time.time()

        print(f"🔍 Analyzing project: {self.project_path}")
        print("=" * 60)

        # 1. Architecture Analysis
        print("\n📐 [1/9] Analyzing architecture...")
        arch_analyzer = ArchitectureAnalyzer(str(self.project_path))
        architecture = arch_analyzer.analyze()
        print(f"   ✓ Primary language: {architecture.primary_language.value}")
        print(f"   ✓ Project type: {architecture.project_type.value}")
        print(f"   ✓ Frameworks: {', '.join(f.name for f in architecture.frameworks) or 'none detected'}")

        # 2. Dependency Analysis
        print("\n📦 [2/9] Analyzing dependencies...")
        dep_analyzer = DependencyAnalyzer(str(self.project_path))
        dependencies = dep_analyzer.analyze()
        print(f"   ✓ Found {dependencies.total_count} dependencies")

        # 3. Security Scan
        print("\n🔐 [3/9] Scanning for secrets and credentials...")
        sec_analyzer = SecurityAnalyzer(str(self.project_path))
        security = sec_analyzer.analyze()
        print(f"   ✓ Secrets found: {security.secrets_count}")
        print(f"   ✓ Sensitive files: {len(security.exposed_env_files)}")

        # 4. Vulnerability Analysis
        print("\n🛡️  [4/9] Analyzing vulnerabilities...")
        vuln_analyzer = VulnerabilityAnalyzer(str(self.project_path))
        vulnerabilities = vuln_analyzer.analyze()
        print(f"   ✓ Vulnerabilities found: {vulnerabilities.total_count}")
        print(f"   ✓ Critical: {vulnerabilities.critical_count}, High: {vulnerabilities.high_count}")

        # 5. Code Quality
        print("\n📊 [5/9] Analyzing code quality...")
        quality_analyzer = CodeQualityAnalyzer(str(self.project_path))
        code_quality = quality_analyzer.analyze()
        print(f"   ✓ Files: {code_quality.total_files}, Lines: {code_quality.total_lines:,}")
        print(f"   ✓ Avg. complexity: {code_quality.average_complexity:.1f}")

        # 6. Git Analysis
        print("\n📈 [6/9] Analyzing Git history...")
        git_analyzer = GitAnalyzer(str(self.project_path))
        git_report = git_analyzer.analyze()
        print(f"   ✓ Commits: {git_report.total_commits}")
        print(f"   ✓ Branches: {len(git_report.branches)}")

        # 7. Performance Analysis
        print("\n⚡ [7/9] Analyzing performance...")
        perf_analyzer = PerformanceAnalyzer(str(self.project_path))
        performance = perf_analyzer.analyze()
        print(f"   ✓ Performance issues: {len(performance.findings)}")

        # 8. AI Analysis
        print("\n🤖 [8/9] Running AI analysis...")
        ai_analyzer = AIAnalyzer(str(self.project_path))
        ai_analysis = ai_analyzer.analyze(
            architecture, dependencies, security, vulnerabilities,
            code_quality, git_report, performance,
        )
        print(f"   ✓ Recommendations: {len(ai_analysis.recommendations)}")

        # 9. Documentation Generation
        print("\n📝 [9/9] Generating documentation...")
        doc_generator = DocumentationGenerator(str(self.project_path))
        documentation = doc_generator.analyze(architecture, dependencies, security, code_quality)
        print(f"   ✓ README generated: {'yes' if documentation.readme_generated else 'no'}")

        # Executive Report
        print("\n📋 Generating executive report...")
        exec_generator = ExecutiveReportGenerator()
        executive_report = exec_generator.generate(
            architecture, dependencies, security, vulnerabilities,
            code_quality, git_report, performance, ai_analysis, documentation,
        )

        elapsed = time.time() - start_time

        print(f"\n{'=' * 60}")
        print(f"✅ Analysis complete in {elapsed:.1f}s")
        print(f"\n{executive_report.summary}")

        return FullAnalysisResult(
            project_path=str(self.project_path),
            project_name=self.project_path.name,
            architecture=architecture,
            dependencies=dependencies,
            security=security,
            vulnerabilities=vulnerabilities,
            code_quality=code_quality,
            git=git_report,
            performance=performance,
            ai_analysis=ai_analysis,
            documentation=documentation,
            executive_report=executive_report,
            scan_duration_seconds=round(elapsed, 2),
        )

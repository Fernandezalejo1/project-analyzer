"""Project Analyzer - All analysis modules."""

from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.code_quality import CodeQualityAnalyzer
from app.analyzers.dependencies import DependencyAnalyzer
from app.analyzers.documentation import DocumentationGenerator
from app.analyzers.executive_report import ExecutiveReportGenerator
from app.analyzers.git_analyzer import GitAnalyzer
from app.analyzers.security import SecurityAnalyzer
from app.analyzers.vulnerabilities import VulnerabilityAnalyzer
from app.analyzers.performance import PerformanceAnalyzer
from app.analyzers.ai_analysis import AIAnalyzer

__all__ = [
    "ArchitectureAnalyzer",
    "CodeQualityAnalyzer",
    "DependencyAnalyzer",
    "DocumentationGenerator",
    "ExecutiveReportGenerator",
    "GitAnalyzer",
    "SecurityAnalyzer",
    "VulnerabilityAnalyzer",
    "PerformanceAnalyzer",
    "AIAnalyzer",
]

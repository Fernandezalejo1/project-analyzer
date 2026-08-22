"""Data models for the Project Analyzer."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProjectType(str, Enum):
    MONOLITH = "monolith"
    MICROSERVICES = "microservices"
    API_REST = "api_rest"
    DESKTOP = "desktop"
    MOBILE = "mobile"
    LIBRARY = "library"
    CLI = "cli"
    UNKNOWN = "unknown"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    CSHARP = "csharp"
    CPP = "cpp"
    RUBY = "ruby"
    PHP = "php"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    DART = "dart"
    UNKNOWN = "unknown"


# ── Architecture ───────────────────────────────────────────────────────────

class Framework(BaseModel):
    name: str
    version: str | None = None
    confidence: float = Field(ge=0, le=1)


class ArchitectureMap(BaseModel):
    layers: list[str] = Field(default_factory=list)
    connections: list[dict[str, str]] = Field(default_factory=list)
    description: str = ""


class ArchitectureAnalysis(BaseModel):
    primary_language: Language
    languages_detected: list[dict[str, Any]] = Field(default_factory=list)
    frameworks: list[Framework] = Field(default_factory=list)
    project_type: ProjectType
    architecture_map: ArchitectureMap
    structure_summary: str = ""


# ── Dependencies ───────────────────────────────────────────────────────────

class DependencyInfo(BaseModel):
    name: str
    version: str
    latest_version: str | None = None
    is_outdated: bool = False
    is_vulnerable: bool = False
    vulnerability_ids: list[str] = Field(default_factory=list)
    is_deprecated: bool = False
    has_maintenance_issues: bool = False
    license: str | None = None


class DependencyReport(BaseModel):
    total_count: int = 0
    outdated_count: int = 0
    critical_count: int = 0
    deprecated_count: int = 0
    vulnerable_count: int = 0
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    summary: str = ""


# ── Security ───────────────────────────────────────────────────────────────

class SecretFinding(BaseModel):
    file_path: str
    line_number: int
    secret_type: str
    severity: Severity
    context: str  # surrounding code
    recommendation: str


class SecurityReport(BaseModel):
    secrets_found: list[SecretFinding] = Field(default_factory=list)
    secrets_count: int = 0
    exposed_env_files: list[str] = Field(default_factory=list)
    exposed_certificates: list[str] = Field(default_factory=list)
    exposed_credentials: list[str] = Field(default_factory=list)
    summary: str = ""


# ── Vulnerabilities ────────────────────────────────────────────────────────

class VulnerabilityFinding(BaseModel):
    file_path: str
    line_number: int
    vulnerability_type: str  # SQL Injection, XSS, etc.
    severity: Severity
    description: str
    code_snippet: str
    recommendation: str
    cwe_id: str | None = None


class VulnerabilityReport(BaseModel):
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    total_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    summary: str = ""


# ── Code Quality ───────────────────────────────────────────────────────────

class FileMetrics(BaseModel):
    file_path: str
    lines_of_code: int = 0
    complexity: float = 0.0
    duplicated_lines: int = 0
    maintainability_index: float = 0.0
    issues: list[str] = Field(default_factory=list)


class CodeQualityReport(BaseModel):
    total_files: int = 0
    total_lines: int = 0
    average_complexity: float = 0.0
    average_maintainability: float = 0.0
    duplicated_percentage: float = 0.0
    dead_code_files: list[str] = Field(default_factory=list)
    large_functions: list[dict[str, Any]] = Field(default_factory=list)
    large_classes: list[dict[str, Any]] = Field(default_factory=list)
    unused_imports_count: int = 0
    technical_debt_hours: float = 0.0
    file_metrics: list[FileMetrics] = Field(default_factory=list)
    summary: str = ""


# ── Git Analysis ───────────────────────────────────────────────────────────

class GitCommitAnalysis(BaseModel):
    hash: str
    message: str
    author: str
    date: str
    files_changed: int = 0
    insertions: int = 0
    deletions: int = 0
    has_secret: bool = False
    is_too_large: bool = False
    has_no_description: bool = False


class GitReport(BaseModel):
    total_commits: int = 0
    branches: list[str] = Field(default_factory=list)
    abandoned_branches: list[str] = Field(default_factory=list)
    large_commits: list[GitCommitAnalysis] = Field(default_factory=list)
    commits_without_description: list[GitCommitAnalysis] = Field(default_factory=list)
    secrets_in_history: list[GitCommitAnalysis] = Field(default_factory=list)
    top_contributors: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


# ── Performance ────────────────────────────────────────────────────────────

class PerformanceFinding(BaseModel):
    file_path: str
    line_number: int
    issue_type: str  # N+1 query, expensive loop, heavy load, etc.
    severity: Severity
    description: str
    recommendation: str


class PerformanceReport(BaseModel):
    findings: list[PerformanceFinding] = Field(default_factory=list)
    large_files: list[dict[str, Any]] = Field(default_factory=list)
    heavy_images: list[dict[str, Any]] = Field(default_factory=list)
    summary: str = ""


# ── AI Analysis ────────────────────────────────────────────────────────────

class AIRecommendation(BaseModel):
    category: str  # architecture, security, performance, quality
    priority: Severity
    title: str
    description: str
    impact: str
    affected_files: list[str] = Field(default_factory=list)


class AIAnalysisReport(BaseModel):
    recommendations: list[AIRecommendation] = Field(default_factory=list)
    architecture_suggestions: list[str] = Field(default_factory=list)
    scalability_concerns: list[str] = Field(default_factory=list)
    summary: str = ""


# ── Documentation ──────────────────────────────────────────────────────────

class DocumentationReport(BaseModel):
    readme_generated: str = ""
    api_docs: str = ""
    architecture_diagram: str = ""  # Mermaid diagram
    onboarding_guide: str = ""
    has_existing_readme: bool = False
    has_existing_docs: bool = False


# ── Executive Report (the big one) ────────────────────────────────────────

class CategoryScore(BaseModel):
    name: str
    score: float = Field(ge=0, le=10)  # 0-10 scale
    details: str = ""


class Priority(BaseModel):
    level: str  # critical, important, recommendation
    title: str
    description: str


class ExecutiveReport(BaseModel):
    overall_score: float = Field(ge=0, le=100)
    categories: list[CategoryScore] = Field(default_factory=list)
    priorities_critical: list[Priority] = Field(default_factory=list)
    priorities_important: list[Priority] = Field(default_factory=list)
    priorities_recommendations: list[Priority] = Field(default_factory=list)
    summary: str = ""


# ── Full Analysis Result ──────────────────────────────────────────────────

class FullAnalysisResult(BaseModel):
    project_path: str
    project_name: str
    architecture: ArchitectureAnalysis
    dependencies: DependencyReport
    security: SecurityReport
    vulnerabilities: VulnerabilityReport
    code_quality: CodeQualityReport
    git: GitReport
    performance: PerformanceReport
    ai_analysis: AIAnalysisReport
    documentation: DocumentationReport
    executive_report: ExecutiveReport
    scan_duration_seconds: float = 0.0

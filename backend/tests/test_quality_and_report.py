"""Tests de métricas de calidad, análisis de git y reporte ejecutivo."""

from __future__ import annotations

from pathlib import Path

from app.analyzers.ai_analysis import AIAnalyzer
from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.code_quality import CodeQualityAnalyzer
from app.analyzers.dependencies import DependencyAnalyzer
from app.analyzers.documentation import DocumentationGenerator
from app.analyzers.executive_report import ExecutiveReportGenerator
from app.analyzers.git_analyzer import GitAnalyzer
from app.analyzers.performance import PerformanceAnalyzer
from app.analyzers.security import SecurityAnalyzer
from app.analyzers.vulnerabilities import VulnerabilityAnalyzer
from app.models.schemas import ExecutiveReport


def _full_analysis(root: str) -> ExecutiveReport:
    """Corre todos los analyzers y devuelve el reporte ejecutivo.

    Centraliza el cableado (que es fácil de romper al cambiar una firma) para
    que los tests de integración no repitan la secuencia de llamadas.
    """
    architecture = ArchitectureAnalyzer(root).analyze()
    dependencies = DependencyAnalyzer(root).analyze()
    security = SecurityAnalyzer(root).analyze()
    vulnerabilities = VulnerabilityAnalyzer(root).analyze()
    code_quality = CodeQualityAnalyzer(root).analyze()
    git_report = GitAnalyzer(root).analyze()
    performance = PerformanceAnalyzer(root).analyze()

    documentation = DocumentationGenerator(root).analyze(
        architecture, dependencies, security, code_quality
    )
    ai_analysis = AIAnalyzer(root).analyze(
        architecture,
        dependencies,
        security,
        vulnerabilities,
        code_quality,
        git_report,
        performance,
    )

    return ExecutiveReportGenerator().generate(
        architecture,
        dependencies,
        security,
        vulnerabilities,
        code_quality,
        git_report,
        performance,
        ai_analysis,
        documentation,
    )


def _category_score(report: ExecutiveReport, name: str) -> float:
    for category in report.categories:
        if category.name == name:
            return category.score
    raise AssertionError(f"categoría {name} ausente en el reporte ejecutivo")


def test_cuenta_archivos_y_lineas(messy_project: Path) -> None:
    report = CodeQualityAnalyzer(str(messy_project)).analyze()

    assert report.total_files == 2
    assert report.total_lines > 0


def test_calcula_complejidad(messy_project: Path) -> None:
    report = CodeQualityAnalyzer(str(messy_project)).analyze()

    assert report.average_complexity > 0
    assert 0 <= report.average_maintainability <= 100


def test_detecta_imports_sin_usar(messy_project: Path) -> None:
    report = CodeQualityAnalyzer(str(messy_project)).analyze()

    assert report.unused_imports_count >= 3


def test_metricas_por_archivo_son_relativas(messy_project: Path) -> None:
    report = CodeQualityAnalyzer(str(messy_project)).analyze()

    rutas = {m.file_path for m in report.file_metrics}
    assert "messy.py" in rutas
    assert all(not r.startswith(str(messy_project)) for r in rutas)


def test_tech_debt_no_es_negativa(clean_project: Path) -> None:
    report = CodeQualityAnalyzer(str(clean_project)).analyze()

    assert report.technical_debt_hours >= 0


def test_git_analyzer_sobre_directorio_sin_repo(clean_project: Path) -> None:
    report = GitAnalyzer(str(clean_project)).analyze()

    assert report.total_commits == 0
    assert report.branches == []


def test_performance_analyzer_corre_sobre_proyecto_chico(clean_project: Path) -> None:
    report = PerformanceAnalyzer(str(clean_project)).analyze()

    # No debe explotar ni inventar hallazgos en un archivo trivial.
    assert report.findings == []


def test_reporte_ejecutivo_calcula_score_y_categorias(python_api_project: Path) -> None:
    report = _full_analysis(str(python_api_project))

    assert 0 <= report.overall_score <= 100
    nombres = {c.name for c in report.categories}
    assert {"Architecture", "Security", "Code Quality"} <= nombres
    assert report.summary


def test_secretos_bajan_el_score_de_seguridad(
    python_api_project: Path, leaked_secrets_project: Path
) -> None:
    """El score de seguridad debe penalizar secretos filtrados y vulnerabilidades."""
    limpio = _full_analysis(str(python_api_project))
    filtrado = _full_analysis(str(leaked_secrets_project))

    assert _category_score(filtrado, "Security") < _category_score(limpio, "Security")

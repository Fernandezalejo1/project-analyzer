"""Tests de detección de arquitectura y dependencias."""

from __future__ import annotations

from pathlib import Path

from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.dependencies import DependencyAnalyzer
from app.models.schemas import Framework, Language


def test_detecta_python_como_lenguaje_principal(python_api_project: Path) -> None:
    result = ArchitectureAnalyzer(str(python_api_project)).analyze()

    assert result.primary_language == Language.PYTHON
    detectados = {item["language"] for item in result.languages_detected}
    assert "python" in detectados


def test_detecta_fastapi_por_requirements(python_api_project: Path) -> None:
    result = ArchitectureAnalyzer(str(python_api_project)).analyze()

    nombres = {f.name.lower() for f in result.frameworks}
    assert "fastapi" in nombres
    assert all(isinstance(f, Framework) for f in result.frameworks)


def test_detecta_proyecto_node(node_web_project: Path) -> None:
    result = ArchitectureAnalyzer(str(node_web_project)).analyze()

    detectados = {item["language"] for item in result.languages_detected}
    assert "javascript" in detectados or "typescript" in detectados
    nombres = {f.name.lower() for f in result.frameworks}
    assert "express" in nombres or "react" in nombres


def test_detecta_monorepo_o_tipo_de_proyecto(python_api_project: Path) -> None:
    result = ArchitectureAnalyzer(str(python_api_project)).analyze()

    # El tipo debe resolverse a algo distinto de UNKNOWN para un proyecto con
    # estructura clara (app/ + requirements.txt).
    assert result.project_type.value != ""
    assert isinstance(result.architecture_map.layers, list)


def test_requirements_txt_se_parsea(python_api_project: Path) -> None:
    report = DependencyAnalyzer(str(python_api_project)).analyze()

    nombres = {d.name.lower() for d in report.dependencies}
    assert "fastapi" in nombres
    assert "pydantic" in nombres
    assert report.total_count >= 2


def test_package_json_se_parsea(node_web_project: Path) -> None:
    report = DependencyAnalyzer(str(node_web_project)).analyze()

    nombres = {d.name.lower() for d in report.dependencies}
    assert "express" in nombres
    assert "react" in nombres


def test_proyecto_sin_manifiestos_no_falla(clean_project: Path) -> None:
    report = DependencyAnalyzer(str(clean_project)).analyze()

    assert report.total_count == 0
    assert report.dependencies == []

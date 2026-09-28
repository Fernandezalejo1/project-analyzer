"""Tests de detección de secretos y vulnerabilidades."""

from __future__ import annotations

from pathlib import Path

from app.analyzers.security import SecurityAnalyzer
from app.analyzers.vulnerabilities import VulnerabilityAnalyzer
from app.models.schemas import Severity


def test_detecta_api_key_generica(leaked_secrets_project: Path) -> None:
    report = SecurityAnalyzer(str(leaked_secrets_project)).analyze()

    assert report.secrets_count >= 1
    assert any("api key" in s.secret_type.lower() for s in report.secrets_found)


def test_detecta_clave_estilo_openai(leaked_secrets_project: Path) -> None:
    report = SecurityAnalyzer(str(leaked_secrets_project)).analyze()

    criticos = [s for s in report.secrets_found if s.severity == Severity.CRITICAL]
    assert criticos, "se esperaba al menos un hallazgo CRITICAL"
    assert any("openai" in s.secret_type.lower() for s in criticos)


def test_detecta_aws_access_key(leaked_secrets_project: Path) -> None:
    report = SecurityAnalyzer(str(leaked_secrets_project)).analyze()

    assert any("aws" in s.secret_type.lower() for s in report.secrets_found)


def test_marca_el_env_real_como_expuesto(leaked_secrets_project: Path) -> None:
    report = SecurityAnalyzer(str(leaked_secrets_project)).analyze()

    assert any(path.endswith(".env") for path in report.exposed_env_files)


def test_no_marca_env_example_como_secreto(leaked_secrets_project: Path) -> None:
    """`.env.example` es una buena práctica: no debe reportarse como fuga."""
    report = SecurityAnalyzer(str(leaked_secrets_project)).analyze()

    assert not any("example" in path for path in report.exposed_env_files)


def test_proyecto_limpio_no_reporta_secretos(python_api_project: Path) -> None:
    report = SecurityAnalyzer(str(python_api_project)).analyze()

    assert report.secrets_count == 0
    assert report.secrets_found == []


def test_detecta_sql_injection_por_f_string(vulnerable_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(vulnerable_project)).analyze()

    tipos = {f.vulnerability_type for f in report.findings}
    assert "SQL Injection" in tipos
    assert report.critical_count >= 1


def test_detecta_eval_con_input(vulnerable_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(vulnerable_project)).analyze()

    tipos = {f.vulnerability_type for f in report.findings}
    assert "Code Injection" in tipos


def test_detecta_ejecucion_de_comandos(vulnerable_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(vulnerable_project)).analyze()

    tipos = {f.vulnerability_type for f in report.findings}
    assert "Command Injection" in tipos


def test_detecta_criptografia_debil(vulnerable_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(vulnerable_project)).analyze()

    tipos = {f.vulnerability_type for f in report.findings}
    assert "Weak Crypto" in tipos


def test_hallazgos_incluyen_ubicacion_y_recomendacion(vulnerable_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(vulnerable_project)).analyze()

    assert report.findings, "el proyecto de prueba debe generar hallazgos"
    for finding in report.findings:
        assert finding.line_number >= 1
        assert finding.recommendation
        assert finding.file_path


def test_proyecto_limpio_no_reporta_vulnerabilidades(clean_project: Path) -> None:
    report = VulnerabilityAnalyzer(str(clean_project)).analyze()

    assert report.total_count == 0
    assert report.findings == []

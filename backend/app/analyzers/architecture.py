"""Architecture Analyzer - Detects languages, frameworks, project type, and generates architecture maps."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.models.schemas import (
    ArchitectureAnalysis,
    ArchitectureMap,
    Framework,
    Language,
    ProjectType,
)

# ── Language detection by file extension ────────────────────────────────────

EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".kt": Language.KOTLIN,
    ".kts": Language.KOTLIN,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".cs": Language.CSHARP,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".c": Language.CPP,
    ".h": Language.CPP,
    ".rb": Language.RUBY,
    ".php": Language.PHP,
    ".swift": Language.SWIFT,
    ".dart": Language.DART,
}

# ── Framework detection patterns ───────────────────────────────────────────

FRAMEWORK_DETECTORS: list[dict[str, Any]] = [
    # JavaScript / TypeScript
    {
        "name": "React",
        "version_file": "package.json",
        "key_patterns": ["react", "next", "remix", "gatsby"],
        "file_extensions": [".jsx", ".tsx"],
        "import_patterns": ["from 'react'", 'from "react"', "import React"],
    },
    {
        "name": "Vue",
        "version_file": "package.json",
        "key_patterns": ["vue", "nuxt"],
        "file_extensions": [".vue"],
        "import_patterns": ["from 'vue'", 'from "vue"', "Vue.createApp"],
    },
    {
        "name": "Angular",
        "version_file": "package.json",
        "key_patterns": ["@angular/core"],
        "file_extensions": [".component.ts"],
        "import_patterns": ["@Component", "@Injectable", "@NgModule"],
    },
    {
        "name": "Svelte",
        "version_file": "package.json",
        "key_patterns": ["svelte", "sveltekit"],
        "file_extensions": [".svelte"],
        "import_patterns": [],
    },
    {
        "name": "Express",
        "version_file": "package.json",
        "key_patterns": ["express"],
        "import_patterns": ["require('express')", 'require("express")', "from 'express'"],
    },
    {
        "name": "Fastify",
        "version_file": "package.json",
        "key_patterns": ["fastify"],
        "import_patterns": ["require('fastify')", "from 'fastify'"],
    },
    # Python
    {
        "name": "Django",
        "version_file": "requirements.txt",
        "key_patterns": ["django"],
        "import_patterns": ["from django", "import django"],
    },
    {
        "name": "FastAPI",
        "version_file": "requirements.txt",
        "key_patterns": ["fastapi"],
        "import_patterns": ["from fastapi", "import fastapi"],
    },
    {
        "name": "Flask",
        "version_file": "requirements.txt",
        "key_patterns": ["flask"],
        "import_patterns": ["from flask", "import Flask"],
    },
    {
        "name": "Tornado",
        "version_file": "requirements.txt",
        "key_patterns": ["tornado"],
        "import_patterns": ["import tornado"],
    },
    # Java
    {
        "name": "Spring Boot",
        "version_file": "pom.xml",
        "key_patterns": ["spring-boot", "spring-framework"],
        "import_patterns": ["import org.springframework"],
    },
    {
        "name": "Quarkus",
        "version_file": "pom.xml",
        "key_patterns": ["quarkus"],
        "import_patterns": ["import io.quarkus"],
    },
    # Go
    {
        "name": "Gin",
        "version_file": "go.mod",
        "key_patterns": ["github.com/gin-gonic"],
        "import_patterns": ['"github.com/gin-gonic'],
    },
    {
        "name": "Echo",
        "version_file": "go.mod",
        "key_patterns": ["github.com/labstack/echo"],
        "import_patterns": ['"github.com/labstack/echo'],
    },
    # Rust
    {
        "name": "Actix",
        "version_file": "Cargo.toml",
        "key_patterns": ["actix-web"],
        "import_patterns": ["use actix_web"],
    },
    {
        "name": "Axum",
        "version_file": "Cargo.toml",
        "key_patterns": ["axum"],
        "import_patterns": ["use axum"],
    },
    # Mobile
    {
        "name": "React Native",
        "version_file": "package.json",
        "key_patterns": ["react-native"],
        "import_patterns": ["from 'react-native'"],
    },
    {
        "name": "Flutter",
        "version_file": "pubspec.yaml",
        "key_patterns": ["flutter"],
        "import_patterns": ["import 'package:flutter"],
    },
    # .NET
    {
        "name": "ASP.NET",
        "version_file": "*.csproj",
        "key_patterns": ["Microsoft.AspNetCore"],
        "import_patterns": ["using Microsoft.AspNetCore"],
    },
]


class ArchitectureAnalyzer:
    """Analyzes project architecture, detecting languages, frameworks, and project type."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._file_counts: dict[str, int] = {}
        self._all_files: list[Path] = []
        self._scanned_files_content: dict[str, str] = {}

    # ── Public API ─────────────────────────────────────────────────────

    def analyze(self) -> ArchitectureAnalysis:
        """Run full architecture analysis."""
        self._scan_files()
        primary_lang = self._detect_primary_language()
        languages = self._get_language_distribution()
        frameworks = self._detect_frameworks()
        project_type = self._detect_project_type()
        arch_map = self._build_architecture_map()

        return ArchitectureAnalysis(
            primary_language=primary_lang,
            languages_detected=languages,
            frameworks=frameworks,
            project_type=project_type,
            architecture_map=arch_map,
            structure_summary=self._generate_structure_summary(primary_lang, frameworks, project_type),
        )

    # ── Private methods ────────────────────────────────────────────────

    def _scan_files(self):
        """Walk the project tree and collect all source files."""
        skip_dirs = {
            "node_modules", ".git", "__pycache__", ".venv", "venv",
            "dist", "build", ".next", ".nuxt", "target", "bin", "obj",
            ".idea", ".vscode", ".tox", ".mypy_cache", ".pytest_cache",
            "coverage", ".eggs", "*.egg-info",
        }

        for root, dirs, files in os.walk(self.root):
            # Filter out skip directories
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]

            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                if ext in EXTENSION_MAP:
                    self._all_files.append(fpath)
                    lang = EXTENSION_MAP[ext].value
                    self._file_counts[lang] = self._file_counts.get(lang, 0) + 1

    def _detect_primary_language(self) -> Language:
        """Return the language with the most files."""
        if not self._file_counts:
            return Language.UNKNOWN

        primary = max(self._file_counts, key=self._file_counts.get)  # type: ignore
        try:
            return Language(primary)
        except ValueError:
            return Language.UNKNOWN

    def _get_language_distribution(self) -> list[dict[str, Any]]:
        """Return list of {language, file_count, percentage}."""
        total = sum(self._file_counts.values())
        if total == 0:
            return []

        result = []
        for lang, count in sorted(self._file_counts.items(), key=lambda x: -x[1]):
            result.append({
                "language": lang,
                "file_count": count,
                "percentage": round(count / total * 100, 1),
            })
        return result

    def _detect_frameworks(self) -> list[Framework]:
        """Detect frameworks by scanning dependency files and source imports."""
        detected: list[Framework] = []
        seen: set[str] = set()

        # Scan source files for import patterns (sample up to 50 files)
        source_samples = self._all_files[:50]
        file_contents: list[str] = []
        for fp in source_samples:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                file_contents.append(content)
            except Exception:
                pass

        for detector in FRAMEWORK_DETECTORS:
            if detector["name"] in seen:
                continue

            found = False

            # Check dependency files
            for key_pattern in detector.get("key_patterns", []):
                # Check package.json
                pkg_json = self.root / "package.json"
                if pkg_json.exists():
                    try:
                        pkg_content = pkg_json.read_text(encoding="utf-8", errors="ignore")
                        if key_pattern in pkg_content:
                            found = True
                            break
                    except Exception:
                        pass

                # Check requirements.txt
                req_txt = self.root / "requirements.txt"
                if req_txt.exists():
                    try:
                        req_content = req_txt.read_text(encoding="utf-8", errors="ignore")
                        if key_pattern in req_content.lower():
                            found = True
                            break
                    except Exception:
                        pass

                # Check pom.xml
                pom = self.root / "pom.xml"
                if pom.exists():
                    try:
                        pom_content = pom.read_text(encoding="utf-8", errors="ignore")
                        if key_pattern in pom_content:
                            found = True
                            break
                    except Exception:
                        pass

                # Check go.mod
                go_mod = self.root / "go.mod"
                if go_mod.exists():
                    try:
                        go_content = go_mod.read_text(encoding="utf-8", errors="ignore")
                        if key_pattern in go_content:
                            found = True
                            break
                    except Exception:
                        pass

                # Check Cargo.toml
                cargo = self.root / "Cargo.toml"
                if cargo.exists():
                    try:
                        cargo_content = cargo.read_text(encoding="utf-8", errors="ignore")
                        if key_pattern in cargo_content:
                            found = True
                            break
                    except Exception:
                        pass

            # Check source imports
            if not found:
                for import_pattern in detector.get("import_patterns", []):
                    for content in file_contents:
                        if import_pattern in content:
                            found = True
                            break
                    if found:
                        break

            # Check file extensions
            if not found and detector.get("file_extensions"):
                for fpath in self._all_files[:200]:
                    if fpath.suffix in detector["file_extensions"]:
                        found = True
                        break

            if found:
                seen.add(detector["name"])
                detected.append(Framework(
                    name=detector["name"],
                    confidence=0.9 if any(k in str(self.root) for k in detector.get("key_patterns", [])) else 0.75,
                ))

        return detected

    def _detect_project_type(self) -> ProjectType:
        """Detect the type of project based on structure and dependencies."""
        indicators: dict[ProjectType, int] = {t: 0 for t in ProjectType}

        # Check for mobile indicators
        if (self.root / "pubspec.yaml").exists():
            indicators[ProjectType.MOBILE] += 3
        if (self.root / "android").exists() or (self.root / "ios").exists():
            indicators[ProjectType.MOBILE] += 2
        if any(f.suffix == ".dart" for f in self._all_files[:50]):
            indicators[ProjectType.MOBILE] += 2

        # Check for desktop indicators
        if (self.root / "*.csproj").exists():
            indicators[ProjectType.DESKTOP] += 2
        if any(f.suffix in (".cs", ".xaml") for f in self._all_files[:50]):
            indicators[ProjectType.DESKTOP] += 1

        # Check for CLI indicators
        cli_args = ["argparse", "click", "typer", "cobra", "clap"]
        for fp in self._all_files[:30]:
            try:
                content = fp.read_text(encoding="utf-8", errors="ignore")
                for arg in cli_args:
                    if arg in content:
                        indicators[ProjectType.CLI] += 2
                        break
            except Exception:
                pass

        # Check for library indicators
        if (self.root / "setup.py").exists() or (self.root / "setup.cfg").exists():
            indicators[ProjectType.LIBRARY] += 1
        if (self.root / "lib").exists() and not (self.root / "src").exists():
            indicators[ProjectType.LIBRARY] += 1

        # Check for microservices
        docker_compose = self.root / "docker-compose.yml"
        docker_compose2 = self.root / "docker-compose.yaml"
        if docker_compose.exists() or docker_compose2.exists():
            indicators[ProjectType.MICROSERVICES] += 2
        if (self.root / "services").exists():
            indicators[ProjectType.MICROSERVICES] += 3
        if (self.root / "k8s").exists() or (self.root / "kubernetes").exists():
            indicators[ProjectType.MICROSERVICES] += 2

        # Check for API indicators
        api_dirs = ["api", "routes", "controllers", "endpoints"]
        for d in api_dirs:
            if (self.root / d).exists():
                indicators[ProjectType.API_REST] += 2

        # Check for web frontend indicators
        if (self.root / "public").exists() and (self.root / "src").exists():
            indicators[ProjectType.API_REST] += 1  # likely SPA

        # Default: monolith
        if all(v == 0 for v in indicators.values()):
            indicators[ProjectType.MONOLITH] = 1

        # Return highest scoring type
        best = max(indicators, key=indicators.get)  # type: ignore
        return best

    def _build_architecture_map(self) -> ArchitectureMap:
        """Generate a Mermaid-style architecture map of the project."""
        layers: list[str] = []
        connections: list[dict[str, str]] = []

        # Detect top-level directories
        top_dirs = sorted([
            d.name for d in self.root.iterdir()
            if d.is_dir() and not d.name.startswith(".") and d.name not in ("node_modules", "__pycache__", "venv")
        ])

        # Classify directories into layers
        frontend_keywords = {"frontend", "client", "web", "ui", "components", "pages", "views", "templates", "static", "assets"}
        backend_keywords = {"backend", "server", "api", "routes", "controllers", "handlers", "middleware", "services"}
        data_keywords = {"database", "db", "models", "migrations", "schemas", "repositories", "data"}
        test_keywords = {"test", "tests", "spec", "__tests__", "e2e"}
        infra_keywords = {"infrastructure", "infra", "deploy", "k8s", "docker", "terraform", "ci", ".github"}

        frontend_dirs = []
        backend_dirs = []
        data_dirs = []
        test_dirs = []
        infra_dirs = []
        other_dirs = []

        for d in top_dirs:
            lower = d.lower()
            if any(k in lower for k in frontend_keywords):
                frontend_dirs.append(d)
            elif any(k in lower for k in backend_keywords):
                backend_dirs.append(d)
            elif any(k in lower for k in data_keywords):
                data_dirs.append(d)
            elif any(k in lower for k in test_keywords):
                test_dirs.append(d)
            elif any(k in lower for k in infra_keywords):
                infra_dirs.append(d)
            else:
                other_dirs.append(d)

        if frontend_dirs:
            layers.append(f"Frontend: {', '.join(frontend_dirs)}")
        if backend_dirs:
            layers.append(f"Backend: {', '.join(backend_dirs)}")
        if data_dirs:
            layers.append(f"Data Layer: {', '.join(data_dirs)}")
        if test_dirs:
            layers.append(f"Tests: {', '.join(test_dirs)}")
        if infra_dirs:
            layers.append(f"Infrastructure: {', '.join(infra_dirs)}")
        if other_dirs:
            layers.append(f"Other: {', '.join(other_dirs[:5])}")

        # Build connections
        if frontend_dirs and backend_dirs:
            connections.append({"from": "Frontend", "to": "Backend", "type": "HTTP/WebSocket"})
        if backend_dirs and data_dirs:
            connections.append({"from": "Backend", "to": "Data Layer", "type": "ORM/Direct"})

        description = f"Project with {len(top_dirs)} top-level directories"
        if layers:
            description += f": {', '.join(layers)}"

        return ArchitectureMap(
            layers=layers,
            connections=connections,
            description=description,
        )

    def _generate_structure_summary(
        self, language: Language, frameworks: list[Framework], project_type: ProjectType
    ) -> str:
        """Generate a human-readable summary."""
        fw_names = ", ".join(f.name for f in frameworks) if frameworks else "none detected"
        file_count = len(self._all_files)

        return (
            f"This is a {project_type.value} project primarily written in {language.value} "
            f"using {fw_names}. It contains {file_count} source files across "
            f"{len(self._file_counts)} language(s)."
        )

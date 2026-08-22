"""Dependency Analyzer - Scans dependency files and checks for issues."""

from __future__ import annotations

import json
import re
from pathlib import Path

from app.models.schemas import DependencyInfo, DependencyReport


# ── Supported dependency files ─────────────────────────────────────────────

class DependencyFile:
    """Represents a detected dependency file."""

    def __init__(self, path: Path, manager: str, dependencies: list[dict[str, str]]):
        self.path = path
        self.manager = manager
        self.dependencies = dependencies  # [{name, version}]


class DependencyAnalyzer:
    """Scans and analyzes project dependencies."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._dep_files: list[DependencyFile] = []

    def analyze(self) -> DependencyReport:
        """Run full dependency analysis."""
        self._scan_dependency_files()
        all_deps: list[DependencyInfo] = []

        for dep_file in self._dep_files:
            for dep in dep_file.dependencies:
                info = DependencyInfo(
                    name=dep["name"],
                    version=dep.get("version", "*"),
                )
                # Quick checks
                self._check_version_patterns(info)
                all_deps.append(info)

        # Deduplicate by name (keep highest version seen)
        unique_deps: dict[str, DependencyInfo] = {}
        for dep in all_deps:
            key = dep.name.lower()
            if key not in unique_deps:
                unique_deps[key] = dep

        deps_list = list(unique_deps.values())
        report = DependencyReport(
            total_count=len(deps_list),
            dependencies=deps_list,
        )

        # Calculate counts
        for dep in deps_list:
            if dep.is_outdated:
                report.outdated_count += 1
            if dep.is_vulnerable:
                report.vulnerable_count += 1
            if dep.is_deprecated:
                report.deprecated_count += 1

        report.summary = self._generate_summary(report)
        return report

    # ── Private ────────────────────────────────────────────────────────

    def _scan_dependency_files(self):
        """Find and parse all dependency files."""
        parsers = [
            ("package.json", self._parse_package_json),
            ("requirements.txt", self._parse_requirements_txt),
            ("Pipfile", self._parse_pipfile),
            ("pyproject.toml", self._parse_pyproject_toml),
            ("Cargo.toml", self._parse_cargo_toml),
            ("pom.xml", self._parse_pom_xml),
            ("build.gradle", self._parse_build_gradle),
            ("go.mod", self._parse_go_mod),
            ("Gemfile", self._parse_gemfile),
            ("composer.json", self._parse_composer_json),
            ("pubspec.yaml", self._parse_pubspec_yaml),
            ("*.csproj", self._parse_csproj),
        ]

        for filename, parser in parsers:
            if "*" in filename:
                # Glob pattern
                for fpath in self.root.glob(filename):
                    try:
                        deps = parser(fpath)
                        if deps:
                            self._dep_files.append(DependencyFile(fpath, filename, deps))
                    except Exception:
                        pass
            else:
                fpath = self.root / filename
                if fpath.exists():
                    try:
                        deps = parser(fpath)
                        if deps:
                            self._dep_files.append(DependencyFile(fpath, filename, deps))
                    except Exception:
                        pass

        # Also check nested package.json files (monorepos)
        for fpath in self.root.glob("*/package.json"):
            if fpath.parent != self.root:
                try:
                    deps = self._parse_package_json(fpath)
                    if deps:
                        self._dep_files.append(DependencyFile(fpath, "package.json (nested)", deps))
                except Exception:
                    pass

    def _parse_package_json(self, path: Path) -> list[dict[str, str]]:
        """Parse package.json dependencies."""
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return []

        deps = []
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            for name, version in data.get(section, {}).items():
                # Clean version string
                version = version.lstrip("^~>=<!")
                deps.append({"name": name, "version": version})
        return deps

    def _parse_requirements_txt(self, path: Path) -> list[dict[str, str]]:
        """Parse requirements.txt."""
        deps = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle ==, >=, <=, ~=, etc.
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=!~]+.*)?$", line)
                if match:
                    name = match.group(1)
                    version = (match.group(2) or "*").strip()
                    deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _parse_pipfile(self, path: Path) -> list[dict[str, str]]:
        """Parse Pipfile (basic extraction)."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Simple regex extraction
            for match in re.finditer(r'^(\w[\w.-]*)\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE):
                name = match.group(1)
                version = match.group(2).lstrip("^~>=<!")
                if name not in ("name", "requires", "packages"):
                    deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _parse_pyproject_toml(self, path: Path) -> list[dict[str, str]]:
        """Parse pyproject.toml dependencies."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Find dependencies section
            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == "dependencies = [":
                    in_deps = True
                    continue
                if in_deps:
                    if stripped == "]":
                        break
                    match = re.match(r'["\']([a-zA-Z0-9_.-]+)(.*)["\']', stripped.rstrip(","))
                    if match:
                        name = match.group(1)
                        version_part = match.group(2).strip()
                        version_match = re.search(r"([><=!~]+\s*[\d.*]+)", version_part)
                        version = version_match.group(1) if version_match else "*"
                        deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _parse_cargo_toml(self, path: Path) -> list[dict[str, str]]:
        """Parse Cargo.toml dependencies."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                    in_deps = True
                    continue
                if stripped.startswith("[") and in_deps:
                    in_deps = False
                    continue
                if in_deps:
                    match = re.match(r'^([\w-]+)\s*=\s*["\'](.+)["\']', stripped)
                    if match:
                        deps.append({"name": match.group(1), "version": match.group(2)})
                    else:
                        # Handle version = "x" style
                        match2 = re.match(r'^([\w-]+)\s*=\s*\{.*version\s*=\s*["\'](.+)["\']', stripped)
                        if match2:
                            deps.append({"name": match2.group(1), "version": match2.group(2)})
        except OSError:
            pass
        return deps

    def _parse_pom_xml(self, path: Path) -> list[dict[str, str]]:
        """Parse pom.xml dependencies."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Extract dependency blocks
            dep_pattern = re.compile(
                r"<dependency>\s*"
                r"<groupId>([^<]+)</groupId>\s*"
                r"<artifactId>([^<]+)</artifactId>\s*"
                r"(?:<version>([^<]+)</version>)?",
                re.DOTALL,
            )
            for match in dep_pattern.finditer(content):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = (match.group(3) or "*").strip()
                deps.append({"name": f"{group_id}:{artifact_id}", "version": version})
        except OSError:
            pass
        return deps

    def _parse_build_gradle(self, path: Path) -> list[dict[str, str]]:
        """Parse build.gradle dependencies."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Match implementation 'group:artifact:version' style
            for match in re.finditer(
                r"(?:implementation|api|compile|testImplementation)\s+['\"]([^'\"]+)['\"]",
                content,
            ):
                parts = match.group(1).split(":")
                if len(parts) >= 3:
                    deps.append({"name": f"{parts[0]}:{parts[1]}", "version": parts[2]})
                elif len(parts) == 2:
                    deps.append({"name": match.group(1), "version": "*"})
        except OSError:
            pass
        return deps

    def _parse_go_mod(self, path: Path) -> list[dict[str, str]]:
        """Parse go.mod dependencies."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            in_require = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == "require (":
                    in_require = True
                    continue
                if stripped == ")" and in_require:
                    in_require = False
                    continue
                if in_require and stripped and not stripped.startswith("//"):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        deps.append({"name": parts[0], "version": parts[1]})
                elif stripped.startswith("require "):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        deps.append({"name": parts[1], "version": parts[2]})
        except OSError:
            pass
        return deps

    def _parse_gemfile(self, path: Path) -> list[dict[str, str]]:
        """Parse Gemfile."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(r"""gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?""", content):
                name = match.group(1)
                version = match.group(2) or "*"
                deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _parse_composer_json(self, path: Path) -> list[dict[str, str]]:
        """Parse composer.json."""
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (json.JSONDecodeError, OSError):
            return []

        deps = []
        for section in ["require", "require-dev"]:
            for name, version in data.get(section, {}).items():
                if name.startswith("php"):
                    continue
                deps.append({"name": name, "version": str(version).lstrip("^~>=<!")})
        return deps

    def _parse_pubspec_yaml(self, path: Path) -> list[dict[str, str]]:
        """Parse pubspec.yaml (Flutter/Dart)."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            in_deps = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped == "dependencies:":
                    in_deps = True
                    continue
                if stripped == "dev_dependencies:":
                    in_deps = False
                    continue
                if in_deps and stripped and not stripped.startswith("#"):
                    match = re.match(r"^([\w]+):\s*(.+)$", stripped)
                    if match:
                        name = match.group(1)
                        version = match.group(2).strip()
                        if version.startswith("^"):
                            version = version[1:]
                        deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _parse_csproj(self, path: Path) -> list[dict[str, str]]:
        """Parse .csproj files for NuGet packages."""
        deps = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(
                r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?',
                content,
            ):
                name = match.group(1)
                version = match.group(2) or "*"
                deps.append({"name": name, "version": version})
        except OSError:
            pass
        return deps

    def _check_version_patterns(self, dep: DependencyInfo):
        """Check for version pattern issues."""
        ver = dep.version
        # Heuristic: if version has many pre-release tags or is very old patterns
        if ver in ("*", "latest", "HEAD"):
            dep.is_outdated = True  # Unpinned = potential risk

    def _generate_summary(self, report: DependencyReport) -> str:
        """Generate a human-readable summary."""
        parts = [f"Found {report.total_count} dependencies across {len(self._dep_files)} dependency file(s)."]

        if self._dep_files:
            managers = set(df.manager for df in self._dep_files)
            parts.append(f"Package managers detected: {', '.join(managers)}.")

        if report.vulnerable_count:
            parts.append(f"⚠️  {report.vulnerable_count} potentially vulnerable.")
        if report.outdated_count:
            parts.append(f"📦 {report.outdated_count} potentially outdated or unpinned.")
        if report.deprecated_count:
            parts.append(f"🗑️  {report.deprecated_count} deprecated.")

        if not report.vulnerable_count and not report.outdated_count:
            parts.append("✅ No obvious dependency issues detected (offline scan — a full audit requires network access).")

        return " ".join(parts)

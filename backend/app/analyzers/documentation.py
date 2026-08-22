"""Documentation Generator - Auto-generates documentation for the project."""

from __future__ import annotations

from pathlib import Path

from app.models.schemas import (
    ArchitectureAnalysis,
    CodeQualityReport,
    DependencyReport,
    DocumentationReport,
    SecurityReport,
)


class DocumentationGenerator:
    """Generates project documentation based on analysis results."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)

    def analyze(
        self,
        architecture: ArchitectureAnalysis,
        dependencies: DependencyReport,
        security: SecurityReport,
        quality: CodeQualityReport,
    ) -> DocumentationReport:
        """Generate documentation for the project."""
        has_readme = (self.root / "README.md").exists() or (self.root / "README.rst").exists() or (self.root / "README").exists()
        has_docs = (self.root / "docs").exists() or (self.root / "doc").exists()

        report = DocumentationReport(
            has_existing_readme=has_readme,
            has_existing_docs=has_docs,
            readme_generated=self._generate_readme(architecture, dependencies, security, quality),
            architecture_diagram=self._generate_architecture_diagram(architecture),
            onboarding_guide=self._generate_onboarding(architecture, dependencies),
        )

        return report

    def _generate_readme(
        self,
        arch: ArchitectureAnalysis,
        deps: DependencyReport,
        security: SecurityReport,
        quality: CodeQualityReport,
    ) -> str:
        """Generate a README for the project."""
        parts = [
            f"# {self.root.name}",
            "",
            "## Overview",
            "",
            f"**Primary Language:** {arch.primary_language.value}",
        ]

        if arch.languages_detected:
            langs = ", ".join(f"{l['language']} ({l['percentage']}%)" for l in arch.languages_detected[:5])
            parts.append(f"**Languages:** {langs}")

        if arch.frameworks:
            fws = ", ".join(f.name for f in arch.frameworks)
            parts.append(f"**Frameworks:** {fws}")

        parts.extend([
            f"**Project Type:** {arch.project_type.value}",
            "",
            f"## Project Statistics",
            "",
            f"- **Files:** {quality.total_files}",
            f"- **Lines of Code:** {quality.total_lines:,}",
            f"- **Dependencies:** {deps.total_count}",
            f"- **Avg. Complexity:** {quality.average_complexity:.1f}",
            f"- **Maintainability:** {quality.average_maintainability:.1f}/100",
            "",
        ])

        # Architecture
        if arch.architecture_map.layers:
            parts.extend([
                "## Architecture",
                "",
                "```",
            ])
            for layer in arch.architecture_map.layers:
                parts.append(f"  📁 {layer}")
            parts.extend(["```", ""])

        # Dependencies
        if deps.total_count > 0:
            parts.extend([
                "## Dependencies",
                "",
                f"Total: {deps.total_count} | Outdated: {deps.outdated_count} | Vulnerable: {deps.vulnerable_count}",
                "",
            ])

        # Security notes
        if security.secrets_count > 0:
            parts.extend([
                "## ⚠️ Security Notice",
                "",
                f"**{security.secrets_count} potential secret(s) detected!** Please review and remediate.",
                "",
            ])

        # Installation
        parts.extend([
            "## Getting Started",
            "",
            "### Prerequisites",
            "",
            f"- {arch.primary_language.value} runtime",
            "",
            "### Installation",
            "",
            "```bash",
            "# Clone the repository",
            "git clone <repository-url>",
            f"cd {self.root.name}",
            "",
            "# Install dependencies",
        ])

        if arch.primary_language.value == "python":
            parts.append("pip install -r requirements.txt")
        elif arch.primary_language.value in ("javascript", "typescript"):
            parts.append("npm install")
        elif arch.primary_language.value == "go":
            parts.append("go mod download")
        elif arch.primary_language.value == "rust":
            parts.append("cargo build")
        elif arch.primary_language.value == "java":
            parts.append("./mvnw install")
        else:
            parts.append("# Install dependencies using your package manager")

        parts.extend(["```", ""])

        return "\n".join(parts)

    def _generate_architecture_diagram(self, arch: ArchitectureAnalysis) -> str:
        """Generate a Mermaid architecture diagram."""
        parts = [
            "```mermaid",
            "graph TD",
        ]

        nodes: list[str] = []

        if arch.architecture_map.layers:
            for i, layer in enumerate(arch.architecture_map.layers):
                node_id = f"A{i}"
                label = layer.split(":")[0].strip() if ":" in layer else layer
                nodes.append(f"    {node_id}[\"{label}\"]")
                parts.append(f"    {node_id}[\"{label}\"]")

            # Add connections
            for i in range(len(nodes) - 1):
                parts.append(f"    A{i} --> A{i + 1}")

        if arch.frameworks:
            parts.append("")
            parts.append("    subgraph Frameworks")
            for fw in arch.frameworks:
                fw_id = fw.name.replace(" ", "_").replace(".", "_")
                parts.append(f"        {fw_id}({fw.name})")
            parts.append("    end")

        parts.extend(["```", ""])
        return "\n".join(parts)

    def _generate_onboarding(self, arch: ArchitectureAnalysis, deps: DependencyReport) -> str:
        """Generate an onboarding guide for new developers."""
        parts = [
            "# Developer Onboarding Guide",
            "",
            "## Welcome!",
            "",
            f"Welcome to the {self.root.name} project! Here's what you need to know:",
            "",
            "## Project Overview",
            "",
            f"This project is a **{arch.project_type.value}** built primarily with **{arch.primary_language.value}**.",
            "",
        ]

        if arch.frameworks:
            parts.extend([
                "## Key Technologies",
                "",
            ])
            for fw in arch.frameworks:
                parts.append(f"- **{fw.name}**")
            parts.append("")

        parts.extend([
            "## Project Structure",
            "",
            arch.architecture_map.description,
            "",
            "## Setting Up Your Environment",
            "",
            "1. Clone the repository",
            "2. Install dependencies (see README.md)",
            "3. Set up environment variables (see .env.example if available)",
            "4. Run the development server",
            "",
            "## Important Notes",
            "",
        ])

        if deps.total_count > 50:
            parts.append(f"- The project has {deps.total_count} dependencies. Familiarize yourself with the main ones first.")

        parts.extend([
            "- Check the README.md for additional setup instructions",
            "- Ask your team lead for access credentials",
            "",
        ])

        return "\n".join(parts)

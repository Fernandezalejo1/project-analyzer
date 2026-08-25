"""Main entry point - FastAPI app and CLI."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

# Fix Windows console encoding for emoji output
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Project Analyzer",
        description="AI-powered software project analyzer and auditor",
        version="0.1.0",
    )

    # CORS - allow frontend dev server
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    @app.get("/")
    async def root():
        return {
            "name": "Project Analyzer",
            "version": "0.1.0",
            "docs": "/docs",
            "api": "/api",
        }

    return app


app = create_app()


def cli_main():
    """CLI entry point for direct project analysis."""
    if len(sys.argv) < 2:
        print("Usage: analyzer <project-path>")
        print("  or:  analyzer serve          (start API server)")
        print("")
        print("Examples:")
        print("  analyzer ./my-project        Analyze a local project")
        print("  analyzer https://github.com/user/repo  Analyze a GitHub repo")
        print("  analyzer serve               Start the web API server")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "serve":
        import uvicorn
        print("🚀 Starting Project Analyzer API server...")
        print("📖 Swagger docs: http://localhost:8000/docs")
        uvicorn.run(app, host="0.0.0.0", port=8000)
        return

    project_path = arg

    # Check if it's a git URL
    if project_path.startswith("http"):
        import subprocess
        import tempfile

        print(f"📥 Cloning {project_path}...")
        tmp_dir = tempfile.mkdtemp(prefix="analyzer_")

        result = subprocess.run(
            ["git", "clone", "--depth", "1", project_path, tmp_dir],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"❌ Failed to clone: {result.stderr}")
            sys.exit(1)

        project_path = tmp_dir

    # Validate path
    if not Path(project_path).exists():
        print(f"❌ Path not found: {project_path}")
        sys.exit(1)

    # Run analysis
    from app.analyzer import ProjectAnalyzer

    analyzer = ProjectAnalyzer(project_path)
    result = analyzer.analyze()

    # Save report
    output_file = Path(project_path) / "analysis-report.json"
    report_data = result.model_dump()
    output_file.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    print(f"\n📄 Full report saved to: {output_file}")

    # Also save a markdown version
    md_report = _generate_markdown_report(result)
    md_file = Path(project_path) / "analysis-report.md"
    md_file.write_text(md_report, encoding="utf-8")
    print(f"📝 Markdown report saved to: {md_file}")


def _generate_markdown_report(result) -> str:
    """Generate a comprehensive markdown report."""
    parts = [
        f"# 🔍 Project Analysis Report: {result.project_name}",
        "",
        f"**Scan Duration:** {result.scan_duration_seconds}s",
        f"**Project Path:** `{result.project_path}`",
        "",
        "---",
        "",
        "## 📋 Executive Summary",
        "",
        result.executive_report.summary,
        "",
        "---",
        "",
    ]

    # Category scores
    parts.append("## 📊 Category Scores")
    parts.append("")
    parts.append("| Category | Score | Details |")
    parts.append("|----------|-------|---------|")
    for cat in result.executive_report.categories:
        bar = "█" * int(cat.score) + "░" * (10 - int(cat.score))
        parts.append(f"| {cat.name} | {bar} {cat.score}/10 | {cat.details} |")
    parts.append("")

    # Critical priorities
    if result.executive_report.priorities_critical:
        parts.append("## 🔴 Critical Issues")
        parts.append("")
        for p in result.executive_report.priorities_critical:
            parts.append(f"### ❌ {p.title}")
            parts.append(f"{p.description}")
            parts.append("")

    # Important
    if result.executive_report.priorities_important:
        parts.append("## 🟠 Important Issues")
        parts.append("")
        for p in result.executive_report.priorities_important:
            parts.append(f"### ⚠️ {p.title}")
            parts.append(f"{p.description}")
            parts.append("")

    # Recommendations
    if result.executive_report.priorities_recommendations:
        parts.append("## 🟢 Recommendations")
        parts.append("")
        for p in result.executive_report.priorities_recommendations:
            parts.append(f"- **{p.title}**: {p.description}")
        parts.append("")

    # Architecture
    parts.append("---")
    parts.append("")
    parts.append("## 📐 Architecture")
    parts.append("")
    parts.append(result.architecture.structure_summary)
    parts.append("")

    if result.architecture.architecture_map.layers:
        parts.append("**Project Structure:**")
        parts.append("```")
        for layer in result.architecture.architecture_map.layers:
            parts.append(f"  📁 {layer}")
        parts.append("```")
        parts.append("")

    # Dependencies
    parts.append("## 📦 Dependencies")
    parts.append("")
    parts.append(result.dependencies.summary)
    parts.append("")

    # Security
    parts.append("## 🔐 Security")
    parts.append("")
    parts.append(result.security.summary)
    parts.append("")

    if result.security.secrets_found:
        parts.append("### Leaked Secrets")
        parts.append("")
        for s in result.security.secrets_found[:20]:
            parts.append(f"- **{s.secret_type}** ({s.severity.value}) in `{s.file_path}` line {s.line_number}")
        parts.append("")

    # Vulnerabilities
    parts.append("## 🛡️ Vulnerabilities")
    parts.append("")
    parts.append(result.vulnerabilities.summary)
    parts.append("")

    if result.vulnerabilities.findings:
        parts.append("### Findings")
        parts.append("")
        for v in result.vulnerabilities.findings[:20]:
            parts.append(f"- **{v.vulnerability_type}** ({v.severity.value}) in `{v.file_path}` line {v.line_number}")
            parts.append(f"  {v.description}")
            parts.append("")

    # Code Quality
    parts.append("## 📊 Code Quality")
    parts.append("")
    parts.append(result.code_quality.summary)
    parts.append("")

    # Git
    parts.append("## 📈 Git Analysis")
    parts.append("")
    parts.append(result.git.summary)
    parts.append("")

    # Performance
    parts.append("## ⚡ Performance")
    parts.append("")
    parts.append(result.performance.summary)
    parts.append("")

    # AI Analysis
    parts.append("## 🤖 AI Analysis")
    parts.append("")
    parts.append(result.ai_analysis.summary)
    parts.append("")

    if result.ai_analysis.architecture_suggestions:
        parts.append("### Architecture Suggestions")
        parts.append("")
        for s in result.ai_analysis.architecture_suggestions:
            parts.append(f"- {s}")
        parts.append("")

    if result.ai_analysis.scalability_concerns:
        parts.append("### Scalability Concerns")
        parts.append("")
        for s in result.ai_analysis.scalability_concerns:
            parts.append(f"- {s}")
        parts.append("")

    # Architecture diagram
    if result.documentation.architecture_diagram:
        parts.append("## 🗺️ Architecture Diagram")
        parts.append("")
        parts.append(result.documentation.architecture_diagram)

    parts.extend([
        "",
        "---",
        "",
        f"*Generated by Project Analyzer — {result.scan_duration_seconds}s scan*",
    ])

    return "\n".join(parts)


if __name__ == "__main__":
    cli_main()

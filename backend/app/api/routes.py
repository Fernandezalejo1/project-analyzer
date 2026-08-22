"""FastAPI API Routes for the Project Analyzer."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.analyzer import ProjectAnalyzer
from app.models.schemas import FullAnalysisResult


router = APIRouter(prefix="/api", tags=["analyzer"])


# ── Request / Response models ─────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Request to analyze a project."""
    path: str = Field(..., description="Local path to the project directory")
    git_url: str | None = Field(None, description="GitHub URL to clone and analyze")


class AnalyzeResponse(BaseModel):
    """Response with the full analysis result."""
    success: bool
    message: str
    result: FullAnalysisResult | None = None


class QuickScanRequest(BaseModel):
    """Quick security-only scan."""
    path: str


# ── Routes ─────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_project(request: AnalyzeRequest):
    """Run a full analysis on a project."""
    try:
        project_path = request.path

        # If git URL provided, clone first
        if request.git_url:
            project_path = await _clone_repo(request.git_url)

        # Validate path
        if not os.path.exists(project_path):
            raise HTTPException(status_code=400, detail=f"Path not found: {project_path}")

        # Run analysis
        analyzer = ProjectAnalyzer(project_path)
        result = analyzer.analyze()

        return AnalyzeResponse(
            success=True,
            message=f"Analysis complete for {result.project_name}",
            result=result,
        )

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/quick-scan")
async def quick_scan(request: QuickScanRequest):
    """Quick security-only scan (secrets + vulnerabilities)."""
    try:
        if not os.path.exists(request.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")

        from app.analyzers.security import SecurityAnalyzer
        from app.analyzers.vulnerabilities import VulnerabilityAnalyzer

        sec = SecurityAnalyzer(request.path).analyze()
        vulns = VulnerabilityAnalyzer(request.path).analyze()

        return {
            "success": True,
            "security": sec.model_dump(),
            "vulnerabilities": vulns.model_dump(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "project-analyzer"}


@router.get("/supported-files")
async def supported_files():
    """List supported dependency files and languages."""
    return {
        "languages": [
            "python", "javascript", "typescript", "java", "go", "rust",
            "csharp", "cpp", "ruby", "php", "swift", "kotlin", "dart",
        ],
        "dependency_files": [
            "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
            "Cargo.toml", "pom.xml", "build.gradle", "go.mod", "Gemfile",
            "composer.json", "pubspec.yaml", "*.csproj",
        ],
    }


# ── Helpers ────────────────────────────────────────────────────────────────

async def _clone_repo(git_url: str) -> str:
    """Clone a git repository to a temp directory."""
    import subprocess

    tmp_dir = tempfile.mkdtemp(prefix="analyzer_")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")

        return tmp_dir

    except subprocess.TimeoutExpired:
        raise Exception("Git clone timed out (120s)")
    except FileNotFoundError:
        raise Exception("Git is not installed. Please install git and try again.")

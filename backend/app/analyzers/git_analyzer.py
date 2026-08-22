"""Git Analyzer - Analyzes commit history, branches, secrets in history, and contributor stats."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from app.models.schemas import GitCommitAnalysis, GitReport, Severity

try:
    import git

    HAS_GIT = True
except ImportError:
    HAS_GIT = False


# ── Secrets patterns to check in git history ───────────────────────────────

import re

HISTORY_SECRET_PATTERNS = [
    re.compile(r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]"""),
    re.compile(r"""(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"""),
    re.compile(r"""sk-[a-zA-Z0-9]{20,}"""),
    re.compile(r"""ghp_[a-zA-Z0-9]{36}"""),
    re.compile(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]"""),
    re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""),
    re.compile(r"""(?i)secret[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]"""),
]


class GitAnalyzer:
    """Analyzes git repository history and metadata."""

    def __init__(self, root_path: str):
        self.root = Path(root_path)
        self._repo = None

    def analyze(self) -> GitReport:
        """Run full git analysis."""
        if not HAS_GIT:
            return GitReport(summary="⚠️ GitPython not installed. Git analysis skipped.")

        try:
            self._repo = git.Repo(self.root)
        except (git.InvalidGitRepositoryError, git.NoSuchPathError):
            return GitReport(summary="⚠️ Not a Git repository. Git analysis skipped.")

        report = GitReport()

        # Get branches
        try:
            report.branches = [b.name for b in self._repo.branches]
        except Exception:
            pass

        # Analyze commits
        self._analyze_commits(report)

        # Find abandoned branches
        self._find_abandoned_branches(report)

        # Top contributors
        self._get_top_contributors(report)

        report.summary = self._generate_summary(report)
        return report

    # ── Private ────────────────────────────────────────────────────────

    def _analyze_commits(self, report: GitReport):
        """Analyze recent commits for issues."""
        try:
            commits = list(self._repo.iter_commits(max_count=200))
        except Exception:
            return

        report.total_commits = len(commits)

        for commit in commits:
            analysis = GitCommitAnalysis(
                hash=commit.hexsha[:8],
                message=commit.message.strip().split("\n")[0][:200],
                author=str(commit.author),
                date=commit.committed_datetime.isoformat(),
            )

            # Count files changed
            try:
                stats = commit.stats
                analysis.files_changed = stats.total.get("files", 0)
                analysis.insertions = stats.total.get("insertions", 0)
                analysis.deletions = stats.total.get("deletions", 0)
            except Exception:
                pass

            # Check for large commits
            if analysis.files_changed > 30 or (analysis.insertions + analysis.deletions) > 1000:
                analysis.is_too_large = True
                report.large_commits.append(analysis)

            # Check for missing description
            lines = commit.message.strip().split("\n")
            if len(lines) < 2 or not lines[1].strip():
                # Allow short subject-only commits for small changes
                if analysis.files_changed > 5:
                    analysis.has_no_description = True
                    report.commits_without_description.append(analysis)

            # Check for secrets in commit diffs
            if self._commit_has_secrets(commit):
                analysis.has_secret = True
                report.secrets_in_history.append(analysis)

    def _commit_has_secrets(self, commit) -> bool:
        """Check if a commit's diff contains potential secrets."""
        try:
            diff = commit.diff(create_patch=True)
            for diff_item in diff:
                try:
                    diff_text = str(diff_item)
                    for pattern in HISTORY_SECRET_PATTERNS:
                        if pattern.search(diff_text):
                            return True
                except Exception:
                    pass
        except Exception:
            pass
        return False

    def _find_abandoned_branches(self, report: GitReport):
        """Find branches that haven't been updated in 90+ days."""
        try:
            now = datetime.now()
            for branch in self._repo.branches:
                try:
                    last_commit = branch.commit.committed_datetime
                    if hasattr(last_commit, "tzinfo") and last_commit.tzinfo:
                        days_since = (now - last_commit.replace(tzinfo=None)).days
                    else:
                        days_since = (now - last_commit).days
                    if days_since > 90 and branch.name not in ("main", "master", "develop"):
                        report.abandoned_branches.append(f"{branch.name} ({days_since} days)")
                except Exception:
                    pass
        except Exception:
            pass

    def _get_top_contributors(self, report: GitReport):
        """Get top contributors by commit count."""
        try:
            authors: dict[str, int] = {}
            for commit in self._repo.iter_commits(max_count=500):
                author = str(commit.author)
                authors[author] = authors.get(author, 0) + 1

            sorted_authors = sorted(authors.items(), key=lambda x: -x[1])[:10]
            report.top_contributors = [
                {"author": name, "commits": count}
                for name, count in sorted_authors
            ]
        except Exception:
            pass

    def _generate_summary(self, report: GitReport) -> str:
        """Generate a human-readable summary."""
        parts = [f"📈 Analyzed {report.total_commits} commits."]

        if report.branches:
            parts.append(f"Branches: {len(report.branches)} ({', '.join(report.branches[:5])})")

        if report.abandoned_branches:
            parts.append(f"🗑️  {len(report.abandoned_branches)} abandoned branch(es).")
            for b in report.abandoned_branches[:3]:
                parts.append(f"  • {b}")

        if report.large_commits:
            parts.append(f"⚠️  {len(report.large_commits)} unusually large commit(s).")

        if report.commits_without_description:
            parts.append(f"📝 {len(report.commits_without_description)} commit(s) without description.")

        if report.secrets_in_history:
            parts.append(f"🔴 {len(report.secrets_in_history)} commit(s) may contain secrets in history!")

        if report.top_contributors:
            parts.append("Top contributors:")
            for c in report.top_contributors[:3]:
                parts.append(f"  • {c['author']}: {c['commits']} commits")

        return "\n".join(parts)

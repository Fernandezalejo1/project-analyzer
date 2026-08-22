/* ═══════════════════════════════════════════════════════════════
   Project Analyzer — Frontend Application
   ═══════════════════════════════════════════════════════════════ */

const API_BASE = 'http://localhost:8000/api';

let currentResult = null;

// ═══════════════════ NAVIGATION ═══════════════════

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const section = item.dataset.section;
        navigateTo(section);

        // Update active state
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
    });
});

// Menu toggle for mobile
document.getElementById('menuToggle').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

function navigateTo(section) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.style.display = 'none');

    if (section === 'home') {
        document.getElementById('section-home').style.display = '';
        document.getElementById('pageTitle').textContent = 'Project Analyzer';
    } else if (currentResult) {
        showDetailSection(section);
    }
}

function showDetailSection(section) {
    // Show executive summary if viewing detail sections
    const resultSection = document.getElementById('section-results');
    resultSection.style.display = '';

    // Scroll to relevant content
    const targetId = `section-${section}`;
    const target = document.getElementById(targetId);
    if (target) {
        target.style.display = '';

        // Update title
        const titles = {
            architecture: '📐 Architecture',
            security: '🔐 Security',
            vulnerabilities: '🛡️ Vulnerabilities',
            quality: '📊 Code Quality',
            dependencies: '📦 Dependencies',
            performance: '⚡ Performance',
            git: '📈 Git History',
            ai: '🤖 AI Analysis',
            docs: '📝 Documentation',
        };
        document.getElementById('pageTitle').textContent = titles[section] || 'Results';
    }
}

// ═══════════════════ ANALYSIS ═══════════════════

async function startAnalysis() {
    const path = document.getElementById('projectPath').value.trim();
    const gitUrl = document.getElementById('gitUrl').value.trim();

    if (!path && !gitUrl) {
        alert('Please enter a project path or GitHub URL');
        return;
    }

    showScanning('Analyzing project...', 'Running all 9 analysis modules');

    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path || undefined, git_url: gitUrl || undefined }),
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Analysis failed');
        }

        const data = await response.json();
        currentResult = data.result;
        hideScanning();
        renderResults(currentResult);
    } catch (error) {
        hideScanning();
        alert(`Error: ${error.message}`);
    }
}

async function startQuickScan() {
    const path = document.getElementById('projectPath').value.trim();

    if (!path) {
        alert('Please enter a project path for quick scan');
        return;
    }

    showScanning('Quick scanning...', 'Checking for secrets and vulnerabilities');

    try {
        const response = await fetch(`${API_BASE}/quick-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path }),
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Scan failed');
        }

        const data = await response.json();
        hideScanning();
        alert(`Quick scan complete!\n\nSecrets: ${data.security.secrets_count}\nVulnerabilities: ${data.vulnerabilities.total_count}`);
    } catch (error) {
        hideScanning();
        alert(`Error: ${error.message}`);
    }
}

function showScanning(title, detail) {
    document.getElementById('scanningOverlay').style.display = 'flex';
    document.getElementById('scanStatus').textContent = title;
    document.getElementById('scanDetail').textContent = detail;
}

function hideScanning() {
    document.getElementById('scanningOverlay').style.display = 'none';
}

// ═══════════════════ RENDER RESULTS ═══════════════════

function renderResults(result) {
    // Hide home, show results
    document.getElementById('section-home').style.display = 'none';

    renderExecutiveSummary(result.executive_report);
    renderScores(result.executive_report);
    renderPriorities(result.executive_report);
    renderArchitecture(result.architecture);
    renderSecurity(result.security);
    renderVulnerabilities(result.vulnerabilities);
    renderCodeQuality(result.code_quality);
    renderDependencies(result.dependencies);
    renderPerformance(result.performance);
    renderGit(result.git);
    renderAIAnalysis(result.ai_analysis);
    renderDocumentation(result.documentation);

    // Show results section
    const resultSection = document.getElementById('section-results');
    resultSection.style.display = '';

    // Auto-navigate to architecture
    navigateTo('architecture');
    document.querySelector('[data-section="architecture"]').classList.add('active');
    document.querySelector('[data-section="home"]').classList.remove('active');
}

// ─── Executive Summary ──────────────────────────────────────────────

function renderExecutiveSummary(report) {
    const overall = report.overall_score;
    let ratingClass = 'critical';
    let rating = 'CRITICAL';

    if (overall >= 90) { ratingClass = 'excellent'; rating = 'EXCELLENT'; }
    else if (overall >= 75) { ratingClass = 'good'; rating = 'GOOD'; }
    else if (overall >= 60) { ratingClass = 'fair'; rating = 'FAIR'; }
    else if (overall >= 40) { ratingClass = 'poor'; rating = 'POOR'; }

    document.getElementById('executiveSummary').innerHTML = `
        <div class="score-hero">
            <div class="big-score ${ratingClass}">${overall}</div>
            <div class="rating ${ratingClass}">${rating}</div>
            <div class="rating-label">Overall Project Score</div>
        </div>
    `;
}

// ─── Category Scores ────────────────────────────────────────────────

function renderScores(report) {
    const grid = document.getElementById('scoresGrid');
    grid.innerHTML = report.categories.map(cat => {
        let barClass = 'excellent';
        if (cat.score < 4) barClass = 'critical';
        else if (cat.score < 6) barClass = 'poor';
        else if (cat.score < 8) barClass = 'fair';
        else if (cat.score < 9) barClass = 'good';

        const icons = {
            Architecture: '📐',
            Security: '🔐',
            'Code Quality': '📊',
            Performance: '⚡',
            Dependencies: '📦',
            Documentation: '📝',
        };

        return `
            <div class="score-card">
                <div class="score-card-header">
                    <span class="score-card-title">${icons[cat.name] || ''} ${cat.name}</span>
                    <span class="score-card-value">${cat.score}</span>
                </div>
                <div class="score-bar">
                    <div class="score-bar-fill ${barClass}" style="width: ${cat.score * 10}%"></div>
                </div>
                <div class="score-card-details">${cat.details}</div>
            </div>
        `;
    }).join('');
}

// ─── Priorities ─────────────────────────────────────────────────────

function renderPriorities(report) {
    const container = document.getElementById('prioritiesContainer');
    let html = '';

    if (report.priorities_critical.length > 0) {
        html += `<div class="priority-group">
            <h3>🔴 Critical — Immediate Action Required</h3>
            ${report.priorities_critical.map(p => `
                <div class="priority-item critical">
                    <h4>${escapeHtml(p.title)}</h4>
                    <p>${escapeHtml(p.description)}</p>
                </div>
            `).join('')}
        </div>`;
    }

    if (report.priorities_important.length > 0) {
        html += `<div class="priority-group">
            <h3>🟠 Important</h3>
            ${report.priorities_important.map(p => `
                <div class="priority-item important">
                    <h4>${escapeHtml(p.title)}</h4>
                    <p>${escapeHtml(p.description)}</p>
                </div>
            `).join('')}
        </div>`;
    }

    if (report.priorities_recommendations.length > 0) {
        html += `<div class="priority-group">
            <h3>🟢 Recommendations</h3>
            ${report.priorities_recommendations.map(p => `
                <div class="priority-item recommendation">
                    <h4>${escapeHtml(p.title)}</h4>
                    <p>${escapeHtml(p.description)}</p>
                </div>
            `).join('')}
        </div>`;
    }

    container.innerHTML = html;
}

// ─── Architecture ───────────────────────────────────────────────────

function renderArchitecture(arch) {
    const container = document.getElementById('architectureContent');

    let frameworksHtml = '';
    if (arch.frameworks.length > 0) {
        frameworksHtml = `
            <div class="info-card">
                <h3>Frameworks Detected</h3>
                <table class="data-table">
                    <thead><tr><th>Name</th><th>Confidence</th></tr></thead>
                    <tbody>
                        ${arch.frameworks.map(f => `
                            <tr>
                                <td>${escapeHtml(f.name)}</td>
                                <td>${(f.confidence * 100).toFixed(0)}%</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    let languagesHtml = '';
    if (arch.languages_detected.length > 0) {
        languagesHtml = `
            <div class="info-card">
                <h3>Languages</h3>
                <table class="data-table">
                    <thead><tr><th>Language</th><th>Files</th><th>Percentage</th></tr></thead>
                    <tbody>
                        ${arch.languages_detected.map(l => `
                            <tr>
                                <td>${escapeHtml(l.language)}</td>
                                <td>${l.file_count}</td>
                                <td>${l.percentage}%</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    let archMapHtml = '';
    if (arch.architecture_map.layers.length > 0) {
        archMapHtml = `
            <div class="info-card">
                <h3>Project Structure</h3>
                <div class="arch-map">
                    ${arch.architecture_map.layers.map((layer, i) => `
                        ${i > 0 ? '<div class="arch-arrow">↓</div>' : ''}
                        <div class="arch-layer">
                            <span class="layer-icon">📁</span>
                            <span>${escapeHtml(layer)}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${arch.primary_language.value}</div>
                <div class="stat-label">Primary Language</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${arch.project_type.value}</div>
                <div class="stat-label">Project Type</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${arch.languages_detected.length}</div>
                <div class="stat-label">Languages</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${arch.frameworks.length}</div>
                <div class="stat-label">Frameworks</div>
            </div>
        </div>
        <div class="info-card">
            <p>${escapeHtml(arch.structure_summary)}</p>
        </div>
        ${frameworksHtml}
        ${languagesHtml}
        ${archMapHtml}
    `;
}

// ─── Security ───────────────────────────────────────────────────────

function renderSecurity(security) {
    const container = document.getElementById('securityContent');

    let secretsHtml = '';
    if (security.secrets_found.length > 0) {
        secretsHtml = `
            <div class="info-card">
                <h3>🔴 Secrets Found (${security.secrets_count})</h3>
                <ul class="finding-list">
                    ${security.secrets_found.map(s => `
                        <li class="finding-item">
                            <span class="finding-severity severity-${s.severity}">${s.severity}</span>
                            <div class="finding-details">
                                <strong>${escapeHtml(s.secret_type)}</strong>
                                <div class="finding-file">${escapeHtml(s.file_path)}:${s.line_number}</div>
                                <div class="finding-recommendation">${escapeHtml(s.recommendation)}</div>
                            </div>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    let filesHtml = '';
    if (security.exposed_env_files.length > 0) {
        filesHtml = `
            <div class="info-card">
                <h3>⚠️ Sensitive Files</h3>
                <ul class="finding-list">
                    ${security.exposed_env_files.map(f => `
                        <li class="finding-item">
                            <span class="finding-severity severity-high">EXPOSED</span>
                            <div class="finding-details">
                                <div class="finding-file">${escapeHtml(f)}</div>
                            </div>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value" style="color: ${security.secrets_count > 0 ? 'var(--critical)' : 'var(--success)'}">${security.secrets_count}</div>
                <div class="stat-label">Secrets Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${security.exposed_env_files.length}</div>
                <div class="stat-label">Sensitive Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${security.exposed_certificates.length}</div>
                <div class="stat-label">Certificates</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(security.summary)}</pre></p>
        </div>
        ${secretsHtml}
        ${filesHtml}
    `;
}

// ─── Vulnerabilities ────────────────────────────────────────────────

function renderVulnerabilities(vulns) {
    const container = document.getElementById('vulnerabilitiesContent');

    let findingsHtml = '';
    if (vulns.findings.length > 0) {
        findingsHtml = `
            <div class="info-card">
                <h3>Findings (${vulns.total_count})</h3>
                <ul class="finding-list">
                    ${vulns.findings.map(v => `
                        <li class="finding-item">
                            <span class="finding-severity severity-${v.severity}">${v.severity}</span>
                            <div class="finding-details">
                                <strong>${escapeHtml(v.vulnerability_type)}${v.cwe_id ? ` (${v.cwe_id})` : ''}</strong>
                                <div class="finding-file">${escapeHtml(v.file_path)}:${v.line_number}</div>
                                <div class="finding-desc">${escapeHtml(v.description)}</div>
                                <div class="finding-recommendation">💡 ${escapeHtml(v.recommendation)}</div>
                            </div>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${vulns.total_count}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--critical)">${vulns.critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--danger)">${vulns.high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--warning)">${vulns.medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(vulns.summary)}</pre></p>
        </div>
        ${findingsHtml}
    `;
}

// ─── Code Quality ───────────────────────────────────────────────────

function renderCodeQuality(quality) {
    const container = document.getElementById('qualityContent');

    let largeFuncsHtml = '';
    if (quality.large_functions.length > 0) {
        largeFuncsHtml = `
            <div class="info-card">
                <h3>📏 Oversized Functions (${quality.large_functions.length})</h3>
                <table class="data-table">
                    <thead><tr><th>File</th><th>Function</th><th>Lines</th></tr></thead>
                    <tbody>
                        ${quality.large_functions.map(f => `
                            <tr>
                                <td class="finding-file">${escapeHtml(f.file)}</td>
                                <td>${escapeHtml(f.name)}</td>
                                <td>${f.lines}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${quality.total_files}</div>
                <div class="stat-label">Files Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${quality.total_lines.toLocaleString()}</div>
                <div class="stat-label">Lines of Code</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${quality.average_complexity}</div>
                <div class="stat-label">Avg. Complexity</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${quality.average_maintainability}</div>
                <div class="stat-label">Maintainability</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${quality.duplicated_percentage}%</div>
                <div class="stat-label">Duplication</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${quality.technical_debt_hours}h</div>
                <div class="stat-label">Tech Debt</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(quality.summary)}</pre></p>
        </div>
        ${largeFuncsHtml}
    `;
}

// ─── Dependencies ───────────────────────────────────────────────────

function renderDependencies(deps) {
    const container = document.getElementById('dependenciesContent');

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${deps.total_count}</div>
                <div class="stat-label">Total Dependencies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--warning)">${deps.outdated_count}</div>
                <div class="stat-label">Outdated</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--critical)">${deps.vulnerable_count}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${deps.deprecated_count}</div>
                <div class="stat-label">Deprecated</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(deps.summary)}</pre></p>
        </div>
    `;
}

// ─── Performance ────────────────────────────────────────────────────

function renderPerformance(perf) {
    const container = document.getElementById('performanceContent');

    let findingsHtml = '';
    if (perf.findings.length > 0) {
        findingsHtml = `
            <div class="info-card">
                <h3>Performance Issues (${perf.findings.length})</h3>
                <ul class="finding-list">
                    ${perf.findings.map(f => `
                        <li class="finding-item">
                            <span class="finding-severity severity-${f.severity}">${f.severity}</span>
                            <div class="finding-details">
                                <strong>${escapeHtml(f.issue_type)}</strong>
                                <div class="finding-file">${escapeHtml(f.file_path)}:${f.line_number}</div>
                                <div class="finding-desc">${escapeHtml(f.description)}</div>
                                <div class="finding-recommendation">💡 ${escapeHtml(f.recommendation)}</div>
                            </div>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${perf.findings.length}</div>
                <div class="stat-label">Issues Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${perf.large_files.length}</div>
                <div class="stat-label">Large Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${perf.heavy_images.length}</div>
                <div class="stat-label">Heavy Media</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(perf.summary)}</pre></p>
        </div>
        ${findingsHtml}
    `;
}

// ─── Git ────────────────────────────────────────────────────────────

function renderGit(git) {
    const container = document.getElementById('gitContent');

    let contributorsHtml = '';
    if (git.top_contributors.length > 0) {
        contributorsHtml = `
            <div class="info-card">
                <h3>👥 Top Contributors</h3>
                <table class="data-table">
                    <thead><tr><th>Author</th><th>Commits</th></tr></thead>
                    <tbody>
                        ${git.top_contributors.map(c => `
                            <tr>
                                <td>${escapeHtml(c.author)}</td>
                                <td>${c.commits}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    let issuesHtml = '';
    const issues = [];
    if (git.large_commits.length > 0) {
        issues.push(`<div class="priority-item important"><h4>⚠️ ${git.large_commits.length} Large Commit(s)</h4><p>Commits that changed many files or lines.</p></div>`);
    }
    if (git.commits_without_description.length > 0) {
        issues.push(`<div class="priority-item recommendation"><h4>📝 ${git.commits_without_description.length} Commit(s) Without Description</h4></div>`);
    }
    if (git.secrets_in_history.length > 0) {
        issues.push(`<div class="priority-item critical"><h4>🔴 ${git.secrets_in_history.length} Commit(s) With Secrets</h4><p>Secrets were detected in git history.</p></div>`);
    }
    if (git.abandoned_branches.length > 0) {
        issues.push(`<div class="priority-item recommendation"><h4>🗑️ ${git.abandoned_branches.length} Abandoned Branch(es)</h4></div>`);
    }

    if (issues.length > 0) {
        issuesHtml = `<div class="info-card"><h3>Issues</h3>${issues.join('')}</div>`;
    }

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${git.total_commits}</div>
                <div class="stat-label">Commits Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${git.branches.length}</div>
                <div class="stat-label">Branches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${git.abandoned_branches.length}</div>
                <div class="stat-label">Abandoned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${git.top_contributors.length}</div>
                <div class="stat-label">Contributors</div>
            </div>
        </div>
        <div class="info-card">
            <p><pre>${escapeHtml(git.summary)}</pre></p>
        </div>
        ${issuesHtml}
        ${contributorsHtml}
    `;
}

// ─── AI Analysis ────────────────────────────────────────────────────

function renderAIAnalysis(ai) {
    const container = document.getElementById('aiContent');

    let recsHtml = '';
    if (ai.recommendations.length > 0) {
        recsHtml = `
            <div class="info-card">
                <h3>Recommendations (${ai.recommendations.length})</h3>
                <ul class="finding-list">
                    ${ai.recommendations.map(r => `
                        <li class="finding-item">
                            <span class="finding-severity severity-${r.priority}">${r.priority}</span>
                            <div class="finding-details">
                                <strong>${escapeHtml(r.title)}</strong>
                                <div class="finding-desc">${escapeHtml(r.description)}</div>
                                <div class="finding-recommendation">🎯 Impact: ${escapeHtml(r.impact)}</div>
                            </div>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    let archHtml = '';
    if (ai.architecture_suggestions.length > 0) {
        archHtml = `
            <div class="info-card">
                <h3>📐 Architecture Suggestions</h3>
                <ul style="list-style: none; padding: 0;">
                    ${ai.architecture_suggestions.map(s => `
                        <li style="padding: 8px 0; border-bottom: 1px solid var(--border);">💡 ${escapeHtml(s)}</li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    let scaleHtml = '';
    if (ai.scalability_concerns.length > 0) {
        scaleHtml = `
            <div class="info-card">
                <h3>📈 Scalability Concerns</h3>
                <ul style="list-style: none; padding: 0;">
                    ${ai.scalability_concerns.map(s => `
                        <li style="padding: 8px 0; border-bottom: 1px solid var(--border);">⚠️ ${escapeHtml(s)}</li>
                    `).join('')}
                </ul>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="info-card">
            <p><pre>${escapeHtml(ai.summary)}</pre></p>
        </div>
        ${recsHtml}
        ${archHtml}
        ${scaleHtml}
    `;
}

// ─── Documentation ──────────────────────────────────────────────────

function renderDocumentation(docs) {
    const container = document.getElementById('docsContent');

    container.innerHTML = `
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-value">${docs.has_existing_readme ? '✅' : '❌'}</div>
                <div class="stat-label">Existing README</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${docs.has_existing_docs ? '✅' : '❌'}</div>
                <div class="stat-label">Existing Docs</div>
            </div>
        </div>
        ${docs.readme_generated ? `
            <div class="info-card">
                <h3>📄 Generated README</h3>
                <div class="code-block">${escapeHtml(docs.readme_generated)}</div>
            </div>
        ` : ''}
        ${docs.architecture_diagram ? `
            <div class="info-card">
                <h3>🗺️ Architecture Diagram (Mermaid)</h3>
                <div class="code-block">${escapeHtml(docs.architecture_diagram)}</div>
            </div>
        ` : ''}
        ${docs.onboarding_guide ? `
            <div class="info-card">
                <h3>🎓 Onboarding Guide</h3>
                <div class="code-block">${escapeHtml(docs.onboarding_guide)}</div>
            </div>
        ` : ''}
    `;
}

// ═══════════════════ UTILITIES ═══════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function showScanModal() {
    // Scroll to the scan form
    document.getElementById('section-home').style.display = '';
    document.querySelectorAll('.section').forEach(s => {
        if (s.id !== 'section-home') s.style.display = 'none';
    });
    document.getElementById('projectPath').focus();
    document.querySelector('[data-section="home"]').classList.add('active');
    document.querySelectorAll('.nav-item').forEach(n => {
        if (n.dataset.section !== 'home') n.classList.remove('active');
    });
}

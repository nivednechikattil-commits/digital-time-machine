/**
 * DIGITAL TIME MACHINE — EVIDENCE DNA CONTROLLER
 * Manages the Evidence Details panel for incident correlation findings.
 * Provides granular event lineage, factual vs inferred segregation,
 * plain language explanations, and direct navigation to Timeline / Evidence Explorer.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || new URLSearchParams(window.location.search).get('case_id') || 'CASE-2026-001';

    const dnaCard = document.getElementById('evidenceDnaCard');
    const dnaFindingId = document.getElementById('dnaFindingId');
    const dnaSeverityBadge = document.getElementById('dnaSeverityBadge');
    const dnaEvidenceStatusBadge = document.getElementById('dnaEvidenceStatusBadge');
    const dnaPanelBody = document.getElementById('dnaPanelBody');
    const btnCloseDnaPanel = document.getElementById('btnCloseDnaPanel');
    const findingRows = document.querySelectorAll('.finding-row');

    if (!dnaCard) return;

    // Attach click handlers to finding rows and inspect buttons
    findingRows.forEach(row => {
        row.addEventListener('click', (e) => {
            const fid = row.getAttribute('data-id');
            if (fid) selectFinding(fid);
        });
    });

    const inspectButtons = document.querySelectorAll('.btn-inspect-dna');
    inspectButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fid = btn.getAttribute('data-id');
            if (fid) selectFinding(fid);
        });
    });

    if (btnCloseDnaPanel) {
        btnCloseDnaPanel.addEventListener('click', () => {
            dnaCard.style.display = 'none';
            findingRows.forEach(r => r.classList.remove('active'));
        });
    }

    // Check for finding_id in query parameters (e.g., from deep link)
    const urlParams = new URLSearchParams(window.location.search);
    const preselectedFinding = urlParams.get('finding_id');
    if (preselectedFinding) {
        selectFinding(preselectedFinding);
    }

    function selectFinding(fid) {
        // Highlight active row in table
        findingRows.forEach(r => {
            if (r.getAttribute('data-id') === fid) {
                r.classList.add('active');
            } else {
                r.classList.remove('active');
            }
        });

        loadEvidenceDna(fid);
    }

    async function loadEvidenceDna(fid) {
        dnaCard.style.display = 'block';
        dnaFindingId.innerText = `[${fid}]`;
        dnaSeverityBadge.innerText = 'LOADING';
        dnaSeverityBadge.className = 'pill';
        dnaEvidenceStatusBadge.innerText = 'RETRIEVING...';
        dnaEvidenceStatusBadge.className = 'pill';

        dnaPanelBody.innerHTML = `
            <div style="text-align: center; padding: 30px; color: var(--text-muted);">
                <div style="font-family: var(--font-mono); font-size: 13px; color: var(--accent-cyan); margin-bottom: 8px;">
                    🧬 Synthesizing Evidence DNA Profile...
                </div>
                <div>Fetching verified SQLite telemetry for finding ${fid}...</div>
            </div>
        `;

        try {
            const res = await fetch(`/api/incidents/${encodeURIComponent(fid)}/evidence-dna?case_id=${encodeURIComponent(caseId)}`);
            if (!res.ok) {
                throw new Error(`Finding ${fid} not found (HTTP ${res.status})`);
            }
            const data = await res.json();
            renderEvidenceDna(data);
            dnaCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } catch (err) {
            dnaPanelBody.innerHTML = `
                <div style="padding: 16px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--sev-critical); border-radius: 4px; color: var(--sev-critical);">
                    <strong>Failed to load Evidence DNA:</strong> ${err.message}
                </div>
            `;
        }
    }

    function renderEvidenceDna(data) {
        const finding = data.finding || {};
        const inferred = data.inferred_conclusions || {};
        const facts = data.recorded_facts || [];
        const gaps = data.contradictory_or_missing || [];
        const isAvailable = data.evidence_status === 'available';

        // Update Header Badges
        dnaFindingId.innerText = `[${data.finding_id}]`;
        dnaSeverityBadge.innerText = (finding.severity || 'UNKNOWN').toUpperCase();
        dnaSeverityBadge.className = `pill badge-sev-${finding.severity || 'medium'}`;

        if (isAvailable) {
            dnaEvidenceStatusBadge.innerText = `EVIDENCE LINKED (${data.supporting_event_count})`;
            dnaEvidenceStatusBadge.className = 'pill pill-observed';
            dnaEvidenceStatusBadge.style.background = 'rgba(16, 185, 129, 0.15)';
            dnaEvidenceStatusBadge.style.color = '#10B981';
            dnaEvidenceStatusBadge.style.border = '1px solid rgba(16, 185, 129, 0.4)';
        } else {
            dnaEvidenceStatusBadge.innerText = 'EVIDENCE UNAVAILABLE';
            dnaEvidenceStatusBadge.className = 'pill badge-sev-critical';
            dnaEvidenceStatusBadge.style.background = 'rgba(239, 68, 68, 0.15)';
            dnaEvidenceStatusBadge.style.color = '#EF4444';
            dnaEvidenceStatusBadge.style.border = '1px solid rgba(239, 68, 68, 0.4)';
        }

        // 1. Plain Language Rationale Block
        const rationaleHtml = `
            <div style="background-color: var(--bg-surface-elevated); padding: 14px; border-radius: var(--radius-md); border-left: 3px solid var(--accent-blue);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-size: 11px; font-weight: 700; color: var(--accent-blue); letter-spacing: 0.5px; text-transform: uppercase;">
                        Detection Rule: ${inferred.rule_id} — ${inferred.rule_name}
                    </span>
                    <span class="mono" style="font-size: 11px; color: var(--text-muted);">
                        Time Window: ${inferred.start_time ? inferred.start_time.replace('T', ' ') : 'N/A'} → ${inferred.end_time ? inferred.end_time.replace('T', ' ') : 'N/A'}
                    </span>
                </div>
                <div style="color: var(--text-primary); font-size: 13px; line-height: 1.6;">
                    <strong>Trigger Rationale:</strong> ${inferred.explanation || 'No rule explanation recorded.'}
                </div>
            </div>
        `;

        // 2. Section A: Recorded Facts (Observed Telemetry)
        let factsTableHtml = '';
        if (isAvailable && facts.length > 0) {
            let rowsHtml = '';
            facts.forEach((ev, idx) => {
                rowsHtml += `
                    <tr>
                        <td class="mono" style="color: var(--text-muted); font-size: 11px;">${idx + 1}</td>
                        <td class="mono" style="color: var(--accent-cyan); font-weight: 600; font-size: 11px;">${ev.event_id}</td>
                        <td class="mono" style="white-space: nowrap; font-size: 11px;">${ev.timestamp.replace('T', ' ')}</td>
                        <td><span style="text-transform: uppercase; font-size: 11px; font-weight: 600; color: var(--text-secondary);">${ev.source}</span></td>
                        <td class="mono" style="color: var(--accent-blue); font-size: 11px;">${ev.event_type}</td>
                        <td><span class="mono" style="color: var(--text-primary); font-size: 11px;">${ev.actor}</span></td>
                        <td style="max-width: 170px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${ev.target_object}">
                            <span class="mono" style="font-size: 11px;">${ev.target_object}</span>
                        </td>
                        <td><span class="mono" style="color: var(--text-muted); font-size: 11px;">${ev.evidence_ref}</span></td>
                        <td style="white-space: nowrap;">
                            <div style="display: flex; gap: 4px;">
                                <a href="${ev.timeline_url}" class="dna-action-link" title="Jump to this event on Timeline">
                                    Timeline ↗
                                </a>
                                <a href="${ev.evidence_explorer_url}" class="dna-action-link dna-action-link-explorer" title="Inspect source file in Evidence Explorer">
                                    Explorer ↗
                                </a>
                            </div>
                        </td>
                    </tr>
                `;
            });

            factsTableHtml = `
                <div class="table-container" style="margin-top: 8px; max-height: 260px; overflow-y: auto;">
                    <table class="dtm-table">
                        <thead>
                            <tr>
                                <th style="width: 25px;">#</th>
                                <th>Event ID</th>
                                <th>Timestamp</th>
                                <th>Source</th>
                                <th>Type</th>
                                <th>Actor</th>
                                <th>Target Object</th>
                                <th>Evidence Source</th>
                                <th>Forensic Navigation</th>
                            </tr>
                        </thead>
                        <tbody>${rowsHtml}</tbody>
                    </table>
                </div>
            `;
        } else {
            factsTableHtml = `
                <div style="background: rgba(239, 68, 68, 0.08); border-left: 3px solid var(--sev-critical); padding: 12px; border-radius: var(--radius-sm); margin-top: 8px;">
                    <div style="color: var(--sev-critical); font-weight: 700; margin-bottom: 4px;">Supporting Evidence Unavailable</div>
                    <div style="color: var(--text-secondary); font-size: 12px; line-height: 1.5;">
                        No recorded log events are linked to this finding in the database. 
                        The system maintains strict forensic neutrality and does not synthesize, infer, or invent missing telemetry links.
                    </div>
                </div>
            `;
        }

        const sectionFactsHtml = `
            <div class="dna-section">
                <div class="dna-section-header">
                    <span style="font-size: 12px; font-weight: 700; color: #FFFFFF; display: flex; align-items: center; gap: 6px;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #10B981;"></span>
                        RECORDED FACTS (OBSERVED TELEMETRY)
                    </span>
                    <span class="pill pill-observed">Direct SQLite Log Records</span>
                </div>
                <p style="color: var(--text-muted); font-size: 11px;">
                    Immutable forensic events directly retrieved from the SQLite evidence repository. Every event contains verified SHA-256 baseline references.
                </p>
                ${factsTableHtml}
            </div>
        `;

        // 3. Section B: Inferred Conclusions (Rule Deductions)
        const sectionConclusionsHtml = `
            <div class="dna-section" style="border-left: 3px solid var(--conf-inferred);">
                <div class="dna-section-header">
                    <span style="font-size: 12px; font-weight: 700; color: #FFFFFF; display: flex; align-items: center; gap: 6px;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #C084FC;"></span>
                        INFERRED CONCLUSIONS (ALGORITHMIC DEDUCTIONS)
                    </span>
                    <span class="pill pill-inferred">${inferred.confidence.toUpperCase()}</span>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 6px;">
                    <div>
                        <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Heuristic Deduction Limitations:</span>
                        <p style="color: var(--text-secondary); font-size: 12px; margin-top: 3px; line-height: 1.5;">
                            ${inferred.limitations || 'Temporal sequence does not prove malice. Correlation is based on chronological proximity.'}
                        </p>
                    </div>
                    <div>
                        <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Recommended Investigative Action:</span>
                        <p style="color: var(--accent-cyan); font-size: 12px; margin-top: 3px; line-height: 1.5;">
                            ${inferred.recommended_action || 'Inspect raw disk artifacts and interview system custodians.'}
                        </p>
                    </div>
                </div>
            </div>
        `;

        // 4. Section C: Contradictory or Missing Evidence (Dataset Gap Analysis)
        let gapsBodyHtml = '';
        if (data.has_contradictions_or_gaps && gaps.length > 0) {
            let gapItemsHtml = '';
            gaps.forEach(g => {
                gapItemsHtml += `
                    <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--sev-medium); padding: 8px 12px; border-radius: 4px; margin-top: 6px;">
                        <div style="color: var(--sev-medium); font-weight: 600; font-size: 12px;">${g.title}</div>
                        <div style="color: var(--text-secondary); font-size: 11px; margin-top: 2px;">${g.description}</div>
                    </div>
                `;
            });
            gapsBodyHtml = `
                <div style="margin-top: 6px;">
                    <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">
                        ${data.dataset_gap_note}
                    </div>
                    ${gapItemsHtml}
                </div>
            `;
        } else {
            gapsBodyHtml = `
                <div style="background: rgba(16, 185, 129, 0.05); border-left: 3px solid var(--sev-low); padding: 10px 12px; border-radius: 4px; margin-top: 6px;">
                    <div style="color: var(--sev-low); font-weight: 600; font-size: 12px;">✓ Dataset Integrity Check Passed</div>
                    <div style="color: var(--text-secondary); font-size: 11px; margin-top: 2px;">
                        ${data.dataset_gap_note}
                    </div>
                </div>
            `;
        }

        const sectionGapsHtml = `
            <div class="dna-section">
                <div class="dna-section-header">
                    <span style="font-size: 12px; font-weight: 700; color: #FFFFFF; display: flex; align-items: center; gap: 6px;">
                        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${data.has_contradictions_or_gaps ? 'var(--sev-medium)' : '#10B981'};"></span>
                        CONTRADICTORY & MISSING EVIDENCE CHECK
                    </span>
                    <span class="pill ${data.has_contradictions_or_gaps ? 'badge-sev-medium' : 'badge-sev-low'}">
                        ${data.has_contradictions_or_gaps ? 'Gaps Detected' : 'No Contradictions'}
                    </span>
                </div>
                ${gapsBodyHtml}
            </div>
        `;

        // 5. Action Bar
        const startTimeParam = encodeURIComponent(finding.start_time || '');
        const actionBarHtml = `
            <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 6px; border-top: 1px solid var(--border-color);">
                <div style="display: flex; gap: 8px;">
                    ${finding.start_time ? `
                        <a href="/timeline?case_id=${encodeURIComponent(caseId)}&timestamp=${startTimeParam}" class="btn btn-primary btn-sm">
                            Open Timeline at Finding Start (${finding.start_time.slice(11, 19)}) →
                        </a>
                    ` : ''}
                    <a href="/graph?case_id=${encodeURIComponent(caseId)}" class="btn btn-outline btn-sm">
                        View in Incident Graph →
                    </a>
                </div>
                <button type="button" class="btn btn-outline btn-sm" id="btnDismissDnaBottom">
                    Close Details
                </button>
            </div>
        `;

        // Combine into panel
        dnaPanelBody.innerHTML = `
            ${rationaleHtml}
            ${sectionFactsHtml}
            ${sectionConclusionsHtml}
            ${sectionGapsHtml}
            ${actionBarHtml}
        `;

        const btnDismiss = document.getElementById('btnDismissDnaBottom');
        if (btnDismiss) {
            btnDismiss.addEventListener('click', () => {
                dnaCard.style.display = 'none';
                findingRows.forEach(r => r.classList.remove('active'));
            });
        }
    }
});


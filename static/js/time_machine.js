/**
 * Investigation Time Machine Client Logic
 * Handles saving immutable analysis snapshots, SHA-256 integrity verification,
 * and side-by-side comparative evolution analysis.
 */

document.addEventListener("DOMContentLoaded", function () {
    const caseId = new URLSearchParams(window.location.search).get("case_id") || "CASE-001";
    let snapshotsList = [];
    let currentComparisonData = null;
    let currentDiffFilter = "all";

    // UI Elements
    const btnToggleNewSnapshot = document.getElementById("btnToggleNewSnapshot");
    const newSnapshotCard = document.getElementById("newSnapshotCard");
    const newSnapshotForm = document.getElementById("newSnapshotForm");
    const snapshotNameInput = document.getElementById("snapshotNameInput");
    const snapshotNoteInput = document.getElementById("snapshotNoteInput");
    const btnCancelSnapshot = document.getElementById("btnCancelSnapshot");

    const selectSnapshotA = document.getElementById("selectSnapshotA");
    const selectSnapshotB = document.getElementById("selectSnapshotB");
    const btnCompareSnapshots = document.getElementById("btnCompareSnapshots");

    const comparisonContainer = document.getElementById("comparisonContainer");
    const metaA_Name = document.getElementById("metaA_Name");
    const metaA_Id = document.getElementById("metaA_Id");
    const metaA_Time = document.getElementById("metaA_Time");
    const metaA_Findings = document.getElementById("metaA_Findings");
    const metaA_Files = document.getElementById("metaA_Files");
    const metaA_Integrity = document.getElementById("metaA_Integrity");

    const metaB_Name = document.getElementById("metaB_Name");
    const metaB_Id = document.getElementById("metaB_Id");
    const metaB_Time = document.getElementById("metaB_Time");
    const metaB_Findings = document.getElementById("metaB_Findings");
    const metaB_Files = document.getElementById("metaB_Files");
    const metaB_Integrity = document.getElementById("metaB_Integrity");

    const kpiAddedFindings = document.getElementById("kpiAddedFindings");
    const kpiChangedFindings = document.getElementById("kpiChangedFindings");
    const kpiRemovedFindings = document.getElementById("kpiRemovedFindings");
    const kpiUnchangedFindings = document.getElementById("kpiUnchangedFindings");
    const kpiEvidenceDelta = document.getElementById("kpiEvidenceDelta");
    const kpiNewContradictions = document.getElementById("kpiNewContradictions");

    const diffItemsContainer = document.getElementById("diffItemsContainer");
    const evidenceDiffContainer = document.getElementById("evidenceDiffContainer");
    const savedSnapshotsTableBody = document.getElementById("savedSnapshotsTableBody");
    const savedSnapshotsCountBadge = document.getElementById("savedSnapshotsCountBadge");

    // Load saved snapshots list
    async function loadSnapshots() {
        savedSnapshotsTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;"><span class="spinner-inline" style="margin-right: 8px;"></span>Loading historical analysis snapshots...</td></tr>`;
        try {
            const resp = await fetch(`/api/snapshots?case_id=${encodeURIComponent(caseId)}`);
            if (!resp.ok) throw new Error("Failed to load investigation snapshots.");
            const data = await resp.json();
            snapshotsList = data.snapshots || [];

            renderSavedSnapshotsTable(snapshotsList);
            populateSnapshotSelectors(snapshotsList);
        } catch (err) {
            savedSnapshotsTableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--sev-critical); padding: 20px;">Error: ${escapeHtml(err.message)}</td></tr>`;
        }
    }

    function renderSavedSnapshotsTable(snapshots) {
        savedSnapshotsCountBadge.textContent = `${snapshots.length} Snapshot${snapshots.length === 1 ? '' : 's'}`;
        if (!snapshots || snapshots.length === 0) {
            savedSnapshotsTableBody.innerHTML = `
                <tr>
                    <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 28px;">
                        No analysis snapshots captured yet for case <strong>${escapeHtml(caseId)}</strong>.<br>
                        Click "Capture New Snapshot" above to preserve an immutable investigation milestone.
                    </td>
                </tr>
            `;
            return;
        }

        savedSnapshotsTableBody.innerHTML = snapshots.map(s => {
            const isVerified = s.integrity_status === "verified";
            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan); font-size: 12px;">
                        ${escapeHtml(s.id)}
                    </td>
                    <td>
                        <div style="font-weight: 600; color: var(--text-primary); font-size: 13px;">${escapeHtml(s.name)}</div>
                        ${s.note ? `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(s.note)}</div>` : ''}
                    </td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                        ${escapeHtml(s.created_at)}
                    </td>
                    <td>
                        <span class="pill pill-inferred" style="font-size: 10px;">${escapeHtml(s.rule_version)}</span>
                    </td>
                    <td style="font-weight: 600; color: var(--text-primary);">
                        ${escapeHtml(s.finding_count)}
                    </td>
                    <td style="font-weight: 600; color: var(--text-primary);">
                        ${escapeHtml(s.evidence_file_count)}
                    </td>
                    <td>
                        <span class="integrity-badge ${isVerified ? 'verified' : 'tampered'}">
                            ${isVerified ? '✓ SHA-256 OK' : '⚠ TAMPERED'}
                        </span>
                    </td>
                    <td style="text-align: right;">
                        <div style="display: flex; gap: 4px; justify-content: flex-end;">
                            <button class="btn btn-outline btn-xs btn-set-base" data-snap-id="${escapeHtml(s.id)}" title="Set as Baseline (A)">
                                Set A
                            </button>
                            <button class="btn btn-outline btn-xs btn-set-compare" data-snap-id="${escapeHtml(s.id)}" title="Set as Comparison (B)">
                                Set B
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");

        // Attach quick select buttons
        savedSnapshotsTableBody.querySelectorAll(".btn-set-base").forEach(btn => {
            btn.addEventListener("click", () => {
                selectSnapshotA.value = btn.getAttribute("data-snap-id");
            });
        });

        savedSnapshotsTableBody.querySelectorAll(".btn-set-compare").forEach(btn => {
            btn.addEventListener("click", () => {
                selectSnapshotB.value = btn.getAttribute("data-snap-id");
            });
        });
    }

    function populateSnapshotSelectors(snapshots) {
        const prevA = selectSnapshotA.value;
        const prevB = selectSnapshotB.value;

        const options = snapshots.map(s => 
            `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.created_at)})</option>`
        ).join("");

        selectSnapshotA.innerHTML = `<option value="">-- Select Baseline Snapshot (A) --</option>` + options;
        selectSnapshotB.innerHTML = `<option value="">-- Select Comparison Snapshot (B) --</option>` + options;

        if (prevA && snapshots.some(s => s.id === prevA)) selectSnapshotA.value = prevA;
        if (prevB && snapshots.some(s => s.id === prevB)) selectSnapshotB.value = prevB;

        // Auto-select if at least two exist and none selected
        if (!selectSnapshotA.value && snapshots.length >= 2) {
            selectSnapshotA.value = snapshots[snapshots.length - 1].id; // Oldest
            selectSnapshotB.value = snapshots[0].id; // Newest
        }
    }

    // Toggle Capture Form
    btnToggleNewSnapshot.addEventListener("click", () => {
        if (newSnapshotCard.style.display === "none") {
            newSnapshotCard.style.display = "block";
            snapshotNameInput.focus();
        } else {
            newSnapshotCard.style.display = "none";
        }
    });

    btnCancelSnapshot.addEventListener("click", () => {
        newSnapshotCard.style.display = "none";
    });

    // Submit New Snapshot Form
    newSnapshotForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        const name = snapshotNameInput.value.trim();
        const note = snapshotNoteInput.value.trim();

        if (!name) {
            alert("Please provide a milestone name for the snapshot.");
            return;
        }

        const btn = document.getElementById("btnSubmitSnapshot");
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-inline" style="margin-right: 6px;"></span>Saving...`;

        try {
            const resp = await fetch("/api/snapshots", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    case_id: caseId,
                    name: name,
                    note: note,
                    rule_version: "v1.2.0-deterministic"
                })
            });

            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || "Failed to save snapshot.");

            newSnapshotCard.style.display = "none";
            snapshotNameInput.value = "";
            snapshotNoteInput.value = "";

            await loadSnapshots();
        } catch (err) {
            alert("Error saving snapshot: " + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = "Save Snapshot";
        }
    });

    // Run Comparison
    btnCompareSnapshots.addEventListener("click", async function () {
        const idA = selectSnapshotA.value;
        const idB = selectSnapshotB.value;

        if (!idA || !idB) {
            alert("Please select both Snapshot A and Snapshot B to compare.");
            return;
        }

        btnCompareSnapshots.disabled = true;
        btnCompareSnapshots.innerHTML = `<span class="spinner-inline" style="margin-right: 6px;"></span>Comparing...`;

        try {
            const resp = await fetch(`/api/snapshots/compare?case_id=${encodeURIComponent(caseId)}&snapshot_a_id=${encodeURIComponent(idA)}&snapshot_b_id=${encodeURIComponent(idB)}`);
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || "Comparison failed.");

            currentComparisonData = data;
            renderComparison(data);
        } catch (err) {
            alert("Comparison Error: " + err.message);
        } finally {
            btnCompareSnapshots.disabled = false;
            btnCompareSnapshots.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="16 3 21 3 21 8"></polyline>
                    <line x1="4" y1="20" x2="21" y2="3"></line>
                    <polyline points="21 16 21 21 16 21"></polyline>
                    <line x1="15" y1="15" x2="21" y2="21"></line>
                    <line x1="4" y1="4" x2="9" y2="9"></line>
                </svg>
                Compare Snapshots
            `;
        }
    });

    function renderComparison(data) {
        comparisonContainer.style.display = "block";

        // Metadata A
        const a = data.baseline_snapshot;
        metaA_Name.textContent = a.name;
        metaA_Id.textContent = a.id;
        metaA_Time.textContent = a.created_at;
        metaA_Findings.textContent = `${a.finding_count} findings`;
        metaA_Files.textContent = `${a.evidence_file_count} files`;
        metaA_Integrity.className = `integrity-badge ${a.integrity_status === 'verified' ? 'verified' : 'tampered'}`;
        metaA_Integrity.textContent = a.integrity_status === 'verified' ? '✓ SHA-256 OK' : '⚠ TAMPERED';

        // Metadata B
        const b = data.comparison_snapshot;
        metaB_Name.textContent = b.name;
        metaB_Id.textContent = b.id;
        metaB_Time.textContent = b.created_at;
        metaB_Findings.textContent = `${b.finding_count} findings`;
        metaB_Files.textContent = `${b.evidence_file_count} files`;
        metaB_Integrity.className = `integrity-badge ${b.integrity_status === 'verified' ? 'verified' : 'tampered'}`;
        metaB_Integrity.textContent = b.integrity_status === 'verified' ? '✓ SHA-256 OK' : '⚠ TAMPERED';

        // Summary KPIs
        const s = data.summary;
        kpiAddedFindings.textContent = s.findings_added_count || 0;
        kpiChangedFindings.textContent = s.findings_changed_count || 0;
        kpiRemovedFindings.textContent = s.findings_removed_count || 0;
        kpiUnchangedFindings.textContent = s.findings_unchanged_count || 0;
        kpiEvidenceDelta.textContent = (s.evidence_files_added_count || 0) + (s.evidence_files_removed_count || 0);
        kpiNewContradictions.textContent = s.newly_detected_contradictions_count || 0;

        renderFilteredDiffItems();
        renderEvidenceDiff(data.evidence_diff);

        // Scroll to comparison
        comparisonContainer.scrollIntoView({ behavior: "smooth" });
    }

    function renderFilteredDiffItems() {
        if (!currentComparisonData) return;

        let items = [];
        if (currentDiffFilter === "all" || currentDiffFilter === "Added") {
            items = items.concat(currentComparisonData.added_findings || []);
        }
        if (currentDiffFilter === "all" || currentDiffFilter === "Changed") {
            items = items.concat(currentComparisonData.changed_findings || []);
        }
        if (currentDiffFilter === "all" || currentDiffFilter === "Removed") {
            items = items.concat(currentComparisonData.removed_findings || []);
        }
        if (currentDiffFilter === "all" || currentDiffFilter === "Unchanged") {
            items = items.concat(currentComparisonData.unchanged_findings || []);
        }

        if (items.length === 0) {
            diffItemsContainer.innerHTML = `
                <div style="background: var(--bg-surface-elevated); border: 1px dashed var(--border-color); border-radius: var(--radius-sm); padding: 20px; text-align: center; color: var(--text-muted); font-size: 13px;">
                    No findings match filter "${escapeHtml(currentDiffFilter)}".
                </div>
            `;
            return;
        }

        diffItemsContainer.innerHTML = items.map(item => {
            const diffType = item.diff_type;
            let badgeClass = "diff-unchanged";
            let borderColor = "#64748B";

            if (diffType === "Added") {
                badgeClass = "diff-added";
                borderColor = "#10B981";
            } else if (diffType === "Removed") {
                badgeClass = "diff-removed";
                borderColor = "#EF4444";
            } else if (diffType === "Changed") {
                badgeClass = "diff-changed";
                borderColor = "#F59E0B";
            }

            // Timeline supporting links
            const eventIds = item.supporting_event_ids || [];
            const timelineLinks = eventIds.map(eid => `
                <a href="/timeline?case_id=${encodeURIComponent(caseId)}&event_id=${encodeURIComponent(eid)}" 
                   class="dna-action-link" title="Navigate to timeline event">
                    ${escapeHtml(eid)} ↗
                </a>
            `).join(" ");

            // Changes detail if mutated
            let changesHtml = "";
            if (diffType === "Changed" && item.changes) {
                changesHtml = `
                    <div style="margin-top: 8px; padding: 6px 10px; background: rgba(0,0,0,0.25); border-radius: 4px; font-size: 11px;">
                        <strong style="color: #F59E0B;">Mutations:</strong>
                        <ul style="margin-left: 16px; margin-top: 4px; color: var(--text-secondary);">
                            ${item.changes.map(c => `<li>${escapeHtml(c.description)}</li>`).join("")}
                        </ul>
                    </div>
                `;
            }

            return `
                <div style="background: var(--bg-surface-elevated); border-left: 4px solid ${borderColor}; border: 1px solid var(--border-color); border-left-width: 4px; border-left-color: ${borderColor}; border-radius: var(--radius-sm); padding: 12px 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="diff-badge ${badgeClass}">${escapeHtml(diffType)}</span>
                            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan); font-size: 13px;">
                                ${escapeHtml(item.finding_id || item.id)}
                            </span>
                            <span style="font-size: 12px; font-weight: 600; color: var(--text-primary);">
                                ${escapeHtml(item.rule_name || item.rule_id)}
                            </span>
                        </div>
                        <span class="pill pill-inferred" style="font-size: 10px;">Status: ${escapeHtml(item.status || 'open')}</span>
                    </div>

                    <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 8px;">
                        ${escapeHtml(item.explanation || '')}
                    </p>

                    ${changesHtml}

                    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px; padding-top: 6px; border-top: 1px dashed var(--border-color); font-size: 11px;">
                        <div style="color: var(--text-muted);">
                            <strong style="color: var(--accent-cyan);">Attribution:</strong> ${escapeHtml(item.attribution || 'Direct correlation deduction.')}
                        </div>
                        <div style="display: flex; gap: 4px; align-items: center;">
                            <span style="color: var(--text-muted); font-size: 10px;">Supporting Events:</span>
                            ${timelineLinks || '<span style="color: var(--text-muted);">None</span>'}
                        </div>
                    </div>
                </div>
            `;
        }).join("");
    }

    function renderEvidenceDiff(evDiff) {
        if (!evDiff) return;
        const added = evDiff.added || [];
        const removed = evDiff.removed || [];
        const modified = evDiff.modified || [];

        if (added.length === 0 && removed.length === 0 && modified.length === 0) {
            evidenceDiffContainer.innerHTML = `
                <div style="font-size: 12px; color: var(--text-muted); padding: 8px 12px; background: var(--bg-surface-elevated); border-radius: var(--radius-sm);">
                    ✓ Evidence set is identical between Baseline A and Comparison B. No files added or removed.
                </div>
            `;
            return;
        }

        let html = "";
        if (added.length > 0) {
            html += `
                <div style="margin-bottom: 8px;">
                    <div style="font-size: 11px; font-weight: 700; color: #10B981; margin-bottom: 4px; text-transform: uppercase;">New Evidence Ingested in Snapshot B:</div>
                    ${added.map(f => `
                        <div style="display: flex; justify-content: space-between; font-size: 12px; padding: 4px 8px; background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.25); border-radius: 3px; margin-bottom: 4px;">
                            <span><strong>${escapeHtml(f.filename)}</strong> (${escapeHtml(f.record_count)} records)</span>
                            <span style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">SHA-256: ${escapeHtml((f.sha256_hash || '').substring(0, 16))}...</span>
                        </div>
                    `).join("")}
                </div>
            `;
        }

        if (removed.length > 0) {
            html += `
                <div style="margin-bottom: 8px;">
                    <div style="font-size: 11px; font-weight: 700; color: #EF4444; margin-bottom: 4px; text-transform: uppercase;">Evidence Excluded in Snapshot B:</div>
                    ${removed.map(f => `
                        <div style="display: flex; justify-content: space-between; font-size: 12px; padding: 4px 8px; background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25); border-radius: 3px; margin-bottom: 4px;">
                            <span><strong>${escapeHtml(f.filename)}</strong></span>
                            <span style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);">SHA-256: ${escapeHtml((f.sha256_hash || '').substring(0, 16))}...</span>
                        </div>
                    `).join("")}
                </div>
            `;
        }

        evidenceDiffContainer.innerHTML = html;
    }

    // Filter Buttons
    document.querySelectorAll(".btn-diff-filter").forEach(btn => {
        btn.addEventListener("click", function () {
            document.querySelectorAll(".btn-diff-filter").forEach(b => b.classList.remove("active"));
            this.classList.add("active");
            currentDiffFilter = this.getAttribute("data-filter");
            renderFilteredDiffItems();
        });
    });

    // Initial load
    loadSnapshots();
});

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


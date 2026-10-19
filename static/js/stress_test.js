/**
 * Conclusion Stress Tester Client Logic
 * Evaluates whether findings and hypotheses are supported, partially supported,
 * contradictory, or insufficient based on recorded digital telemetry.
 */

document.addEventListener("DOMContentLoaded", function () {
    const caseId = new URLSearchParams(window.location.search).get("case_id") || "CASE-001";
    let stressData = null;
    let selectedFindingId = null;

    // UI Elements
    const kpiSupported = document.getElementById("kpiSupported");
    const kpiPartiallySupported = document.getElementById("kpiPartiallySupported");
    const kpiRequiresReview = document.getElementById("kpiRequiresReview");
    const kpiInsufficient = document.getElementById("kpiInsufficient");
    const kpiContradictory = document.getElementById("kpiContradictory");
    const findingsTableBody = document.getElementById("findingsStressTableBody");
    const findingsCountBadge = document.getElementById("findingsCountBadge");

    const noFindingPrompt = document.getElementById("noFindingSelectedPrompt");
    const findingDetailPanel = document.getElementById("findingDetailPanel");
    const detailFindingId = document.getElementById("detailFindingId");
    const detailRuleId = document.getElementById("detailRuleId");
    const detailExplanation = document.getElementById("detailExplanation");
    const detailStatusBadge = document.getElementById("detailStatusBadge");
    const detailStatusReason = document.getElementById("detailStatusReason");
    const warningsListContainer = document.getElementById("warningsListContainer");
    const warningsCountBadge = document.getElementById("warningsCountBadge");
    const supportingEventsTableBody = document.getElementById("supportingEventsTableBody");
    const supportingCountBadge = document.getElementById("supportingCountBadge");
    const contradictorySection = document.getElementById("contradictorySection");
    const contradictoryEventsTableBody = document.getElementById("contradictoryEventsTableBody");

    const btnRunStressTest = document.getElementById("btnRunStressTest");
    const btnToggleCustomTest = document.getElementById("btnToggleCustomTest");
    const customHypothesisCard = document.getElementById("customHypothesisCard");
    const customHypothesisForm = document.getElementById("customHypothesisForm");
    const customConclusionInput = document.getElementById("customConclusionInput");
    const customEventsInput = document.getElementById("customEventsInput");
    const customResultContainer = document.getElementById("customResultContainer");
    const customStatusBadge = document.getElementById("customStatusBadge");
    const customStatusReason = document.getElementById("customStatusReason");
    const customWarningsList = document.getElementById("customWarningsList");

    // Helper: Badge class for status
    function getStatusBadgeClass(status) {
        switch (status) {
            case "Supported by available evidence":
                return "stress-supported";
            case "Partially supported":
                return "stress-partially-supported";
            case "Contradictory evidence found":
                return "stress-contradictory";
            case "Insufficient evidence":
                return "stress-insufficient";
            case "Requires investigator review":
                return "stress-requires-review";
            default:
                return "stress-requires-review";
        }
    }

    // Load full case stress test data
    async function loadStressTest() {
        findingsTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;"><span class="spinner-inline" style="margin-right: 8px;"></span>Evaluating evidence against correlation conclusions...</td></tr>`;
        try {
            const resp = await fetch(`/api/stress-test?case_id=${encodeURIComponent(caseId)}`);
            if (!resp.ok) throw new Error("Failed to load stress test evaluations.");
            stressData = await resp.json();

            renderSummaryKPIs(stressData.status_summary);
            renderFindingsTable(stressData.evaluations);

            // Auto-select first finding if available
            if (stressData.evaluations && stressData.evaluations.length > 0) {
                renderFindingDetail(stressData.evaluations[0]);
            }
        } catch (err) {
            findingsTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--sev-critical); padding: 24px;">Error: ${escapeHtml(err.message)}</td></tr>`;
        }
    }

    function renderSummaryKPIs(summary) {
        if (!summary) return;
        kpiSupported.textContent = summary["Supported by available evidence"] || 0;
        kpiPartiallySupported.textContent = summary["Partially supported"] || 0;
        kpiRequiresReview.textContent = summary["Requires investigator review"] || 0;
        kpiInsufficient.textContent = summary["Insufficient evidence"] || 0;
        kpiContradictory.textContent = summary["Contradictory evidence found"] || 0;
    }

    function renderFindingsTable(evaluations) {
        findingsCountBadge.textContent = `${evaluations.length} Findings`;
        if (!evaluations || evaluations.length === 0) {
            findingsTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 24px;">No correlation findings present in this case.</td></tr>`;
            return;
        }

        findingsTableBody.innerHTML = evaluations.map((item, idx) => {
            const badgeCls = getStatusBadgeClass(item.status);
            const isSelected = item.finding_id === selectedFindingId;
            return `
                <tr class="finding-row ${isSelected ? 'active' : ''}" data-finding-id="${escapeHtml(item.finding_id)}" style="cursor: pointer;">
                    <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">
                        ${escapeHtml(item.finding_id)}
                    </td>
                    <td>
                        <div style="font-weight: 600; font-size: 12px; color: var(--text-primary); margin-bottom: 2px;">
                            ${escapeHtml(item.rule_name || item.rule_id)}
                        </div>
                        <div style="font-size: 11px; color: var(--text-secondary); max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                            ${escapeHtml(item.explanation || '')}
                        </div>
                    </td>
                    <td>
                        <span class="stress-badge ${badgeCls}">${escapeHtml(item.status)}</span>
                    </td>
                    <td style="text-align: right;">
                        <button class="btn btn-outline btn-xs btn-inspect-finding" data-finding-id="${escapeHtml(item.finding_id)}">
                            Inspect
                        </button>
                    </td>
                </tr>
            `;
        }).join("");

        // Attach click listeners to rows
        findingsTableBody.querySelectorAll(".finding-row").forEach(row => {
            row.addEventListener("click", () => {
                const fid = row.getAttribute("data-finding-id");
                const item = evaluations.find(e => e.finding_id === fid);
                if (item) renderFindingDetail(item);
            });
        });
    }

    function renderFindingDetail(item) {
        selectedFindingId = item.finding_id;

        // Update active class on table rows
        findingsTableBody.querySelectorAll(".finding-row").forEach(r => {
            if (r.getAttribute("data-finding-id") === selectedFindingId) {
                r.classList.add("active");
            } else {
                r.classList.remove("active");
            }
        });

        noFindingPrompt.style.display = "none";
        findingDetailPanel.style.display = "flex";

        detailFindingId.textContent = item.finding_id;
        detailRuleId.textContent = item.rule_id || "RULE";
        detailExplanation.textContent = item.explanation || "No statement provided.";
        detailStatusReason.textContent = item.status_reason || "";

        const badgeCls = getStatusBadgeClass(item.status);
        detailStatusBadge.className = `stress-badge ${badgeCls}`;
        detailStatusBadge.textContent = item.status;

        // Render Triggered Warnings
        const warnings = item.warnings || [];
        warningsCountBadge.textContent = `${warnings.length} Warning${warnings.length === 1 ? '' : 's'}`;
        if (warnings.length === 0) {
            warningsListContainer.innerHTML = `
                <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-sm); padding: 10px 14px; font-size: 12px; color: #10B981;">
                    ✓ Zero warnings triggered. All claims in this sequence are corroborated by primary evidence.
                </div>
            `;
        } else {
            warningsListContainer.innerHTML = warnings.map(w => {
                const sevColor = w.severity === 'critical' ? '#EF4444' : (w.severity === 'high' ? '#F97316' : '#F59E0B');
                return `
                    <div style="background: var(--bg-surface-elevated); border-left: 3px solid ${sevColor}; border-radius: var(--radius-sm); padding: 10px 12px; border-top: 1px solid var(--border-color); border-right: 1px solid var(--border-color); border-bottom: 1px solid var(--border-color);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <strong style="color: ${sevColor}; font-size: 12px;">${escapeHtml(w.warning_title)}</strong>
                            <span class="pill pill-inferred" style="font-size: 9px;">${escapeHtml(w.rule_triggered)}</span>
                        </div>
                        <p style="font-size: 12px; color: var(--text-primary); line-height: 1.5; margin-bottom: 6px;">
                            ${escapeHtml(w.explanation)}
                        </p>
                        <div style="font-size: 11px; color: var(--text-secondary); background: rgba(0,0,0,0.2); padding: 6px 8px; border-radius: 3px;">
                            <strong style="color: var(--accent-cyan);">Additional Evidence Needed:</strong> ${escapeHtml(w.additional_evidence_needed || 'Collect supplementary logs.')}
                        </div>
                    </div>
                `;
            }).join("");
        }

        // Render Supporting Events
        const events = item.supporting_events || [];
        supportingCountBadge.textContent = `${events.length} Record${events.length === 1 ? '' : 's'}`;
        if (events.length === 0) {
            supportingEventsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--sev-critical); padding: 14px;">No supporting records in evidence.</td></tr>`;
        } else {
            supportingEventsTableBody.innerHTML = events.map(ev => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-cyan);">
                        ${escapeHtml(ev.id)}
                    </td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                        ${escapeHtml(ev.timestamp)}
                    </td>
                    <td>
                        <span class="pill pill-observed">${escapeHtml(ev.source)}</span>
                    </td>
                    <td style="font-size: 12px; max-width: 180px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                        ${escapeHtml(ev.actor || 'SYSTEM')} → ${escapeHtml(ev.object || '')}
                    </td>
                    <td style="text-align: right;">
                        <a href="/timeline?case_id=${encodeURIComponent(caseId)}&event_id=${encodeURIComponent(ev.id)}" 
                           class="dna-action-link" title="Jump to timeline event">
                            Timeline ↗
                        </a>
                    </td>
                </tr>
            `).join("");
        }

        // Render Contradictory Events (if any)
        const contradictions = item.contradictory_events || [];
        if (contradictions.length > 0) {
            contradictorySection.style.display = "block";
            contradictoryEventsTableBody.innerHTML = contradictions.map(ev => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 700; color: #EF4444;">${escapeHtml(ev.id)}</td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${escapeHtml(ev.timestamp)}</td>
                    <td><span class="pill" style="background: rgba(239,68,68,0.2); color: #EF4444;">${escapeHtml(ev.source)}</span></td>
                    <td style="font-size: 12px; color: var(--text-primary);">${escapeHtml(ev.description || '')}</td>
                </tr>
            `).join("");
        } else {
            contradictorySection.style.display = "none";
        }
    }

    // Toggle custom hypothesis form
    btnToggleCustomTest.addEventListener("click", function () {
        if (customHypothesisCard.style.display === "none") {
            customHypothesisCard.style.display = "block";
            customConclusionInput.focus();
        } else {
            customHypothesisCard.style.display = "none";
        }
    });

    // Quick Presets
    document.querySelectorAll(".btn-preset-hypo").forEach(btn => {
        btn.addEventListener("click", function () {
            customConclusionInput.value = this.getAttribute("data-conclusion");
            customEventsInput.value = this.getAttribute("data-events");
        });
    });

    // Handle Custom Hypothesis Stress Test Submission
    customHypothesisForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        const conclusionText = customConclusionInput.value.trim();
        const eventIdsStr = customEventsInput.value.trim();
        const eventIds = eventIdsStr ? eventIdsStr.split(",").map(s => s.trim()).filter(Boolean) : [];

        if (!conclusionText) {
            alert("Please enter a conclusion statement to evaluate.");
            return;
        }

        const btn = document.getElementById("btnEvaluateCustom");
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-inline" style="margin-right: 6px;"></span>Stress Testing...`;

        try {
            const resp = await fetch("/api/stress-test/custom", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    case_id: caseId,
                    conclusion: conclusionText,
                    event_ids: eventIds
                })
            });

            const result = await resp.json();
            if (!resp.ok) throw new Error(result.error || "Failed to evaluate hypothesis.");

            // Display custom evaluation
            customResultContainer.style.display = "block";
            const badgeCls = getStatusBadgeClass(result.status);
            customStatusBadge.className = `stress-badge ${badgeCls}`;
            customStatusBadge.textContent = result.status;
            customStatusReason.textContent = result.status_reason || "";

            const warnings = result.warnings || [];
            if (warnings.length === 0) {
                customWarningsList.innerHTML = `
                    <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: var(--radius-sm); padding: 8px 12px; font-size: 12px; color: #10B981;">
                        ✓ No warnings triggered. Hypothesis is corroborated by referenced evidence.
                    </div>
                `;
            } else {
                customWarningsList.innerHTML = warnings.map(w => `
                    <div style="background: var(--bg-surface); border-left: 3px solid #F97316; border-radius: 4px; padding: 10px 12px; border: 1px solid var(--border-color); border-left-width: 3px; border-left-color: #F97316;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                            <strong style="color: #F97316; font-size: 12px;">${escapeHtml(w.warning_title)}</strong>
                            <span class="pill pill-inferred" style="font-size: 9px;">${escapeHtml(w.rule_triggered)}</span>
                        </div>
                        <p style="font-size: 12px; color: var(--text-primary); margin-bottom: 6px; line-height: 1.4;">
                            ${escapeHtml(w.explanation)}
                        </p>
                        <div style="font-size: 11px; color: var(--text-secondary); background: rgba(0,0,0,0.2); padding: 4px 8px; border-radius: 3px;">
                            <strong style="color: var(--accent-cyan);">What Would Help:</strong> ${escapeHtml(w.additional_evidence_needed || 'Collect additional logs.')}
                        </div>
                    </div>
                `).join("");
            }
        } catch (err) {
            alert("Error: " + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = "Run Stress Test on Hypothesis";
        }
    });

    btnRunStressTest.addEventListener("click", loadStressTest);

    // Initial load
    loadStressTest();
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


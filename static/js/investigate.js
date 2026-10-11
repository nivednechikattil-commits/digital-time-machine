/**
 * DIGITAL TIME MACHINE — INVESTIGATOR WORKSPACE CONTROLLER
 * Loads forensic inquiry Q&A, manages case notes, handles interactive timeline queries,
 * and persists finding status updates to SQLite.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-001';
    const inquiriesContainer = document.getElementById('inquiriesListContainer');
    const notesContainer = document.getElementById('notesContainer');
    const notesCountBadge = document.getElementById('notesCountBadge');
    const noteForm = document.getElementById('noteForm');
    const noteAuthor = document.getElementById('noteAuthor');
    const noteText = document.getElementById('noteText');
    const btnSaveNote = document.getElementById('btnSaveNote');

    // Query Bar DOM
    const queryForm = document.getElementById('investigatorQueryForm');
    const queryInput = document.getElementById('queryInput');
    const btnRunQuery = document.getElementById('btnRunQuery');
    const queryResultCard = document.getElementById('queryResultCard');
    const queryResultTitle = document.getElementById('queryResultTitle');
    const queryResultText = document.getElementById('queryResultText');
    const queryResultCaveats = document.getElementById('queryResultCaveats');
    const queryResultPills = document.getElementById('queryResultPills');
    const queryConfidenceBadge = document.getElementById('queryConfidenceBadge');

    // Findings Status Table
    const findingsStatusTableBody = document.getElementById('findingsStatusTableBody');

    // 1. Run Interactive Timeline Query
    async function executeQuery(queryText) {
        if (!queryText) return;
        btnRunQuery.disabled = true;
        btnRunQuery.innerText = 'Evaluating...';

        try {
            const res = await fetch('/api/investigate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    case_id: caseId,
                    query: queryText
                })
            });
            const data = await res.json();

            queryResultCard.style.display = 'block';
            queryResultTitle.innerText = `Inquiry: "${queryText}"`;
            queryResultText.innerText = data.answer || "No response generated.";
            queryConfidenceBadge.innerText = data.confidence || "observed";

            if (data.uncertainties) {
                queryResultCaveats.innerHTML = `<strong>Forensic Caveat:</strong> ${data.uncertainties}`;
                queryResultCaveats.style.display = 'block';
            } else {
                queryResultCaveats.style.display = 'none';
            }

            const suppPills = (data.supporting_event_ids || []).map(id => `
                <a href="/timeline?case_id=${encodeURIComponent(caseId)}&event_id=${id}" class="mono" style="background: rgba(6, 182, 212, 0.15); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); padding: 2px 6px; border-radius: 3px; font-size: 11px; text-decoration: none;">
                    ${id}
                </a>
            `).join(' ');
            queryResultPills.innerHTML = suppPills ? `<span style="font-size: 11px; color: var(--text-muted);">Supporting Events:</span> ${suppPills}` : '';

        } catch (err) {
            window.showToast("Query evaluation failed: " + err.message, "error");
        } finally {
            btnRunQuery.disabled = false;
            btnRunQuery.innerText = 'Ask Timeline';
        }
    }

    if (queryForm) {
        queryForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const text = queryInput.value.trim();
            if (text) executeQuery(text);
        });
    }

    document.querySelectorAll('.btn-preset-q').forEach(btn => {
        btn.addEventListener('click', () => {
            const q = btn.getAttribute('data-q');
            queryInput.value = q;
            executeQuery(q);
        });
    });

    // 2. Load and Manage Finding Statuses
    async function loadFindingsStatus() {
        try {
            const res = await fetch(`/api/incidents?case_id=${encodeURIComponent(caseId)}`);
            const data = await res.json();
            const findings = data.findings || [];

            if (!findingsStatusTableBody) return;

            if (findings.length === 0) {
                findingsStatusTableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 15px;">No correlation findings recorded.</td></tr>';
                return;
            }

            let html = '';
            findings.forEach(f => {
                const currentStatus = f.status || 'open';
                const statusBadgeClass = currentStatus === 'resolved' ? 'badge-sev-low' : (currentStatus === 'under_review' ? 'badge-sev-medium' : 'badge-sev-high');
                const statusLabel = currentStatus.replace('_', ' ').toUpperCase();

                html += `
                    <tr>
                        <td class="mono" style="color: var(--accent-cyan); font-weight: 700;">${f.id}</td>
                        <td>
                            <div><strong>${f.rule_name}</strong></div>
                            <span class="pill badge-sev-${f.severity}">${f.severity}</span>
                        </td>
                        <td>
                            <span id="badge-status-${f.id}" class="pill ${statusBadgeClass}">${statusLabel}</span>
                        </td>
                        <td style="text-align: right;">
                            <select class="btn btn-outline btn-xs select-finding-status" data-id="${f.id}" style="padding: 3px 6px;">
                                <option value="open" ${currentStatus === 'open' ? 'selected' : ''}>Open</option>
                                <option value="under_review" ${currentStatus === 'under_review' ? 'selected' : ''}>Under Review</option>
                                <option value="resolved" ${currentStatus === 'resolved' ? 'selected' : ''}>Resolved</option>
                            </select>
                        </td>
                    </tr>
                `;
            });
            findingsStatusTableBody.innerHTML = html;

            document.querySelectorAll('.select-finding-status').forEach(sel => {
                sel.addEventListener('change', async (e) => {
                    const fId = sel.getAttribute('data-id');
                    const newStatus = sel.value;
                    await updateFindingStatus(fId, newStatus);
                });
            });

        } catch (err) {
            if (findingsStatusTableBody) {
                findingsStatusTableBody.innerHTML = `<tr><td colspan="4" style="color: var(--sev-critical); padding: 15px;">Failed to load findings: ${err.message}</td></tr>`;
            }
        }
    }

    async function updateFindingStatus(findingId, newStatus) {
        try {
            const res = await fetch(`/api/incidents/${encodeURIComponent(findingId)}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    case_id: caseId,
                    status: newStatus
                })
            });
            const data = await res.json();
            if (res.ok && data.success) {
                window.showToast(`Finding ${findingId} marked as ${newStatus.replace('_', ' ')} (persisted in SQLite)`, "success");
                const badge = document.getElementById(`badge-status-${findingId}`);
                if (badge) {
                    badge.className = `pill ${newStatus === 'resolved' ? 'badge-sev-low' : (newStatus === 'under_review' ? 'badge-sev-medium' : 'badge-sev-high')}`;
                    badge.innerText = newStatus.replace('_', ' ').toUpperCase();
                }
            } else {
                window.showToast(data.error || "Failed to update finding status", "error");
            }
        } catch (err) {
            window.showToast("Network error: " + err.message, "error");
        }
    }

    // 3. Load Standard Inquiries
    async function loadInquiries() {
        try {
            const res = await fetch(`/api/investigate?case_id=${encodeURIComponent(caseId)}`);
            const data = await res.json();
            const inquiries = data.inquiries || [];

            if (inquiries.length === 0) {
                inquiriesContainer.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No inquiries generated.</div>';
                return;
            }

            let html = '';
            inquiries.forEach((item) => {
                const ans = item.answer_data || {};
                const suppPills = (ans.supporting_event_ids || []).map(id => `
                    <a href="/timeline?case_id=${encodeURIComponent(caseId)}&event_id=${id}" class="mono" style="background: rgba(6, 182, 212, 0.15); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); padding: 2px 6px; border-radius: 3px; font-size: 11px; text-decoration: none;">
                        ${id}
                    </a>
                `).join(' ');

                html += `
                    <div style="background-color: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span class="mono" style="font-weight: 700; color: var(--accent-cyan); font-size: 12px;">INQUIRY ${item.id} — ${item.category.toUpperCase()}</span>
                            <span class="pill pill-observed">${ans.confidence || 'observed'}</span>
                        </div>
                        <h3 style="font-size: 14px; font-weight: 600; color: #FFFFFF; margin-bottom: 8px;">${item.question}</h3>
                        
                        <div style="font-size: 13px; color: var(--text-primary); line-height: 1.6; margin-bottom: 10px; white-space: pre-line;">
                            ${ans.answer}
                        </div>

                        ${ans.uncertainties ? `
                        <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid var(--sev-medium); padding: 8px 10px; font-size: 11px; color: var(--text-secondary); margin-bottom: 8px;">
                            <strong style="color: var(--sev-medium);">Forensic Caveat & What Remains Uncertain:</strong> ${ans.uncertainties}
                        </div>
                        ` : ''}

                        <div style="display: flex; align-items: center; gap: 8px; font-size: 11px;">
                            <span style="color: var(--text-muted); font-weight: 600;">Supporting Evidence:</span>
                            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                                ${suppPills || '<span style="color: var(--text-muted);">None required / inconclusive</span>'}
                            </div>
                        </div>
                    </div>
                `;
            });

            inquiriesContainer.innerHTML = html;
        } catch (e) {
            inquiriesContainer.innerHTML = `<div style="color: var(--sev-critical); padding: 20px;">Failed to evaluate inquiries: ${e.message}</div>`;
        }
    }

    // 4. Load Case Notes
    async function loadNotes() {
        try {
            const res = await fetch(`/api/notes?case_id=${encodeURIComponent(caseId)}`);
            const data = await res.json();
            const notes = data.notes || [];

            notesCountBadge.innerText = `${notes.length} Recorded`;

            if (notes.length === 0) {
                notesContainer.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No notes recorded yet.</div>';
                return;
            }

            let html = '';
            notes.forEach(n => {
                html += `
                    <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: 4px; border-left: 2px solid var(--accent-blue);">
                        <div style="display: flex; justify-content: space-between; font-size: 10px; color: var(--text-muted); margin-bottom: 4px;">
                            <strong style="color: var(--text-secondary);">${n.author}</strong>
                            <span class="mono">${n.timestamp}</span>
                        </div>
                        <div style="color: var(--text-primary); font-size: 12px; line-height: 1.4;">${n.note}</div>
                    </div>
                `;
            });
            notesContainer.innerHTML = html;
        } catch (e) {
            notesContainer.innerHTML = `<div style="color: var(--sev-critical); padding: 10px;">Failed to load notes: ${e.message}</div>`;
        }
    }

    // 5. Save Note
    if (noteForm) {
        noteForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const text = noteText.value.trim();
            const author = noteAuthor.value.trim() || 'Investigator';
            if (!text) return;

            btnSaveNote.disabled = true;
            btnSaveNote.innerText = 'Saving...';

            try {
                const res = await fetch('/api/notes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        case_id: caseId,
                        note: text,
                        author: author
                    })
                });

                if (res.ok) {
                    noteText.value = '';
                    window.showToast("Note successfully recorded in case log", "success");
                    loadNotes();
                } else {
                    window.showToast("Failed to save note", "error");
                }
            } catch (err) {
                window.showToast("Error: " + err.message, "error");
            } finally {
                btnSaveNote.disabled = false;
                btnSaveNote.innerText = 'Save Note to Investigation Log';
            }
        });
    }

    // Initial load
    loadFindingsStatus();
    loadInquiries();
    loadNotes();
});

/**
 * DIGITAL TIME MACHINE — INVESTIGATOR WORKSPACE CONTROLLER
 * Loads forensic inquiry Q&A and manages case notes.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-2026-001';
    const inquiriesContainer = document.getElementById('inquiriesListContainer');
    const notesContainer = document.getElementById('notesContainer');
    const notesCountBadge = document.getElementById('notesCountBadge');
    const noteForm = document.getElementById('noteForm');
    const noteAuthor = document.getElementById('noteAuthor');
    const noteText = document.getElementById('noteText');
    const btnSaveNote = document.getElementById('btnSaveNote');

    // 1. Load Forensic Inquiries
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
            inquiries.forEach((item, idx) => {
                const ans = item.answer_data || {};
                const suppPills = (ans.supporting_event_ids || []).map(id => `
                    <a href="/timeline?case_id=${caseId}" class="mono" style="background: rgba(6, 182, 212, 0.15); border: 1px solid var(--accent-cyan); color: var(--accent-cyan); padding: 2px 6px; border-radius: 3px; font-size: 11px; text-decoration: none;">
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

    // 2. Load Case Notes
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

    // 3. Save Note
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

    // Initial load
    loadInquiries();
    loadNotes();
});


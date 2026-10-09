/**
 * DIGITAL TIME MACHINE — EVIDENCE INGESTION CONTROLLER
 * Handles file preview, safe upload, duplicate check alerts, and validation reports.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-2026-001';
    const form = document.getElementById('uploadEvidenceForm');
    const fileInput = document.getElementById('evidenceFile');
    const btnSubmit = document.getElementById('btnUploadSubmit');
    const previewArea = document.getElementById('filePreviewArea');
    const previewFilename = document.getElementById('previewFilename');
    const previewSize = document.getElementById('previewSize');
    const previewSnippet = document.getElementById('previewSnippet');
    const diagnosticStatus = document.getElementById('diagnosticStatus');
    const diagnosticResults = document.getElementById('diagnosticResults');

    // Show preview upon file selection
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) {
            previewArea.style.display = 'none';
            return;
        }

        previewFilename.innerText = file.name;
        previewSize.innerText = file.size;
        previewArea.style.display = 'block';

        const reader = new FileReader();
        reader.onload = (evt) => {
            const text = evt.target.result;
            previewSnippet.innerText = text.slice(0, 300) + (text.length > 300 ? '\n... [truncated]' : '');
        };
        reader.readAsText(file.slice(0, 2048));
    });

    // Handle form upload
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) {
            window.showToast("Please choose an evidence file first.", "error");
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('case_id', caseId);

        btnSubmit.disabled = true;
        btnSubmit.innerText = 'Validating & Ingesting...';
        diagnosticStatus.innerText = 'Processing...';

        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (res.ok && data.success) {
                diagnosticStatus.innerText = 'Success';
                diagnosticStatus.className = 'pill badge-sev-low';

                let errorsList = '';
                if (data.rejected > 0) {
                    errorsList = `
                        <div style="margin-top: 8px; color: var(--sev-medium);">
                            <strong>Rejection Diagnostics (${data.rejected} invalid records):</strong>
                            <ul style="margin-left: 16px; margin-top: 4px;">
                                ${data.errors.map(err => `<li>Line ${err.line_number}: ${err.error}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                }

                diagnosticResults.innerHTML = `
                    <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-low);">
                        <strong style="color: var(--sev-low); font-size: 13px;">Evidence Successfully Ingested</strong>
                        <div style="margin-top: 6px;" class="mono">SHA-256: ${data.sha256}</div>
                        <div style="margin-top: 4px;">Records Processed: <strong>${data.total_records}</strong> (Accepted: <span style="color: var(--sev-low);">${data.accepted}</span>, Rejected: <span style="color: var(--sev-critical);">${data.rejected}</span>)</div>
                        ${errorsList}
                    </div>
                `;

                window.showToast(`Imported ${data.accepted} events successfully!`, "success");
                setTimeout(() => window.location.reload(), 1500);

            } else {
                diagnosticStatus.innerText = data.duplicate ? 'Duplicate Detected' : 'Import Failed';
                diagnosticStatus.className = 'pill badge-sev-critical';

                diagnosticResults.innerHTML = `
                    <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-critical);">
                        <strong style="color: var(--sev-critical);">${data.duplicate ? 'Duplicate Evidence Blocked' : 'Ingestion Error'}</strong>
                        <div style="margin-top: 6px;">${data.error || 'Failed to parse file'}</div>
                        ${data.sha256 ? `<div class="mono" style="margin-top: 4px; font-size: 11px;">SHA-256: ${data.sha256}</div>` : ''}
                    </div>
                `;
                window.showToast(data.error || "Upload failed", "error");
            }
        } catch (err) {
            diagnosticStatus.innerText = 'Network Error';
            diagnosticStatus.className = 'pill badge-sev-critical';
            diagnosticResults.innerHTML = `<div style="color: var(--sev-critical);">Upload failed: ${err.message}</div>`;
            window.showToast("Network error: " + err.message, "error");
        } finally {
            btnSubmit.disabled = false;
            btnSubmit.innerText = 'Verify & Ingest Evidence';
        }
    });
});


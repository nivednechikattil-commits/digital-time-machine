/**
 * DIGITAL TIME MACHINE — EVIDENCE INGESTION CONTROLLER
 * Handles file preview, pre-ingestion validation, safe upload,
 * SHA-256 duplicate detection & identification, and dynamic table updates.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = new URLSearchParams(window.location.search).get('case_id') || window.CURRENT_CASE_ID || 'CASE-2026-001';
    const form = document.getElementById('uploadEvidenceForm');
    const fileInput = document.getElementById('evidenceFile');
    const btnSubmit = document.getElementById('btnUploadSubmit');
    const previewArea = document.getElementById('filePreviewArea');
    const previewFilename = document.getElementById('previewFilename');
    const previewSize = document.getElementById('previewSize');
    const previewSnippet = document.getElementById('previewSnippet');
    const diagnosticStatus = document.getElementById('diagnosticStatus');
    const diagnosticResults = document.getElementById('diagnosticResults');
    const evidenceFilesBody = document.getElementById('evidenceFilesBody');
    const evidenceCountTitle = document.getElementById('evidenceCountTitle');

    // Application state
    let selectedFile = null;
    let isProcessing = false;

    /**
     * Formats bytes into human-readable size
     */
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * Validates file before submission
     * Returns { valid: boolean, error?: string }
     */
    function validateFile(file) {
        if (!file) {
            return { valid: false, error: 'No file selected.' };
        }

        const name = (file.name || '').toLowerCase();
        const ext = name.includes('.') ? name.split('.').pop() : '';
        if (!['csv', 'json'].includes(ext)) {
            return {
                valid: false,
                error: `Unsupported file format ".${ext}". Digital Time Machine accepts only .csv and .json forensic evidence files.`
            };
        }

        if (file.size === 0) {
            return {
                valid: false,
                error: 'The selected evidence file is empty (0 bytes). Forensic ingestion requires valid data records.'
            };
        }

        const maxBytes = 16 * 1024 * 1024; // 16MB
        if (file.size > maxBytes) {
            return {
                valid: false,
                error: `File size exceeds the 16MB maximum upload limit (${formatBytes(file.size)}).`
            };
        }

        return { valid: true };
    }

    /**
     * Inspects CSV text snippet for header validation
     */
    function inspectCsvSnippet(snippet) {
        const lines = snippet.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (lines.length === 0) {
            return { validHeaders: false, error: 'CSV file contains no readable lines.' };
        }
        const headerLine = lines[0];
        const headers = headerLine.split(',').map(h => h.trim().toLowerCase().replace(/^["']|["']$/g, ''));

        // Check for essential forensic headers
        const recommendedFields = ['timestamp', 'source', 'event_type'];
        const missing = recommendedFields.filter(f => !headers.includes(f));

        if (missing.length > 0) {
            return {
                validHeaders: false,
                warning: `Notice: Header row missing recommended field(s): ${missing.join(', ')}. The backend will validate individual row schemas upon ingestion.`
            };
        }

        return {
            validHeaders: true,
            detectedColumns: headers.length,
            sampleRows: Math.max(0, lines.length - 1)
        };
    }

    /**
     * Handles file selection and updates UI state
     */
    function handleFileSelection(file) {
        if (!file) {
            selectedFile = null;
            if (btnSubmit) btnSubmit.disabled = true;
            if (previewArea) previewArea.style.display = 'none';
            if (diagnosticStatus) {
                diagnosticStatus.innerText = 'Ready';
                diagnosticStatus.className = 'pill pill-observed';
            }
            return;
        }

        const validation = validateFile(file);

        if (!validation.valid) {
            selectedFile = null;
            if (btnSubmit) btnSubmit.disabled = true;
            if (previewArea) previewArea.style.display = 'none';

            if (diagnosticStatus) {
                diagnosticStatus.innerText = 'Invalid File';
                diagnosticStatus.className = 'pill badge-sev-critical';
            }
            if (diagnosticResults) {
                diagnosticResults.innerHTML = `
                    <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-critical);">
                        <strong style="color: var(--sev-critical); font-size: 13px;">Validation Error:</strong>
                        <div style="margin-top: 6px; color: var(--text-primary); font-size: 12px;">${escapeHtml(validation.error)}</div>
                    </div>
                `;
            }
            if (window.showToast) {
                window.showToast(validation.error, "error");
            }
            return;
        }

        // Store selected file in state
        selectedFile = file;

        // Enable button
        if (btnSubmit) {
            btnSubmit.disabled = false;
        }

        // Show preview area
        if (previewArea) previewArea.style.display = 'block';
        if (previewFilename) previewFilename.innerText = file.name;
        if (previewSize) previewSize.innerText = `${formatBytes(file.size)} (${file.size} bytes)`;

        // Read sample for preview
        const reader = new FileReader();
        reader.onload = (evt) => {
            const text = evt.target.result;
            if (previewSnippet) {
                previewSnippet.innerText = text.slice(0, 500) + (text.length > 500 ? '\n... [truncated for preview]' : '');
            }

            // CSV header check preview
            if (file.name.toLowerCase().endsWith('.csv')) {
                const headerCheck = inspectCsvSnippet(text.slice(0, 2048));
                if (diagnosticStatus) {
                    diagnosticStatus.innerText = headerCheck.validHeaders ? 'File Verified' : 'Ready (Header Warning)';
                    diagnosticStatus.className = headerCheck.validHeaders ? 'pill badge-sev-low' : 'pill badge-sev-medium';
                }
                if (diagnosticResults) {
                    if (headerCheck.warning) {
                        diagnosticResults.innerHTML = `
                            <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-medium);">
                                <strong style="color: var(--sev-medium); font-size: 13px;">Pre-Ingestion Notice</strong>
                                <div style="margin-top: 6px; color: var(--text-primary); font-size: 11px;">${escapeHtml(headerCheck.warning)}</div>
                                <div style="margin-top: 6px; color: var(--text-secondary); font-size: 11px;">Click <strong>Verify & Ingest Evidence</strong> to proceed with ingestion and baseline hashing.</div>
                            </div>
                        `;
                    } else {
                        diagnosticResults.innerHTML = `
                            <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-low);">
                                <strong style="color: var(--sev-low); font-size: 13px;">Ready for Ingestion: ${escapeHtml(file.name)}</strong>
                                <div style="margin-top: 6px; color: var(--text-secondary); font-size: 11px;">
                                    Detected ${headerCheck.detectedColumns || 0} columns. Click <strong>Verify & Ingest Evidence</strong> to compute SHA-256 hash, validate all event rows, and update timeline correlations.
                                </div>
                            </div>
                        `;
                    }
                }
            } else {
                if (diagnosticStatus) {
                    diagnosticStatus.innerText = 'Ready for Ingestion';
                    diagnosticStatus.className = 'pill badge-sev-low';
                }
                if (diagnosticResults) {
                    diagnosticResults.innerHTML = `
                        <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-low);">
                            <strong style="color: var(--sev-low); font-size: 13px;">Ready for Ingestion: ${escapeHtml(file.name)}</strong>
                            <div style="margin-top: 6px; color: var(--text-secondary); font-size: 11px;">
                                JSON evidence selected. Click <strong>Verify & Ingest Evidence</strong> to parse records and compute SHA-256 baseline.
                            </div>
                        </div>
                    `;
                }
            }
        };
        reader.onerror = () => {
            if (previewSnippet) previewSnippet.innerText = 'Failed to read file preview.';
        };
        reader.readAsText(file.slice(0, 4096));
    }

    /**
     * Highlights and identifies existing evidence row in the UI table
     */
    function highlightExistingEvidenceRow(sha256) {
        if (!sha256) return null;

        // Search by data-sha256 attribute
        let row = document.querySelector(`tr[data-sha256="${sha256}"]`);

        // Fallback: search row text content if attribute not directly matched
        if (!row && evidenceFilesBody) {
            const rows = evidenceFilesBody.querySelectorAll('tr');
            for (const r of rows) {
                if (r.textContent.includes(sha256)) {
                    row = r;
                    break;
                }
            }
        }

        if (row) {
            // Remove previous highlights
            document.querySelectorAll('#evidenceFilesBody tr.duplicate-highlight').forEach(r => {
                r.classList.remove('duplicate-highlight');
                r.style.outline = '';
                r.style.backgroundColor = '';
            });

            // Smoothly scroll existing row into view
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });

            // Apply visual identification highlight
            row.classList.add('duplicate-highlight');
            row.style.outline = '2px solid var(--accent-cyan)';
            row.style.backgroundColor = 'rgba(6, 182, 212, 0.25)';

            // Ease into subtle persistent outline
            setTimeout(() => {
                row.style.backgroundColor = 'rgba(6, 182, 212, 0.12)';
                row.style.outline = '1px solid var(--accent-cyan)';
            }, 4000);

            return row;
        }
        return null;
    }

    /**
     * Appends an ingested evidence record dynamically to the table
     */
    function appendEvidenceRow(data) {
        if (!evidenceFilesBody) return;

        // Remove empty row if present
        const emptyRow = document.getElementById('emptyEvidenceRow');
        if (emptyRow) {
            emptyRow.remove();
        }

        const ext = (data.filename || '').split('.').pop().toUpperCase() || 'EVIDENCE';
        const formattedDate = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const formattedSize = data.file_size ? `${(data.file_size / 1024).toFixed(1)} KB` : 'N/A';

        const tr = document.createElement('tr');
        if (data.sha256) {
            tr.setAttribute('data-sha256', data.sha256);
            tr.id = `evidence-row-${data.sha256.slice(0, 12)}`;
        }
        tr.style.backgroundColor = 'rgba(16, 185, 129, 0.12)';
        tr.style.transition = 'background-color 2.5s ease';

        tr.innerHTML = `
            <td class="mono" style="font-weight: 600; color: var(--text-primary);">${escapeHtml(data.filename)}</td>
            <td><span class="pill pill-observed">${escapeHtml(ext)}</span></td>
            <td class="mono" style="font-size: 10px; color: var(--accent-cyan); max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(data.sha256)}">
                ${escapeHtml(data.sha256)}
            </td>
            <td class="mono">${data.total_records || 0}</td>
            <td class="mono" style="color: var(--sev-low); font-weight: 700;">${data.accepted || 0}</td>
            <td class="mono" style="color: ${(data.rejected > 0) ? 'var(--sev-critical)' : 'var(--text-muted)'}; font-weight: 700;">${data.rejected || 0}</td>
            <td class="mono" style="font-size: 11px;">${formattedDate}</td>
            <td class="mono" style="font-size: 11px;">${formattedSize}</td>
        `;

        // Prepend to top of table
        if (evidenceFilesBody.firstChild) {
            evidenceFilesBody.insertBefore(tr, evidenceFilesBody.firstChild);
        } else {
            evidenceFilesBody.appendChild(tr);
        }

        // Fade highlight after 3 seconds
        setTimeout(() => {
            tr.style.backgroundColor = 'transparent';
        }, 3000);

        // Update count title if present
        if (evidenceCountTitle) {
            const currentRows = evidenceFilesBody.querySelectorAll('tr:not(#emptyEvidenceRow)').length;
            evidenceCountTitle.innerText = `Ingested Evidence Files (${currentRows})`;
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Main Verify & Ingest handler
     */
    async function handleVerifyAndIngest(e) {
        if (e && e.preventDefault) e.preventDefault();

        // Prevent double submissions caused by repeated clicks
        if (isProcessing) {
            return;
        }

        const fileToUpload = selectedFile || (fileInput && fileInput.files ? fileInput.files[0] : null);

        if (!fileToUpload) {
            if (window.showToast) window.showToast("Please choose an evidence file first.", "warning");
            if (diagnosticStatus) {
                diagnosticStatus.innerText = 'No File Selected';
                diagnosticStatus.className = 'pill badge-sev-medium';
            }
            return;
        }

        // Pre-validate
        const check = validateFile(fileToUpload);
        if (!check.valid) {
            if (window.showToast) window.showToast(check.error, "error");
            return;
        }

        // Lock processing
        isProcessing = true;
        if (btnSubmit) {
            btnSubmit.disabled = true;
            btnSubmit.innerHTML = `<span class="spinner-inline" style="margin-right: 8px;"></span> Verifying & Ingesting...`;
        }
        if (diagnosticStatus) {
            diagnosticStatus.innerText = 'Hashing & Ingesting...';
            diagnosticStatus.className = 'pill pill-observed';
        }
        if (diagnosticResults) {
            diagnosticResults.innerHTML = `
                <div style="background-color: var(--bg-surface-elevated); padding: 14px; border-radius: 4px; display: flex; align-items: center; gap: 12px;">
                    <span class="spinner-inline"></span>
                    <div>
                        <strong style="color: var(--accent-cyan); font-size: 13px;">Processing Forensic Ingestion Stream</strong>
                        <div style="color: var(--text-secondary); font-size: 11px; margin-top: 3px;">
                            Computing SHA-256 cryptographic digest, validating schema integrity, and linking correlation rules...
                        </div>
                    </div>
                </div>
            `;
        }

        const formData = new FormData();
        formData.append('file', fileToUpload);
        formData.append('case_id', caseId);

        try {
            const res = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();

            if (res.ok && data.success) {
                // Success
                if (diagnosticStatus) {
                    diagnosticStatus.innerText = 'Ingested & Verified';
                    diagnosticStatus.className = 'pill badge-sev-low';
                }

                let errorsList = '';
                if (data.rejected > 0 && Array.isArray(data.errors) && data.errors.length > 0) {
                    errorsList = `
                        <div style="margin-top: 10px; color: var(--sev-medium);">
                            <strong>Rejection Diagnostics (${data.rejected} invalid records):</strong>
                            <ul style="margin-left: 18px; margin-top: 4px; max-height: 120px; overflow-y: auto;">
                                ${data.errors.map(err => `<li>Line ${escapeHtml(String(err.line_number))}: ${escapeHtml(err.error)}</li>`).join('')}
                            </ul>
                        </div>
                    `;
                }

                if (diagnosticResults) {
                    diagnosticResults.innerHTML = `
                        <div style="background-color: var(--bg-surface-elevated); padding: 14px; border-radius: 4px; border-left: 4px solid var(--sev-low);">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <strong style="color: var(--sev-low); font-size: 13px;">✓ Evidence Successfully Ingested</strong>
                                <span class="pill badge-sev-low">${data.accepted} Events Accepted</span>
                            </div>
                            <div style="margin-top: 8px;" class="mono" style="font-size: 11px; word-break: break-all;">
                                <strong>SHA-256 Digest:</strong> <span style="color: var(--accent-cyan);">${escapeHtml(data.sha256)}</span>
                            </div>
                            <div style="margin-top: 6px; font-size: 12px; color: var(--text-secondary);">
                                File: <strong style="color: var(--text-primary);">${escapeHtml(data.filename)}</strong> (${formatBytes(data.file_size || 0)}) |
                                Processed: <strong>${data.total_records}</strong> records (Accepted: <span style="color: var(--sev-low); font-weight: 600;">${data.accepted}</span>, Rejected: <span style="color: var(--sev-critical); font-weight: 600;">${data.rejected}</span>)
                            </div>
                            ${errorsList}
                        </div>
                    `;
                }

                // Append to evidence table
                appendEvidenceRow(data);

                // Toast notification
                if (window.showToast) {
                    window.showToast(`Successfully ingested ${data.filename} (${data.accepted} events accepted)!`, "success");
                }

                // Reset file input & selection state
                if (fileInput) fileInput.value = '';
                selectedFile = null;

            } else {
                // Duplicate or Validation error
                const isDup = Boolean(data.duplicate);
                if (isDup) {
                    if (diagnosticStatus) {
                        diagnosticStatus.innerText = 'Duplicate Blocked';
                        diagnosticStatus.className = 'pill badge-sev-critical';
                    }

                    const existingRecord = data.existing_file || {};
                    const existingName = existingRecord.original_filename || data.filename || 'Evidence File';
                    const existingDate = existingRecord.imported_at || 'Existing Session';
                    const existingRecords = existingRecord.valid_count !== undefined ? `${existingRecord.valid_count} accepted events` : 'Already ingested';

                    if (diagnosticResults) {
                        diagnosticResults.innerHTML = `
                            <div style="background-color: var(--bg-surface-elevated); padding: 14px; border-radius: 4px; border-left: 4px solid var(--sev-critical);">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <strong style="color: var(--sev-critical); font-size: 13px;">Duplicate Evidence Detected</strong>
                                    <span class="pill badge-sev-critical">Hash Collision Blocked</span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-primary); margin-bottom: 10px; font-weight: 500;">
                                    Duplicate evidence detected. This file has already been ingested.
                                </div>
                                <div style="background: rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.08); padding: 10px; border-radius: 4px; font-size: 11px; line-height: 1.6;">
                                    <div style="color: var(--accent-cyan); font-weight: 600; text-transform: uppercase; font-size: 10px; margin-bottom: 4px;">
                                        Existing Evidence Record in Store:
                                    </div>
                                    <div>Original Filename: <strong style="color: var(--text-primary);">${escapeHtml(existingName)}</strong></div>
                                    <div>Ingestion Timestamp: <span class="mono" style="color: var(--text-secondary);">${escapeHtml(existingDate)}</span></div>
                                    <div>SHA-256 Digest: <span class="mono" style="color: var(--accent-cyan); word-break: break-all;">${escapeHtml(data.sha256)}</span></div>
                                    <div>Timeline Events: <span class="mono" style="color: var(--sev-low);">${escapeHtml(String(existingRecords))}</span></div>
                                </div>
                                <div style="margin-top: 8px; font-size: 11px; color: var(--text-secondary);">
                                    <em>Note: The existing evidence artifact in the table below has been identified and highlighted. No duplicate records or timeline events were created.</em>
                                </div>
                            </div>
                        `;
                    }

                    // Identify and visually highlight the existing evidence record in the UI table
                    highlightExistingEvidenceRow(data.sha256);

                    // Required notification
                    if (window.showToast) {
                        window.showToast("Duplicate evidence detected. This file has already been ingested.", "warning");
                    }

                    // Reset selection state
                    if (fileInput) fileInput.value = '';
                    selectedFile = null;

                } else {
                    if (diagnosticStatus) {
                        diagnosticStatus.innerText = 'Ingestion Error';
                        diagnosticStatus.className = 'pill badge-sev-critical';
                    }

                    if (diagnosticResults) {
                        diagnosticResults.innerHTML = `
                            <div style="background-color: var(--bg-surface-elevated); padding: 14px; border-radius: 4px; border-left: 4px solid var(--sev-critical);">
                                <strong style="color: var(--sev-critical); font-size: 13px;">Ingestion Validation Failed</strong>
                                <div style="margin-top: 6px; color: var(--text-primary); font-size: 12px;">
                                    ${escapeHtml(data.error || 'Failed to process evidence file.')}
                                </div>
                                ${data.sha256 ? `<div class="mono" style="margin-top: 6px; font-size: 11px; color: var(--accent-cyan);">SHA-256: ${escapeHtml(data.sha256)}</div>` : ''}
                            </div>
                        `;
                    }

                    if (window.showToast) {
                        window.showToast(data.error || "Evidence ingestion failed.", "error");
                    }
                }
            }
        } catch (err) {
            if (diagnosticStatus) {
                diagnosticStatus.innerText = 'Network Error';
                diagnosticStatus.className = 'pill badge-sev-critical';
            }
            if (diagnosticResults) {
                diagnosticResults.innerHTML = `
                    <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 4px solid var(--sev-critical);">
                        <strong style="color: var(--sev-critical);">Network Error</strong>
                        <div style="margin-top: 4px;">${escapeHtml(err.message)}</div>
                    </div>
                `;
            }
            if (window.showToast) {
                window.showToast("Network connection error: " + err.message, "error");
            }
        } finally {
            isProcessing = false;
            if (btnSubmit) {
                btnSubmit.disabled = !selectedFile;
                btnSubmit.innerHTML = `Verify & Ingest Evidence`;
            }
        }
    }

    // Expose handleVerifyAndIngest & highlightExistingEvidenceRow globally
    window.handleVerifyAndIngest = handleVerifyAndIngest;
    window.highlightExistingEvidenceRow = highlightExistingEvidenceRow;

    // Listeners
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0] ? e.target.files[0] : null;
            handleFileSelection(file);
        });
    }

    if (btnSubmit) {
        btnSubmit.addEventListener('click', (e) => {
            e.preventDefault();
            handleVerifyAndIngest(e);
        });
    }

    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            handleVerifyAndIngest(e);
        });
    }

    // Highlight specific evidence file if navigated from Evidence DNA
    const targetFile = new URLSearchParams(window.location.search).get('file');
    if (targetFile) {
        const rows = document.querySelectorAll('.dtm-table tbody tr');
        rows.forEach(r => {
            if (r.textContent.includes(targetFile)) {
                r.scrollIntoView({ behavior: 'smooth', block: 'center' });
                r.style.backgroundColor = 'rgba(6, 182, 212, 0.15)';
                r.style.outline = '2px solid var(--accent-cyan)';
            }
        });
    }
});

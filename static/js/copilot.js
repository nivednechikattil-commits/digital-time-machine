/**
 * Evidence-Grounded AI Investigation Copilot Client Logic
 * Provides conversational inquiry into digital forensics telemetry,
 * with server-side citation validation, rate limiting, and zero credential exposure.
 */

document.addEventListener("DOMContentLoaded", function () {
    const caseId = new URLSearchParams(window.location.search).get("case_id") || window.CURRENT_CASE_ID || "CASE-001";
    let chatHistory = [];
    let isSubmitting = false;
    let isProviderConfigured = null; // null = pending check, true = active, false = setup required

    // UI Elements
    const chatForm = document.getElementById("copilotChatForm");
    const questionInput = document.getElementById("copilotQuestionInput");
    const btnSend = document.getElementById("btnSendQuestion");
    const charCounter = document.getElementById("charCounter");
    const messagesContainer = document.getElementById("copilotMessagesContainer");
    const chatEmptyState = document.getElementById("chatEmptyState");
    const sessionMsgCountBadge = document.getElementById("sessionMsgCountBadge");
    const btnClearChat = document.getElementById("btnClearChat");
    const verifiedCitationsContainer = document.getElementById("verifiedCitationsContainer");
    const activeCitationsCountBadge = document.getElementById("activeCitationsCountBadge");
    const suggestedButtons = document.querySelectorAll(".btn-suggested-q");

    const providerStatusDot = document.getElementById("providerStatusDot");
    const providerStatusTitle = document.getElementById("providerStatusTitle");
    const providerStatusDesc = document.getElementById("providerStatusDesc");

    // Check provider status on load
    checkProviderStatus();

    // Textarea input handling (Auto-resize, character count, Enter vs Shift+Enter)
    if (questionInput) {
        // Auto-resize and character count
        questionInput.addEventListener("input", function () {
            // Auto-adjust height to content (min 40px, max 120px)
            this.style.height = "auto";
            this.style.height = Math.min(this.scrollHeight, 120) + "px";

            // Character counter
            const len = this.value.length;
            if (charCounter) {
                charCounter.textContent = `${len} / 500`;
                if (len >= 480) {
                    charCounter.style.color = "#EF4444";
                } else if (len >= 400) {
                    charCounter.style.color = "#F59E0B";
                } else {
                    charCounter.style.color = "var(--text-muted)";
                }
            }
        });

        // Keyboard handler: Enter submits, Shift+Enter inserts newline
        questionInput.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                if (e.shiftKey) {
                    // Shift+Enter -> allow default browser behavior (inserts newline)
                    return;
                }
                // Enter without Shift -> submit inquiry
                e.preventDefault();
                if (!isSubmitting) {
                    const q = questionInput.value.trim();
                    if (q) {
                        submitQuestion(q);
                    } else {
                        highlightEmptyInput();
                    }
                }
            }
        });
    }

    // Suggested question buttons
    suggestedButtons.forEach(btn => {
        btn.addEventListener("click", function () {
            const q = this.getAttribute("data-q");
            if (q && !isSubmitting) {
                if (questionInput) {
                    questionInput.value = q;
                    questionInput.dispatchEvent(new Event("input"));
                }
                submitQuestion(q);
            }
        });
    });

    // Clear chat button
    if (btnClearChat) {
        btnClearChat.addEventListener("click", function () {
            if (chatHistory.length === 0) return;
            if (confirm("Clear current session chat history? (This does not affect forensic database records)")) {
                chatHistory = [];
                messagesContainer.innerHTML = "";
                if (chatEmptyState) {
                    messagesContainer.appendChild(chatEmptyState);
                    chatEmptyState.style.display = "block";
                }
                updateMessageCount();
                resetCitationsPanel();
            }
        });
    }

    // Form submit handler (triggers when Send button is clicked or form submitted)
    if (chatForm) {
        chatForm.addEventListener("submit", function (e) {
            e.preventDefault();
            if (isSubmitting) return;
            const q = questionInput ? questionInput.value.trim() : "";
            if (!q) {
                highlightEmptyInput();
                return;
            }
            submitQuestion(q);
        });
    }

    // Visual feedback when attempting to send empty message
    function highlightEmptyInput() {
        if (!questionInput) return;
        questionInput.focus();
        questionInput.style.borderColor = "#EF4444";
        questionInput.style.boxShadow = "0 0 8px rgba(239, 68, 68, 0.4)";
        setTimeout(() => {
            questionInput.style.borderColor = "";
            questionInput.style.boxShadow = "";
        }, 1200);
        if (window.showToast) {
            window.showToast("Please enter a question before sending.", "info");
        }
    }

    // Fetch and sync provider status
    async function checkProviderStatus() {
        try {
            const res = await fetch("/api/copilot/status");
            if (!res.ok) return;
            const data = await res.json();
            isProviderConfigured = Boolean(data.configured);

            if (providerStatusDot && providerStatusTitle && providerStatusDesc) {
                if (data.configured) {
                    providerStatusDot.style.backgroundColor = "#10B981";
                    providerStatusDot.style.boxShadow = "0 0 6px #10B981";
                    providerStatusTitle.textContent = `Provider Active: ${(data.provider || 'OpenAI').toUpperCase()} (${data.model || 'gpt-4o-mini'})`;
                    providerStatusDesc.textContent = data.status_message || "Ready for evidence-grounded forensic inquiries.";
                } else {
                    providerStatusDot.style.backgroundColor = "#F59E0B";
                    providerStatusDot.style.boxShadow = "0 0 6px #F59E0B";
                    providerStatusTitle.textContent = "AI Provider Setup Required";
                    providerStatusDesc.textContent = data.status_message || "Set OPENAI_API_KEY environment variable on server.";
                }
            }
            return data;
        } catch (err) {
            console.warn("Unable to fetch Copilot provider status:", err);
            return null;
        }
    }

    // Main inquiry submission
    async function submitQuestion(questionText) {
        if (!questionText || isSubmitting) return;

        const trimmedQ = questionText.trim();
        if (trimmedQ.length < 3) {
            if (window.showToast) {
                window.showToast("Please enter a question with at least 3 characters.", "info");
            } else {
                alert("Please enter a question with at least 3 characters.");
            }
            if (questionInput) questionInput.focus();
            return;
        }

        if (trimmedQ.length > 500) {
            if (window.showToast) {
                window.showToast("Question cannot exceed 500 characters.", "error");
            } else {
                alert("Question cannot exceed 500 characters.");
            }
            return;
        }

        // Hide empty state if visible
        if (chatEmptyState && chatEmptyState.parentElement) {
            chatEmptyState.style.display = "none";
        }

        // 1. ALWAYS append user message to UI immediately (NEVER silently discard!)
        appendUserMessage(trimmedQ);
        chatHistory.push({ role: "user", content: trimmedQ });
        updateMessageCount();

        // 2. Clear input field and reset height
        if (questionInput) {
            questionInput.value = "";
            questionInput.style.height = "auto";
            questionInput.dispatchEvent(new Event("input"));
        }

        // 3. Check if provider is unconfigured before network request
        if (isProviderConfigured === false) {
            // Render clear configuration guidance in chat directly without sending doomed request
            appendUnconfiguredProviderMessage(trimmedQ);
            if (questionInput) questionInput.focus();
            scrollToBottom();
            return;
        }

        // 4. Provider is active or checking: show loading indicator
        isSubmitting = true;
        setFormEnabled(false);
        const loadingElem = appendLoadingIndicator();
        scrollToBottom();

        try {
            const response = await fetch("/api/copilot/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    question: trimmedQ,
                    case_id: caseId,
                    history: chatHistory.slice(-6)
                })
            });

            // Remove loading indicator
            if (loadingElem && loadingElem.parentElement) {
                loadingElem.parentElement.removeChild(loadingElem);
            }

            const data = await response.json();

            if (!response.ok) {
                if (response.status === 503) {
                    isProviderConfigured = false;
                }
                handleErrorResponse(response.status, data, trimmedQ);
                return;
            }

            // Success: render assistant answer
            isProviderConfigured = true;
            appendAssistantMessage(data.answer, data.citations || []);
            chatHistory.push({ role: "assistant", content: data.answer });
            updateMessageCount();

            // Update citations panel
            if (data.citations && data.citations.length > 0) {
                renderVerifiedCitations(data.citations);
            }

        } catch (netErr) {
            if (loadingElem && loadingElem.parentElement) {
                loadingElem.parentElement.removeChild(loadingElem);
            }
            appendErrorMessage(
                `Network error: Failed to connect to Copilot service. ${escapeHtml(netErr.message || "")}`,
                trimmedQ
            );
        } finally {
            isSubmitting = false;
            setFormEnabled(true);
            if (questionInput) questionInput.focus();
            scrollToBottom();
        }
    }

    // Handles API error status codes
    function handleErrorResponse(status, data, originalQuestion) {
        let title = "Copilot Request Failed";
        let detail = data.error || "An unexpected error occurred.";
        let retryable = true;

        switch (status) {
            case 503:
                appendUnconfiguredProviderMessage(originalQuestion, data.error, data.setup_help);
                return;
            case 429:
                title = "Rate Limit Exceeded (429)";
                detail = "Too many inquiries sent in a short window. Please wait a few seconds before asking another question.";
                break;
            case 504:
                title = "Gateway Timeout (504)";
                detail = "The AI service took too long to generate a grounded response. Telemetry context may be busy.";
                break;
            case 502:
                title = "AI Provider Error (502)";
                detail = `Upstream AI provider error: ${escapeHtml(data.error || "")}`;
                break;
            case 404:
                title = "Case Not Found (404)";
                detail = `The active investigation case '${escapeHtml(caseId)}' could not be located in the database.`;
                retryable = false;
                break;
            case 400:
                title = "Validation Error (400)";
                detail = escapeHtml(data.error || "Invalid question input.");
                retryable = false;
                break;
            default:
                detail = escapeHtml(data.error || "Internal server error occurred.");
        }

        appendErrorMessage(`${title}: ${detail}`, retryable ? originalQuestion : null);
    }

    // Render clear setup message when provider is unconfigured
    function appendUnconfiguredProviderMessage(originalQuestion, customError, customHelp) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const row = document.createElement("div");
        row.className = "chat-message-row assistant";
        row.innerHTML = `
            <div class="chat-avatar assistant" style="border-color: #F59E0B; color: #F59E0B; background: rgba(245, 158, 11, 0.15);" title="Configuration Required">
                ⚙️
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-start; max-width: 86%;">
                <div class="chat-bubble assistant" style="border-left: 3px solid #F59E0B;">
                    <div style="display: flex; align-items: center; gap: 6px; color: #F59E0B; font-weight: 700; font-size: 13px; margin-bottom: 6px;">
                        <span>AI Provider Setup Required</span>
                    </div>
                    <p style="color: var(--text-secondary); line-height: 1.5; font-size: 12px; margin-bottom: 10px;">
                        ${escapeHtml(customError || "The AI Investigation Copilot is not yet configured with an OpenAI API key on the server.")}
                    </p>
                    <div style="background: rgba(0, 0, 0, 0.35); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 10px 12px; font-size: 11px; margin-bottom: 10px;">
                        <strong style="color: var(--text-primary); display: block; margin-bottom: 4px;">Configuration Instructions:</strong>
                        <div style="color: var(--text-secondary); line-height: 1.6;">
                            1. Set the <code class="mono" style="color: var(--accent-emerald);">OPENAI_API_KEY</code> environment variable on your server:<br>
                            <code class="mono" style="display: block; background: #101113; padding: 4px 8px; border-radius: 4px; margin: 3px 0; color: #36E6B5;">export OPENAI_API_KEY="your-api-key-here"</code>
                            2. (Optional) Set model name (default: <code class="mono">gpt-4o-mini</code>):<br>
                            <code class="mono" style="display: block; background: #101113; padding: 4px 8px; border-radius: 4px; margin: 3px 0; color: #36E6B5;">export OPENAI_MODEL="gpt-4o-mini"</code>
                            3. Restart the Flask application.
                        </div>
                    </div>
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                        <button type="button" class="btn btn-outline btn-xs btn-recheck-provider" style="border-color: var(--accent-emerald); color: var(--accent-emerald);">
                            ↻ Re-check Status
                        </button>
                        ${originalQuestion ? `
                        <button type="button" class="btn btn-outline btn-xs btn-restore-q">
                            Restore Question to Input
                        </button>` : ''}
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted); line-height: 1.4; border-top: 1px solid var(--border-subtle); padding-top: 6px;">
                        ℹ️ <strong>Deterministic Forensic Modules Active:</strong> Rewindable Timeline, Evidence Explorer, Incident Graph, System State, Conclusion Stress Tester, and Investigation Time Machine remain fully operational without external AI APIs.
                    </div>
                </div>
                <span class="chat-time">${timeStr}</span>
            </div>
        `;

        // Recheck status button click handler
        const recheckBtn = row.querySelector(".btn-recheck-provider");
        if (recheckBtn) {
            recheckBtn.addEventListener("click", async function () {
                recheckBtn.disabled = true;
                recheckBtn.textContent = "Checking...";
                const status = await checkProviderStatus();
                if (status && status.configured) {
                    if (window.showToast) {
                        window.showToast("AI Provider is active and ready!", "success");
                    }
                    recheckBtn.textContent = "✓ Provider Active";
                    recheckBtn.style.color = "#10B981";
                    recheckBtn.style.borderColor = "#10B981";
                } else {
                    if (window.showToast) {
                        window.showToast("OPENAI_API_KEY still not detected in server environment.", "info");
                    }
                    recheckBtn.disabled = false;
                    recheckBtn.textContent = "↻ Re-check Status";
                }
            });
        }

        // Restore question button handler
        const restoreBtn = row.querySelector(".btn-restore-q");
        if (restoreBtn && questionInput && originalQuestion) {
            restoreBtn.addEventListener("click", function () {
                questionInput.value = originalQuestion;
                questionInput.dispatchEvent(new Event("input"));
                questionInput.focus();
                if (window.showToast) {
                    window.showToast("Question restored to input.", "info");
                }
            });
        }

        messagesContainer.appendChild(row);
        scrollToBottom();
    }

    // Render User Message
    function appendUserMessage(text) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const row = document.createElement("div");
        row.className = "chat-message-row user";
        row.innerHTML = `
            <div class="chat-avatar user" title="Investigator">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                </svg>
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-end; max-width: 82%;">
                <div class="chat-bubble user">
                    ${escapeHtml(text)}
                </div>
                <span class="chat-time">${timeStr}</span>
            </div>
        `;
        messagesContainer.appendChild(row);
    }

    // Render Assistant Message with interactive citation links
    function appendAssistantMessage(text, citations) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const formattedText = formatAnswerWithCitations(text, citations);

        const row = document.createElement("div");
        row.className = "chat-message-row assistant";
        row.innerHTML = `
            <div class="chat-avatar assistant" title="Forensic Copilot">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2a4 4 0 0 1 4 4v1a4 4 0 0 1-8 0V6a4 4 0 0 1 4-4z"></path>
                    <path d="M16 11v2a4 4 0 0 1-8 0v-2"></path>
                    <circle cx="9" cy="18" r="1"></circle>
                    <circle cx="15" cy="18" r="1"></circle>
                    <path d="M10 22h4"></path>
                </svg>
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-start; max-width: 82%;">
                <div class="chat-bubble assistant">
                    ${formattedText}
                </div>
                <div style="display: flex; gap: 8px; align-items: center; margin-top: 4px;">
                    <span class="chat-time">${timeStr}</span>
                    <span style="font-size: 10px; color: #10B981; font-weight: 600;">✓ Grounded</span>
                    ${citations && citations.length > 0 ? `<span style="font-size: 10px; color: var(--accent-emerald); font-family: var(--font-mono);">${citations.length} cited</span>` : ''}
                </div>
            </div>
        `;
        messagesContainer.appendChild(row);
    }

    // Render Error Message with optional retry
    function appendErrorMessage(htmlContent, retryQuestion) {
        const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const row = document.createElement("div");
        row.className = "chat-message-row assistant";

        let retryHtml = "";
        if (retryQuestion) {
            retryHtml = `
                <div style="margin-top: 8px; display: flex; gap: 8px;">
                    <button type="button" class="btn btn-outline btn-xs btn-retry-inquiry" style="border-color: #EF4444; color: #EF4444;">
                        ↻ Retry Question
                    </button>
                    <button type="button" class="btn btn-outline btn-xs btn-restore-failed-q">
                        Restore to Input
                    </button>
                </div>
            `;
        }

        row.innerHTML = `
            <div class="chat-avatar assistant" style="border-color: #EF4444; color: #EF4444; background: rgba(239, 68, 68, 0.15);" title="Error">
                ⚠️
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-start; max-width: 82%;">
                <div class="chat-bubble error">
                    ${htmlContent}
                    ${retryHtml}
                </div>
                <span class="chat-time">${timeStr}</span>
            </div>
        `;

        if (retryQuestion) {
            const retryBtn = row.querySelector(".btn-retry-inquiry");
            if (retryBtn) {
                retryBtn.addEventListener("click", function () {
                    submitQuestion(retryQuestion);
                });
            }
            const restoreBtn = row.querySelector(".btn-restore-failed-q");
            if (restoreBtn && questionInput) {
                restoreBtn.addEventListener("click", function () {
                    questionInput.value = retryQuestion;
                    questionInput.dispatchEvent(new Event("input"));
                    questionInput.focus();
                });
            }
        }

        messagesContainer.appendChild(row);
    }

    // Render Loading Typing Indicator
    function appendLoadingIndicator() {
        const row = document.createElement("div");
        row.className = "chat-message-row assistant";
        row.id = "copilotTypingRow";
        row.innerHTML = `
            <div class="chat-avatar assistant" title="Analyzing Telemetry...">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
            </div>
            <div class="chat-bubble assistant" style="padding: 10px 14px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="copilot-typing-indicator">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                    <span style="font-size: 11px; color: var(--text-muted);">Analyzing verified case telemetry...</span>
                </div>
            </div>
        `;
        messagesContainer.appendChild(row);
        return row;
    }

    // Format text: convert newlines to <br>, format markdown bold/code, replace verified citations with links
    function formatAnswerWithCitations(rawText, citations) {
        if (!rawText) return "";

        // Build citation map by ID
        const citMap = {};
        if (citations && citations.length > 0) {
            citations.forEach(c => {
                citMap[c.id] = c;
            });
        }

        // HTML escape first
        let html = escapeHtml(rawText);

        // Replace verified citations [EVT-xxx]
        html = html.replace(/\[(EVT-[A-Za-z0-9_\-]+)\]/g, function (match, evtId) {
            const cit = citMap[evtId];
            if (cit) {
                const titleTooltip = escapeHtml(`${cit.timestamp || ''} | ${cit.source || ''}: ${cit.description || ''}`);
                return `<a href="${cit.timeline_url}" class="citation-pill-inline" target="_blank" title="${titleTooltip}">🔍 ${evtId}</a>`;
            }
            // Fallback link if citation exists in case
            return `<a href="/timeline?case_id=${encodeURIComponent(caseId)}&event_id=${encodeURIComponent(evtId)}" class="citation-pill-inline" target="_blank" title="Inspect event ${evtId}">🔍 ${evtId}</a>`;
        });

        // Replace unverified citations [Unverified Ref: EVT-xxx]
        html = html.replace(/\[Unverified Ref: (EVT-[A-Za-z0-9_\-]+)\]/g, function (match, evtId) {
            return `<span class="citation-pill-unverified" title="Citation not found in active case telemetry">⚠️ Unverified: ${evtId}</span>`;
        });

        // Format basic markdown elements: bold and inline code
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/`([^`]+)`/g, '<code class="mono" style="background: rgba(255,255,255,0.06); padding: 1px 4px; border-radius: 3px;">$1</code>');

        // Convert double newlines to paragraph breaks, single newlines to <br>
        const paragraphs = html.split(/\n\s*\n/);
        return paragraphs.map(p => `<p style="margin-bottom: 8px;">${p.replace(/\n/g, '<br>')}</p>`).join("");
    }

    // Render verified citations in right panel
    function renderVerifiedCitations(citations) {
        if (!verifiedCitationsContainer) return;

        verifiedCitationsContainer.innerHTML = "";
        if (activeCitationsCountBadge) {
            activeCitationsCountBadge.textContent = `${citations.length} Citation${citations.length === 1 ? '' : 's'}`;
        }

        citations.forEach(c => {
            const card = document.createElement("div");
            card.className = "citation-card-item";
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: var(--accent-emerald); font-family: var(--font-mono); font-size: 11px;">
                        ${escapeHtml(c.id)}
                    </strong>
                    <span class="pill pill-observed" style="font-size: 9px; padding: 1px 5px;">
                        ${escapeHtml(c.source || 'telemetry')}
                    </span>
                </div>
                <div style="color: var(--text-secondary); font-size: 11px; line-height: 1.4;">
                    ${escapeHtml(c.description || '')}
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; font-size: 10px;">
                    <span style="color: var(--text-muted); font-family: var(--font-mono);">
                        ${escapeHtml(c.timestamp || '')}
                    </span>
                    <div style="display: flex; gap: 6px;">
                        <a href="${c.timeline_url}" class="btn btn-outline btn-xs" style="padding: 1px 6px; font-size: 10px;" target="_blank">
                            Timeline ↗
                        </a>
                        ${c.evidence_url ? `
                        <a href="${c.evidence_url}" class="btn btn-outline btn-xs" style="padding: 1px 6px; font-size: 10px;" target="_blank">
                            Evidence ↗
                        </a>` : ''}
                    </div>
                </div>
            `;
            verifiedCitationsContainer.appendChild(card);
        });
    }

    // Reset citations panel to default empty state
    function resetCitationsPanel() {
        if (verifiedCitationsContainer) {
            verifiedCitationsContainer.innerHTML = `
                <div style="font-size: 12px; color: var(--text-muted); text-align: center; padding: 20px;">
                    Citations generated by the Copilot will appear here with direct links to the Timeline and Evidence Explorer.
                </div>
            `;
        }
        if (activeCitationsCountBadge) {
            activeCitationsCountBadge.textContent = "0 Citations";
        }
    }

    // Updates message counter badge in chat card header
    function updateMessageCount() {
        if (sessionMsgCountBadge) {
            sessionMsgCountBadge.textContent = `${chatHistory.length} Message${chatHistory.length === 1 ? '' : 's'}`;
        }
    }

    // Toggle form controls during request
    function setFormEnabled(enabled) {
        if (questionInput) questionInput.disabled = !enabled;
        if (btnSend) btnSend.disabled = !enabled;
        suggestedButtons.forEach(btn => {
            btn.disabled = !enabled;
        });
    }

    // Scroll chat container to bottom
    function scrollToBottom() {
        if (messagesContainer) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    // HTML escape utility
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});

/**
 * DIGITAL TIME MACHINE — REWINDABLE TIMELINE LOGIC
 * Implements interactive temporal scrubbing, playback timer, filter rules,
 * and dynamic state reconstruction synchronization.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-2026-001';

    // DOM Elements
    const slider = document.getElementById('timelineSlider');
    const currentTimeReadout = document.getElementById('currentTimeReadout');
    const eventCounterReadout = document.getElementById('eventCounterReadout');
    const sliderStartTime = document.getElementById('sliderStartTime');
    const sliderEndTime = document.getElementById('sliderEndTime');
    const btnPlayPause = document.getElementById('btnPlayPause');
    const playText = document.getElementById('playText');
    const btnStepForward = document.getElementById('btnStepForward');
    const btnStepBack = document.getElementById('btnStepBack');
    const btnRestart = document.getElementById('btnRestart');
    const speedSelect = document.getElementById('speedSelect');
    const filterSource = document.getElementById('filterSource');
    const filterSeverity = document.getElementById('filterSeverity');
    const tableBody = document.getElementById('eventsTableBody');
    const visibleEventsCount = document.getElementById('visibleEventsCount');
    
    // Inspector elements
    const inspectorEventId = document.getElementById('inspectorEventId');
    const inspectorContent = document.getElementById('inspectorContent');
    const peekSessions = document.getElementById('peekSessions');
    const peekFiles = document.getElementById('peekFiles');
    const peekDevices = document.getElementById('peekDevices');
    const peekNet = document.getElementById('peekNet');

    // State Variables
    let allEvents = [];
    let currentIndex = 0;
    let isPlaying = false;
    let playbackTimer = null;
    let playbackIntervalMs = 1000;

    // Load initial events from backend
    async function loadEvents() {
        try {
            const res = await fetch(`/api/events?case_id=${encodeURIComponent(caseId)}`);
            const data = await res.json();
            allEvents = data.events || [];
            
            if (allEvents.length === 0) {
                tableBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No events found in this case.</td></tr>';
                return;
            }

            // Set slider bounds
            slider.min = 0;
            slider.max = allEvents.length - 1;
            slider.value = allEvents.length - 1;
            currentIndex = allEvents.length - 1;

            sliderStartTime.innerText = allEvents[0].timestamp.replace('T', ' ');
            sliderEndTime.innerText = allEvents[allEvents.length - 1].timestamp.replace('T', ' ');

            updateScrubber(currentIndex);
        } catch (e) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--sev-critical); padding: 30px;">Failed to load events: ${e.message}</td></tr>`;
        }
    }

    // Update scrubber position, visible feed, and sync system state
    function updateScrubber(targetIndex) {
        if (targetIndex < 0) targetIndex = 0;
        if (targetIndex >= allEvents.length) targetIndex = allEvents.length - 1;

        currentIndex = targetIndex;
        slider.value = currentIndex;

        const currentEv = allEvents[currentIndex];
        if (!currentEv) return;

        currentTimeReadout.innerText = currentEv.timestamp.replace('T', ' ');
        eventCounterReadout.innerText = `(${currentIndex + 1} of ${allEvents.length} events observed)`;

        // Render filtered events up to target timestamp (never show future events as observed!)
        renderEventsFeed();

        // Highlight inspector with current event
        inspectEvent(currentEv);

        // Fetch point-in-time system state peek
        fetchSystemStatePeek(currentEv.timestamp);
    }

    // Render event feed based on scrubber position and active filters
    function renderEventsFeed() {
        const currentTs = allEvents[currentIndex].timestamp;
        const srcFilter = filterSource.value;
        const sevFilter = filterSeverity.value;

        // Take only events up to current scrubber timestamp
        const candidateEvents = allEvents.slice(0, currentIndex + 1);

        const filtered = candidateEvents.filter(ev => {
            if (srcFilter !== 'all' && ev.source !== srcFilter) return false;
            if (sevFilter !== 'all') {
                if (sevFilter === 'critical' && ev.severity !== 'critical') return false;
                if (sevFilter === 'high' && !['high', 'critical'].includes(ev.severity)) return false;
                if (sevFilter === 'medium' && !['medium', 'high', 'critical'].includes(ev.severity)) return false;
            }
            return true;
        });

        visibleEventsCount.innerText = `Showing ${filtered.length} of ${currentIndex + 1} observed events`;

        if (filtered.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">No events match the selected filters at this point in time.</td></tr>';
            return;
        }

        let html = '';
        filtered.forEach((ev, idx) => {
            const isCurrent = (ev.id === allEvents[currentIndex].id);
            const rowClass = isCurrent ? 'style="background-color: rgba(6, 182, 212, 0.15); border-left: 3px solid var(--accent-cyan);"' : '';
            
            html += `
                <tr ${rowClass} class="event-row" data-id="${ev.id}" style="cursor: pointer;">
                    <td class="mono" style="color: var(--text-muted);">${idx + 1}</td>
                    <td class="mono" style="white-space: nowrap; font-size: 11px;">${ev.timestamp.replace('T', ' ')}</td>
                    <td style="text-transform: uppercase; font-size: 11px; font-weight: 600;">${ev.source}</td>
                    <td class="mono" style="color: var(--accent-blue); font-size: 11px;">${ev.event_type}</td>
                    <td>${ev.actor}</td>
                    <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${ev.object}">${ev.object}</td>
                    <td><span class="pill badge-sev-${ev.severity}">${ev.severity}</span></td>
                    <td><span class="pill pill-${ev.confidence}">${ev.confidence}</span></td>
                </tr>
            `;
        });

        tableBody.innerHTML = html;

        // Add click listener to rows
        document.querySelectorAll('.event-row').forEach(row => {
            row.addEventListener('click', () => {
                const evId = row.getAttribute('data-id');
                const target = allEvents.find(e => e.id === evId);
                if (target) inspectEvent(target);
            });
        });
    }

    // Inspect single event details
    function inspectEvent(ev) {
        inspectorEventId.innerText = ev.id;

        let detailsObj = {};
        try {
            detailsObj = (typeof ev.details === 'string') ? JSON.parse(ev.details) : (ev.details || {});
        } catch (e) {
            detailsObj = { raw: ev.details };
        }

        let detailsRows = '';
        for (const [k, v] of Object.entries(detailsObj)) {
            detailsRows += `<tr><td style="color: var(--text-muted); font-size: 11px;">${k}</td><td class="mono" style="font-size: 11px;">${JSON.stringify(v)}</td></tr>`;
        }

        inspectorContent.innerHTML = `
            <div style="background-color: var(--bg-surface-elevated); padding: 10px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <span class="pill badge-sev-${ev.severity}">${ev.severity.toUpperCase()}</span>
                    <span class="pill pill-${ev.confidence}">${ev.confidence.toUpperCase()}</span>
                </div>
                <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">${ev.description}</div>
                <div style="color: var(--text-secondary); font-size: 11px;">Source: <strong>${ev.source.toUpperCase()}</strong> | Ref: <span class="mono">${ev.evidence_ref}</span></div>
            </div>

            <div style="margin-top: 6px;">
                <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Artifact Details:</span>
                <table class="dtm-table" style="margin-top: 4px;">
                    <tbody>
                        <tr><td style="color: var(--text-muted); font-size: 11px;">Timestamp</td><td class="mono">${ev.timestamp}</td></tr>
                        <tr><td style="color: var(--text-muted); font-size: 11px;">Actor</td><td class="mono">${ev.actor}</td></tr>
                        <tr><td style="color: var(--text-muted); font-size: 11px;">Target Object</td><td class="mono" style="word-break: break-all;">${ev.object}</td></tr>
                        ${detailsRows}
                    </tbody>
                </table>
            </div>
        `;
    }

    // Fetch system state metrics for quick peek
    async function fetchSystemStatePeek(timestamp) {
        try {
            const res = await fetch(`/api/state?case_id=${encodeURIComponent(caseId)}&timestamp=${encodeURIComponent(timestamp)}`);
            const data = await res.json();
            const state = data.state || {};

            peekSessions.innerText = Object.keys(state.active_sessions || {}).length;
            peekFiles.innerText = Object.keys(state.file_system || {}).length;
            peekDevices.innerText = Object.values(state.connected_devices || {}).filter(d => d.is_connected).length;
            peekNet.innerText = Object.keys(state.network_connections || {}).length;
        } catch (e) {
            // Silently ignore minor state peek network glitches during rapid scrub
        }
    }

    // Playback Controller
    function startPlayback() {
        if (isPlaying) return;
        isPlaying = true;
        playText.innerText = 'Pause';
        
        // If at end, start from 0
        if (currentIndex >= allEvents.length - 1) {
            currentIndex = 0;
        }

        playbackTimer = setInterval(() => {
            if (currentIndex < allEvents.length - 1) {
                updateScrubber(currentIndex + 1);
            } else {
                stopPlayback();
            }
        }, playbackIntervalMs);
    }

    function stopPlayback() {
        if (!isPlaying) return;
        isPlaying = false;
        playText.innerText = 'Play';
        if (playbackTimer) {
            clearInterval(playbackTimer);
            playbackTimer = null;
        }
    }

    // Event Listeners
    slider.addEventListener('input', (e) => {
        stopPlayback();
        updateScrubber(parseInt(e.target.value, 10));
    });

    btnPlayPause.addEventListener('click', () => {
        if (isPlaying) stopPlayback();
        else startPlayback();
    });

    btnStepForward.addEventListener('click', () => {
        stopPlayback();
        updateScrubber(currentIndex + 1);
    });

    btnStepBack.addEventListener('click', () => {
        stopPlayback();
        updateScrubber(currentIndex - 1);
    });

    btnRestart.addEventListener('click', () => {
        stopPlayback();
        updateScrubber(0);
    });

    speedSelect.addEventListener('change', (e) => {
        playbackIntervalMs = parseInt(e.target.value, 10);
        if (isPlaying) {
            stopPlayback();
            startPlayback();
        }
    });

    filterSource.addEventListener('change', renderEventsFeed);
    filterSeverity.addEventListener('change', renderEventsFeed);

    // Initial load
    loadEvents();
});


/**
 * DIGITAL TIME MACHINE — SYSTEM STATE CONTROLLER
 * Fetches and renders historical system state at user-specified timestamps.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-2026-001';
    const timestampInput = document.getElementById('stateTimestampInput');
    const btnReconstruct = document.getElementById('btnReconstructState');

    // Stats
    const statEventsApplied = document.getElementById('statEventsApplied');
    const statEventsTotal = document.getElementById('statEventsTotal');

    // Tables
    const tableSessionsBody = document.getElementById('tableSessionsBody');
    const badgeActiveSessionsCount = document.getElementById('badgeActiveSessionsCount');

    const tableDevicesBody = document.getElementById('tableDevicesBody');
    const badgeConnectedDevicesCount = document.getElementById('badgeConnectedDevicesCount');

    const tableFilesBody = document.getElementById('tableFilesBody');
    const badgeFilesCount = document.getElementById('badgeFilesCount');

    const tableNetBody = document.getElementById('tableNetBody');
    const badgeNetCount = document.getElementById('badgeNetCount');

    const tableBrowserBody = document.getElementById('tableBrowserBody');
    const deltaEventsContainer = document.getElementById('deltaEventsContainer');

    async function loadSystemState(ts) {
        try {
            btnReconstruct.disabled = true;
            btnReconstruct.innerText = 'Calculating...';

            const res = await fetch(`/api/state?case_id=${encodeURIComponent(caseId)}&timestamp=${encodeURIComponent(ts)}`);
            const data = await res.json();
            const state = data.state || {};

            statEventsApplied.innerText = state.events_applied_count || 0;
            statEventsTotal.innerText = state.total_events_in_case || 0;

            // 1. Sessions
            const sessions = Object.entries(state.active_sessions || {});
            badgeActiveSessionsCount.innerText = `${sessions.length} Sessions`;
            if (sessions.length === 0) {
                tableSessionsBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active sessions identified at this timestamp.</td></tr>';
            } else {
                let html = '';
                sessions.forEach(([user, s]) => {
                    html += `
                        <tr>
                            <td class="mono" style="font-weight: 700; color: var(--accent-cyan);">${user}</td>
                            <td class="mono">${s.workstation}</td>
                            <td class="mono">${s.login_time.replace('T', ' ')}</td>
                            <td class="mono">${s.last_active.replace('T', ' ')}</td>
                            <td><span class="state-badge-active">${s.status}</span></td>
                        </tr>
                    `;
                });
                tableSessionsBody.innerHTML = html;
            }

            // 2. Removable Devices
            const devices = Object.values(state.connected_devices || {});
            const connectedDevices = devices.filter(d => d.is_connected);
            badgeConnectedDevicesCount.innerText = `${connectedDevices.length} Mounted`;
            if (devices.length === 0) {
                tableDevicesBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No removable storage connected at this timestamp.</td></tr>';
            } else {
                let html = '';
                devices.forEach(d => {
                    const statusClass = d.is_connected ? 'state-badge-active' : 'pill badge-sev-low';
                    const statusText = d.is_connected ? 'MOUNTED' : 'REMOVED';
                    html += `
                        <tr>
                            <td style="font-weight: 600;">${d.device_name}</td>
                            <td class="mono">${d.serial_number} (${d.mount_point || 'E:\\'})</td>
                            <td class="mono">${(d.connected_at || 'N/A').replace('T', ' ')}</td>
                            <td><span class="${statusClass}">${statusText}</span></td>
                            <td>${d.actor}</td>
                        </tr>
                    `;
                });
                tableDevicesBody.innerHTML = html;
            }

            // 3. Filesystem Activity
            const files = Object.values(state.file_system || {});
            badgeFilesCount.innerText = `${files.length} Files`;
            if (files.length === 0) {
                tableFilesBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No filesystem activity recorded yet.</td></tr>';
            } else {
                let html = '';
                files.forEach(f => {
                    const lastAction = f.history && f.history.length > 0 ? f.history[f.history.length - 1] : {};
                    html += `
                        <tr>
                            <td class="mono" style="word-break: break-all; font-size: 11px;">${f.file_path}</td>
                            <td><span class="pill pill-observed">${f.status}</span></td>
                            <td>${f.last_actor}</td>
                            <td class="mono" style="font-size: 11px;">${lastAction.timestamp ? lastAction.timestamp.replace('T', ' ') : 'N/A'}</td>
                        </tr>
                    `;
                });
                tableFilesBody.innerHTML = html;
            }

            // 4. Network Connections
            const netConns = Object.values(state.network_connections || {});
            badgeNetCount.innerText = `${netConns.length} Flows`;
            if (netConns.length === 0) {
                tableNetBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No network flows recorded.</td></tr>';
            } else {
                let html = '';
                netConns.forEach(n => {
                    const bytesFormatted = n.bytes_transferred > 1000000 
                        ? `${(n.bytes_transferred / 1000000).toFixed(1)} MB` 
                        : `${n.bytes_transferred} B`;
                    html += `
                        <tr>
                            <td class="mono" style="color: var(--accent-blue);">${n.destination}</td>
                            <td class="mono">${n.port}</td>
                            <td class="mono" style="font-weight: 700; color: ${n.bytes_transferred > 1000000 ? 'var(--sev-critical)' : 'inherit'};">${bytesFormatted}</td>
                            <td>${n.actor}</td>
                            <td class="mono">${n.timestamp.replace('T', ' ')}</td>
                        </tr>
                    `;
                });
                tableNetBody.innerHTML = html;
            }

            // 5. Browser History
            const browserList = state.browser_history || [];
            if (browserList.length === 0) {
                tableBrowserBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No browser navigation records.</td></tr>';
            } else {
                let html = '';
                browserList.forEach(b => {
                    html += `
                        <tr>
                            <td class="mono" style="font-size: 11px;">${b.timestamp.replace('T', ' ')}</td>
                            <td class="mono" style="color: var(--accent-cyan); word-break: break-all; font-size: 11px;">${b.url}</td>
                            <td>${b.actor}</td>
                        </tr>
                    `;
                });
                tableBrowserBody.innerHTML = html;
            }

            // 6. Delta Events at timestamp
            const delta = state.changes_at_point || [];
            if (delta.length === 0) {
                deltaEventsContainer.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 20px;">No specific events executed at this exact timestamp mark.</div>';
            } else {
                let html = '';
                delta.forEach(d => {
                    html += `
                        <div style="background-color: var(--bg-surface-elevated); padding: 8px 12px; border-radius: 4px; border-left: 3px solid var(--accent-cyan);">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                                <strong class="mono" style="color: var(--accent-blue);">${d.event_type}</strong>
                                <span class="pill badge-sev-${d.severity}">${d.severity}</span>
                            </div>
                            <div style="color: var(--text-primary); font-size: 12px;">${d.description}</div>
                            <div class="mono" style="color: var(--text-muted); font-size: 10px; margin-top: 4px;">Target: ${d.object} | Actor: ${d.actor}</div>
                        </div>
                    `;
                });
                deltaEventsContainer.innerHTML = html;
            }

        } catch (e) {
            window.showToast("Failed to reconstruct state: " + e.message, "error");
        } finally {
            btnReconstruct.disabled = false;
            btnReconstruct.innerText = 'Reconstruct State';
        }
    }

    btnReconstruct.addEventListener('click', () => {
        loadSystemState(timestampInput.value.trim());
    });

    // Initial load
    if (timestampInput.value.trim()) {
        loadSystemState(timestampInput.value.trim());
    }
});


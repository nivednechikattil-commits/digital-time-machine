/**
 * DIGITAL TIME MACHINE — INCIDENT RELATIONSHIP GRAPH
 * Renders SVG interactive entity graph connecting users, devices, files,
 * websites, and network flows with observed vs inferred relationship semantics.
 */

document.addEventListener('DOMContentLoaded', () => {
    const caseId = window.CURRENT_CASE_ID || 'CASE-2026-001';
    const svgEdgesLayer = document.getElementById('svgEdgesLayer');
    const svgNodesLayer = document.getElementById('svgNodesLayer');
    const graphEntityCounts = document.getElementById('graphEntityCounts');
    const graphSelectionBadge = document.getElementById('graphSelectionBadge');
    const graphInspectorBody = document.getElementById('graphInspectorBody');

    const nodeColors = {
        user: '#18D6A0',
        device: '#36E6B5',
        file: '#F59E0B',
        website: '#38BDF8',
        network: '#EF4444'
    };

    let graphData = { nodes: [], edges: [] };
    let nodePositions = {};

    async function loadGraph() {
        try {
            const res = await fetch(`/api/graph?case_id=${encodeURIComponent(caseId)}`);
            const data = await res.json();
            graphData = data.graph || { nodes: [], edges: [] };

            const c = graphData.counts || {};
            graphEntityCounts.innerText = `${c.total_nodes || 0} Entities | ${c.observed_edges || 0} Observed Links | ${c.inferred_edges || 0} Inferred Links`;

            calculateLayout();
            renderGraph();
        } catch (e) {
            graphEntityCounts.innerText = 'Failed to load graph: ' + e.message;
        }
    }

    // Assign aesthetically pleasing deterministic positions based on entity category
    function calculateLayout() {
        nodePositions = {};
        const width = 800;
        const height = 500;
        const cx = width / 2;
        const cy = height / 2;

        const nodes = graphData.nodes;
        const byType = {};
        nodes.forEach(n => {
            byType[n.type] = byType[n.type] || [];
            byType[n.type].push(n);
        });

        // Fixed / Radial sector distribution
        // Users on Left-Center
        (byType['user'] || []).forEach((n, idx, arr) => {
            const y = (height / (arr.length + 1)) * (idx + 1);
            nodePositions[n.id] = { x: 120, y: y };
        });

        // Workstations / Devices Top-Mid
        (byType['device'] || []).forEach((n, idx, arr) => {
            const x = 260 + idx * 160;
            const y = 80 + (idx % 2) * 50;
            nodePositions[n.id] = { x, y };
        });

        // Websites Upper-Right
        (byType['website'] || []).forEach((n, idx, arr) => {
            const x = 460 + idx * 120;
            const y = 140 + idx * 50;
            nodePositions[n.id] = { x: Math.min(x, 720), y };
        });

        // Files Center-Right
        (byType['file'] || []).forEach((n, idx, arr) => {
            const x = 440 + idx * 120;
            const y = 260 + (idx % 2) * 50;
            nodePositions[n.id] = { x: Math.min(x, 700), y };
        });

        // Network Lower-Right
        (byType['network'] || []).forEach((n, idx, arr) => {
            const x = 500 + idx * 140;
            const y = 400 + (idx % 2) * 40;
            nodePositions[n.id] = { x: Math.min(x, 730), y: Math.min(y, 460) };
        });

        // Any remaining node
        nodes.forEach((n, idx) => {
            if (!nodePositions[n.id]) {
                const angle = (idx / nodes.length) * 2 * Math.PI;
                nodePositions[n.id] = {
                    x: cx + 180 * Math.cos(angle),
                    y: cy + 140 * Math.sin(angle)
                };
            }
        });
    }

    function renderGraph() {
        svgEdgesLayer.innerHTML = '';
        svgNodesLayer.innerHTML = '';

        // 1. Draw Edges
        graphData.edges.forEach((edge, idx) => {
            const p1 = nodePositions[edge.source];
            const p2 = nodePositions[edge.target];
            if (!p1 || !p2) return;

            const isInferred = edge.relation_type === 'inferred';
            const marker = isInferred ? 'url(#arrowInferred)' : 'url(#arrowObserved)';

            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', p1.x);
            line.setAttribute('y1', p1.y);
            line.setAttribute('x2', p2.x);
            line.setAttribute('y2', p2.y);
            line.setAttribute('class', `svg-edge ${edge.relation_type}`);
            line.setAttribute('marker-end', marker);

            line.addEventListener('click', (e) => {
                e.stopPropagation();
                inspectEdge(edge);
            });

            svgEdgesLayer.appendChild(line);
        });

        // 2. Draw Nodes
        graphData.nodes.forEach((node) => {
            const p = nodePositions[node.id];
            if (!p) return;

            const color = nodeColors[node.type] || '#94A3B8';

            const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
            g.setAttribute('class', 'svg-node');
            g.setAttribute('transform', `translate(${p.x}, ${p.y})`);

            // Outer Circle
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('r', '16');
            circle.setAttribute('fill', '#0E1626');
            circle.setAttribute('stroke', color);
            circle.setAttribute('stroke-width', '2');

            // Text Label
            const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            text.setAttribute('y', '26');
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('fill', '#E2E8F0');
            text.setAttribute('font-size', '10px');
            text.setAttribute('font-family', 'ui-monospace, monospace');
            
            // Truncate long labels
            const shortLabel = node.label.length > 18 ? node.label.slice(0, 16) + '..' : node.label;
            text.textContent = shortLabel;

            g.appendChild(circle);
            g.appendChild(text);

            g.addEventListener('click', (e) => {
                e.stopPropagation();
                inspectNode(node);
            });

            svgNodesLayer.appendChild(g);
        });
    }

    function inspectNode(node) {
        graphSelectionBadge.innerText = node.type.toUpperCase();
        graphSelectionBadge.className = 'pill pill-observed';

        let eventsList = (node.associated_events || []).map(id => `<span class="mono" style="color: var(--accent-cyan); margin-right: 6px;">${id}</span>`).join('');

        let detailsRows = '';
        for (const [k, v] of Object.entries(node.details || {})) {
            detailsRows += `<tr><td style="color: var(--text-muted); font-size: 11px;">${k}</td><td class="mono" style="font-size: 11px;">${v}</td></tr>`;
        }

        graphInspectorBody.innerHTML = `
            <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 3px solid ${nodeColors[node.type]};">
                <span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Entity Label</span>
                <div class="mono" style="font-size: 14px; font-weight: 700; color: #FFFFFF; word-break: break-all; margin-top: 2px;">${node.label}</div>
                <div style="margin-top: 6px; font-size: 11px; color: var(--text-secondary);">Type: <strong>${node.type.toUpperCase()}</strong></div>
            </div>

            <div style="margin-top: 8px;">
                <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Attributes:</span>
                <table class="dtm-table" style="margin-top: 4px;">
                    <tbody>${detailsRows}</tbody>
                </table>
            </div>

            <div style="margin-top: 8px;">
                <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Associated Evidence (${node.evidence_count} Events):</span>
                <div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;">
                    ${eventsList || '<span style="color: var(--text-muted);">None</span>'}
                </div>
            </div>
        `;
    }

    function inspectEdge(edge) {
        const isInferred = edge.relation_type === 'inferred';
        graphSelectionBadge.innerText = isInferred ? 'INFERRED LINK' : 'OBSERVED LINK';
        graphSelectionBadge.className = `pill ${isInferred ? 'pill-inferred' : 'pill-observed'}`;

        graphInspectorBody.innerHTML = `
            <div style="background-color: var(--bg-surface-elevated); padding: 12px; border-radius: 4px; border-left: 3px solid ${isInferred ? 'var(--conf-inferred)' : 'var(--conf-observed)'};">
                <span style="font-size: 10px; color: var(--text-muted); text-transform: uppercase;">Relationship Action</span>
                <div class="mono" style="font-size: 13px; font-weight: 700; color: ${isInferred ? '#C084FC' : 'var(--accent-blue)'}; margin-top: 2px;">
                    ${edge.label}
                </div>
                <div style="margin-top: 6px; font-size: 11px; color: var(--text-secondary);">
                    Class: <strong>${isInferred ? 'Deduction / Inferred Rule' : 'Direct Recorded Log'}</strong>
                </div>
            </div>

            <div style="margin-top: 8px; font-size: 12px; line-height: 1.6; color: var(--text-primary);">
                <strong>Forensic Basis:</strong>
                <p style="color: var(--text-secondary); margin-top: 4px;">${edge.explanation}</p>
            </div>

            <div style="margin-top: 8px;">
                <span style="font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">Supporting Event Records:</span>
                <div style="margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px;">
                    ${(edge.supporting_event_ids || []).map(id => `<span class="mono" style="background: var(--bg-surface-elevated); padding: 3px 6px; border-radius: 3px; color: var(--accent-cyan); font-size: 11px;">${id}</span>`).join('')}
                </div>
            </div>
        `;
    }

    // Initial load
    loadGraph();
});


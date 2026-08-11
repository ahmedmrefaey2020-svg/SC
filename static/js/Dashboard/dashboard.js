const uiElements = {
    riskScore: document.getElementById('riskScore'),
    activeConn: document.getElementById('activeConn'),
    packetRate: document.getElementById('packetRate'),
    activityTable: document.getElementById('activityTable'),
    predictionAlert: document.getElementById('predictionAlert'),
};

let currentFlows = [];

function processDashboardData(data) {
    if (!data) return;

    if (uiElements.activeConn) {
        const activeConn = data.active_connections ?? data.connections ?? 0;
        uiElements.activeConn.innerText = Number(activeConn).toLocaleString();
    }
    if (uiElements.packetRate) {
        uiElements.packetRate.innerText = Number(data.packet_rate || 0).toLocaleString();
    }

    if (uiElements.riskScore) {
        const riskScore = data.risk_score ?? data.score ?? 0;
        const riskMessage = data.risk_message ?? data.message ?? 'System behavior is normal';
        
        uiElements.riskScore.innerHTML = `${riskScore}<span>%</span>`;
        uiElements.riskScore.className = `card-value ${riskScore > 70 ? 'risk-high' : 'risk-low'}`;
        if (uiElements.riskScore.nextElementSibling) {
            uiElements.riskScore.nextElementSibling.innerText = riskMessage;
        }
    }

    if (uiElements.predictionAlert) {
        const isAnomaly = Boolean(data.is_anomaly);
        uiElements.predictionAlert.classList.toggle('active', isAnomaly);
        
        if (isAnomaly) {
            const obs = data.agent_observation || {};
            const targetIp = obs.target_ip || (data.recent_flows?.find(f => f.status === 'anomaly')?.src) || '192.168.1.100';
            const targetPort = obs.target_port || 80;
            const protocol = obs.protocol || 'TCP';
            const attackType = obs.attack_type || 'Suspicious Intrusion Activity';
            const score = data.risk_score ?? data.score ?? 85;
            const isAuto = (data.block_mode === 'auto');

            const alertTitleEl = document.getElementById('alertTitle');
            const alertDetailsEl = document.getElementById('alertDetailsText');
            const alertButtonsEl = document.getElementById('alertButtons');
            const alertModeBadgeEl = document.getElementById('alertModeBadge');

            if (alertModeBadgeEl) {
                alertModeBadgeEl.textContent = isAuto ? ' AUTO-BLOCK ENFORCED' : ' MANUAL BLOCK REQUIRED';
                alertModeBadgeEl.style.background = isAuto ? '#991b1b' : 'rgba(239, 68, 68, 0.2)';
                alertModeBadgeEl.style.color = isAuto ? '#fffcfcfb' : '#f87171';
            }

            if (alertTitleEl) {
                alertTitleEl.textContent = `Attack Detected: ${attackType}`;
            }

            if (alertDetailsEl) {
                alertDetailsEl.innerHTML = `
                    <strong>Origin IP:</strong> <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px;color:#94a3b8;">${targetIp}</code> | 
                    <strong>Target Port:</strong> ${targetPort} (${protocol}) | 
                    <strong>Risk Score:</strong> <span style="color:#94a3b8;font-weight:700;">${score}%</span> | 
                    <strong>Threat Vector:</strong> ${attackType}
                `;
            }

            if (alertButtonsEl) {
                if (isAuto) {
                    alertButtonsEl.innerHTML = `<span style="color:#94a3b8;font-weight:600;font-size:0.9rem;">IP ${targetIp} auto-blocked by Sentinel AutoBlockAgent</span>`;
                } else {
                    alertButtonsEl.innerHTML = `
                        <button class="btn-action btn-block-ip" id="btnBlockIp" onclick="handleManualBlock('${targetIp}', '${attackType}')" style="background:#991b1b;color:#ffffff;border:none;padding:10px 18px;border-radius:8px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                            Block IP
                        </button>
                        <button class="btn-action btn-leave-ip" id="btnLeaveIp" onclick="handleManualLeave('${targetIp}')" style="background:rgba(255,255,255,0.1);color:#94a3b8;border:1px solid rgba(255,255,255,0.2);padding:10px 18px;border-radius:8px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:6px;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            Leave IP
                        </button>
                    `;
                }
            }
        }
    }

    // Requirement #9: Model vs Analysis Agent Consensus Comparison
    if (data.comparison) {
        const textEl = document.getElementById('consensusText');
        const badgeEl = document.getElementById('consensusBadge');
        if (textEl && badgeEl) {
            const matrix = data.comparison.comparison_matrix || {};
            const modelInfo = data.comparison.detection_model || {};
            const agentInfo = data.comparison.analyzing_agent || {};
            
            textEl.textContent = matrix.summary || `Model (${modelInfo.verdict}) vs Agent (${agentInfo.verdict})`;
            if (matrix.is_match) {
                if (modelInfo.verdict === 'Normal') {
                    badgeEl.textContent = 'MATCH — Clean Traffic';
                    badgeEl.style.background = 'rgba(16, 185, 129, 0.15)';
                    badgeEl.style.color = '#10b981';
                } else {
                    badgeEl.textContent = 'MATCH — Attack Confirmed!';
                    badgeEl.style.background = 'rgba(239, 68, 68, 0.15)';
                    badgeEl.style.color = '#991b1b';
                }
            } else {
                badgeEl.textContent = 'DIVERGENCE — Audit Required';
                badgeEl.style.background = 'rgba(245, 158, 11, 0.15)';
                badgeEl.style.color = '#f59e0b';
            }
        }
    }

    currentFlows = data.recent_flows || data.flows || data.traffic || data.network_flows || [];
    renderTable(currentFlows);
    
    if (typeof SentinelUI.updateMonitoringStatusBadge === 'function') {
        SentinelUI.updateMonitoringStatusBadge(
            data.monitoring_mode,
            data.is_fallback_active,
            data.user_api_token
        );
    }
}

async function handleManualBlock(ip, attackType) {
    if (!ip || ip === 'N/A') {
        alert('No valid IP address to block.');
        return;
    }
    try {
        const response = await fetch('/api/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip }),
        });
        const result = await response.json();
        alert(`${result.message || 'IP Blocked successfully'}`);
        if (uiElements.predictionAlert) {
            uiElements.predictionAlert.classList.remove('active');
        }
        fetchDashboardData();
    } catch (error) {
        console.error('Error blocking IP:', error);
        alert('Failed to block IP.');
    }
}

function handleManualLeave(ip) {
    if (confirm(`Are you sure you want to leave IP ${ip} unblocked and dismiss this threat warning?`)) {
        if (uiElements.predictionAlert) {
            uiElements.predictionAlert.classList.remove('active');
        }
    }
}

function renderTable(flows) {
    if (!uiElements.activityTable) return;
    uiElements.activityTable.innerHTML = '';

    if (!flows || flows.length === 0) {
        uiElements.activityTable.innerHTML = '<tr><td colspan="5" class="text-center" style="text-align: center; color: #888;">No active traffic</td></tr>';
        return;
    }

    flows.slice(0, 25).forEach((flow) => {
        const tr = document.createElement('tr');
        
        const timeVal = flow.time || flow.timestamp || 'Just now';
        const srcVal = flow.src || flow.source_ip || flow.src_ip || '127.0.0.1';
        const portVal = flow.port ?? flow.dest_port ?? flow.dst_port ?? '443';
        const protoVal = flow.proto || flow.protocol || 'TCP';
        
        const rawStatus = (flow.status || (flow.is_ioc ? 'anomaly' : 'normal')).toLowerCase();
        const isAnomaly = rawStatus === 'anomaly' || rawStatus === 'danger';
        const badgeClass = isAnomaly ? 'danger' : 'success';
        const badgeText = isAnomaly ? 'Anomaly' : 'Normal';

        tr.innerHTML = `
            <td>${timeVal}</td>
            <td>${srcVal}</td>
            <td>${portVal}</td>
            <td>${protoVal}</td>
            <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        `;
        uiElements.activityTable.appendChild(tr);
    });
}

async function fetchDashboardData() {
    try {
        const data = await SentinelUI.fetchDashboardData();
        processDashboardData(data);
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
    }
}

// Fetch initial data on page load
fetchDashboardData();

// Enable real-time WebSocket listening
SentinelUI.connectLiveSocket((data) => {
    processDashboardData(data);
});
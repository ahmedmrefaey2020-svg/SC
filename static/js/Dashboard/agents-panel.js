(function () {
    'use strict';

    function updateAgentPanel(data) {
        if (!data) return;
        const analysis = data.agent_analysis;
        const observation = data.agent_observation;

        const analyzerVerdict = document.getElementById('analyzerVerdict');
        const analyzerBody = document.getElementById('analyzerBody');
        const analyzerMeta = document.getElementById('analyzerMeta');
        const analyzerCard = document.getElementById('analyzerCard');
        const observationVerdict = document.getElementById('observationVerdict');
        const observationBody = document.getElementById('observationBody');
        const observationMeta = document.getElementById('observationMeta');
        const observationCard = document.getElementById('observationCard');
        const emailMeta = document.getElementById('emailMeta');

        if (analysis) {
            const isAttack = Boolean(analysis.is_attack);
            if (analyzerVerdict) {
                analyzerVerdict.textContent = analysis.status_title || (isAttack ? 'Attack Detected' : 'Normal Traffic');
                analyzerVerdict.className = 'agent-verdict ' + (isAttack ? 'verdict-attack' : 'verdict-normal');
            }
            if (analyzerBody) {
                analyzerBody.textContent = analysis.comparison || 'No analysis available.';
            }
            if (analyzerMeta) {
                analyzerMeta.textContent = [
                    analysis.model_used ? 'Model: ' + analysis.model_used.toUpperCase() : '',
                    analysis.confidence != null ? 'Confidence: ' + Number(analysis.confidence).toFixed(1) + '%' : '',
                    analysis.timestamp || ''
                ].filter(Boolean).join(' · ');
            }
            if (analyzerCard) {
                analyzerCard.classList.toggle('card-threat', isAttack);
                analyzerCard.classList.toggle('card-safe', !isAttack);
            }
        }

        if (observation) {
            const isActive = observation.attack_type && observation.attack_type !== 'None';
            if (observationVerdict) {
                observationVerdict.textContent = isActive ? (observation.attack_type || 'Threat Detected') : 'Clean';
                observationVerdict.className = 'agent-verdict ' + (isActive ? 'verdict-attack' : 'verdict-normal');
            }
            if (observationBody) {
                let bodyText = observation.observation || 'No active threat observed.';
                if (isActive && observation.firewall_rule && observation.firewall_rule !== 'N/A') {
                    bodyText += '\n\nRecommended Rule: ' + observation.firewall_rule;
                }
                observationBody.textContent = bodyText;
            }
            if (observationMeta) {
                observationMeta.textContent = [
                    isActive ? 'Severity: ' + (observation.severity || 'High') : '',
                    observation.target_ip && observation.target_ip !== 'N/A' ? 'Source IP: ' + observation.target_ip : '',
                    observation.timestamp || ''
                ].filter(Boolean).join(' · ');
            }
            if (observationCard) {
                observationCard.classList.toggle('card-threat', isActive);
                observationCard.classList.toggle('card-safe', !isActive);
            }
        }

        const autoblock = data.agent_autoblock;
        const autoblockVerdict = document.getElementById('autoblockVerdict');
        const autoblockBody = document.getElementById('autoblockBody');
        const autoblockMeta = document.getElementById('autoblockMeta');
        const autoblockCard = document.getElementById('autoblockCard');

        if (autoblock) {
            const isMitigated = autoblock.status === 'Auto-Mitigated';
            if (autoblockVerdict) {
                autoblockVerdict.textContent = autoblock.status || 'Active';
                autoblockVerdict.className = 'agent-verdict ' + (isMitigated ? 'verdict-attack' : 'verdict-normal');
            }
            if (autoblockBody) {
                // Show richer details for manual mode: include action buttons when in Manual mode
                const detailsText = autoblock.details || 'Auto-block active.';
                autoblockBody.textContent = detailsText;
                if ((data.block_mode || '').toLowerCase() === 'manual' && autoblock.target_ip && autoblock.target_ip !== 'N/A') {
                    const ip = autoblock.target_ip;
                    const actionsDiv = document.createElement('div');
                    actionsDiv.className = 'autoblock-actions';
                    actionsDiv.style.marginTop = '12px';
                    actionsDiv.innerHTML = `Actions: <button class="btn-deploy" onclick="deployCountermeasures('${ip}')">Deploy Countermeasures</button> <button class="btn-ignore" onclick="ignoreIp('${ip}')">Leave IP</button>`;
                    // append DOM node so buttons are interactive
                    if (!autoblockBody.querySelector) {
                        // in case autoblockBody is a text node wrapper, replace it with a container
                        const wrapper = document.createElement('div');
                        wrapper.textContent = detailsText;
                        wrapper.appendChild(actionsDiv);
                        autoblockBody.parentNode.replaceChild(wrapper, autoblockBody);
                    } else {
                        autoblockBody.appendChild(actionsDiv);
                    }
                }
            }
            if (autoblockMeta) {
                autoblockMeta.textContent = [
                    'Mode: ' + (data.auto_block ? 'Auto' : 'Manual'),
                    autoblock.target_ip && autoblock.target_ip !== 'N/A' ? 'Target: ' + autoblock.target_ip : '',
                    autoblock.timestamp || ''
                ].filter(Boolean).join(' · ');
            }
            if (autoblockCard) {
                autoblockCard.classList.toggle('card-threat', isMitigated);
                autoblockCard.classList.toggle('card-safe', !isMitigated);
            }
        }

        if (emailMeta) {
            const adminEmail = data.admin_email || '';
            emailMeta.textContent = adminEmail && adminEmail !== 'admin@network.local'
                ? 'Recipient: ' + adminEmail + ' · Interval: 30 min'
                : 'Configure admin email in Settings to enable.';
        }
    }

    async function initAgentPanel() {
        try {
            const resp = await fetch('/api/agents/status');
            if (!resp.ok) return;
            const status = await resp.json();

            const dashResp = await fetch('/api/dashboard-data');
            if (dashResp.ok) {
                const dashData = await dashResp.json();
                dashData.agent_analysis = status.analyzer;
                dashData.agent_observation = status.observation;
                updateAgentPanel(dashData);
            }
        } catch (_) {}
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = protocol + '//' + window.location.host + '/api/ws/live-traffic';
    let agentSocket = null;

    function connectAgentSocket() {
        agentSocket = new WebSocket(wsUrl);
        agentSocket.onmessage = function (event) {
            try {
                const data = JSON.parse(event.data);
                updateAgentPanel(data);
            } catch (_) {}
        };
        agentSocket.onclose = function () {
            agentSocket = null;
            setTimeout(connectAgentSocket, 5000);
        };
    }

    if (document.getElementById('multiAgentPanel')) {
        initAgentPanel();
        connectAgentSocket();
    }
})();

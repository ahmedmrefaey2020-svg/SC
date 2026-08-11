const SentinelUI = (() => {
    const badgeCss = `
.monitoring-status-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 14px;
    border-radius: 30px;
    font-size: 0.85rem;
    font-weight: 600;
    transition: all 0.3s ease;
    border: 1px solid rgba(255, 255, 255, 0.08);
}
.monitoring-status-badge .badge-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
}
.mode-scapy {
    background-color: rgba(59, 130, 246, 0.1);
    color: #60a5fa;
    border-color: rgba(59, 130, 246, 0.2);
}
.mode-scapy .badge-dot {
    background-color: #3b82f6;
    box-shadow: 0 0 8px #3b82f6;
}
.mode-agent {
    background-color: rgba(16, 185, 129, 0.1);
    color: #34d399;
    border-color: rgba(16, 185, 129, 0.2);
}
.mode-agent .badge-dot {
    background-color: #10b981;
    box-shadow: 0 0 8px #10b981;
}
.mode-fallback {
    background-color: rgba(245, 158, 11, 0.1);
    color: #fbbf24;
    border-color: rgba(245, 158, 11, 0.2);
    animation: alert-pulse 1.5s infinite;
}
.mode-fallback .badge-dot {
    background-color: #f59e0b;
    box-shadow: 0 0 8px #f59e0b;
}
@keyframes alert-pulse {
    0% { opacity: 0.8; }
    50% { opacity: 1; }
    100% { opacity: 0.8; }
}`;

    let cssReady = false;

    function ensureBadgeStyles() {
        if (cssReady) return;
        const style = document.createElement('style');
        style.textContent = badgeCss;
        document.head.appendChild(style);
        cssReady = true;
    }

    function updateMonitoringStatusBadge(mode, isFallback, tokenPreview) {
        ensureBadgeStyles();
        let badge = document.getElementById('monitoring-status-badge');
        if (!badge) {
            badge = document.createElement('div');
            badge.id = 'monitoring-status-badge';
            const header = document.querySelector('header');
            if (header) header.appendChild(badge);
            else return;
        }

        if (mode === 'scapy') {
            badge.className = 'monitoring-status-badge mode-scapy';
            badge.innerHTML = '<span class="badge-dot"></span> Scapy Sniffing Active';
            return;
        }

        if (isFallback) {
            badge.className = 'monitoring-status-badge mode-fallback';
            badge.innerHTML = '<span class="badge-dot"></span> Telemetry Agent Offline — Waiting for Site Data';
            return;
        }

        const preview = tokenPreview ? `${tokenPreview}...` : 'Configured';
        badge.className = 'monitoring-status-badge mode-agent';
        badge.innerHTML = `<span class="badge-dot"></span> Agent Active (${preview})`;
    }

    async function fetchDashboardData() {
        const response = await fetch('/api/dashboard-data');
        if (!response.ok) throw new Error(`Dashboard HTTP ${response.status}`);
        const data = await response.json();
        
        updateMonitoringStatusBadge(
            data.monitoring_mode, 
            data.is_fallback_active, 
            data.user_api_token
        );

        return data;
    }

    function connectLiveSocket(onData) {
        if (window.ws && window.ws.readyState === WebSocket.OPEN) {
            return window.ws;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/ws/live-traffic`;
        const socket = new WebSocket(wsUrl);
        
        window.ws = socket;

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.monitoring_mode) {
                    updateMonitoringStatusBadge(
                        data.monitoring_mode,
                        data.is_fallback_active,
                        data.user_api_token
                    );
                }

                if (typeof onData === 'function') {
                    onData(data);
                }
            } catch (err) {
                console.error("Error parsing WebSocket message:", err);
            }
        };

        socket.onerror = (err) => {
            console.error("WebSocket error:", err);
        };

        socket.onclose = () => {
            window.ws = null;
        
            setTimeout(() => {
                if (!window.ws) {
                    connectLiveSocket(onData);
                }
            }, 5000);
        };

        return socket;
    }

    function flowsFrom(data) {
        return data.recent_flows || data.network_flows || [];
    }

    /* ─── Scan Mode Switcher (used by Vulnerability Scanner page) ───
       Tracks whether the user is currently targeting a single file,
       a folder, or a Git repo URL, and reflects that visually on the
       "Choose File" / "Choose Folder" buttons and the repo input row.
       Safe to call even if those elements aren't present on the page. */
    let currentScanMode = 'file';

    function switchScanMode(mode) {
        const validModes = ['file', 'folder', 'repo'];
        if (!validModes.includes(mode)) mode = 'file';
        currentScanMode = mode;

        const fileBtn = document.querySelector('.btn-drop-action:not(.btn-folder)');
        const folderBtn = document.querySelector('.btn-drop-action.btn-folder');
        const repoWrap = document.getElementById('repoInputWrap');

        [fileBtn, folderBtn].forEach(btn => btn && btn.classList.remove('mode-active'));
        if (repoWrap) repoWrap.classList.remove('mode-active');

        if (mode === 'file' && fileBtn) fileBtn.classList.add('mode-active');
        else if (mode === 'folder' && folderBtn) folderBtn.classList.add('mode-active');
        else if (mode === 'repo' && repoWrap) repoWrap.classList.add('mode-active');

        return currentScanMode;
    }

    function getScanMode() {
        return currentScanMode;
    }

    return {
        updateMonitoringStatusBadge,
        fetchDashboardData,
        connectLiveSocket,
        flowsFrom,
        switchScanMode,
        getScanMode,
    };
})();

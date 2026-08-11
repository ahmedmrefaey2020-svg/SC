async function loadSettings() {
    try {
        const response = await fetch('/api/get-settings');
        if (!response.ok) throw new Error('HTTP ' + response.status);
        const data = await response.json();

        // 1. General Information
        if (document.getElementById('orgName')) document.getElementById('orgName').value = data.orgName || '';
        if (document.getElementById('adminEmail')) document.getElementById('adminEmail').value = data.adminEmail || '';
        if (document.getElementById('timezone')) document.getElementById('timezone').value = data.timezone || 'EST';
        
        // 2. Alert & Notification Preferences
        if (document.getElementById('pushToggle')) document.getElementById('pushToggle').checked = data.pushNotifications ?? true;
        if (document.getElementById('emailToggle')) document.getElementById('emailToggle').checked = data.emailAlerts ?? true;
        if (document.getElementById('reportInterval')) document.getElementById('reportInterval').value = data.reportInterval || 30;

        // 3. SMTP Gateway Config
        if (document.getElementById('smtpServer')) document.getElementById('smtpServer').value = data.smtpServer || '';
        if (document.getElementById('smtpPort')) document.getElementById('smtpPort').value = data.smtpPort || 587;
        if (document.getElementById('smtpUser')) document.getElementById('smtpUser').value = data.smtpUser || '';
        if (document.getElementById('smtpPass')) document.getElementById('smtpPass').value = data.smtpPass || '';

        // 4. Linked External Site
        if (document.getElementById('linkedSiteUrl')) document.getElementById('linkedSiteUrl').value = data.linkedSiteUrl || '';
        if (document.getElementById('linkedSiteToken')) document.getElementById('linkedSiteToken').value = data.linkedSiteToken || '';

        // 5. Threat Response Mode
        const blockMode = data.blockMode || (data.autoBlock ? 'auto' : 'manual');
        if (blockMode === 'manual') {
            const manualRadio = document.getElementById('blockModeManual');
            if (manualRadio) manualRadio.checked = true;
        } else {
            const autoRadio = document.getElementById('blockModeAuto');
            if (autoRadio) autoRadio.checked = true;
        }

        // 6. Telemetry Monitoring Mode & API Token
        if (document.getElementById('monitoringMode')) document.getElementById('monitoringMode').value = data.monitoringMode || 'scapy';
        if (document.getElementById('apiToken')) document.getElementById('apiToken').value = data.token || '';

        // 7. Detection Engine AI Model & Confidence
        if (document.getElementById('activeModel')) document.getElementById('activeModel').value = data.activeModel || 'lstm';
        
        const confidenceSlider = document.getElementById('confidenceSlider');
        if (confidenceSlider) {
            const confVal = data.confidence || 85;
            confidenceSlider.value = confVal;
            const thresholdValue = document.getElementById('thresholdValue');
            if (thresholdValue) thresholdValue.textContent = confVal + '%';
        }

        if (typeof SentinelUI !== 'undefined' && typeof SentinelUI.setTheme === 'function') {
            SentinelUI.setTheme(data.themeMode || 'dark');
        }
    } catch (err) {
        console.error('Failed to load settings:', err);
    }
}

async function saveSettings() {
    const orgName = document.getElementById('orgName')?.value || 'Sentinel IDS';
    const adminEmail = document.getElementById('adminEmail')?.value || 'admin@network.local';
    const timezone = document.getElementById('timezone')?.value || 'UTC';
    
    const pushNotifications = document.getElementById('pushToggle')?.checked ?? true;
    const emailAlerts = document.getElementById('emailToggle')?.checked ?? true;
    const reportInterval = parseInt(document.getElementById('reportInterval')?.value || '30', 10);

    const smtpServer = document.getElementById('smtpServer')?.value || '';
    const smtpPort = parseInt(document.getElementById('smtpPort')?.value || '587', 10);
    const smtpUser = document.getElementById('smtpUser')?.value || '';
    const smtpPass = document.getElementById('smtpPass')?.value || '';

    const linkedSiteUrl = document.getElementById('linkedSiteUrl')?.value || '';
    const linkedSiteToken = document.getElementById('linkedSiteToken')?.value || '';

    const blockMode = document.querySelector('input[name="blockMode"]:checked')?.value || 'auto';
    const autoBlock = (blockMode === 'auto');

    const monitoringMode = document.getElementById('monitoringMode')?.value || 'scapy';
    const token = document.getElementById('apiToken')?.value || '';

    const activeModel = document.getElementById('activeModel')?.value || 'lstm';
    const confidence = parseInt(document.getElementById('confidenceSlider')?.value || '85', 10);

    const payload = {
        orgName,
        adminEmail,
        timezone,
        pushNotifications,
        emailAlerts,
        reportInterval,
        smtpServer,
        smtpPort,
        smtpUser,
        smtpPass,
        smtpUseTls: true,
        linkedSiteUrl,
        linkedSiteToken,
        autoBlock,
        blockMode,
        monitoringMode,
        token,
        activeModel,
        confidence
    };

    try {
        const response = await fetch('/api/update-settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) throw new Error('HTTP ' + response.status);

        showToast('Settings successfully updated.', 'success');
    } catch (err) {
        console.error('Failed to save settings:', err);
        showToast('Failed to save settings.', 'error');
    }
}

async function testEmailDelivery() {
    showToast('Sending test email...', 'info');
    try {
        const res = await fetch('/api/send-test-email', { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.status === 'success') {
            showToast('Test Email sent successfully!', 'success');
        } else {
            showToast(data.message || 'Failed to send test email', 'error');
        }
    } catch (err) {
        showToast('SMTP Test Connection Error', 'error');
    }
}

function showToast(msg, type = 'info') {
    const toast = document.getElementById('toastBox');
    if (!toast) return;
    
    const span = toast.querySelector('span') || toast;
    span.textContent = msg;
    
    toast.className = `toast show`;
    setTimeout(() => {
        toast.className = 'toast';
    }, 3500);
}

// Bind events on page load
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();

    // Update confidence threshold label dynamically on slider drag
    const confidenceSlider = document.getElementById('confidenceSlider');
    const thresholdValue = document.getElementById('thresholdValue');
    if (confidenceSlider && thresholdValue) {
        confidenceSlider.addEventListener('input', (e) => {
            thresholdValue.textContent = e.target.value + '%';
        });
    }

    // Attach event listeners to action buttons
    const btnSave = document.getElementById('btnSave');
    if (btnSave) {
        btnSave.addEventListener('click', saveSettings);
    }

    const btnTestEmail = document.getElementById('btnTestEmail');
    if (btnTestEmail) {
        btnTestEmail.addEventListener('click', testEmailDelivery);
    }

    const btnCancel = document.getElementById('btnCancel');
    if (btnCancel) {
        btnCancel.addEventListener('click', () => {
            loadSettings(); // Reload initial configuration
            showToast('Changes discarded.', 'info');
        });
    }
});
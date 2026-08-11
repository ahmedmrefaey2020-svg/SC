'use strict';

function escapeHTML(str) {
    return (str || '').replace(/[&<>'"]/g, tag => (
        {'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[tag]
    ));
}

function showToast(msg, type = '') {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = `toast ${type} show`;
    setTimeout(() => { t.className = 'toast'; }, 3800);
}

async function runFullAudit() {
    showToast('Running full security audit — codebase + linked site...', 'info');
    const titleEl = document.getElementById('auditTitle');
    const subTitleEl = document.getElementById('auditSubtitle');
    const listEl = document.getElementById('auditList');

    if (titleEl) titleEl.textContent = 'Full Security Audit — Codebase & Linked Site';
    if (subTitleEl) subTitleEl.textContent = 'SiteSecurityAuditAgent scanning all files and external endpoints...';
    if (listEl) {
        listEl.innerHTML = `
            <div style="padding: 32px; text-align: center; color: #94a3b8;">
                <div style="width:32px;height:32px;border:3px solid #6366f1;border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 12px;"></div>
                Scanning codebase files and linked site...
            </div>`;
    }

    try {
        const res = await fetch('/api/agents/site-audit', { method: 'POST' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        renderFullAudit(data);
    } catch (e) {
        showToast('Failed to execute audit: ' + (e.message || ''), 'error');
        if (listEl) {
            listEl.innerHTML = `<div style="color: #ef4444; padding: 20px;">Audit failed. Check that the server is running.</div>`;
        }
    }
}

// Legacy aliases redirect to full audit
async function runInternalAudit() { return runFullAudit(); }
async function runLinkedSiteAudit() { return runFullAudit(); }

function renderFullAudit(data) {
    const listEl = document.getElementById('auditList');
    const sevRow = document.getElementById('auditSeverityRow');
    if (!listEl) return;
    listEl.innerHTML = '';

    const codebase = data.codebase_audit || {};
    const linked = data.linked_site_audit || null;
    const totalVulns = data.total_vulnerabilities || 0;

    // Summary banner
    const summaryBanner = document.createElement('div');
    summaryBanner.style.cssText = 'background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.3);border-radius:10px;padding:16px 20px;margin-bottom:20px;';
    summaryBanner.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
            <div>
                <div style="font-size:0.9rem;font-weight:600;color:#f8fafc;">Audit Complete — ${new Date().toLocaleString()}</div>
                <div style="font-size:0.8rem;color:#94a3b8;margin-top:4px;">
                    Files scanned: <strong style="color:#818cf8;">${codebase.files_scanned || 0}</strong> &nbsp;|&nbsp;
                    Total findings: <strong style="color:${totalVulns > 0 ? '#f59e0b' : '#10b981'};">${totalVulns}</strong>
                    ${linked ? ` &nbsp;|&nbsp; Linked site: <strong style="color:#818cf8;">${escapeHTML(linked.target_url || 'N/A')}</strong>` : ''}
                </div>
            </div>
            <div style="font-size:0.78rem;color:#64748b;">Results automatically included in periodic email report</div>
        </div>`;
    listEl.appendChild(summaryBanner);

    // Severity summary chips
    const allVulns = [
        ...(codebase.vulnerabilities || []),
        ...(linked ? (linked.vulnerabilities || []) : []),
    ];

    if (sevRow) {
        const counts = {};
        allVulns.forEach(v => {
            const s = (v.severity || 'info').toLowerCase();
            counts[s] = (counts[s] || 0) + 1;
        });
        const chipColors = {critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981', info: '#6366f1'};
        sevRow.innerHTML = Object.entries(counts)
            .map(([s, c]) => `<span class="sev-chip" style="color:${chipColors[s]||'#94a3b8'};border-color:${chipColors[s]||'#334155'};">● ${s.charAt(0).toUpperCase()+s.slice(1)} (${c})</span>`)
            .join('') || '<span class="sev-chip sev-info">● All Clean</span>';
    }

    // Render codebase section
    if (codebase.vulnerabilities && codebase.vulnerabilities.length > 0) {
        const h = document.createElement('h3');
        h.style.cssText = 'color:#818cf8;font-size:0.9rem;margin:8px 0;display:flex;align-items:center;gap:8px;';
        h.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg> Codebase Findings (${codebase.vulnerabilities.length})`;
        listEl.appendChild(h);
        codebase.vulnerabilities.forEach(v => listEl.appendChild(buildVulnCard(v)));
    }

    // Render linked site section
    if (linked) {
        const h2 = document.createElement('h3');
        h2.style.cssText = 'color:#818cf8;font-size:0.9rem;margin:16px 0 8px;display:flex;align-items:center;gap:8px;';
        h2.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> Linked Site: ${escapeHTML(linked.target_url || 'N/A')} (${(linked.vulnerabilities||[]).length})`;
        listEl.appendChild(h2);
        if (linked.status === 'Connection Error') {
            const errDiv = document.createElement('div');
            errDiv.style.cssText = 'color:#f87171;padding:12px;background:rgba(239,68,68,0.08);border-radius:8px;font-size:0.85rem;';
            errDiv.textContent = linked.summary || 'Connection failed';
            listEl.appendChild(errDiv);
        } else {
            (linked.vulnerabilities || []).forEach(v => listEl.appendChild(buildVulnCard(v)));
        }
    }

    if (allVulns.length === 0) {
        const ok = document.createElement('div');
        ok.style.cssText = 'color:#10b981;padding:20px;text-align:center;font-size:0.9rem;';
        ok.innerHTML = 'No vulnerabilities found. All security checks passed!';
        listEl.appendChild(ok);
    }
}

function buildVulnCard(v) {
    const card = document.createElement('div');
    card.style.cssText = 'background:#0f172a;border:1px solid #334155;border-radius:10px;padding:18px 22px;transition:border-color 0.2s;';
    card.addEventListener('mouseenter', () => card.style.borderColor = '#475569');
    card.addEventListener('mouseleave', () => card.style.borderColor = '#334155');

    const sev = (v.severity || 'Medium').toLowerCase();
    const colorMap = {critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981', info: '#6366f1'};
    const badgeColor = colorMap[sev] || '#94a3b8';

    card.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;gap:12px;">
            <h3 style="margin:0;font-size:0.95rem;color:#f8fafc;font-weight:600;">${escapeHTML(v.title || 'Finding')}</h3>
            <span style="flex-shrink:0;font-size:0.72rem;font-weight:600;padding:3px 10px;border-radius:12px;background:rgba(255,255,255,0.04);color:${badgeColor};border:1px solid ${badgeColor};">${v.severity || 'Medium'}</span>
        </div>
        ${v.file ? `<div style="font-size:0.78rem;color:#818cf8;margin-bottom:8px;font-family:'JetBrains Mono',monospace;background:rgba(99,102,241,0.06);padding:4px 8px;border-radius:4px;display:inline-block;">File: ${escapeHTML(v.file)}</div>` : ''}
        <div style="font-size:0.85rem;color:#cbd5e1;margin-bottom:6px;"><strong style="color:#e2e8f0;">Issue :</strong> ${escapeHTML(v.issue || '')}</div>
        <div style="font-size:0.85rem;color:#cbd5e1;margin-bottom:12px;"><strong style="color:#e2e8f0;">Solution :</strong> ${escapeHTML(v.solution || '')}</div>
        ${v.remediation_code ? `
            <div style="background:#1e293b;border:1px solid #334155;border-left:4px solid #38bdf8;border-radius:8px;padding:12px 14px;margin-top:10px;">
                <div style="font-size:0.75rem;color:#38bdf8;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:6px;">
                    Remediation Code Fix:
                </div>
                <pre style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;color:#e2e8f0;white-space:pre-wrap;margin:0;">${escapeHTML(v.remediation_code)}</pre>
            </div>` : ''}`;
    return card;
}


document.addEventListener('DOMContentLoaded', () => {
    if (!document.getElementById('spin-style')) {
        const s = document.createElement('style');
        s.id = 'spin-style';
        s.textContent = '@keyframes spin { to { transform:rotate(360deg); } }';
        document.head.appendChild(s);
    }
    const chipStyle = document.createElement('style');
    chipStyle.textContent = `.sev-chip { font-size:0.78rem;padding:3px 10px;border-radius:20px;border:1px solid;margin-right:6px; }`;
    document.head.appendChild(chipStyle);

    runFullAudit();
});

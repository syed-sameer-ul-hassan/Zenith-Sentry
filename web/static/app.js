

'use strict';

const API = '/api/v1';
let _allFindings = [];
let _refreshInterval = null;

function initNav() {
  const links = document.querySelectorAll('.nav-link');
  links.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const section = link.dataset.section;
      switchSection(section);
    });
  });

  const hash = window.location.hash.replace('#', '') || 'dashboard';
  switchSection(hash);
  window.addEventListener('hashchange', () => {
    const h = window.location.hash.replace('#', '') || 'dashboard';
    switchSection(h);
  });
}

function switchSection(name) {

  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  const target = document.getElementById(name);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.section === name);
  });

  if (name === 'dashboard') {
    loadDashboardData();
  } else if (name === 'findings') {
    loadFindings();
  } else if (name === 'defense') {
    loadScanHistory();
    loadConfig();
  } else if (name === 'system') {
    loadSystemData();
  }
}

async function apiFetch(path, opts = {}) {
  try {
    const res = await fetch(API + path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) }
    });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`HTTP ${res.status}: ${txt}`);
    }
    return await res.json();
  } catch (err) {
    console.error('[ZS API]', path, err);
    throw err;
  }
}

async function checkConnection() {
  const dot = document.getElementById('statusDot');
  const lbl = document.getElementById('statusLabel');
  try {
    await apiFetch('/system/info');
    dot.className = 'status-dot online';
    lbl.textContent = 'CONNECTED';
  } catch {
    dot.className = 'status-dot offline';
    lbl.textContent = 'OFFLINE';
  }
}

async function loadDashboardData() {
  await Promise.all([
    loadResourceStats(),
    loadNetworkData(),
    loadProcessData(),
    loadLatestScanScore(),
    loadEventStream()
  ]);
}

async function loadResourceStats() {
  try {
    const d = await apiFetch('/system/resources');
    const cpu = d.cpu?.percent ?? 0;
    const mem = d.memory?.percent ?? 0;
    const disk = d.disk?.percent ?? 0;
    const procs = await apiFetch('/system/processes?limit=1');

    setText('cpuValue', cpu.toFixed(1) + '%');
    setText('memValue', mem.toFixed(1) + '%');
    setText('diskValue', disk.toFixed(1) + '%');
    setText('procCount', procs.total ?? '—');

    setBar('cpuBar', cpu);
    setBar('memBar', mem);
    setBar('diskBar', disk);
  } catch (e) {
    ['cpuValue', 'memValue', 'diskValue', 'procCount'].forEach(id => setText(id, 'ERR'));
  }
}

async function loadLatestScanScore() {
  try {
    const scans = await apiFetch('/scans/');
    if (!scans.length) {
      setText('riskScore', '—');
      setText('riskLevel', 'NO SCAN');
      setText('findingsCount', '—');
      setText('lastScanTime', 'RUN A SCAN');
      return;
    }
    const latest = scans[0];
    const score = latest.summary?.risk_score ?? latest.score ?? 0;
    setText('riskScore', score);
    setText('riskLevel', riskLabel(score));
    setText('findingsCount', latest.findings?.length ?? latest.summary?.total ?? 0);
    setText('lastScanTime', 'SCAN: ' + (latest.start_time || latest.timestamp || '').replace('T', ' ').slice(0, 16));
    document.getElementById('riskScore').className = 'stat-value ' + scoreClass(score) + (score > 50 ? '' : ' cyan-glow');
  } catch {
    setText('riskScore', '—');
    setText('riskLevel', 'API ERROR');
  }
}

async function loadNetworkData() {
  try {
    const d = await apiFetch('/system/network');
    const conns = d.connections ?? [];
    setText('netTotal', d.total ?? conns.length);

    const countBy = status => conns.filter(c => c.status === status).length;
    setText('netEstab', countBy('ESTABLISHED'));
    setText('netListen', countBy('LISTEN'));
    setText('netTimeWait', countBy('TIME_WAIT'));

    const tbody = document.getElementById('networkBody');
    if (!conns.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">NO ACTIVE CONNECTIONS</td></tr>';
      return;
    }
    tbody.innerHTML = conns.slice(0, 60).map(c => `
      <tr>
        <td>${esc(c.laddr || '—')}</td>
        <td>${esc(c.raddr || '—')}</td>
        <td><span class="risk-badge ${statusClass(c.status)}">${esc(c.status || '—')}</span></td>
        <td>${c.pid || '—'}</td>
      </tr>
    `).join('');
  } catch (e) {
    document.getElementById('networkBody').innerHTML =
      '<tr><td colspan="4" class="loading-cell">FAILED TO LOAD — ' + esc(e.message) + '</td></tr>';
  }
}

async function loadProcessData() {
  try {
    const d = await apiFetch('/system/processes?limit=20');
    const procs = d.processes ?? [];
    const tbody = document.getElementById('processBody');
    if (!procs.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">NO PROCESSES</td></tr>';
      return;
    }
    tbody.innerHTML = procs.map(p => `
      <tr>
        <td>${p.pid}</td>
        <td style="color:#fff">${esc(p.name || '—')}</td>
        <td>${esc(p.username || '—')}</td>
        <td style="color:var(--text-muted)">${esc((p.cmdline || []).join(' ').slice(0, 60) || '—')}</td>
      </tr>
    `).join('');
  } catch (e) {
    document.getElementById('processBody').innerHTML =
      '<tr><td colspan="4" class="loading-cell">FAILED — ' + esc(e.message) + '</td></tr>';
  }
}

async function loadEventStream() {
  const log = document.getElementById('eventLog');
  try {
    const scans = await apiFetch('/scans/');
    const events = [];

    for (const scan of scans.slice(0, 5)) {
      const ts = (scan.start_time || scan.timestamp || '').replace('T', ' ').slice(11, 19) || '--:--:--';

      events.push({ time: ts, type: 'INFO', msg: `SCAN ${scan.scan_id?.slice(0, 8)?.toUpperCase() || 'COMPLETED'}`, data: `SCORE:${scan.summary?.risk_score ?? scan.score ?? '?'}` });

      (scan.findings || []).slice(0, 8).forEach(f => {
        events.push({ time: ts, type: f.risk?.toUpperCase() || 'INFO', msg: f.description?.slice(0, 60) || f.module?.toUpperCase() || '', data: f.tactic || '' });
      });
    }

    if (!events.length) {
      log.innerHTML = '<div class="event-row"><span class="evt-time">[READY]</span><span class="evt-type info">INFO</span><span class="evt-msg">NO EVENTS — EXECUTE A SCAN TO SEE LIVE STREAM</span></div>';
      return;
    }

    log.innerHTML = events.map(e => `
      <div class="event-row">
        <span class="evt-time">[${esc(e.time)}]</span>
        <span class="evt-type ${eventTypeClass(e.type)}">${esc(e.type.slice(0, 4))}</span>
        <span class="evt-msg">${esc(e.msg)}</span>
        <span class="evt-data">${esc(e.data)}</span>
      </div>
    `).join('');

    log.scrollTop = 0;
  } catch (e) {
    log.innerHTML = `<div class="event-row"><span class="evt-time">[ERR]</span><span class="evt-type crit">CRIT</span><span class="evt-msg">FAILED TO LOAD EVENTS: ${esc(e.message)}</span></div>`;
  }
}

async function loadFindings() {
  const tbody = document.getElementById('findingsBody');
  tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">LOADING FINDINGS...</td></tr>';
  try {
    const data = await apiFetch('/findings/');
    _allFindings = data.findings || data || [];
    renderFindings(_allFindings);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">API ERROR: ${esc(e.message)}</td></tr>`;
  }
}

function renderFindings(findings) {
  const tbody = document.getElementById('findingsBody');
  if (!findings.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">NO FINDINGS FOUND — RUN A SCAN FIRST</td></tr>';
    return;
  }
  tbody.innerHTML = findings.map(f => `
    <tr>
      <td><span class="risk-badge ${(f.risk || 'info').toLowerCase()}">${esc(f.risk || '—')}</span></td>
      <td style="color:#fff">${esc(f.module || '—')}</td>
      <td>${esc(f.tactic || '—')}</td>
      <td style="max-width:360px">${esc(f.description || '—')}</td>
      <td>${esc(f.severity || '—')}</td>
    </tr>
  `).join('');
}

function filterFindings() {
  const filter = document.getElementById('riskFilter').value;
  if (!filter) { renderFindings(_allFindings); return; }
  renderFindings(_allFindings.filter(f => (f.risk || '').toUpperCase() === filter));
}

async function loadScanHistory() {
  const tbody = document.getElementById('scanHistoryBody');
  tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">LOADING...</td></tr>';
  try {
    const scans = await apiFetch('/scans/');
    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">NO SCANS IN HISTORY</td></tr>';
      return;
    }
    tbody.innerHTML = scans.map(s => {
      const score = s.summary?.risk_score ?? s.score ?? 0;
      const ts = (s.start_time || s.timestamp || '—').replace('T', ' ').slice(0, 16);
      return `
        <tr>
          <td style="color:var(--text-muted);font-size:10px">${esc(s.scan_id?.slice(0, 12) || '—')}...</td>
          <td>${esc(ts)}</td>
          <td><span class="risk-badge ${scoreClass(score)}">${score}</span></td>
          <td>${s.findings?.length ?? s.summary?.total ?? 0}</td>
          <td><span class="risk-badge ${s.status === 'completed' ? 'low' : 'info'}">${esc(s.status || '—')}</span></td>
        </tr>
      `;
    }).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">ERROR: ${esc(e.message)}</td></tr>`;
  }
}

async function loadConfig() {
  try {
    const d = await apiFetch('/system/config');
    setText('cfgPorts', (d.network?.suspicious_ports || []).slice(0, 12).join(', ') + '...');
    setText('cfgDirs', (d.persistence?.scan_dirs || []).join(', ') || '—');
    setText('cfgBins', (d.ebpf?.critical_bins || []).join(', ') || '—');
    const mit = d.ebpf?.mitigation || {};
    setText('cfgMitigation', `SAFE:${mit.safe_mode ? 'ON' : 'OFF'} | KILL_PID:${mit.kill_pid ? 'ON' : 'OFF'} | BLOCK_IP:${mit.block_ip ? 'ON' : 'OFF'}`);
  } catch {
    ['cfgPorts', 'cfgDirs', 'cfgBins', 'cfgMitigation'].forEach(id => setText(id, 'CONFIG ENDPOINT UNAVAILABLE'));
  }
}

async function loadSystemData() {
  await Promise.all([loadSysInfo(), loadSysResources(), loadFullProcessList()]);
}

async function loadSysInfo() {
  try {
    const d = await apiFetch('/system/info');
    setText('sysOs', `${d.os?.system || '?'} ${d.os?.release || '?'}`);
    setText('sysKernel', d.kernel?.slice?.(0, 80) || '—');
    setText('sysHost', d.hostname || '—');
    setText('sysArch', d.architecture || '—');
    setText('sysCpu', d.os?.processor || '—');
    const res = await apiFetch('/system/resources');
    setText('sysCores', res.cpu?.count || '—');
  } catch (e) {
    ['sysOs', 'sysKernel', 'sysHost', 'sysArch', 'sysCpu', 'sysCores'].forEach(id => setText(id, 'UNAVAILABLE'));
  }
}

async function loadSysResources() {
  try {
    const d = await apiFetch('/system/resources');
    const cpu = d.cpu?.percent ?? 0;
    const mem = d.memory?.percent ?? 0;
    const disk = d.disk?.percent ?? 0;

    setText('sysCpuVal', cpu.toFixed(1) + '%');
    setText('sysRamVal', mem.toFixed(1) + '%');
    setText('sysDiskVal', disk.toFixed(1) + '%');
    setBar('sysCpuBar', cpu);
    setBar('sysRamBar', mem);
    setBar('sysDiskBar', disk);
  } catch { }
}

async function loadFullProcessList() {
  const tbody = document.getElementById('fullProcBody');
  tbody.innerHTML = '<tr><td colspan="3" class="loading-cell">LOADING...</td></tr>';
  try {
    const d = await apiFetch('/system/processes?limit=100');
    const procs = d.processes || [];
    if (!procs.length) { tbody.innerHTML = '<tr><td colspan="3" class="loading-cell">NO PROCESSES</td></tr>'; return; }
    tbody.innerHTML = procs.map(p => `
      <tr>
        <td>${p.pid}</td>
        <td style="color:#fff">${esc(p.name || '—')}</td>
        <td style="color:var(--text-muted)">${esc(p.username || '—')}</td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="3" class="loading-cell">ERROR: ${esc(e.message)}</td></tr>`;
  }
}

async function triggerScan(scanType) {
  const modal = document.getElementById('scanModal');
  const sub = document.getElementById('scanModalSub');
  const log = document.getElementById('scanModalLog');
  const btn = document.getElementById('runScanBtn');

  modal.removeAttribute('hidden');
  sub.textContent = `EXECUTING: ${scanType.toUpperCase()} SCAN...`;
  log.innerHTML = '';
  if (btn) btn.disabled = true;

  const logLine = msg => {
    const d = document.createElement('div');
    d.textContent = `[${new Date().toISOString().slice(11, 19)}] ${msg}`;
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
  };

  logLine('Initialising scan engine...');
  logLine(`Scan type: ${scanType}`);

  try {
    const result = await apiFetch('/scans/', {
      method: 'POST',
      body: JSON.stringify({ scan_type: scanType, json_output: true })
    });

    logLine(`Scan started — ID: ${result.scan_id}`);
    logLine('Collecting telemetry...');

    let attempts = 0;
    const maxAttempts = 60;
    while (attempts < maxAttempts) {
      await sleep(2000);
      attempts++;
      try {
        const status = await apiFetch('/scans/' + result.scan_id);
        logLine(`Status: ${status.status} | Findings: ${status.findings?.length ?? status.summary?.total ?? 0}`);
        if (status.status === 'completed' || status.status === 'failed') {
          if (status.status === 'completed') {
            logLine('SCAN COMPLETE.');
            showToast('SCAN COMPLETE — ' + (status.findings?.length ?? 0) + ' FINDINGS', 'success');
          } else {
            logLine('SCAN FAILED.');
            showToast('SCAN FAILED', 'error');
          }
          break;
        }
      } catch { logLine('Polling...'); }
    }

    modal.setAttribute('hidden', '');

    await loadDashboardData();
  } catch (e) {
    logLine('ERROR: ' + e.message);
    showToast('SCAN ERROR: ' + e.message, 'error');
    await sleep(2000);
    modal.setAttribute('hidden', '');
  } finally {
    if (btn) btn.disabled = false;
  }
}

let _toastTimer = null;
function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast show ' + type;
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { toast.className = 'toast'; }, 4000);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val ?? '—';
}

function setBar(id, pct) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.width = Math.min(pct, 100) + '%';
  el.className = 'stat-bar ' + (pct > 85 ? 'danger' : pct > 65 ? 'warn' : '');
}

function esc(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function riskLabel(score) {
  if (score >= 75) return 'CRITICAL RISK';
  if (score >= 50) return 'HIGH RISK';
  if (score >= 25) return 'MEDIUM RISK';
  if (score > 0) return 'LOW RISK';
  return 'CLEAN';
}

function scoreClass(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

function statusClass(status) {
  if (!status) return 'info';
  if (status === 'ESTABLISHED') return 'low';
  if (status === 'LISTEN') return 'info';
  if (status === 'TIME_WAIT') return 'medium';
  return 'info';
}

function eventTypeClass(type) {
  const t = (type || '').toUpperCase();
  if (t === 'CRITICAL' || t === 'CRIT') return 'crit';
  if (t === 'WARNING' || t === 'WARN' || t === 'HIGH') return 'warn';
  return 'info';
}

function initLockdown() {
  const m = document.getElementById('lockdownModule');
  if (!m) return;
  const trigger = async () => {
    if (!confirm('⚠ AUTHORIZE SYSTEM LOCKDOWN?\n\nThis will attempt to isolate all suspicious activity.\nThis action requires root privileges.')) return;
    showToast('LOCKDOWN SEQUENCE INITIATED...', 'warn');
    try {
      await apiFetch('/defense/lockdown', { method: 'POST' });
      showToast('LOCKDOWN PROTOCOL ACTIVE', 'error');
    } catch {
      showToast('LOCKDOWN UNAVAILABLE — CHECK SERVER PERMISSIONS', 'error');
    }
  };
  m.addEventListener('click', trigger);
  m.addEventListener('keypress', e => { if (e.key === 'Enter' || e.key === ' ') trigger(); });
}

document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initLockdown();
  checkConnection();

  _refreshInterval = setInterval(() => {
    const active = document.querySelector('.section.active')?.id;
    if (active === 'dashboard') loadResourceStats();
    checkConnection();
  }, 30000);
});

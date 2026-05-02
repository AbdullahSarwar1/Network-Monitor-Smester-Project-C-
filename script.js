// State
const API = 'http://localhost:8080';
let isCapturing = false;
let pollTimer = null;
let prevCount = 0;
let prevTime = Date.now();
let displayedPackets = [];

let activeFilter = { proto: 'ALL', src: '', dst: '' };

// Theme Management
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeIcon(newTheme);
  addLog('info', `Switched to ${newTheme} theme`);
}

function updateThemeIcon(theme) {
  const svg = document.getElementById('themeIcon');
  if (svg) {
    const moon = svg.querySelector('.moon');
    const suns = svg.querySelectorAll('.sun');
    if (theme === 'light') {
      moon.style.display = 'block';
      suns.forEach(s => s.style.display = 'none');
    } else {
      moon.style.display = 'none';
      suns.forEach(s => s.style.display = 'block');
    }
  }
}

// Init
window.addEventListener('DOMContentLoaded', () => {
  initTheme();
  loadDevices();
  addLog('info', 'Interface loaded. Backend: ' + API);
});

// Devices
async function loadDevices() {
  try {
    const res = await fetch(API + '/api/devices');
    const devs = await res.json();
    const sel = document.getElementById('deviceSelect');
    sel.innerHTML = '';
    if (!devs.length) {
      sel.innerHTML = '<option value="">No interfaces found</option>';
      addLog('warn', 'No network interfaces found. Run as Administrator!');
      return;
    }
    devs.forEach(d => {
      const opt = document.createElement('option');
      opt.value = d.name;
      opt.textContent = (d.desc || d.name).substring(0, 55);
      sel.appendChild(opt);
    });
    addLog('info', 'Found ' + devs.length + ' network interface(s)');
  } catch (e) {
    document.getElementById('deviceSelect').innerHTML =
      '<option value="">Backend offline (run network_monitor.exe)</option>';
    addLog('error', 'Cannot connect to backend. Is network_monitor.exe running?');
  }
}

// Start / Stop
async function startCapture() {
  const dev = document.getElementById('deviceSelect').value;
  if (!dev) { showNotif('Select a network interface first!', 'error'); return; }

  try {
    const res = await fetch(API + '/api/start?device=' + encodeURIComponent(dev));
    const data = await res.json();
    if (data.status === 'started' || data.status === 'already_running') {
      isCapturing = true;
      updateStatus(true);
      document.getElementById('btnStart').disabled = true;
      document.getElementById('btnStop').disabled = false;
      addLog('info', 'Capture started on: ' + dev.substring(0,40));
      showNotif('Monitoring started!', 'success');
      startPolling();
    }
  } catch (e) {
    showNotif('Failed to start. Is backend running as Admin?', 'error');
    addLog('error', 'Start failed: ' + e.message);
  }
}

async function stopCapture() {
  try {
    await fetch(API + '/api/stop');
    isCapturing = false;
    stopPolling();
    updateStatus(false);
    document.getElementById('btnStart').disabled = false;
    document.getElementById('btnStop').disabled = true;
    addLog('warn', 'Capture stopped. ' + displayedPackets.length + ' packets recorded.');
    showNotif('Monitoring stopped.', 'info');
  } catch (e) {
    addLog('error', 'Stop failed: ' + e.message);
  }
}

// Polling
function startPolling() {
  pollTimer = setInterval(async () => {
    await refreshPackets();
    await refreshStats();
  }, 1200);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

// Filter
function applyFilter() {
  activeFilter.proto = document.getElementById('filterProto').value;
  activeFilter.src = document.getElementById('filterSrc').value.trim();
  activeFilter.dst = document.getElementById('filterDst').value.trim();

  let parts = [];
  if (activeFilter.proto !== 'ALL') parts.push('Proto: ' + activeFilter.proto);
  if (activeFilter.src) parts.push('Src: ' + activeFilter.src);
  if (activeFilter.dst) parts.push('Dst: ' + activeFilter.dst);
  document.getElementById('filterInfo').textContent = parts.length ? '⊞ ' + parts.join(' | ') : '';

  addLog('info', 'Filter applied: ' + (parts.join(', ') || 'ALL'));
  refreshPackets();
}

function resetFilter() {
  document.getElementById('filterProto').value = 'ALL';
  document.getElementById('filterSrc').value = '';
  document.getElementById('filterDst').value = '';
  activeFilter = { proto: 'ALL', src: '', dst: '' };
  document.getElementById('filterInfo').textContent = '';
  addLog('info', 'Filter cleared.');
  refreshPackets();
}

// Data Refresh
async function refreshPackets() {
  try {
    let url = API + '/api/packets?proto=' + encodeURIComponent(activeFilter.proto)
      + '&src=' + encodeURIComponent(activeFilter.src)
      + '&dst=' + encodeURIComponent(activeFilter.dst);
    const res = await fetch(url);
    const pkts = await res.json();
    displayedPackets = pkts;
    renderTable(pkts);
    document.getElementById('headerCount').textContent = 'PKTS: ' + pkts.length;
  } catch (e) {
    addLog('error', 'Failed to refresh packets: ' + e.message);
  }
}

async function refreshStats() {
  try {
    const res = await fetch(API + '/api/stats');
    const s = await res.json();
    document.getElementById('statTotal').textContent = fmt(s.total);
    document.getElementById('statAvg').textContent = fmtB(s.avg_size);
    document.getElementById('statBytes').textContent = fmtKB(s.total_bytes);

    const now = Date.now();
    const dt = (now - prevTime) / 1000;
    const rate = dt > 0 ? Math.round((s.total - prevCount) / dt) : 0;
    document.getElementById('statRate').textContent = Math.max(0, rate);
    prevCount = s.total;
    prevTime = now;

    const total = s.total || 1;
    const protos = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0, ...s.proto };
    ['TCP','UDP','ICMP','OTHER'].forEach(p => {
      const cnt = protos[p] || 0;
      document.getElementById('bar' + p).style.width = Math.round(cnt/total*100) + '%';
      document.getElementById('cnt' + p).textContent = cnt;
    });
  } catch (e) {
    addLog('error', 'Failed to refresh stats: ' + e.message);
  }
}

// Table Render
function renderTable(pkts) {
  const tbody = document.getElementById('packetTable');
  if (!pkts.length) {
    tbody.innerHTML = '<tr><td colspan="9"><div class="empty-state"><span class="empty-state-icon">◉</span><span class="empty-state-text">' +
      (isCapturing ? 'Waiting for packets...' : 'No packets captured yet') + '</span></div></td></tr>';
    document.getElementById('rowCount').textContent = '0 packets displayed';
    return;
  }

  const display = pkts.slice(-500).reverse();
  let html = '';
  display.forEach((p, i) => {
    const svcClass = (p.service === 'Unknown' || p.service === '-') ? 'unknown' : '';
    // Handle port display: 0 is valid for ICMP, null/undefined shows '-'
    const srcPort = p.src_port !== null && p.src_port !== undefined ? p.src_port : '-';
    const dstPort = p.dst_port !== null && p.dst_port !== undefined ? p.dst_port : '-';
    html += `<tr>
      <td style="color:var(--text-muted)">${pkts.length - i}</td>
      <td>${p.time}</td>
      <td>${p.src_ip}</td>
      <td style="color:var(--text-muted)">${srcPort}</td>
      <td>${p.dst_ip}</td>
      <td style="color:var(--text-muted)">${dstPort}</td>
      <td><span class="badge badge-${p.protocol.toLowerCase()}">${p.protocol}</span></td>
      <td style="color:var(--text-primary)">${p.size}</td>
      <td><span class="service-tag ${svcClass}">${p.service}</span></td>
    </tr>`;
  });
  tbody.innerHTML = html;
  document.getElementById('rowCount').textContent = pkts.length + ' packets displayed';
}

// Export - downloads file directly to browser
async function exportCSV() {
  try {
    const res = await fetch(API + '/api/export');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'capture_log.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    showNotif('CSV downloaded successfully', 'success');
    addLog('info', 'Exported ' + displayedPackets.length + ' records to CSV');
  } catch (e) {
    showNotif('Export failed - check backend is running', 'error');
  }
}

// CSV Upload
function handleCSVUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const text = e.target.result;
      const lines = text.split('\n').filter(line => line.trim());
      
      if (lines.length < 2) {
        showNotif('CSV file is empty or invalid', 'error');
        return;
      }

      const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
      const packets = [];

      for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',').map(v => v.trim());
        if (values.length < 8) continue;

        const packet = {
          time: values[0] || '-',
          src_ip: values[1] || '-',
          dst_ip: values[2] || '-',
          protocol: values[3] || 'OTHER',
          size: parseInt(values[4]) || 0,
          src_port: values[5] || '-',
          dst_port: values[6] || '-',
          service: values[7] || 'Unknown'
        };
        packets.push(packet);
      }

      displayedPackets = packets;
      renderTable(packets);
      
      document.getElementById('headerCount').textContent = 'PKTS: ' + packets.length;
      document.getElementById('statTotal').textContent = packets.length;
      
      let totalBytes = packets.reduce((sum, p) => sum + p.size, 0);
      document.getElementById('statAvg').textContent = packets.length > 0 ? Math.round(totalBytes / packets.length) + ' B' : '0 B';
      document.getElementById('statBytes').textContent = (totalBytes / 1024).toFixed(1) + ' KB';

      const protoCounts = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
      packets.forEach(p => {
        const proto = p.protocol.toUpperCase();
        if (protoCounts.hasOwnProperty(proto)) {
          protoCounts[proto]++;
        } else {
          protoCounts.OTHER++;
        }
      });

      const total = packets.length || 1;
      ['TCP', 'UDP', 'ICMP', 'OTHER'].forEach(p => {
        const cnt = protoCounts[p] || 0;
        document.getElementById('bar' + p).style.width = Math.round(cnt / total * 100) + '%';
        document.getElementById('cnt' + p).textContent = cnt;
      });

      addLog('info', 'Imported ' + packets.length + ' packets from CSV');
      showNotif('CSV imported successfully: ' + packets.length + ' packets', 'success');
    } catch (err) {
      showNotif('Failed to parse CSV file', 'error');
      addLog('error', 'CSV import failed: ' + err.message);
    }
  };
  reader.readAsText(file);
  event.target.value = '';
}

// UI Helpers
function updateStatus(active) {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.className = 'status-dot' + (active ? ' active' : '');
  text.textContent = active ? 'CAPTURING' : 'IDLE';
}

function addLog(type, msg) {
  const log = document.getElementById('logArea');
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  const t = new Date().toTimeString().slice(0,8);
  entry.innerHTML = `<span class="log-time">[${t}]</span><span class="log-msg log-${type}">${msg}</span>`;
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;
}

function showNotif(msg, type = 'info') {
  const notifArea = document.getElementById('notification');
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  const icons = { success: '✓', error: '✕', info: 'ℹ' };
  el.innerHTML = `<span class="toast-icon">${icons[type]}</span><span>${msg}</span>`;
  notifArea.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function fmt(n) { return Number(n).toLocaleString(); }
function fmtB(n) { return Math.round(n) + ' B'; }
function fmtKB(n) { return (n / 1024).toFixed(1) + ' KB'; }

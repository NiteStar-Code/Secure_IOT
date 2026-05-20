// ══════════════════════════════════════════
//  STATE
// ══════════════════════════════════════════
const S = {
  step: 1, totalSteps: 5,
  encryption: null,  // 'AES' | 'XTEA'
  protocol:   null,  // 'MQTTS' | 'HTTPS' | 'ESPNOW'
  role:       null,  // 'SENDER' | 'RECEIVER'
  keyHex: '',
  keyBytes: null,
  code: '',
  cfg: { ssid:'', password:'', serverIp:'', caCert:'', mac:'' }
};

// ══════════════════════════════════════════
//  KEY GENERATION
// ══════════════════════════════════════════
function genKey() {
  const len = S.encryption === 'XTEA' ? 16 : 32;
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  S.keyBytes = arr;
  S.keyHex = Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
  const d = document.getElementById('keyDisplay');
  const i = document.getElementById('keyInfo');
  if (d) { d.textContent = S.keyHex; }
  if (i) { i.textContent = `${S.encryption === 'XTEA' ? 'XTEA-128 · 16 bytes' : 'AES-256 · 32 bytes'} · Share with both devices · Keep secret`; }
}

function regenKey() {
  genKey();
  const btn = document.getElementById('copyKeyBtn');
  if (btn) { btn.textContent = '⧉ Copy Key'; btn.classList.remove('copied'); }
}

function keyToC() {
  const hex = Array.from(S.keyBytes).map(b => '0x' + b.toString(16).padStart(2,'0').toUpperCase());
  const rows = [];
  for (let i = 0; i < hex.length; i += 8) rows.push('    ' + hex.slice(i, i+8).join(', '));
  return '{\n' + rows.join(',\n') + '\n}';
}

function macToC(mac) {
  const raw = (mac || '').replace(/[^0-9A-Fa-f]/g, '');
  if (raw.length !== 12) return '{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}';
  return '{0x' + raw.match(/.{2}/g).join(', 0x').toUpperCase() + '}';
}

function caToC(pem) {
  if (!pem.trim()) {
    return '"-----BEGIN CERTIFICATE-----\\n" \\\n"PASTE_YOUR_CA_CERT_HERE\\n" \\\n"-----END CERTIFICATE-----\\n"';
  }
  const lines = pem.trim().split('\n');
  return lines.map((l, i) => `"${l.trim()}\\n"` + (i < lines.length - 1 ? ' \\' : '')).join('\n');
}

// ══════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════
function pick(field, value, el) {
  S[field] = value;
  el.closest('.card-grid').querySelectorAll('.opt-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
}

function goNext() {
  const cur = S.step;
  if (cur === 1 && !S.encryption) { flashMsg('Please select an encryption algorithm.', true); return; }
  if (cur === 2 && !S.protocol)   { flashMsg('Please select a communication protocol.', true); return; }
  if (cur === 3 && !S.role)       { flashMsg('Please select a device role.', true); return; }
  clearMsg();
  if (cur === 2) buildRoleStep();
  if (cur === 3) { buildConfigForm(); genKey(); }
  S.step++;
  render();
}

function goPrev() { S.step--; render(); }

function startOver() {
  S.step = 1; S.encryption = null; S.protocol = null; S.role = null;
  S.cfg = { ssid:'', password:'', serverIp:'', caCert:'', mac:'' };
  document.querySelectorAll('.opt-card').forEach(c => c.classList.remove('selected'));
  render();
}

function render() {
  document.querySelectorAll('.step').forEach((el, i) => el.classList.toggle('active', i + 1 === S.step));
  buildProgress();
}

function flashMsg(msg, isErr) {
  const a = document.getElementById('alertBox');
  if (!a) { alert(msg); return; }
  a.className = 'alert show ' + (isErr ? 'alert-err' : 'alert-info');
  a.textContent = msg;
}
function clearMsg() {
  const a = document.getElementById('alertBox');
  if (a) a.classList.remove('show');
}

// ══════════════════════════════════════════
//  PROGRESS BAR
// ══════════════════════════════════════════
function buildProgress() {
  const labels = ['Encryption','Protocol','Role','Configure','Download'];
  document.getElementById('progressBar').innerHTML = labels.map((lbl, i) => {
    const n = i + 1;
    const cls = n < S.step ? 'done' : n === S.step ? 'active' : '';
    const icon = n < S.step ? '✓' : n;
    return (i > 0 ? `<div class="prog-line ${n <= S.step ? 'done' : ''}"></div>` : '') +
      `<div class="prog-step">
        <div class="prog-circle ${cls}">${icon}</div>
        <div class="prog-label ${cls}">${lbl}</div>
      </div>`;
  }).join('');
}

// ══════════════════════════════════════════
//  ROLE STEP
// ══════════════════════════════════════════
function buildRoleStep() {
  S.role = null;
  const roles = {
    MQTTS: [
      { id:'SENDER',   icon:'📤', name:'Publisher',  desc:'Encrypts data and publishes to an MQTT topic through the broker.' },
      { id:'RECEIVER', icon:'📥', name:'Subscriber', desc:'Subscribes to an MQTT topic, receives packets, and decrypts them.' }
    ],
    HTTPS: [
      { id:'SENDER',   icon:'📤', name:'Client / Sender',   desc:'Encrypts payload and sends an HTTPS POST to a server endpoint.' },
      { id:'RECEIVER', icon:'🖥',  name:'Server / Receiver', desc:'Runs a lightweight HTTP server on the ESP32, receives and decrypts.' }
    ],
    ESPNOW: [
      { id:'SENDER',   icon:'📡', name:'Sender',   desc:'Encrypts data and transmits to the peer via ESP-Now. Needs peer MAC.' },
      { id:'RECEIVER', icon:'📻', name:'Receiver', desc:'Listens for ESP-Now packets and decrypts them in the receive callback.' }
    ]
  };
  document.getElementById('roleCards').innerHTML = roles[S.protocol].map(r => `
    <div class="opt-card" onclick="pick('role','${r.id}',this)">
      <div class="card-check">✓</div>
      <span class="card-icon">${r.icon}</span>
      <div class="card-name">${r.name}</div>
      <div class="card-desc">${r.desc}</div>
    </div>`).join('');
}

// ══════════════════════════════════════════
//  CONFIG FORM
// ══════════════════════════════════════════
function buildConfigForm() {
  const p = S.protocol, r = S.role;
  const wifi = (p === 'MQTTS' || p === 'HTTPS');
  const ip   = (p === 'MQTTS' || p === 'HTTPS');
  const ca   = (p === 'MQTTS' || (p === 'HTTPS' && r === 'SENDER'));
  const mac  = (p === 'ESPNOW' && r === 'SENDER');
  let h = '';

  if (wifi) h += `
    <div class="form-group">
      <label>WiFi SSID</label>
      <input id="f_ssid" placeholder="YourNetwork" value="${S.cfg.ssid}" oninput="S.cfg.ssid=this.value">
    </div>
    <div class="form-group">
      <label>WiFi Password</label>
      <input type="password" id="f_pass" placeholder="••••••••" value="${S.cfg.password}" oninput="S.cfg.password=this.value">
    </div>`;

  if (ip) h += `
    <div class="form-group">
      <label>${p === 'MQTTS' ? 'MQTT Broker IP' : 'Server IP'}</label>
      <input id="f_ip" placeholder="${p==='MQTTS'?'192.168.0.118':'192.168.0.100'}" value="${S.cfg.serverIp}" oninput="S.cfg.serverIp=this.value">
    </div>`;

  if (mac) h += `
    <div class="form-group">
      <label>Receiver MAC Address</label>
      <input id="f_mac" placeholder="AA:BB:CC:DD:EE:FF" value="${S.cfg.mac}" oninput="S.cfg.mac=this.value">
    </div>`;

  if (!wifi && !mac) h += `<div class="form-group full" style="grid-column:1/-1">
    <div class="alert alert-info show">No additional network configuration required for ESP-Now ${r}. Key is embedded automatically.</div>
  </div>`;

  if (ca) h += `
    <div class="form-group full">
      <label>CA Certificate (PEM) — paste full contents</label>
      <textarea id="f_ca" placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDXTCCAkWgAwIBAgIJA...&#10;-----END CERTIFICATE-----" oninput="S.cfg.caCert=this.value">${S.cfg.caCert}</textarea>
    </div>`;

  document.getElementById('configForm').innerHTML = h;
}

// ══════════════════════════════════════════
//  BUILD & GO (ASYNC)
// ══════════════════════════════════════════
async function buildAndGo() {
  // Sync
  ['f_ssid','f_pass','f_ip','f_mac','f_ca'].forEach((id,i) => {
    const k = ['ssid','password','serverIp','mac','caCert'][i];
    const el = document.getElementById(id); if (el) S.cfg[k] = el.value;
  });

  const wifi = (S.protocol === 'MQTTS' || S.protocol === 'HTTPS');
  const mac  = (S.protocol === 'ESPNOW' && S.role === 'SENDER');

  if (wifi && !S.cfg.ssid)     { flashMsg('WiFi SSID is required.', true); return; }
  if (wifi && !S.cfg.password) { flashMsg('WiFi Password is required.', true); return; }
  if (wifi && !S.cfg.serverIp) { flashMsg('Server IP / Broker IP is required.', true); return; }
  if (mac  && !S.cfg.mac)      { flashMsg('Receiver MAC address is required.', true); return; }

  clearMsg();
  
  const cfg = {
    ssid:    S.cfg.ssid || 'YOUR_SSID',
    pass:    S.cfg.password || 'YOUR_PASSWORD',
    ip:      S.cfg.serverIp || '192.168.0.1',
    macC:    macToC(S.cfg.mac),
    keyC:    keyToC(),
    caC:     caToC(S.cfg.caCert),
    keyHex:  S.keyHex,
    date:    new Date().toISOString().split('T')[0]
  };

  try {
    const btn = document.getElementById('generateBtn');
    const originalText = btn.textContent;
    btn.textContent = "Generating...";
    btn.disabled = true;

    // Dynamically fetch the correct module from the templates folder
    const moduleName = `${S.encryption}_${S.protocol}_${S.role}.ino`;
    const response = await fetch(`templates/${moduleName}`);
    
    if (!response.ok) throw new Error("Template module not found (" + moduleName + ")");
    let rawCode = await response.text();

    // Stitch the payload values into the template
    S.code = rawCode
      .replace(/\{\{DATE\}\}/g, cfg.date)
      .replace(/\{\{KEY_HEX\}\}/g, cfg.keyHex)
      .replace(/\{\{SSID\}\}/g, cfg.ssid)
      .replace(/\{\{PASS\}\}/g, cfg.pass)
      .replace(/\{\{IP\}\}/g, cfg.ip)
      .replace(/\{\{MAC_C\}\}/g, cfg.macC)
      .replace(/\{\{KEY_C\}\}/g, cfg.keyC)
      .replace(/\{\{CA_C\}\}/g, cfg.caC);

    const fname = `esp32_${S.encryption.toLowerCase()}_${S.protocol.toLowerCase()}_${S.role.toLowerCase()}.ino`;
    document.getElementById('codeFilename').textContent = fname;
    document.getElementById('codeOutput').textContent = S.code;
    
    document.getElementById('summaryChips').innerHTML =
      `<span class="chip chip-mauve">${S.encryption}</span>` +
      `<span class="chip chip-blue">${S.protocol}</span>` +
      `<span class="chip chip-green">${S.role}</span>`;

    S.step++;
    render();

    // Reset button
    btn.textContent = originalText;
    btn.disabled = false;

  } catch (err) {
    flashMsg(`Error loading module: ${err.message}. Ensure your local python server is running.`, true);
    const btn = document.getElementById('generateBtn');
    btn.textContent = "Generate Code →";
    btn.disabled = false;
  }
}

// ══════════════════════════════════════════
//  COPY & DOWNLOAD
// ══════════════════════════════════════════
function copyKey(btn) {
  navigator.clipboard.writeText(S.keyHex).then(() => {
    btn.textContent = '✓ Copied!'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '⧉ Copy Key'; btn.classList.remove('copied'); }, 2200);
  });
}
function copyCode(btn) {
  navigator.clipboard.writeText(S.code).then(() => {
    btn.textContent = '✓ Copied!'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = '⧉ Copy'; btn.classList.remove('copied'); }, 2200);
  });
}
function downloadCode() {
  const fname = document.getElementById('codeFilename').textContent || 'sketch.ino';
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(new Blob([S.code], {type:'text/plain'})),
    download: fname
  });
  a.click(); URL.revokeObjectURL(a.href);
}

// ══════════════════════════════════════════
//  INIT
// ══════════════════════════════════════════
buildProgress();

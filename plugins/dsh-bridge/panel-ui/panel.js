const boot = window.__DSH_MOBILE_BRIDGE__ ?? { token: '', base: '/mobile-bridge/api' };

const $ = (id) => document.getElementById(id);
const app = $('app');
const state = {
  pairing: { phase: 'idle', rev: 0 },
  relay: { active: null, configured: null, restartRequired: false },
  pairingTimer: undefined,
  expiryTimer: undefined,
  currentQr: undefined,
  pendingRevoke: undefined,
};

async function api(path, options = {}) {
  const headers = { Authorization: `Bearer ${boot.token}` };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${boot.base}${path}`, {
    method: options.method ?? 'GET',
    headers,
    credentials: 'omit',
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.ok === false) {
    throw new Error(payload?.error?.message ?? `Request failed (${response.status})`);
  }
  return payload.value;
}

function showError(message) {
  $('error-message').textContent = message;
  $('error').hidden = false;
}

function clearError() {
  $('error').hidden = true;
}

function setConnection(kind, label) {
  $('connection-state').dataset.state = kind;
  $('connection-label').textContent = label;
}

async function run(task, { silent = false, button, success } = {}) {
  if (!silent) clearError();
  const originalDisabled = button?.disabled;
  if (button) {
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
  }
  try {
    const result = await task();
    if (success) showToast(success);
    return result;
  } catch (error) {
    showError(error instanceof Error ? error.message : String(error));
    setConnection('warning', 'Action failed');
    return undefined;
  } finally {
    if (button) {
      button.disabled = originalDisabled ?? false;
      button.removeAttribute('aria-busy');
    }
  }
}

async function refreshAll({ announce = false } = {}) {
  $('refresh-all').dataset.loading = 'true';
  try {
    await Promise.all([refreshStatus(), refreshDevices(), refreshRelay(), refreshAudit(), refreshPairing()]);
    setConnection('good', 'Bridge online');
    if (announce) showToast('Dashboard refreshed');
  } finally {
    $('refresh-all').dataset.loading = 'false';
  }
}

async function refreshStatus() {
  const s = await api('/status');
  const dshState = String(s.dsh?.state ?? 'unknown');
  const dshGood = dshState === 'connected';
  const listen = [s.listen?.host, s.listen?.port].filter((value) => value !== undefined).join(':');
  const relayActive = s.relay?.active ?? null;
  const relayConfigured = s.relay?.configured ?? null;

  $('identity').textContent = `${s.bridgeId ?? 'unknown bridge'} · v${s.bridgeVersion ?? '?'}`;
  $('footer-version').textContent = `bridge v${s.bridgeVersion ?? '?'}`;
  $('bridge-health').textContent = 'Running';
  $('bridge-dot').dataset.state = 'good';
  $('bridge-listen').textContent = listen || 'Listener unavailable';
  $('dsh-health').textContent = titleCase(dshState);
  $('dsh-dot').dataset.state = dshGood ? 'good' : 'bad';
  $('dsh-url').textContent = s.dsh?.url ?? 'No dsh URL';
  $('relay-health').textContent = relayActive ? 'Connected' : relayConfigured ? 'Configured' : 'Not configured';
  $('relay-dot').dataset.state = relayActive ? 'good' : relayConfigured ? 'warning' : 'loading';
  $('relay-summary').textContent = relayActive ?? relayConfigured ?? 'Local network only';
  $('device-health').textContent = String(s.activeDevices ?? 0);
  $('device-summary').textContent = `${plural(s.activeDevices ?? 0, 'active device')} · ${s.devices ?? 0} total`;
  $('spki-pin').textContent = s.spkiPin ?? '--';
  $('bridge-key').textContent = s.bridgeKey ?? '--';
}

async function refreshDevices() {
  const { devices = [] } = await api('/devices');
  const list = $('device-list');
  list.querySelectorAll('.device-row').forEach((node) => node.remove());
  $('devices-empty').hidden = devices.length !== 0;
  $('device-count').textContent = String(devices.length);

  for (const device of devices) {
    const row = document.createElement('article');
    row.className = 'device-row';
    row.dataset.revoked = String(Boolean(device.revokedAt));
    const deviceState = device.revokedAt ? 'revoked' : 'active';
    row.innerHTML = `
      <span class="device-avatar" aria-hidden="true">
        <svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 18h4"/></svg>
      </span>
      <span class="device-main">
        <strong>${escapeHtml(device.label || 'Unnamed device')}</strong>
        <span>${escapeHtml(shortId(device.deviceId))}${device.relayRoute ? ' · Relay route' : ''}</span>
      </span>
      <span class="device-meta">
        <strong>${escapeHtml(titleCase(device.tier ?? 'default'))}</strong>
        <span>Paired ${escapeHtml(relativeTime(device.pairedAt))}</span>
      </span>
      <span class="device-meta">
        <strong>${escapeHtml(device.lastSeenAt ? relativeTime(device.lastSeenAt) : 'Never')}</strong>
        <span>Last seen</span>
      </span>
      <span class="device-pill" data-state="${deviceState}">${titleCase(deviceState)}</span>
      ${device.revokedAt ? '' : `
        <button class="device-action" type="button" data-revoke="${escapeAttr(device.deviceId)}" data-label="${escapeAttr(device.label || 'this device')}" aria-label="Revoke ${escapeAttr(device.label || 'device')}" title="Revoke access">
          <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2m-9 0 1 15h8l1-15M10 10v7m4-7v7"/></svg>
        </button>`}
    `;
    list.append(row);
  }

  list.querySelectorAll('[data-revoke]').forEach((button) => {
    button.addEventListener('click', () => openRevokeDialog(button.dataset.revoke, button.dataset.label));
  });
}

function openRevokeDialog(deviceId, label) {
  state.pendingRevoke = { deviceId, label };
  $('confirm-title').textContent = `Revoke ${label}?`;
  $('confirm-description').textContent = 'This device loses access immediately. It must be paired again before it can control dsh.';
  $('confirm-dialog').showModal();
}

async function confirmRevoke() {
  const pending = state.pendingRevoke;
  if (!pending) return;
  const result = await run(async () => {
    await api('/devices/revoke', { method: 'POST', body: { deviceId: pending.deviceId } });
    await Promise.all([refreshDevices(), refreshStatus(), refreshAudit()]);
    return true;
  }, { button: $('confirm-action'), success: `${pending.label} revoked` });
  if (result) $('confirm-dialog').close();
  state.pendingRevoke = undefined;
}

async function refreshRelay() {
  const relay = await api('/relay');
  const managedExternally = relay.managedExternally === true || relay.pinned === true;
  state.relay = relay;
  $('relay-active').textContent = relay.active ?? 'None';
  $('relay-configured').textContent = relay.configured ?? 'None';
  $('relay-url').value = managedExternally ? relay.active ?? '' : relay.configured ?? '';
  $('relay-url').disabled = managedExternally;
  $('relay-form').dataset.readonly = String(managedExternally);
  $('relay-restart').hidden = !relay.restartRequired && !managedExternally;
  $('relay-notice-message').textContent = managedExternally
    ? `Relay is managed by ${relaySourceLabel(relay.source)}. Change it there and restart the bridge.`
    : 'Restart the bridge to apply this change.';
  $('relay-state-badge').textContent = managedExternally
    ? 'Managed externally'
    : relay.restartRequired
      ? 'Restart needed'
      : relay.active
        ? 'Active'
        : relay.configured
          ? 'Configured'
          : 'Off';
  $('relay-state-badge').dataset.state = managedExternally ? 'managed' : relay.restartRequired ? 'restart' : relay.active ? 'active' : 'off';
  $('relay-clear').disabled = managedExternally || relay.configured === null;
  $('relay-save').disabled = managedExternally;
  $('relay-pair-hint').textContent = relay.active
    ? 'Uses the active remote route'
    : relay.configured
      ? 'Restart the bridge before Relay pairing'
      : 'Requires an active Relay';
  $('pair-via-relay').disabled = !relay.active;
  if (!relay.active) $('pair-via-relay').checked = false;
}

function relaySourceLabel(source) {
  return ({ env: 'the environment', config: 'plugin configuration', cli: 'the CLI --relay flag' })[source]
    ?? 'external configuration';
}

function validateRelayUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return 'Enter a valid WebSocket URL.';
  }
  if (parsed.protocol === 'wss:') return undefined;
  if (parsed.protocol === 'ws:' && ['localhost', '127.0.0.1'].includes(parsed.hostname)) return undefined;
  if (parsed.protocol === 'ws:') return 'Use wss:// for remote Relays. ws:// is local testing only.';
  return 'Relay URLs must start with wss://.';
}

function setRelayFieldError(message) {
  $('relay-field-error').textContent = message ?? '';
  $('relay-field-error').hidden = !message;
  $('relay-url').setAttribute('aria-invalid', String(Boolean(message)));
}

async function saveRelay() {
  const url = $('relay-url').value.trim();
  const error = validateRelayUrl(url);
  setRelayFieldError(error);
  if (error) return;
  await run(async () => {
    await api('/relay', { method: 'PUT', body: { url } });
    await Promise.all([refreshRelay(), refreshStatus()]);
  }, { button: $('relay-save'), success: 'Relay configuration saved' });
}

async function clearRelay() {
  await run(async () => {
    await api('/relay', { method: 'DELETE' });
    await Promise.all([refreshRelay(), refreshStatus()]);
  }, { button: $('relay-clear'), success: 'Relay configuration cleared' });
}

async function refreshAudit() {
  const { entries = [] } = await api('/audit?limit=25');
  const list = $('audit-list');
  list.replaceChildren();
  $('audit-empty').hidden = entries.length !== 0;
  $('audit-count').textContent = entries.length ? `${entries.length} events` : 'Last 25';

  for (const entry of entries.slice().reverse()) {
    const decision = entry.decision ?? decisionForEvent(entry.event);
    const item = document.createElement('li');
    item.className = 'audit-entry';
    item.innerHTML = `
      <span class="audit-marker" data-decision="${escapeAttr(decision)}">${escapeHtml(markerForDecision(decision))}</span>
      <span class="audit-event">
        <strong>${escapeHtml(eventLabel(entry.event))}</strong>
        <span>${escapeHtml(decisionLabel(decision))}</span>
      </span>
      <span class="audit-detail">
        <strong>${escapeHtml(auditSubject(entry))}</strong>
        <span>${escapeHtml(auditContext(entry))}</span>
      </span>
      <time class="audit-time" datetime="${escapeAttr(entry.at ?? '')}">${escapeHtml(relativeTime(entry.at))}</time>
    `;
    list.append(item);
  }
}

async function startPairing() {
  const form = new FormData($('pair-form'));
  await run(async () => {
    await api('/pairing', {
      method: 'POST',
      body: { tier: form.get('tier'), relay: form.get('relay') === 'on' },
    });
    await refreshPairing();
    $('pairing-section').scrollIntoView({ block: 'start', behavior: 'smooth' });
  }, { button: $('pair-start') });
}

async function refreshPairing() {
  const pairing = await api('/pairing');
  state.pairing = pairing;
  renderPairing(pairing);
  const active = pairing.phase === 'open' || pairing.phase === 'claimed';
  if (active && state.pairingTimer === undefined) {
    state.pairingTimer = window.setInterval(() => void run(refreshPairing, { silent: true }), 1000);
  } else if (!active && state.pairingTimer !== undefined) {
    clearInterval(state.pairingTimer);
    state.pairingTimer = undefined;
    await Promise.all([refreshDevices(), refreshStatus(), refreshAudit()]);
  }
}

function renderPairing(pairing) {
  const phase = pairing.phase ?? 'idle';
  const terminal = phase === 'done' || phase === 'failed';
  $('pairing-badge').dataset.phase = phase;
  $('pairing-badge').textContent = phaseLabel(phase);
  $('pairing-idle').hidden = phase !== 'idle';
  $('pairing-state').hidden = phase === 'idle';
  $('pairing-open').hidden = phase !== 'open';
  $('pairing-sas').hidden = phase !== 'claimed';
  $('pairing-result').hidden = !terminal;
  $('pairing-cancel').hidden = terminal;

  updateProgress(phase);
  updateExpiryTimer(pairing);

  if (phase === 'open') {
    $('pairing-phase').textContent = pairing.uri ? 'Waiting for scan' : 'Opening pairing window';
    $('pair-tier').textContent = titleCase(pairing.tier ?? 'default');
    $('pair-route').textContent = pairing.relay ? 'Relay' : 'Local network';
    $('pairing-copy-uri').disabled = !pairing.uri;
    if (pairing.uri && state.currentQr !== pairing.uri) drawQr(pairing.uri);
    $('qr-loading').hidden = Boolean(pairing.uri);
  }

  if (phase === 'claimed') {
    $('pairing-sas-code').textContent = formatSas(pairing.sas);
    $('claiming-device').textContent = `${pairing.label ?? 'New device'} · ${shortId(pairing.deviceId)}`;
  }

  if (terminal) {
    const failed = phase === 'failed';
    $('pairing-result-icon').dataset.result = phase;
    $('pairing-result-kicker').textContent = failed ? 'Pairing stopped' : 'Device paired';
    $('pairing-result-title').textContent = failed ? 'Pairing was not completed' : `${pairing.label ?? 'Device'} is ready`;
    $('pairing-result-detail').textContent = failed
      ? pairing.reason ?? 'The pairing request ended before completion.'
      : `${titleCase(pairing.grantedTier ?? pairing.tier ?? 'default')} access was granted.`;
  }
}

function updateProgress(phase) {
  const order = { open: 0, claimed: 1, done: 2, failed: 2 };
  const current = order[phase] ?? 0;
  [$('pair-step-open'), $('pair-step-claimed'), $('pair-step-done')].forEach((step, index) => {
    delete step.dataset.state;
    if (index < current) step.dataset.state = 'done';
    else if (index === current) step.dataset.state = 'current';
  });
}

function updateExpiryTimer(pairing) {
  clearInterval(state.expiryTimer);
  state.expiryTimer = undefined;
  if (pairing.phase !== 'open') return;
  const render = () => {
    if (!pairing.expiresAt) {
      $('pairing-expiry').textContent = 'A secure pairing window is being prepared.';
      return;
    }
    const remaining = Math.max(0, Math.ceil((pairing.expiresAt - Date.now()) / 1000));
    $('pairing-expiry').textContent = `This code expires in ${formatDuration(remaining)}.`;
  };
  render();
  state.expiryTimer = window.setInterval(render, 1000);
}

function drawQr(uri) {
  state.currentQr = uri;
  const canvas = $('pairing-canvas');
  const context = canvas.getContext('2d', { alpha: false });
  const qrFactory = window.qrcode;
  if (!context || typeof qrFactory !== 'function') {
    showError('The local QR renderer could not be loaded.');
    return;
  }
  try {
    const qr = qrFactory(0, 'M');
    qr.addData(uri, 'Byte');
    qr.make();
    const modules = qr.getModuleCount();
    const quiet = 4;
    const total = modules + quiet * 2;
    const scale = Math.max(1, Math.floor(canvas.width / total));
    const drawn = total * scale;
    const offset = Math.floor((canvas.width - drawn) / 2);
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = '#111416';
    for (let row = 0; row < modules; row += 1) {
      for (let column = 0; column < modules; column += 1) {
        if (!qr.isDark(row, column)) continue;
        context.fillRect(offset + (column + quiet) * scale, offset + (row + quiet) * scale, scale, scale);
      }
    }
    $('qr-loading').hidden = true;
  } catch (error) {
    showError(`Could not generate the pairing QR code: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function confirmPairing(accept, button) {
  await run(async () => {
    await api('/pairing/confirm', { method: 'POST', body: { accept } });
    await refreshPairing();
  }, { button, success: accept ? 'Device approved' : 'Pairing rejected' });
}

async function cancelPairing() {
  await run(async () => {
    await api('/pairing', { method: 'DELETE' });
    state.currentQr = undefined;
    await refreshPairing();
  }, { button: $('pairing-cancel'), success: 'Pairing cancelled' });
}

function resetPairingUi() {
  state.currentQr = undefined;
  state.pairing = { phase: 'idle', rev: state.pairing.rev };
  renderPairing(state.pairing);
  $('pair-start').focus();
}

function copyPairingUri() {
  const uri = state.pairing.uri;
  if (!uri) return;
  void run(async () => {
    await navigator.clipboard.writeText(uri);
  }, { button: $('pairing-copy-uri'), success: 'Pairing link copied' });
}

function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  $('toast-region').append(toast);
  window.setTimeout(() => toast.remove(), 3200);
}

function eventLabel(event) {
  const labels = {
    'rpc': 'RPC request',
    'respond': 'Response sent',
    'pair-claim': 'Pairing claimed',
    'pair-confirm': 'Pairing approved',
    'pair-reject': 'Pairing rejected',
    'auth-challenge': 'Auth challenge',
    'auth-success': 'Device authenticated',
    'auth-failure': 'Authentication failed',
    'token-rotate': 'Token rotated',
    'stream-attach': 'Stream attached',
    'stream-detach': 'Stream detached',
    'device-revoke': 'Device revoked',
    'bridge-start': 'Bridge started',
    'bridge-stop': 'Bridge stopped',
  };
  return labels[event] ?? titleCase(String(event ?? 'Event').replaceAll('-', ' '));
}

function decisionForEvent(event) {
  return event === 'auth-failure' || event === 'pair-reject' ? 'denied' : 'allowed';
}

function markerForDecision(decision) {
  if (decision === 'denied' || decision === 'failed') return '!';
  if (decision === 'rate-limited') return '·';
  return '✓';
}

function decisionLabel(decision) {
  return decision === 'rate-limited' ? 'Rate limited' : titleCase(decision ?? 'recorded');
}

function auditSubject(entry) {
  return entry.deviceLabel ?? entry.method ?? (entry.deviceId ? shortId(entry.deviceId) : 'Bridge');
}

function auditContext(entry) {
  const parts = [];
  if (entry.reason) parts.push(entry.reason);
  if (entry.sessionId) parts.push(`session ${shortId(entry.sessionId)}`);
  if (entry.payloadBytes !== undefined) parts.push(`${entry.payloadBytes} bytes`);
  if (entry.peer) parts.push(entry.peer);
  return parts.join(' · ') || 'Local control event';
}

function phaseLabel(phase) {
  return ({ idle: 'Ready', open: 'Scan code', claimed: 'Verify', done: 'Complete', failed: 'Stopped' })[phase] ?? titleCase(phase);
}

function titleCase(value) {
  const text = String(value ?? '');
  return text ? text[0].toUpperCase() + text.slice(1) : '';
}

function plural(value, noun) {
  return `${value} ${noun}${Number(value) === 1 ? '' : 's'}`;
}

function shortId(value) {
  const text = String(value ?? 'Unknown ID');
  return text.length > 18 ? `${text.slice(0, 8)}...${text.slice(-6)}` : text;
}

function formatSas(value) {
  const code = String(value ?? '').replace(/\D/g, '').padStart(6, '0').slice(-6);
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

function formatDuration(seconds) {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}:${String(remainder).padStart(2, '0')}`;
}

function relativeTime(value) {
  if (!value) return 'Unknown';
  const date = typeof value === 'number' ? new Date(value) : new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  const delta = date.getTime() - Date.now();
  const absolute = Math.abs(delta);
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  if (absolute < 60_000) return formatter.format(Math.round(delta / 1000), 'second');
  if (absolute < 3_600_000) return formatter.format(Math.round(delta / 60_000), 'minute');
  if (absolute < 86_400_000) return formatter.format(Math.round(delta / 3_600_000), 'hour');
  if (absolute < 604_800_000) return formatter.format(Math.round(delta / 86_400_000), 'day');
  return date.toLocaleDateString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, '&#96;');
}

function bindEvents() {
  $('refresh-all').addEventListener('click', () => void run(() => refreshAll({ announce: true })));
  $('error-dismiss').addEventListener('click', clearError);
  $('pair-hero-button').addEventListener('click', () => {
    $('pairing-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
    window.setTimeout(() => $('pair-start').focus(), 300);
  });
  $('pair-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void startPairing();
  });
  $('pairing-copy-uri').addEventListener('click', copyPairingUri);
  $('pairing-accept').addEventListener('click', () => void confirmPairing(true, $('pairing-accept')));
  $('pairing-decline').addEventListener('click', () => void confirmPairing(false, $('pairing-decline')));
  $('pairing-cancel').addEventListener('click', () => void cancelPairing());
  $('pairing-reset').addEventListener('click', resetPairingUi);
  $('relay-form').addEventListener('submit', (event) => {
    event.preventDefault();
    void saveRelay();
  });
  $('relay-url').addEventListener('input', () => setRelayFieldError(undefined));
  $('relay-clear').addEventListener('click', () => void clearRelay());
  $('confirm-action').addEventListener('click', (event) => {
    event.preventDefault();
    void confirmRevoke();
  });
  $('confirm-dialog').addEventListener('close', () => {
    if ($('confirm-dialog').returnValue !== 'confirm') state.pendingRevoke = undefined;
  });
}

async function bootstrap() {
  bindEvents();
  if (!boot.token) {
    showError('The panel security bootstrap is missing. Reload this page from dsh web.');
    setConnection('bad', 'Unavailable');
    app.setAttribute('aria-busy', 'false');
    return;
  }
  await run(refreshAll);
  app.setAttribute('aria-busy', 'false');
}

void bootstrap();

from fastapi import APIRouter
from fastapi.responses import HTMLResponse


router = APIRouter(prefix="/ui", tags=["ui"])


@router.get("/policy-explain", response_class=HTMLResponse)
async def policy_explain_page() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>VPN-ZTNA User Portal</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    :root {
      --bg: #f4f5f7;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --border: #d9dee7;
      --text: #17202a;
      --muted: #667085;
      --primary: #0f766e;
      --primary-hover: #0b5f59;
      --danger: #b42318;
      --danger-bg: #fef3f2;
      --success: #027a48;
      --success-bg: #ecfdf3;
      --badge-neutral-bg: #eef2f6;
      --badge-neutral-fg: #344054;
      --shadow: 0 10px 30px rgba(16, 24, 40, 0.08);
      --radius: 14px;
      --radius-sm: 10px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #f6f8fb 0%, #eef2f7 100%);
      color: var(--text);
    }

    .container {
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 16px 64px;
    }

    .hero {
      margin-bottom: 24px;
    }

    .hero h1 {
      margin: 0 0 8px;
      font-size: 2.25rem;
      line-height: 1.1;
      letter-spacing: -0.02em;
    }

    .hero p {
      margin: 0;
      color: var(--muted);
      font-size: 1rem;
      max-width: 760px;
    }

    .grid {
      display: grid;
      grid-template-columns: 360px 1fr;
      gap: 20px;
      align-items: start;
    }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 18px 18px;
    }

    .card h2 {
      margin: 0 0 12px;
      font-size: 1.15rem;
    }

    .subtle {
      color: var(--muted);
      font-size: 0.95rem;
    }

    .help-link {
      color: var(--primary);
      font-weight: 650;
      text-decoration: none;
      text-underline-offset: 3px;
    }

    .help-link:hover,
    .help-link:focus-visible {
      color: var(--primary-hover);
      text-decoration: underline;
    }

    label {
      display: block;
      margin-bottom: 6px;
      font-size: 0.92rem;
      font-weight: 600;
    }

    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 11px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #fff;
      font-size: 0.96rem;
      outline: none;
      margin-bottom: 12px;
    }

    input:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px rgba(15, 118, 110, 0.12);
    }

    button {
      appearance: none;
      border: none;
      border-radius: 10px;
      padding: 11px 14px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.18s ease, opacity 0.18s ease, transform 0.05s ease;
    }

    button:active {
      transform: translateY(1px);
    }

    button:disabled {
      opacity: 0.6;
      cursor: default;
    }

    .btn-primary {
      background: var(--primary);
      color: #fff;
    }

    .btn-primary:hover {
      background: var(--primary-hover);
    }

    .btn-secondary {
      background: #edf2f7;
      color: #1f2937;
    }

    .btn-secondary:hover {
      background: #e5ebf2;
    }

    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 6px;
    }

    .status-line {
      margin-top: 10px;
      min-height: 20px;
      color: var(--muted);
      font-size: 0.92rem;
    }

    .error-box {
      margin-top: 12px;
      display: none;
      padding: 10px 12px;
      border: 1px solid #f3c7c2;
      background: var(--danger-bg);
      color: var(--danger);
      border-radius: 10px;
      font-size: 0.93rem;
      white-space: pre-wrap;
    }

    .success-box {
      margin-top: 12px;
      display: none;
      padding: 10px 12px;
      border: 1px solid #b7ebc6;
      background: var(--success-bg);
      color: var(--success);
      border-radius: 10px;
      font-size: 0.93rem;
    }

    .hidden {
      display: none !important;
    }

    .summary-top {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }

    .badge.mode-full {
      background: #dcfce7;
      color: #166534;
    }

    .badge.mode-split {
      background: #eff6ff;
      color: #1d4ed8;
    }

    .badge.allow {
      background: #e0f2f1;
      color: #0f766e;
    }

    .badge.deny {
      background: #ffebee;
      color: #c62828;
    }

    .badge.neutral {
      background: var(--badge-neutral-bg);
      color: var(--badge-neutral-fg);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .stat {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
    }

    .stat .k {
      color: var(--muted);
      font-size: 0.82rem;
      margin-bottom: 4px;
    }

    .stat .v {
      font-size: 1.1rem;
      font-weight: 700;
      line-height: 1.2;
      word-break: break-word;
    }

    .section-title {
      margin: 0 0 10px;
      font-size: 1rem;
      font-weight: 700;
    }

    .cidr-box {
      border: 1px solid var(--border);
      background: var(--surface-2);
      border-radius: 12px;
      padding: 12px;
      max-height: 190px;
      overflow: auto;
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      background: #eef2f7;
      border-radius: 7px;
      padding: 2px 6px;
      font-size: 0.84rem;
    }

    .cidr-items {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .steps-toolbar {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-top: 18px;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }

    .table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #fff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }

    th, td {
      padding: 10px 10px;
      border-bottom: 1px solid #e8edf3;
      vertical-align: top;
      text-align: left;
    }

    th {
      background: #f8fafc;
      color: #344054;
      font-size: 0.85rem;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .steps-cidrs {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      min-width: 220px;
    }

    .help-list {
      margin: 0;
      padding-left: 18px;
      color: var(--text);
    }

    .help-list li {
      margin-bottom: 8px;
    }

    .footer-note {
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.88rem;
    }

    @media (max-width: 920px) {
      .grid {
        grid-template-columns: 1fr;
      }

      .stats {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 560px) {
      .hero h1 {
        font-size: 1.8rem;
      }

      .stats {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <h1>VPN-ZTNA User Portal</h1>
      <p>
        Review your assigned VPN access, download your WireGuard configuration,
        and connect securely from this device.
      </p>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Sign in</h2>
        <div class="subtle">Sign in with the VPN-ZTNA credentials provided by your administrator.</div>

        <form id="login-form" style="margin-top:14px;">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" required />

          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required />

          <div class="btn-row">
            <button id="login-button" type="submit" class="btn-primary">Login &amp; Load Policy</button>
            <button id="logout-button" type="button" class="btn-secondary hidden">Logout</button>
          </div>

          <div id="login-status" class="status-line"></div>
          <div id="login-error" class="error-box"></div>
          <div id="login-success" class="success-box"></div>
        </form>
      </div>

      <div class="card">
        <h2>Get connected</h2>
        <ol class="help-list">
          <li>Sign in with the username and password supplied by your administrator.</li>
          <li>Review the access mode and routes currently assigned to your account.</li>
          <li>
            Download your configuration, import it into
            <a
              class="help-link"
              href="https://www.wireguard.com/install/"
              target="_blank"
              rel="noopener noreferrer"
            >WireGuard ↗</a>,
            then activate the tunnel.
          </li>
          <li>Keep your WireGuard private key secret. Never send it to another person.</li>
        </ol>

        <div class="footer-note">
          The portal reflects the current policy state for the authenticated user.
        </div>
      </div>
    </div>

    <div id="portal-content" class="hidden" style="margin-top:20px;">
      <div class="card">
        <div class="summary-top">
          <div>
            <h2 style="margin-bottom:6px;">Access summary</h2>
            <div id="summary-subtitle" class="subtle">Current effective access for your provisioned peer.</div>
          </div>
          <div id="mode-badge" class="badge neutral">NOT LOADED</div>
        </div>

        <div class="stats" id="stats-grid"></div>

        <div class="btn-row" style="margin-bottom:16px;">
          <button id="enroll-button" type="button" class="btn-primary">Enroll / Recreate Peer</button>
          <button id="reload-button" type="button" class="btn-secondary">Reload Policy</button>
          <button id="download-button" type="button" class="btn-secondary">Download Config</button>
          <button id="toggle-steps-button" type="button" class="btn-secondary">Show Steps</button>
        </div>

        <div id="action-error" class="error-box"></div>
        <div id="action-success" class="success-box"></div>

        <div>
          <div class="section-title">Final CIDRs before aggregation</div>
          <div class="cidr-box">
            <div id="cidr-container" class="cidr-items"></div>
          </div>
        </div>

        <div id="steps-section" class="hidden">
          <div class="steps-toolbar">
            <div>
              <div class="section-title" style="margin-bottom:4px;">Policy steps</div>
              <div class="subtle">Each row shows how a policy changed the allowed CIDR set.</div>
            </div>
            <div id="steps-count-badge" class="badge neutral">0 STEPS</div>
          </div>

          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Policy</th>
                  <th>Scope</th>
                  <th>Effect</th>
                  <th>Resource CIDR</th>
                  <th>Before</th>
                  <th>After</th>
                </tr>
              </thead>
              <tbody id="steps-body"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const baseUrl = window.location.origin;

    let accessToken = null;
    let currentExplain = null;
    let stepsVisible = false;

    const loginForm = document.getElementById('login-form');
    const loginButton = document.getElementById('login-button');
    const logoutButton = document.getElementById('logout-button');
    const loginStatus = document.getElementById('login-status');
    const loginError = document.getElementById('login-error');
    const loginSuccess = document.getElementById('login-success');

    const portalContent = document.getElementById('portal-content');
    const statsGrid = document.getElementById('stats-grid');
    const modeBadge = document.getElementById('mode-badge');
    const summarySubtitle = document.getElementById('summary-subtitle');

    const cidrContainer = document.getElementById('cidr-container');
    const stepsSection = document.getElementById('steps-section');
    const stepsBody = document.getElementById('steps-body');
    const stepsCountBadge = document.getElementById('steps-count-badge');

    const reloadButton = document.getElementById('reload-button');
    const downloadButton = document.getElementById('download-button');
    const toggleStepsButton = document.getElementById('toggle-steps-button');
    const enrollButton = document.getElementById('enroll-button');

    const actionError = document.getElementById('action-error');
    const actionSuccess = document.getElementById('action-success');

    function showBox(el, text) {
      el.textContent = text;
      el.style.display = 'block';
    }

    function hideBox(el) {
      el.textContent = '';
      el.style.display = 'none';
    }

    function clearMessages() {
      hideBox(loginError);
      hideBox(loginSuccess);
      hideBox(actionError);
      hideBox(actionSuccess);
      loginStatus.textContent = '';
    }

    async function apiLogin(username, password) {
      const resp = await fetch(baseUrl + '/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          username: username,
          password: password
        })
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error('Login failed: ' + resp.status + ' ' + text);
      }

      const data = await resp.json();
      if (!data.access_token) {
        throw new Error('Login response has no access_token');
      }
      return data.access_token;
    }

    async function apiFetchExplain(token) {
      const resp = await fetch(baseUrl + '/api/v1/peers/my/policy-explain', {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });

      if (resp.status === 404) {
        throw new Error('No provisioned peer found for current user.');
      }

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error('Failed to get policy explain: ' + resp.status + ' ' + text);
      }

      return await resp.json();
    }

    async function apiDownloadConfig(token) {
      const resp = await fetch(baseUrl + '/api/v1/peers/my/config', {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });

      if (resp.status === 404) {
        throw new Error('No provisioned peer found for current user.');
      }

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error('Failed to download config: ' + resp.status + ' ' + text);
      }

      const disposition = resp.headers.get('Content-Disposition') || '';
      let filename = 'wg0.conf';
      const marker = 'filename=';
      const idx = disposition.indexOf(marker);
      if (idx !== -1) {
        filename = disposition.slice(idx + marker.length).trim().replaceAll('"', '');
      }

      const text = await resp.text();
      return { filename, text };
    }

    async function apiEnrollMyPeer(token) {
      const resp = await fetch(baseUrl + '/api/v1/peers/my/enroll', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error('Failed to enroll peer: ' + resp.status + ' ' + text);
      }

      return await resp.json();
    }

    function setLoggedInState(isLoggedIn) {
      if (isLoggedIn) {
        logoutButton.classList.remove('hidden');
      } else {
        logoutButton.classList.add('hidden');
        portalContent.classList.add('hidden');
      }
    }

    function statCard(label, value) {
      const div = document.createElement('div');
      div.className = 'stat';
      div.innerHTML = '<div class="k">' + label + '</div><div class="v">' + value + '</div>';
      return div;
    }

    function renderSummary(explain) {
      currentExplain = explain;

      const summary = explain.summary || {};
      const mode = String(summary.effective_access_mode || 'unknown');
      const isFull = Boolean(summary.has_full_internet_access);
      const peerId = explain.peer_id ?? '';
      const userId = explain.user_id ?? '';
      const vpnIp = explain.vpn_ip ?? '';

      statsGrid.innerHTML = '';
      statsGrid.appendChild(statCard('Peer ID', String(peerId)));
      statsGrid.appendChild(statCard('User ID', String(userId)));
      statsGrid.appendChild(statCard('VPN IP', String(vpnIp)));
      statsGrid.appendChild(statCard('Allowed CIDRs count', String(summary.allowed_count ?? 0)));
      statsGrid.appendChild(statCard('Allow policies', String(summary.allowed_policies_count ?? 0)));
      statsGrid.appendChild(statCard('Deny policies', String(summary.denied_policies_count ?? 0)));
      statsGrid.appendChild(statCard('Full internet access', isFull ? 'Yes' : 'No'));
      statsGrid.appendChild(statCard('Mode', mode));

      modeBadge.className = 'badge ' + (mode === 'full_tunnel' ? 'mode-full' : 'mode-split');
      modeBadge.textContent = mode === 'full_tunnel' ? 'FULL TUNNEL' : mode.toUpperCase();

      summarySubtitle.textContent =
        'Peer ' + peerId + ' with VPN IP ' + vpnIp + ' and effective mode ' + mode + '.';

      cidrContainer.innerHTML = '';
      const cidrs = explain.final_cidrs_before_aggregation || [];
      if (cidrs.length === 0) {
        const span = document.createElement('span');
        span.className = 'subtle';
        span.textContent = 'No CIDRs returned.';
        cidrContainer.appendChild(span);
      } else {
        for (const cidr of cidrs) {
          const codeEl = document.createElement('code');
          codeEl.textContent = cidr;
          cidrContainer.appendChild(codeEl);
        }
      }

      renderSteps(explain.steps || []);
      portalContent.classList.remove('hidden');
    }

    function renderSteps(steps) {
      stepsBody.innerHTML = '';
      stepsCountBadge.textContent = String(steps.length) + ' STEPS';

      for (let i = 0; i < steps.length; i++) {
        const s = steps[i];
        const tr = document.createElement('tr');

        const before = Array.isArray(s.before) ? s.before : [];
        const after = Array.isArray(s.after) ? s.after : [];

        tr.innerHTML = `
          <td>${i + 1}</td>
          <td>
            <div style="font-weight:700;">${escapeHtml(s.name || '')}</div>
            <div class="subtle">ID: ${escapeHtml(String(s.policy_id ?? ''))}</div>
          </td>
          <td>${escapeHtml(s.scope || '')}</td>
          <td><span class="badge ${String(s.effect).toLowerCase() === 'allow' ? 'allow' : 'deny'}">${escapeHtml(String(s.effect || '').toUpperCase())}</span></td>
          <td><code>${escapeHtml(s.resource_cidr || '')}</code></td>
          <td>${renderCidrGroup(before)}</td>
          <td>${renderCidrGroup(after)}</td>
        `;

        stepsBody.appendChild(tr);
      }
    }

    function renderCidrGroup(items) {
      if (!items || items.length === 0) {
        return '<span class="subtle">empty</span>';
      }
      return '<div class="steps-cidrs">' + items.map(v => '<code>' + escapeHtml(String(v)) + '</code>').join('') + '</div>';
    }

    function escapeHtml(str) {
      return String(str)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    async function loadPolicy() {
      if (!accessToken) {
        throw new Error('Not authenticated.');
      }
      const explain = await apiFetchExplain(accessToken);
      renderSummary(explain);
      return explain;
    }

    async function handleLogin(username, password) {
      clearMessages();
      loginButton.disabled = true;
      loginStatus.textContent = 'Logging in...';

      try {
        accessToken = await apiLogin(username, password);
        loginStatus.textContent = 'Loading policy...';
        await loadPolicy();
        setLoggedInState(true);
        showBox(loginSuccess, 'Signed in successfully. Policy data loaded.');
        loginStatus.textContent = 'Loaded';
      } catch (err) {
        accessToken = null;
        setLoggedInState(false);
        showBox(loginError, err.message || String(err));
        loginStatus.textContent = '';
      } finally {
        loginButton.disabled = false;
      }
    }

    async function handleReload() {
      hideBox(actionError);
      hideBox(actionSuccess);
      reloadButton.disabled = true;

      try {
        await loadPolicy();
        showBox(actionSuccess, 'Policy reloaded successfully.');
      } catch (err) {
        showBox(actionError, err.message || String(err));
      } finally {
        reloadButton.disabled = false;
      }
    }

    async function handleDownload() {
      hideBox(actionError);
      hideBox(actionSuccess);
      downloadButton.disabled = true;

      try {
        if (!accessToken) {
          throw new Error('Not authenticated.');
        }

        const result = await apiDownloadConfig(accessToken);
        const blob = new Blob([result.text], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = result.filename || 'wg0.conf';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        showBox(actionSuccess, 'WireGuard config downloaded: ' + (result.filename || 'wg0.conf'));
      } catch (err) {
        showBox(actionError, err.message || String(err));
      } finally {
        downloadButton.disabled = false;
      }
    }

    async function handleEnroll() {
      hideBox(actionError);
      hideBox(actionSuccess);

       const confirmed = window.confirm('This action will (re)create your VPN peer. '
        + 'Your VPN IP may change. Allowed routes may be recalculated. '
        + 'You will need to re-import the new config into WireGuard. '
        + 'Do you want to continue?');
      if (!confirmed) {
        return;
      }

      enrollButton.disabled = true;

      try {
        if (!accessToken) {
          throw new Error('Not authenticated.');
        }

        await apiEnrollMyPeer(accessToken);
        await loadPolicy();
        showBox(actionSuccess, 'Peer enrolled successfully. Policy data reloaded.');
      } catch (err) {
        showBox(actionError, err.message || String(err));
      } finally {
        enrollButton.disabled = false;
      }
    }

    function handleLogout() {
      accessToken = null;
      currentExplain = null;
      stepsVisible = false;
      setLoggedInState(false);

      statsGrid.innerHTML = '';
      cidrContainer.innerHTML = '';
      stepsBody.innerHTML = '';
      stepsSection.classList.add('hidden');
      toggleStepsButton.textContent = 'Show Steps';
      modeBadge.className = 'badge neutral';
      modeBadge.textContent = 'NOT LOADED';
      summarySubtitle.textContent = 'Current effective access for your provisioned peer.';
      loginStatus.textContent = '';
      hideBox(loginError);
      hideBox(loginSuccess);
      hideBox(actionError);
      hideBox(actionSuccess);

      document.getElementById('password').value = '';
    }

    function handleToggleSteps() {
      stepsVisible = !stepsVisible;
      if (stepsVisible) {
        stepsSection.classList.remove('hidden');
        toggleStepsButton.textContent = 'Hide Steps';
      } else {
        stepsSection.classList.add('hidden');
        toggleStepsButton.textContent = 'Show Steps';
      }
    }

    loginForm.addEventListener('submit', function (evt) {
      evt.preventDefault();

      const username = (document.getElementById('username').value || '').trim();
      const password = document.getElementById('password').value || '';

      if (!username || !password) {
        clearMessages();
        showBox(loginError, 'Please enter username and password.');
        return;
      }

      handleLogin(username, password);
    });

    reloadButton.addEventListener('click', handleReload);
    downloadButton.addEventListener('click', handleDownload);
    logoutButton.addEventListener('click', handleLogout);
    toggleStepsButton.addEventListener('click', handleToggleSteps);
    enrollButton.addEventListener('click', handleEnroll);
  </script>
</body>
</html>
    """


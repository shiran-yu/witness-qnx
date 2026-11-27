// Witness dashboard client: polls the JSON API, keeps DOM nodes stable so state changes animate.
'use strict';
(() => {
  const POLL_MS = 2000;
  const view = document.getElementById('view');
  const announcer = document.getElementById('announcer');

  const ICON = {
    shieldOk: '<path d="M12 2.8 4.5 5.8v5.6c0 4.7 3.2 8.3 7.5 9.8 4.3-1.5 7.5-5.1 7.5-9.8V5.8L12 2.8Z"/><path d="m8.6 12 2.4 2.4 4.6-4.8"/>',
    shieldBad: '<path d="M12 2.8 4.5 5.8v5.6c0 4.7 3.2 8.3 7.5 9.8 4.3-1.5 7.5-5.1 7.5-9.8V5.8L12 2.8Z"/><path d="m9.3 9.3 5.4 5.4M14.7 9.3l-5.4 5.4"/>',
    alert: '<path d="M10.3 3.9 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4.5M12 17h.01"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    cross: '<path d="m6.5 6.5 11 11M17.5 6.5l-11 11"/>',
    minus: '<path d="M6 12h12"/>',
    plus: '<path d="M12 6v12M6 12h12"/>',
    back: '<path d="M15 5.5 8.5 12l6.5 6.5"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.3-4.9L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.3 4.9L20 16"/><path d="M20 20v-4h-4"/>',
    lock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    unlock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 7.7-1.5"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.5a2.5 2.5 0 0 1 4.8 1c0 1.7-2.4 2-2.4 3.5M12 17h.01"/>',
  };
  const icon = (name, cls = '') =>
    `<svg class="icon ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name]}</svg>`;

  const STATE = {
    'trusted': { cls: 'is-trusted', word: 'TRUSTED', icon: 'shieldOk', tick: 'ok' },
    'not trusted': { cls: 'is-bad', word: 'NOT TRUSTED', icon: 'shieldBad', tick: 'bad' },
    'unreachable': { cls: 'is-warn', word: 'UNREACHABLE', icon: 'alert', tick: 'warn' },
    'checking': { cls: '', word: 'CHECKING', icon: 'clock', tick: 'empty' },
  };
  const stateOf = s => STATE[s] || STATE.checking;

  const SECRET = {
    unsealed: { cls: 'unsealed', text: 'Released', icon: 'unlock' },
    locked: { cls: 'locked', text: 'Locked', icon: 'lock' },  // unproven: the agent reports it, no signature shows it
    'released to an old release': { cls: 'error', text: 'Released to an old signed release', icon: 'alert' },
    error: { cls: 'error', text: 'Error', icon: 'alert' },
  };
  const secret = s => {
    const v = SECRET[s];
    return v ? `<span class="secret ${v.cls}">${icon(v.icon)}${v.text}</span>` : `<span class="secret">${esc(s || 'Unknown')}</span>`;
  };

  const ROW = {
    ok: { cls: '', badge: 'ok', icon: 'check', text: 'Match' },
    changed: { cls: 'row-bad', badge: 'bad', icon: 'cross', text: 'Changed' },
    missing: { cls: 'row-bad', badge: 'bad', icon: 'minus', text: 'Missing' },
    unexpected: { cls: 'row-bad', badge: 'bad', icon: 'plus', text: 'Unexpected' },
    'not measured': { cls: 'row-warn', badge: 'warn', icon: 'alert', text: 'Not measured' },
    info: { cls: '', badge: 'info', icon: 'help', text: 'Not appraised' },
  };

  const PCR_MEANING = ['Firmware code', 'Firmware configuration', 'Option ROM code', 'Option ROM configuration',
    'Boot image (QNX IFS)', 'Boot disk partition table', 'Platform manufacturer', 'Secure Boot policy',
    'System partition (Witness)', 'Applications (Witness)'];

  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  const short = (hex, n = 16) => hex ? `<span title="${esc(hex)}">${esc(hex.slice(0, n))}…</span>` : '—';

  let eventFilter = 'all'; // event log table: 'all' or 'diff'
  let skew = 0; // server clock minus browser clock, seconds
  const now = () => Date.now() / 1000 + skew;
  function ago(t) {
    if (!t) return 'not yet';
    const s = Math.max(0, Math.round(now() - t));
    if (s < 5) return 'just now';
    if (s < 60) return `${s} s ago`;
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    return `${Math.floor(s / 3600)} h ago`;
  }
  const clock = t => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const agoTag = t => `<time datetime="${t ? new Date(t * 1000).toISOString() : ''}" data-ago="${t || ''}">${ago(t)}</time>`;
  setInterval(() => document.querySelectorAll('[data-ago]').forEach(el => {
    const text = ago(Number(el.dataset.ago));
    if (el.textContent !== text) el.textContent = text;
  }), 1000);

  function announce(text) {
    announcer.textContent = '';
    setTimeout(() => { announcer.textContent = text; }, 50);
  }

  // Replace a container's HTML only when its content changed, keeping keyboard focus where it was.
  const signatures = new WeakMap();
  function patch(el, html) {
    if (signatures.get(el) === html) return false;
    const focused = el.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
    el.innerHTML = html;
    signatures.set(el, html);
    if (focused) el.querySelector(`[data-focus="${CSS.escape(focused)}"]`)?.focus();
    return true;
  }
  function flip(el) {
    el.classList.remove('flip');
    void el.offsetWidth;
    el.classList.add('flip');
    setTimeout(() => el.classList.remove('flip'), 1700);
  }

  // Remember each device's last state to notice a flip.
  const lastState = new Map();
  function noteState(device) {
    const before = lastState.get(device.name);
    lastState.set(device.name, device.state);
    if (before && before !== 'checking' && before !== device.state) {
      const finding = device.findings?.[0]?.title || device.error || '';
      announce(`${device.name} is now ${stateOf(device.state).word}${finding ? ': ' + finding : ''}`);
      return true;
    }
    return false;
  }

  async function getJSON(url, options) {
    const response = await fetch(url, Object.assign({ cache: 'no-store' }, options));
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }

  // ---- header ------------------------------------------------------------
  function renderChrome(data) {
    if (data.now) skew = data.now - Date.now() / 1000;
    const mode = data.mode === 'live'
      ? `<span class="dot live" aria-hidden="true"></span><span>Live <span class="long">· re-verifying every ${data.interval} s</span></span>`
      : `<span class="dot replay" aria-hidden="true"></span><span>Replay <span class="long">· captured evidence, verified offline</span></span>`;
    patch(document.getElementById('mode'), mode);
    const r = data.reference || {};
    const created = r.created ? new Date(r.created).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '';
    patch(document.getElementById('context'),
      `<span>Release reference <b>${esc(r.image)}</b> · ${esc((r.boot_mode || '').toUpperCase())} boot${created ? ` · computed ${esc(created)}` : ''}</span>` +
      (r.ifs_sha256 ? `<span>IFS sha256 <b class="mono">${short(r.ifs_sha256, 12)}</b></span>` : '') +
      (data.environment ? `<span>${esc(data.environment)}</span>` : ''));
  }

  // ---- fleet -------------------------------------------------------------
  function historyStrip(history, slots = 16) {
    const items = history.slice(-slots);
    const ticks = items.map(h => `<i class="${stateOf(h.state).tick}" title="${esc(clock(h.time))}: ${esc(stateOf(h.state).word)}"></i>`);
    while (ticks.length < Math.min(slots, 12)) ticks.unshift('<i class="empty"></i>');
    const failed = items.filter(h => h.state !== 'trusted').length;
    const label = `Last ${items.length} verification${items.length === 1 ? '' : 's'}: ${items.length - failed} trusted, ${failed} not trusted`;
    return { html: `<span class="strip" role="img" aria-label="${esc(label)}">${ticks.join('')}</span>`, failed, count: items.length };
  }

  function cardHTML(d) {
    const s = stateOf(d.state);
    const href = `#/device/${encodeURIComponent(d.name)}`;
    const where = d.address ? `witnessd at <span class="mono">${esc(d.address)}</span>` : `Replay of <span class="mono">${esc(d.evidence)}</span>`;
    let note = '';
    if (d.state === 'not trusted') {
      const f = d.findings[0];
      const more = d.findings.length > 1 ? ` and ${d.findings.length - 1} more` : '';
      note = `<p class="card-finding">${icon('alert')}<span>${f ? `<b>${esc(f.title)}</b>${more}` : `Evidence rejected: <b>${esc(d.failed_check || 'verification failed')}</b>`}</span></p>`;
    } else if (d.state === 'unreachable') {
      note = `<p class="card-finding warn">${icon('alert')}<span>No answer from the device. It is not trusted until it attests again.</span></p>`;
    }
    const strip = historyStrip(d.history);
    return `
      <div class="state-band">${icon(s.icon)}<span class="state-word">${s.word}</span></div>
      <div class="card-body">
        <div><h2><a href="${href}" data-focus="card-${esc(d.name)}">${esc(d.name)}</a></h2><p class="where">${where}</p></div>
        ${note}
        <dl class="facts">
          <dt>Device key <span class="hint">${d.sealed_proven ? 'proven by TPM signature' : 'agent’s claim, not verified'}</span></dt><dd>${secret(d.sealed)}</dd>
          <dt>Attestation key</dt><dd class="mono">${esc(d.ak_fingerprint || '—')}</dd>
          <dt>Enrollment</dt><dd>${d.enrolled === false ? 'Not enrolled' : d.enrolled ? 'Enrolled' : '—'}</dd>
          <dt>Last checked</dt><dd>${agoTag(d.time)}</dd>
        </dl>
        <div class="card-foot">${strip.html}<span>${!strip.count ? 'No checks yet' : `Last ${strip.count}: ${strip.failed ? `${strip.failed} failed` : 'all trusted'}`}</span></div>
      </div>`;
  }

  function renderFleet(data) {
    if (view.dataset.view !== 'fleet') {
      view.dataset.view = 'fleet';
      view.innerHTML = `
        <div class="page-head">
          <div><h1>Fleet</h1><p id="fleet-sub"></p></div>
          <div class="head-actions"><div class="tally" id="tally"></div>
            <button class="btn" id="verify-all" type="button"><span class="spinner" aria-hidden="true"></span><span class="btn-icon">${icon('refresh')}</span><span class="label">Verify all now</span></button></div>
        </div>
        <div class="grid" id="grid"></div>`;
      document.getElementById('verify-all').addEventListener('click', verifyAll);
      document.title = 'Witness · Fleet';
    }
    const devices = data.devices;
    const count = st => devices.filter(d => d.state === st).length;
    const trusted = count('trusted'), bad = count('not trusted'), warn = count('unreachable');
    patch(document.getElementById('fleet-sub'),
      `${devices.length} device${devices.length === 1 ? '' : 's'}, each re-verified ${data.mode === 'live' ? `every ${data.interval} s with a fresh nonce` : `every ${data.interval} s from its captured quote`}`);
    patch(document.getElementById('tally'),
      `<span class="ok">${icon('shieldOk')}${trusted} trusted</span>` +
      (bad ? `<span class="bad">${icon('shieldBad')}${bad} not trusted</span>` : '') +
      (warn ? `<span class="warn">${icon('alert')}${warn} unreachable</span>` : ''));
    document.title = bad + warn ? `Witness · ${bad + warn} need attention` : 'Witness · Fleet trusted';

    const grid = document.getElementById('grid');
    for (const d of devices) {
      let card = grid.querySelector(`[data-name="${CSS.escape(d.name)}"]`);
      if (!card) {
        card = document.createElement('article');
        card.dataset.name = d.name;
        grid.appendChild(card);
      }
      const flipped = noteState(d);
      card.className = `card ${stateOf(d.state).cls}`;
      patch(card, cardHTML(d));
      if (flipped && d.state !== 'trusted') flip(card);
    }
  }

  async function verifyAll(event) {
    const button = event.currentTarget;
    busy(button, true, 'Verifying…');
    try {
      const started = Date.now();
      await Promise.all((lastFleet?.devices || []).map(d =>
        getJSON(`/api/devices/${encodeURIComponent(d.name)}/verify`, { method: 'POST' }).catch(() => null)));
      await new Promise(r => setTimeout(r, Math.max(0, 600 - (Date.now() - started))));
      await refresh();
      announce('All devices verified');
    } finally {
      busy(button, false, 'Verify all now');
    }
  }

  function busy(button, on, label) {
    button.disabled = on;
    button.classList.toggle('busy', on);
    button.setAttribute('aria-busy', String(on));
    button.querySelector('.label').textContent = label;
  }

  // ---- device detail -----------------------------------------------------
  function findingsHTML(d, latest) {
    if (d.state === 'checking') return `<p class="empty-note">Waiting for the first verification…</p>`;
    if (d.state === 'unreachable') {
      return `<div class="notice">${icon('alert')}<div><b>No answer from the device.</b><br>${esc(d.error)}<br>It stays not trusted until it answers with a valid quote.</div></div>`;
    }
    if (!d.findings.length && d.trusted) {
      return `<div class="all-clear">${icon('check')}<span>No differences from the release. Every measurement matches.</span></div>`;
    }
    if (!d.findings.length) {
      const failed = (latest.checks || []).filter(c => !c.ok).map(c => `<b>${esc(c.name)}</b>: ${esc(c.detail)}`);
      return `<div class="notice">${icon('alert')}<div>The evidence itself failed verification, so its measurements cannot be trusted.<br>${failed.join('<br>')}</div></div>`;
    }
    return `<ul class="findings">${d.findings.map(f => `
      <li class="finding">
        ${icon('alert')}
        <div class="what"><span class="kind">${esc(f.kind)}</span><code>${esc(f.what)}</code></div>
        <div class="where">${esc(f.title.replace(f.what, '').trim() || f.kind)} · ${esc(f.place)}</div>
        ${f.expected || f.actual ? `<dl class="digests">
          ${f.expected ? `<dt>expected</dt><dd title="${esc(f.expected)}">${esc(f.expected.slice(0, 32))}…</dd>` : ''}
          ${f.actual ? `<dt>measured</dt><dd class="got" title="${esc(f.actual)}">${esc(/^[0-9a-f]{64}$/.test(f.actual) ? f.actual.slice(0, 32) + '…' : f.actual)}</dd>` : ''}
        </dl>` : ''}
      </li>`).join('')}</ul>`;
  }

  function chainHTML(latest) {
    const steps = latest?.chain || [];
    const label = { pass: 'Pass', fail: 'Fail', skipped: 'Skipped', 'not reached': 'Not checked' };
    const node = { pass: 'check', fail: 'cross', skipped: 'minus', 'not reached': 'minus' };
    return `<ol class="chain">${steps.map((s, i) => `
      <li class="step ${s.status.replace(' ', '-')}">
        <span class="node">${icon(node[s.status])}</span>
        <div class="step-box">
          <div class="step-title"><span>${i + 1}. ${esc(s.title)}</span>${s.pcrs ? `<span class="pcr-chip">PCR ${esc(s.pcrs)}</span>` : ''}<span class="step-status">${label[s.status]}</span></div>
          <p class="step-explain">${esc(s.explain)}</p>
          <p class="step-result">${esc(s.detail)}</p>
          ${s.checks.length > 1 ? `<ul class="subchecks">${s.checks.map(c => `<li><span class="${c.ok ? 'ok' : 'bad'}">${icon(c.ok ? 'check' : 'cross')}<span class="sr-only">${c.ok ? 'pass' : 'fail'}</span></span><span class="name">${esc(c.name)}</span><span class="detail">${esc(c.detail)}</span></li>`).join('')}</ul>` : ''}
        </div>
      </li>`).join('')}</ol>`;
  }

  function factsHTML(d, latest, data) {
    const q = latest?.quote;
    return `<dl class="facts wide">
      <dt>Device key</dt><dd>${secret(d.sealed)}<span class="hint">${!d.sealed_proven ? 'Reported by the agent, not proven by a signature.' : d.sealed === 'unsealed' ? 'Proven: the key signed this request, and its TPM policy binds it to this device\'s firmware (PCR 0, 2, 7) and the signed release (PCR 4, 5, 8, 9).' : 'Proven: the key signed this request, but the device booted an older signed release, not the current one.'}</span></dd>
      <dt>Attestation key</dt><dd class="mono">${esc(d.ak_fingerprint || '—')}<span class="hint">ECC P-256, derived in the TPM's endorsement hierarchy</span></dd>
      <dt>Enrollment</dt><dd>${d.enrolled ? 'Enrolled (attestation key and firmware baseline recorded)' : 'Not enrolled: run <span class="mono">witness enroll</span> on a known-good boot'}</dd>
      <dt>Evidence</dt><dd>${d.address ? `Live: witnessd at <span class="mono">${esc(d.address)}</span>, fresh nonce each time` : `Replay of <span class="mono">${esc(d.evidence)}</span> with its saved nonce`}</dd>
      ${latest?.agent_device ? `<dt>Agent reports</dt><dd>hostname <span class="mono">${esc(latest.agent_device)}</span></dd>` : ''}
      ${q ? `<dt>TPM quote</dt><dd>reset ${esc(q.reset_count)} · restart ${esc(q.restart_count)} · TPM clock ${(q.clock_ms / 1000).toFixed(1)} s<span class="hint">firmware ${esc(q.firmware_version)}</span></dd>` : ''}
      <dt>Last checked</dt><dd>${agoTag(d.time)}${latest?.duration_ms != null ? ` <span class="hint">took ${esc(latest.duration_ms)} ms</span>` : ''}</dd>
      ${data?.environment ? `<dt>Environment</dt><dd>${esc(data.environment)}</dd>` : ''}
    </dl>`;
  }

  function eventsHTML(latest) {
    const rows = latest?.events;
    if (!rows) return `<p class="empty-note">No event log in this attestation.</p>`;
    const shown = eventFilter === 'diff' ? rows.filter(r => r.status !== 'ok') : rows;
    const body = shown.map(r => {
      const m = ROW[r.status] || ROW.info;
      const differs = r.expected && r.sha256 !== r.expected;
      return `<tr class="${m.cls}">
        <td class="num" data-label="#">${r.index ?? '—'}</td>
        <td data-label="PCR">${r.pcr}</td>
        <td data-label="Result"><span class="badge ${m.badge}">${icon(m.icon)}${m.text}</span></td>
        <td class="path" data-label="File">${esc(r.path)}</td>
        <td class="digest" data-label="SHA-256">${short(r.sha256)}${differs ? `<span class="exp">expected ${short(r.expected)}</span>` : ''}</td>
      </tr>`;
    }).join('') || `<tr><td colspan="5">No differences: every event matches the release.</td></tr>`;
    return `<div class="table-wrap"><table>
      <caption class="sr-only">Witness event log, ${rows.length} events, compared with the release reference</caption>
      <thead><tr><th scope="col">#</th><th scope="col">PCR</th><th scope="col">Result</th><th scope="col">File</th><th scope="col">SHA-256</th></tr></thead>
      <tbody>${body}</tbody></table></div>`;
  }

  function pcrsHTML(latest) {
    const rows = latest?.pcrs;
    if (!rows) return `<p class="empty-note">No PCR values in this attestation.</p>`;
    return `<div class="table-wrap"><table>
      <caption class="sr-only">PCR 0 to 9 as quoted by the TPM</caption>
      <thead><tr><th scope="col">PCR</th><th scope="col">Measures</th><th scope="col">Result</th><th scope="col">Value</th><th scope="col">Compared with</th></tr></thead>
      <tbody>${rows.map(p => {
        const m = p.status === 'ok' ? ROW.ok : p.status === 'changed' ? ROW.changed : ROW.info;
        return `<tr class="${m.cls}"><td class="num" data-label="PCR">${p.pcr}</td><td class="lead" data-label="Measures"><span class="m-only">PCR ${p.pcr} · </span>${PCR_MEANING[p.pcr]}</td>
          <td data-label="Result"><span class="badge ${m.badge}">${icon(m.icon)}${m.text}</span></td>
          <td class="digest" data-label="Value">${short(p.actual)}${p.status === 'changed' ? `<span class="exp">expected ${short(p.expected)}</span>` : ''}</td>
          <td data-label="Compared with">${esc(p.source)}</td></tr>`;
      }).join('')}</tbody></table></div>`;
  }

  function historyHTML(d) {
    const items = d.history.slice().reverse().slice(0, 12);
    if (!items.length) return `<p class="empty-note">No verifications yet.</p>`;
    return `<ul class="history">${items.map(h => {
      const s = stateOf(h.state);
      const badge = { 'is-trusted': 'ok', 'is-bad': 'bad', 'is-warn': 'warn' }[s.cls] || 'info';
      return `<li><time>${esc(clock(h.time))}</time><span class="badge ${badge}">${icon(s.icon)}${s.word}</span><span class="why">${esc(h.findings.join('; '))}</span></li>`;
    }).join('')}</ul>`;
  }

  function renderDetail(d, data) {
    const key = `device:${d.name}`;
    if (view.dataset.view !== key) {
      view.dataset.view = key;
      eventFilter = 'all';
      view.innerHTML = `
        <a class="crumb" href="#/">${icon('back')}Fleet</a>
        <section class="hero" id="hero" aria-labelledby="hero-name">
          <span id="hero-icon"></span>
          <div><div class="hero-word" id="hero-word"></div><h1 id="hero-name">${esc(d.name)}</h1><p class="sub" id="hero-sub"></p></div>
          <button class="btn primary" id="verify" type="button"><span class="spinner" aria-hidden="true"></span><span class="btn-icon">${icon('refresh')}</span><span class="label">Verify now</span></button>
        </section>
        <section class="panel" aria-labelledby="h-findings"><h2 id="h-findings">What changed</h2><p class="lede">Differences between what this device booted and the released image, by file.</p><div id="findings"></div></section>
        <div class="columns">
          <section class="panel" aria-labelledby="h-chain"><h2 id="h-chain">Trust chain</h2><p class="lede">Each stage is measured into the TPM before it runs; the verifier checks them in boot order.</p><div id="chain"></div></section>
          <section class="panel" aria-labelledby="h-facts"><h2 id="h-facts">Device</h2><div id="facts"></div></section>
        </div>
        <section class="panel" aria-labelledby="h-events">
          <div class="panel-head"><div><h2 id="h-events">Event log</h2><p>Every file the device measured at boot, replayed against the quoted PCRs and compared with the release.</p></div>
            <div class="segmented" role="group" aria-label="Event log filter">
              <button type="button" data-filter="all" aria-pressed="true">All events</button><button type="button" data-filter="diff" aria-pressed="false">Differences only</button>
            </div></div>
          <div id="events"></div>
        </section>
        <section class="panel" aria-labelledby="h-pcrs"><h2 id="h-pcrs">Platform Configuration Registers</h2><p class="lede">PCR 0-9 as signed in the TPM quote.</p><div id="pcrs"></div></section>
        <section class="panel" aria-labelledby="h-history"><h2 id="h-history">Recent verifications</h2><div id="history"></div></section>`;
      document.getElementById('verify').addEventListener('click', () => verifyNow(d.name));
      view.querySelectorAll('[data-filter]').forEach(b => b.addEventListener('click', () => {
        eventFilter = b.dataset.filter;
        view.querySelectorAll('[data-filter]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
        patch(document.getElementById('events'), eventsHTML(lastDetail?.latest));
      }));
    }
    lastDetail = d;
    const s = stateOf(d.state);
    const hero = document.getElementById('hero');
    const flipped = noteState(d);
    hero.className = `hero ${s.cls}`;
    patch(document.getElementById('hero-icon'), icon(s.icon, 'hero-icon'));
    patch(document.getElementById('hero-word'), s.word);
    patch(document.getElementById('hero-sub'),
      `${d.address ? `witnessd at <span class="mono">${esc(d.address)}</span>` : `Replay of <span class="mono">${esc(d.evidence)}</span>`} · last checked ${agoTag(d.time)}`);
    if (flipped && d.state !== 'trusted') flip(hero);
    document.title = `Witness · ${d.name} · ${s.word}`;
    const latest = d.latest || {};
    patch(document.getElementById('findings'), findingsHTML(d, latest));
    patch(document.getElementById('chain'), d.latest ? chainHTML(latest) : '<p class="empty-note">Waiting for the first verification…</p>');
    patch(document.getElementById('facts'), factsHTML(d, d.latest, lastFleet));
    patch(document.getElementById('events'), eventsHTML(d.latest));
    patch(document.getElementById('pcrs'), pcrsHTML(d.latest));
    patch(document.getElementById('history'), historyHTML(d));
  }

  async function verifyNow(name) {
    const button = document.getElementById('verify');
    busy(button, true, 'Verifying…');
    try {
      const started = Date.now();
      const d = await getJSON(`/api/devices/${encodeURIComponent(name)}/verify`, { method: 'POST' });
      await new Promise(r => setTimeout(r, Math.max(0, 600 - (Date.now() - started))));
      if (view.dataset.view === `device:${name}`) renderDetail(d, lastFleet);
      announce(`${name} verified just now: ${stateOf(d.state).word}`);
    } catch (error) {
      announce(`Verification request failed: ${error.message}`);
    } finally {
      busy(button, false, 'Verify now');
    }
  }

  // ---- routing and polling -----------------------------------------------
  let lastFleet = null, lastDetail = null, timer = null;
  const route = () => {
    const m = location.hash.match(/^#\/device\/(.+)$/);
    return m ? { device: decodeURIComponent(m[1]) } : { device: null };
  };

  function renderError(error) {
    if (view.dataset.view === 'error') return;
    view.dataset.view = 'error';
    const offline = error instanceof TypeError && /fetch/i.test(error.message);
    view.innerHTML = `<div class="notice">${icon('alert')}<div><b>${offline ? 'The dashboard server is not answering.' : 'Could not show this view.'}</b><br>${esc(error.message)}. Retrying…</div></div>`;
  }

  async function refresh() {
    const { device } = route();
    try {
      lastFleet = await getJSON('/api/devices');
      renderChrome(lastFleet);
      if (!device) return renderFleet(lastFleet);
      if (!lastFleet.devices.some(d => d.name === device)) {
        view.dataset.view = 'missing';
        view.innerHTML = `<a class="crumb" href="#/">${icon('back')}Fleet</a><div class="notice">${icon('alert')}<div>No device named <b>${esc(device)}</b> in this fleet.</div></div>`;
        return;
      }
      renderDetail(await getJSON(`/api/devices/${encodeURIComponent(device)}`), lastFleet);
    } catch (error) {
      console.error(error);
      renderError(error);
    }
  }

  async function loop() {
    clearTimeout(timer);
    await refresh();
    timer = setTimeout(loop, POLL_MS);
  }

  window.addEventListener('hashchange', () => {
    view.dataset.view = '';
    loop().then(() => {
      document.getElementById('main').focus({ preventScroll: true });
      window.scrollTo(0, 0);
    });
  });
  loop();
})();

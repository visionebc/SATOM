// Network Calculator — IPv4 subnet math for FortiWeb / FortiADC.
// Opened from the header "Tools" menu:  FWNetCalc.open()
// 100% client-side (no server round-trip): parses an address in CIDR
// (192.0.2.0/24) or mask (192.0.2.0 255.255.255.0) form, computes the network,
// broadcast, netmask, wildcard, host range + count, splits a block into
// smaller subnets, and checks whether an IP falls inside a network.
// CSP-safe: createElement + addEventListener only, no inline handlers.
(function () {
  if (window.FWNetCalc) return;

  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function $(id) { return document.getElementById(id); }

  // ---- IPv4 helpers (unsigned 32-bit via >>> 0) ------------------------
  function ipToInt(ip) {
    const p = String(ip).trim().split('.');
    if (p.length !== 4) return null;
    let n = 0;
    for (let i = 0; i < 4; i++) {
      const o = Number(p[i]);
      if (!/^\d+$/.test(p[i]) || o < 0 || o > 255) return null;
      n = (n << 8) | o;
    }
    return n >>> 0;
  }
  function intToIp(n) {
    n = n >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  function maskToPrefix(m) {
    // valid netmask = contiguous 1s then 0s
    let n = ipToInt(m);
    if (n === null) return null;
    let ones = 0, seenZero = false;
    for (let i = 31; i >= 0; i--) {
      const bit = (n >>> i) & 1;
      if (bit === 1) { if (seenZero) return null; ones++; }
      else seenZero = true;
    }
    return ones;
  }
  function prefixToMask(p) { return p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0; }

  // Parse "ip/prefix", "ip mask", or bare "ip" (→ /32)
  function parse(input) {
    const s = String(input).trim();
    if (!s) return null;
    let ipStr, prefix;
    if (s.indexOf('/') >= 0) {
      const parts = s.split('/');
      ipStr = parts[0].trim();
      const pr = parts[1].trim();
      if (/^\d+$/.test(pr)) prefix = Number(pr);
      else prefix = maskToPrefix(pr);            // ip/255.255.255.0
    } else if (/\s/.test(s)) {
      const parts = s.split(/\s+/);
      ipStr = parts[0]; prefix = maskToPrefix(parts[1]);
    } else { ipStr = s; prefix = 32; }
    const ip = ipToInt(ipStr);
    if (ip === null || prefix === null || prefix < 0 || prefix > 32) return null;
    return { ip: ip, prefix: prefix };
  }

  function calc(ip, prefix) {
    const mask = prefixToMask(prefix);
    const network = (ip & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const total = Math.pow(2, 32 - prefix);
    let first, last, usable;
    if (prefix >= 31) { first = network; last = broadcast; usable = total; }
    else { first = (network + 1) >>> 0; last = (broadcast - 1) >>> 0; usable = total - 2; }
    return {
      prefix: prefix, mask: mask, network: network, broadcast: broadcast,
      wildcard: (~mask) >>> 0, first: first, last: last, total: total, usable: usable
    };
  }

  function buildModal() {
    if ($('fw-netcalc')) return;
    const wrap = el('div');
    wrap.innerHTML =
'<div class="modal fade" id="fw-netcalc" tabindex="-1" aria-hidden="true">' +
'  <div class="modal-dialog modal-lg modal-dialog-scrollable">' +
'    <div class="modal-content">' +
'      <div class="modal-header py-2">' +
'        <h6 class="modal-title mb-0"><i class="bi bi-calculator me-1"></i>Network Calculator' +
'          <span class="text-muted small fw-normal ms-1">IPv4 subnetting</span></h6>' +
'        <button type="button" class="btn-close ms-auto" data-bs-dismiss="modal" aria-label="Close"></button>' +
'      </div>' +
'      <div class="modal-body pt-2">' +
'        <label class="form-label small fw-bold mb-1">Address' +
'          <span class="text-muted fw-normal">— CIDR (192.0.2.8/24), mask (192.0.2.8 255.255.255.0) or bare IP</span></label>' +
'        <div class="input-group input-group-sm mb-1">' +
'          <input type="text" class="form-control font-monospace" id="fw-nc-input"' +
'                 placeholder="192.0.2.0/24" autocomplete="off" spellcheck="false">' +
'          <button type="button" class="btn btn-outline-secondary" id="fw-nc-clear" title="Clear"><i class="bi bi-x-lg"></i></button>' +
'        </div>' +
'        <div class="btn-group btn-group-sm flex-wrap mb-2" id="fw-nc-quick" role="group"></div>' +
'        <div id="fw-nc-err" class="small text-danger mb-2"></div>' +
'        <div id="fw-nc-out"></div>' +
'        <hr class="my-3">' +
'        <div class="row g-3">' +
'          <div class="col-md-6">' +
'            <label class="form-label small fw-bold mb-1"><i class="bi bi-diagram-3 me-1"></i>Split into /' +
'              <input type="number" min="0" max="32" id="fw-nc-splitpfx" class="form-control form-control-sm d-inline-block"' +
'                     style="width:5rem" placeholder="26"> subnets</label>' +
'            <div id="fw-nc-split" class="small" style="max-height:220px;overflow:auto"></div>' +
'          </div>' +
'          <div class="col-md-6">' +
'            <label class="form-label small fw-bold mb-1"><i class="bi bi-crosshair me-1"></i>Is this IP inside?</label>' +
'            <input type="text" class="form-control form-control-sm font-monospace mb-1" id="fw-nc-checkip"' +
'                   placeholder="192.0.2.42" autocomplete="off" spellcheck="false">' +
'            <div id="fw-nc-check" class="small"></div>' +
'          </div>' +
'        </div>' +
'      </div>' +
'    </div>' +
'  </div>' +
'</div>';
    document.body.appendChild(wrap.firstElementChild);

    // Quick prefix buttons
    const quick = $('fw-nc-quick');
    [8, 16, 24, 25, 26, 27, 28, 30].forEach(function (p) {
      const b = el('button', 'btn btn-outline-secondary', '/' + p);
      b.type = 'button';
      b.addEventListener('click', function () {
        const cur = parse($('fw-nc-input').value) || { ip: 0 };
        $('fw-nc-input').value = intToIp(cur.ip) + '/' + p;
        run();
      });
      quick.appendChild(b);
    });
    $('fw-nc-input').addEventListener('input', run);
    $('fw-nc-splitpfx').addEventListener('input', run);
    $('fw-nc-checkip').addEventListener('input', run);
    $('fw-nc-clear').addEventListener('click', function () {
      $('fw-nc-input').value = ''; $('fw-nc-splitpfx').value = '';
      $('fw-nc-checkip').value = ''; run();
    });
  }

  function row(label, value, mono) {
    return '<div class="d-flex justify-content-between border-bottom py-1">' +
      '<span class="text-muted">' + esc(label) + '</span>' +
      '<span class="' + (mono ? 'font-monospace ' : '') + 'text-end">' + esc(value) + '</span></div>';
  }

  function run() {
    const raw = $('fw-nc-input').value;
    const err = $('fw-nc-err'), out = $('fw-nc-out');
    const split = $('fw-nc-split'), check = $('fw-nc-check');
    split.innerHTML = ''; check.innerHTML = '';
    if (!raw.trim()) { err.textContent = ''; out.innerHTML = ''; return; }
    const p = parse(raw);
    if (!p) { err.textContent = 'Invalid address / mask / prefix.'; out.innerHTML = ''; return; }
    err.textContent = '';
    const c = calc(p.ip, p.prefix);
    const hostRange = c.usable > 0
      ? intToIp(c.first) + ' – ' + intToIp(c.last)
      : '— (no usable host)';
    out.innerHTML =
      row('Network', intToIp(c.network) + '/' + c.prefix, true) +
      row('Netmask', intToIp(c.mask), true) +
      row('Wildcard', intToIp(c.wildcard), true) +
      row('Broadcast', intToIp(c.broadcast), true) +
      row('Host range', hostRange, true) +
      row('Usable hosts', c.usable.toLocaleString()) +
      row('Total addresses', c.total.toLocaleString());

    // ---- split ----
    const np = Number($('fw-nc-splitpfx').value);
    if ($('fw-nc-splitpfx').value !== '' && (isNaN(np) || np < 0 || np > 32)) {
      split.innerHTML = '<span class="text-danger">Prefix must be 0–32.</span>';
    } else if ($('fw-nc-splitpfx').value !== '') {
      if (np < c.prefix) {
        split.innerHTML = '<span class="text-danger">/' + np + ' is larger than /' + c.prefix + '.</span>';
      } else {
        const count = Math.pow(2, np - c.prefix);
        const step = Math.pow(2, 32 - np);
        const cap = 256;
        let html = '<div class="text-muted mb-1">' + count.toLocaleString() +
          ' × /' + np + '</div><div class="list-group list-group-flush">';
        for (let i = 0; i < Math.min(count, cap); i++) {
          const net = (c.network + i * step) >>> 0;
          html += '<div class="list-group-item px-0 py-1 font-monospace border-0">' +
            esc(intToIp(net) + '/' + np) + '</div>';
        }
        if (count > cap) html += '<div class="text-muted">… ' + (count - cap).toLocaleString() + ' more</div>';
        split.innerHTML = html + '</div>';
      }
    }

    // ---- contains ----
    const cip = $('fw-nc-checkip').value.trim();
    if (cip) {
      const ci = ipToInt(cip);
      if (ci === null) check.innerHTML = '<span class="text-danger">Invalid IP.</span>';
      else {
        const inside = (ci >= c.network && ci <= c.broadcast);
        check.innerHTML = inside
          ? '<span class="text-success"><i class="bi bi-check-circle me-1"></i>' + esc(cip) +
            ' is inside ' + esc(intToIp(c.network) + '/' + c.prefix) + '</span>'
          : '<span class="text-danger"><i class="bi bi-x-circle me-1"></i>' + esc(cip) +
            ' is outside this network</span>';
      }
    }
  }

  function modalObj() {
    if (window.bootstrap && bootstrap.Modal) return bootstrap.Modal.getOrCreateInstance($('fw-netcalc'));
    return null;
  }

  window.FWNetCalc = {
    open: function (prefill) {
      buildModal();
      if (prefill) $('fw-nc-input').value = prefill;
      run();
      const m = modalObj();
      if (m) m.show(); else $('fw-netcalc').style.display = 'block';
      setTimeout(function () { const i = $('fw-nc-input'); if (i) i.focus(); }, 150);
    }
  };
})();

/* Naming patterns in the browser — the live checks of Administrator → Naming.
 *
 * ``toRegex`` is the JavaScript twin of ``services.naming_discovery.
 * pattern_regex``: {name} (and every token listed as free — {host} and the
 * naming variables on a catalog element) is free text, {port}/{num} digits,
 * {proto} a protocol word, any other token one part without a separator. The
 * server re-checks everything it stores; this only gives the operator the
 * count while typing.
 *
 * ``render`` substitutes token VALUES the server computed (POST
 * /naming/preview runs the variables' regular expressions in Python), so the
 * preview never depends on JavaScript's regex dialect.
 */
window.NamingPattern = (function () {
  'use strict';
  var TOKEN = /\{([a-z0-9_-]+)\}/g;
  var SAMPLE = { port: '443', proto: 'https', adom: 'root', num: '1', host: 'shop',
                 ip: '192.0.2.1', device: 'device01', 'class': 'server', date: '20260701',
                 serial: 'a3f1' };

  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function slugify(addr) {
    var s = (addr || '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//, '');
    s = s.split('/')[0].split('?')[0].split(':')[0];
    s = s.replace(/[^a-z0-9]+/g, '-');
    return s.replace(/^-+|-+$/g, '');
  }

  function toRegex(pattern, proto, free) {
    if (!pattern) return null;
    var out = '', pos = 0, m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(pattern)) !== null) {
      out += esc(pattern.slice(pos, m.index));
      var t = m[1];
      if (t === 'name' || (free || []).indexOf(t) >= 0) out += '(?:.+?)';
      else if (t === 'port' || t === 'num') out += '(?:\\d+)';
      else if (t === 'proto') out += '(?:' + (proto || []).map(esc).join('|') + ')';
      else out += '(?:[^\\-_.\\s]+)';
      pos = TOKEN.lastIndex;
    }
    out += esc(pattern.slice(pos));
    try { return new RegExp('^' + out + '$', 'i'); } catch (e) { return null; }
  }

  function check(pattern, names, proto, free) {
    var rx = toRegex(pattern, proto, free);
    if (!rx) return null;
    var misses = (names || []).filter(function (n) { return !rx.test(n); });
    return { conform: names.length - misses.length, total: names.length, misses: misses };
  }

  /* Why an entry SATOM builds names from cannot take this pattern ("" = it can).
   * ``allowed`` is the token list the server sent for the entry
   * (``naming.allowed_tokens``); a boolean is the older call: true = the
   * certificate tokens, false = the site tokens. */
  function derivesProblem(pattern, allowed) {
    if (!Array.isArray(allowed)) {
      allowed = allowed ? ['name', 'class', 'cn', 'date', 'serial'] : ['name', 'host', 'port'];
    }
    var extra = [], m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(pattern)) !== null) {
      if (allowed.indexOf(m[1]) < 0 && extra.indexOf(m[1]) < 0) extra.push('{' + m[1] + '}');
    }
    return extra.length ? 'SATOM only fills in {' + allowed.join('} {') + '} here; '
      + extra.join(', ') + ' would be written literally' : '';
  }

  /* The name a pattern gives the sample site (other tokens get sample values). */
  function sample(pattern, slug) {
    var out = pattern.replace(TOKEN, function (_, t) {
      if (t === 'name' || t === 'cn') return slug;
      return Object.prototype.hasOwnProperty.call(SAMPLE, t) ? SAMPLE[t] : t;
    });
    out = out.replace(/[-_.]{2,}/g, '-').replace(/^[-_.]+|[-_.]+$/g, '');
    return out.substring(0, 63);
  }

  /* A pattern under real token values: unknown tokens stay literal and the
   * result is capped like ``naming.render_pattern``. */
  function render(pattern, tokens) {
    TOKEN.lastIndex = 0;
    var out = (pattern || '').replace(TOKEN, function (whole, t) {
      return Object.prototype.hasOwnProperty.call(tokens || {}, t) ? tokens[t] : whole;
    });
    return out.substring(0, 63);
  }

  /* Why a rendered name cannot be built ("" = it can) — ``naming.unsafe_name``. */
  function unsafe(name) {
    if (!name) return 'renders empty';
    return /^[A-Za-z0-9_-]+$/.test(name) ? '' : 'only letters, digits, _ and - are allowed';
  }

  return { slugify: slugify, toRegex: toRegex, check: check,
           derivesProblem: derivesProblem, sample: sample,
           render: render, unsafe: unsafe };
})();

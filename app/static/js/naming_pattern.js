/* Naming patterns in the browser — the live checks of Administrator → Naming.
 *
 * ``toRegex`` is the JavaScript twin of ``services.naming_discovery.
 * pattern_regex``: {name} is the free part, {port}/{num} digits, {proto} a
 * protocol word, any other token one part without a separator. The server
 * re-checks everything it stores; this only gives the operator the count
 * while typing.
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

  function toRegex(pattern, proto) {
    if (!pattern) return null;
    var out = '', pos = 0, m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(pattern)) !== null) {
      out += esc(pattern.slice(pos, m.index));
      var t = m[1];
      if (t === 'name') out += '(?:.+?)';
      else if (t === 'port' || t === 'num') out += '(?:\\d+)';
      else if (t === 'proto') out += '(?:' + (proto || []).map(esc).join('|') + ')';
      else out += '(?:[^\\-_.\\s]+)';
      pos = TOKEN.lastIndex;
    }
    out += esc(pattern.slice(pos));
    try { return new RegExp('^' + out + '$', 'i'); } catch (e) { return null; }
  }

  function check(pattern, names, proto) {
    var rx = toRegex(pattern, proto);
    if (!rx) return null;
    var misses = (names || []).filter(function (n) { return !rx.test(n); });
    return { conform: names.length - misses.length, total: names.length, misses: misses };
  }

  /* Why an entry SATOM builds names from cannot take this pattern ("" = it can). */
  function derivesProblem(pattern, cert) {
    var allowed = cert ? ['name', 'class', 'cn', 'date', 'serial'] : ['name'];
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

  return { slugify: slugify, toRegex: toRegex, check: check,
           derivesProblem: derivesProblem, sample: sample };
})();

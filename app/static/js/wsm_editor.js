/* Web Server Manager: a small code editor -- a textarea over a highlighted
 * <pre>, line numbers, Tab indents. No third-party code: SATOM serves every
 * browser asset itself (offline installs render the same).
 *
 *   var ed = WsmEditor.create(container, {text: "...", lang: "php"});
 *   ed.value(); ed.setValue(t); ed.setLang("nginx"); ed.onChange(fn);
 *   WsmEditor.langOf("/etc/nginx/sites-available/x") -> "nginx"
 */
(function () {
  'use strict';
  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  var STR = /"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/;
  var NUM = /\b\d+(?:\.\d+)?\b/;
  function kw(list) { return new RegExp('\\b(?:' + list.split(' ').join('|') + ')\\b'); }
  var L = {
    php: [[/\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*/, 'c'], [/<\?php|\?>/, 'd'], [STR, 's'], [/\$[A-Za-z_]\w*/, 'v'],
      [kw('function return if else elseif foreach for while do switch case break continue new class public private protected static echo require require_once include include_once use namespace try catch finally throw array null true false and or isset empty unset'), 'k'], [NUM, 'n']],
    js: [[/\/\*[\s\S]*?\*\/|\/\/[^\n]*/, 'c'], [/`(?:[^`\\]|\\.)*`/, 's'], [STR, 's'],
      [kw('function return if else for while do switch case break continue new class const let var this try catch finally throw typeof instanceof null undefined true false async await import export from default'), 'k'], [NUM, 'n']],
    python: [[/#[^\n]*/, 'c'], [/"""[\s\S]*?"""|'''[\s\S]*?'''/, 's'], [STR, 's'],
      [kw('def return if elif else for while in not and or import from as class try except finally raise with lambda pass break continue None True False yield global async await is'), 'k'], [NUM, 'n']],
    bash: [[/#[^\n]*/, 'c'], [STR, 's'], [/\$\{?[A-Za-z_]\w*\}?|\$[0-9@#?*]/, 'v'],
      [kw('if then else elif fi for while do done case esac in function return export local set echo exit source'), 'k'], [NUM, 'n']],
    css: [[/\/\*[\s\S]*?\*\//, 'c'], [STR, 's'], [/#[0-9A-Fa-f]{3,8}\b/, 'n'], [/[A-Za-z-]+(?=\s*:)/, 'a'], [/[.#][A-Za-z_][\w-]*/, 't'], [NUM, 'n']],
    html: [[/<!--[\s\S]*?-->/, 'c'], [/<\/?[A-Za-z][\w:-]*/, 't'], [/\s[A-Za-z_:][\w:.-]*(?==)/, 'a'], [STR, 's'], [/\/?>/, 't']],
    json: [[/"(?:[^"\\\n]|\\.)*"(?=\s*:)/, 'a'], [STR, 's'], [kw('true false null'), 'k'], [/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/, 'n']],
    yaml: [[/#[^\n]*/, 'c'], [/^[ \t-]*[A-Za-z_][\w .-]*(?=:)/m, 'a'], [STR, 's'], [kw('true false null yes no on off'), 'k'], [NUM, 'n']],
    xml: [[/<!--[\s\S]*?-->/, 'c'], [/<\?[\s\S]*?\?>/, 'd'], [/<\/?[A-Za-z][\w:.-]*/, 't'], [/\s[A-Za-z_:][\w:.-]*(?==)/, 'a'], [STR, 's'], [/\/?>/, 't']],
    nginx: [[/#[^\n]*/, 'c'], [STR, 's'], [/\$[A-Za-z_]\w*/, 'v'], [/^\s*[a-z_]+(?=[\s{;])/m, 'k'], [kw('on off'), 'a'], [NUM, 'n']],
    apache: [[/#[^\n]*/, 'c'], [/<\/?[A-Za-z]+[^>]*>/, 't'], [STR, 's'], [/%\{[A-Z_:]+\}|\$\d/, 'v'], [/^\s*[A-Z][A-Za-z]+(?=\s)/m, 'k'], [/\[[A-Z0-9=,]+\]/, 'a'], [NUM, 'n']],
    ini: [[/[#;][^\n]*/, 'c'], [/^\s*\[[^\]\n]+\]/m, 't'], [/^\s*[A-Za-z_][\w.-]*(?=\s*=)/m, 'a'], [STR, 's'], [NUM, 'n']],
    plain: []
  };
  L.perl = L.bash; L.sh = L.bash; L.htaccess = L.apache; L.cron = L.bash;

  function highlight(text, lang) {
    var rules = L[lang] || [];
    if (!rules.length || text.length > 400000) return esc(text);
    var src = rules.map(function (r) { return '(' + r[0].source + ')'; }).join('|');
    var flags = 'g' + (rules.some(function (r) { return r[0].multiline; }) ? 'm' : '');
    var re = new RegExp(src, flags), out = '', last = 0, m;
    while ((m = re.exec(text)) !== null) {
      if (m[0] === '') { re.lastIndex++; continue; }
      out += esc(text.slice(last, m.index));
      for (var i = 1; i < m.length; i++) {
        if (m[i] !== undefined) { out += '<span class="tk-' + rules[i - 1][1] + '">' + esc(m[0]) + '</span>'; break; }
      }
      last = m.index + m[0].length;
    }
    return out + esc(text.slice(last));
  }

  function langOf(path) {
    var p = (path || '').toLowerCase(), base = p.split('/').pop();
    if (base === '.htaccess' || /\/(apache2|httpd)\//.test(p)) return 'apache';
    if (/\/nginx\//.test(p)) return 'nginx';
    var ext = (base.match(/\.([a-z0-9]+)$/) || [])[1] || '';
    return ({ php: 'php', phtml: 'php', js: 'js', mjs: 'js', ts: 'js', json: 'json', py: 'python',
      sh: 'bash', bash: 'bash', pl: 'perl', css: 'css', scss: 'css', html: 'html', htm: 'html',
      xml: 'xml', svg: 'xml', yml: 'yaml', yaml: 'yaml', ini: 'ini', conf: 'nginx', cnf: 'ini',
      env: 'ini', service: 'ini', timer: 'ini', md: 'plain', txt: 'plain' })[ext] || 'plain';
  }

  function create(host, opts) {
    opts = opts || {};
    host.classList.add('wsm-editor');
    if (opts.height) host.style.height = opts.height;
    host.innerHTML = '<div class="gutter"></div><pre aria-hidden="true"></pre><textarea spellcheck="false" autocapitalize="off" autocomplete="off" aria-label="Editor"></textarea>';
    var gut = host.querySelector('.gutter'), pre = host.querySelector('pre'), ta = host.querySelector('textarea');
    var lang = opts.lang || 'plain', listeners = [];
    if (opts.readOnly) ta.readOnly = true;
    function paint() {
      pre.innerHTML = highlight(ta.value, lang) + '\n';
      var n = ta.value.split('\n').length, g = '';
      for (var i = 1; i <= n; i++) g += i + '\n';
      gut.textContent = g;
      sync();
    }
    function sync() { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; gut.scrollTop = ta.scrollTop; }
    ta.addEventListener('input', function () { paint(); listeners.forEach(function (f) { f(); }); });
    ta.addEventListener('scroll', sync);
    ta.addEventListener('keydown', function (e) {
      if (e.key === 'Tab' && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        var s = ta.selectionStart, en = ta.selectionEnd;
        ta.value = ta.value.slice(0, s) + '    ' + ta.value.slice(en);
        ta.selectionStart = ta.selectionEnd = s + 4;
        paint(); listeners.forEach(function (f) { f(); });
      }
      if ((e.ctrlKey || e.metaKey) && e.key === 's' && opts.onSave) { e.preventDefault(); opts.onSave(); }
    });
    ta.value = opts.text || '';
    paint();
    return {
      value: function () { return ta.value; },
      setValue: function (t) { ta.value = t || ''; paint(); },
      setLang: function (l) { lang = L[l] ? l : 'plain'; paint(); },
      lang: function () { return lang; },
      onChange: function (f) { listeners.push(f); },
      focus: function () { ta.focus(); },
      textarea: ta
    };
  }
  window.WsmEditor = { create: create, langOf: langOf, highlight: highlight, langs: Object.keys(L) };
})();

/* Plugin Studio folder pickers (2026-11-06): every <select data-folder-select>
 * -- the app's Settings, New app, the Apps row "Set folder" and the bundle
 * import -- lists the folders that exist and ends with "+ New folder…".
 * Picking it asks for the name and adds it as the selected option; the
 * folder is made when the form it belongs to is saved
 * (studio_apps.clean_group), so a cancelled form leaves no empty folder.
 * A name that only differs in case from an existing folder picks that one.
 * Same rule as the server (_GROUP_RE): a letter or digit first, then up to
 * 47 letters, digits, spaces and . & ( ) + , ' -
 */
(function () {
  'use strict';
  var NEW = '__new__';
  var RE = /^[\p{L}\p{N}_][\p{L}\p{N}_ .&()+,'-]{0,47}$/u;
  function bind(sel) {
    var last = sel.value === NEW ? '' : sel.value;
    sel.addEventListener('focus', function () { if (sel.value !== NEW) last = sel.value; });
    sel.addEventListener('change', function () {
      if (sel.value !== NEW) { last = sel.value; return; }
      var raw = window.prompt('Name of the new folder:', '');
      var name = (raw || '').split(/\s+/).filter(Boolean).join(' ');
      if (!name) { sel.value = last; return; }
      if (!RE.test(name)) {
        window.alert('A folder name has up to 48 letters, digits, spaces and . & ( ) + , \' - ' +
                     'and starts with a letter or a digit.');
        sel.value = last; return;
      }
      for (var i = 0; i < sel.options.length; i++) {
        var o = sel.options[i];
        if (o.value !== NEW && o.value.charAt(0) !== '_' && o.value &&
            o.value.toLowerCase() === name.toLowerCase()) {
          sel.value = o.value; last = o.value; sel.dispatchEvent(new Event('input')); return;
        }
      }
      var opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name + ' (new)';
      sel.insertBefore(opt, sel.querySelector('option[value="' + NEW + '"]'));
      sel.value = name; last = name;
      sel.dispatchEvent(new Event('input'));
    });
  }
  function init(root) {
    (root || document).querySelectorAll('select[data-folder-select]').forEach(bind);
  }
  window.satomFolderSelect = { init: init, bind: bind };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { init(); });
  else init();
})();

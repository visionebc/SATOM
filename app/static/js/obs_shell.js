/* Observability shell (2026-11-17): Chart.js defaults for SATOM's Monitoring
   pages drawn on the Observability theme. Loaded in <head> right after
   Chart.js and only in the shell (base.html, obs_shell), so every chart a page
   builds later inherits the dark axis, grid and legend colours of the app's
   own charts (theme.css: --viz-axis, --viz-grid, --obs-text-2). */
(function () {
  'use strict';
  if (!window.Chart || !window.Chart.defaults) return;
  var d = window.Chart.defaults;
  d.color = '#a3b3cf';            /* --obs-text-2 */
  d.borderColor = '#1f2c49';      /* --viz-grid */
  d.font.family = "'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif";
  if (d.scale && d.scale.grid) d.scale.grid.color = '#1f2c49';
  if (d.scale && d.scale.ticks) d.scale.ticks.color = '#8394b3';   /* --viz-axis */
  if (d.plugins && d.plugins.tooltip) {
    d.plugins.tooltip.backgroundColor = '#1c2945';                  /* --obs-surface-3 */
    d.plugins.tooltip.borderColor = '#26365a';
    d.plugins.tooltip.borderWidth = 1;
    d.plugins.tooltip.titleColor = '#e6edf7';
    d.plugins.tooltip.bodyColor = '#a3b3cf';
  }
})();

/* ════════════════════════════════════════════════════════════════
   Query Forge — core.js
   Helpers mínimos: esc, toast, copyToClipboard, init Lucide.
   ════════════════════════════════════════════════════════════════ */

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let _toastEl = null;
let _toastTimer = null;
function toast(msg, type) {
  if (!_toastEl) {
    _toastEl = document.createElement('div');
    _toastEl.className = 'toast';
    document.body.appendChild(_toastEl);
  }
  _toastEl.textContent = msg;
  _toastEl.className = 'toast ' + (type || '') + ' show';
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(function() {
    _toastEl.className = 'toast ' + (type || '');
  }, 2200);
}

function copyToClipboard(text) {
  return navigator.clipboard.writeText(text);
}

document.addEventListener('DOMContentLoaded', function() {
  if (window.lucide && typeof lucide.createIcons === 'function') {
    lucide.createIcons();
  }
  if (typeof forgeShowEmpty === 'function') {
    forgeShowEmpty();
  }
});

// threats.js — Threat table interactions

document.addEventListener('DOMContentLoaded', () => {
  // Live search filter on threats table
  const searchInput = document.getElementById('threatSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase();
      document.querySelectorAll('#threatsTable tbody tr[id^="threat-"]').forEach(row => {
        const visible = row.textContent.toLowerCase().includes(q);
        row.style.display = visible ? '' : 'none';
        // Also hide its evidence row
        const evRow = row.nextElementSibling;
        if (evRow && evRow.id && evRow.id.startsWith('ev-')) {
          if (!visible) evRow.style.display = 'none';
        }
      });
    });
  }
});

function toggleEvidence(id) {
  const evRow = document.getElementById('ev-' + id);
  if (!evRow) return;
  const isShown = evRow.style.display !== 'none';
  evRow.style.display = isShown ? 'none' : 'table-row';
}

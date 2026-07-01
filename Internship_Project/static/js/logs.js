// logs.js — Log page interactions

let currentPage = 1;
let currentSessionId = null;

document.addEventListener('DOMContentLoaded', () => {
  // Upload zone drag-and-drop
  const zone = document.getElementById('uploadZone');
  const input = document.getElementById('logfile');

  if (zone && input) {
    zone.addEventListener('dragover', e => {
      e.preventDefault();
      zone.classList.add('dragover');
    });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) {
        input.files = e.dataTransfer.files;
        updateFileName(e.dataTransfer.files[0].name);
      }
    });

    input.addEventListener('change', () => {
      if (input.files.length > 0) updateFileName(input.files[0].name);
    });
  }

  // Session search filter
  const searchInput = document.getElementById('sessionSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase();
      document.querySelectorAll('#sessionsTable tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
});

function updateFileName(name) {
  const title = document.getElementById('uploadTitle');
  if (title) {
    title.textContent = '✅ ' + name;
    title.style.color = 'var(--accent-green)';
  }
}

// Upload form feedback
const uploadForm = document.getElementById('uploadForm');
if (uploadForm) {
  uploadForm.addEventListener('submit', () => {
    const btn = document.getElementById('uploadBtn');
    btn.innerHTML = '<div class="spinner"></div> Analyzing...';
    btn.disabled = true;
  });
}

// Log entries browser
function loadEntries() {
  const sessionId = document.getElementById('sessionSelect').value;
  if (!sessionId) { showToast('Please select a session first.', 'info'); return; }
  currentSessionId = sessionId;
  currentPage = 1;
  fetchEntries();
}

function fetchEntries() {
  const ip     = document.getElementById('ipFilter').value.trim();
  const status = document.getElementById('statusFilter').value.trim();

  const url = `/api/logs/${currentSessionId}?page=${currentPage}&per_page=50`
    + (ip     ? `&ip=${encodeURIComponent(ip)}`     : '')
    + (status ? `&status=${encodeURIComponent(status)}` : '');

  fetch(url)
    .then(r => r.json())
    .then(data => {
      const tbody = document.getElementById('entriesBody');
      tbody.innerHTML = '';

      if (!data.data || data.data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-secondary);padding:20px;">No entries found</td></tr>';
      } else {
        data.data.forEach(e => {
          const statusClass = e.status >= 500 ? 'color:var(--accent-red)' :
                              e.status >= 400 ? 'color:var(--accent-orange)' :
                              e.status >= 300 ? 'color:var(--accent-blue)' :
                              'color:var(--accent-green)';
          tbody.innerHTML += `
            <tr>
              <td><span class="ip-tag">${e.ip || '—'}</span></td>
              <td style="font-size:11px;color:var(--text-secondary);">${e.timestamp || '—'}</td>
              <td><span style="font-family:'JetBrains Mono',monospace;font-size:11px;">${e.method || '—'}</span></td>
              <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;"
                  title="${e.path || ''}">${e.path || '—'}</td>
              <td style="${statusClass};font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;">${e.status || '—'}</td>
              <td class="mono" style="font-size:11px;">${e.bytes_sent ? e.bytes_sent.toLocaleString() : '—'}</td>
            </tr>`;
        });
      }

      document.getElementById('pageInfo').textContent =
        `Page ${data.page} of ${data.pages} (${data.total.toLocaleString()} entries)`;
      document.getElementById('prevBtn').disabled = data.page <= 1;
      document.getElementById('nextBtn').disabled = data.page >= data.pages;
      document.getElementById('entriesContainer').style.display = 'block';
    })
    .catch(() => showToast('Error loading entries.', 'info'));
}

function changePage(delta) {
  currentPage += delta;
  if (currentPage < 1) currentPage = 1;
  fetchEntries();
}

// Delete modal
function confirmDelete(id, name) {
  document.getElementById('deleteMsg').textContent =
    `Are you sure you want to delete "${name}" and all its threats?`;
  document.getElementById('deleteForm').action = `/logs/delete/${id}`;
  document.getElementById('deleteModal').style.display = 'flex';
}

function closeDeleteModal() {
  document.getElementById('deleteModal').style.display = 'none';
}

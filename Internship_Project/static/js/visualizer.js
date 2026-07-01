// visualizer.js — Chart.js interactive visualizations

let charts = {};
let granularity = 'hour';

const CHART_COLORS = {
  blue:   '#58a6ff',
  red:    '#f85149',
  orange: '#d29922',
  green:  '#3fb950',
  purple: '#bc8cff',
  cyan:   '#39c5cf',
  yellow: '#eab308',
  pink:   '#ff7c7c',
};

const SEVERITY_COLORS = {
  Critical: '#f85149',
  High:     '#d29922',
  Medium:   '#eab308',
  Low:      '#3fb950',
};

const PALETTE = Object.values(CHART_COLORS);

const CHART_BASE_OPTIONS = {
  responsive: true,
  maintainAspectRatio: false,
  animation: { duration: 600, easing: 'easeInOutQuart' },
  plugins: {
    legend: {
      labels: {
        color: '#8b949e',
        font: { size: 11, family: 'Inter' },
        usePointStyle: true,
        pointStyleWidth: 8,
      }
    },
    tooltip: {
      backgroundColor: '#161b22',
      borderColor: '#30363d',
      borderWidth: 1,
      titleColor: '#e6edf3',
      bodyColor: '#8b949e',
      padding: 12,
      cornerRadius: 8,
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  applyChartDefaults();
  refreshAllCharts();
});

function getSessionId() {
  const sel = document.getElementById('globalSessionSelect');
  return sel ? sel.value : '';
}

function setGranularity(g) {
  granularity = g;
  loadTimeline();
}

function refreshAllCharts() {
  loadTimeline();
  loadTopIPs();
  loadStatusCodes();
  loadThreatTypes();
  loadSeverityChart();
}

// ── Timeline ─────────────────────────────────────────────────────────
function loadTimeline() {
  const sid = getSessionId();
  const url = `/api/charts/timeline?granularity=${granularity}${sid ? '&session_id=' + sid : ''}`;

  fetch(url).then(r => r.json()).then(data => {
    destroyChart('timelineChart');

    const ctx = document.getElementById('timelineChart').getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 240);
    gradient.addColorStop(0, 'rgba(88, 166, 255, 0.3)');
    gradient.addColorStop(1, 'rgba(88, 166, 255, 0)');

    charts['timelineChart'] = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Requests',
          data: data.data,
          borderColor: CHART_COLORS.blue,
          backgroundColor: gradient,
          fill: true,
          tension: 0.4,
          pointBackgroundColor: CHART_COLORS.blue,
          pointBorderColor: '#0d1117',
          pointBorderWidth: 2,
          pointRadius: data.labels.length > 50 ? 0 : 4,
          pointHoverRadius: 6,
        }]
      },
      options: {
        ...CHART_BASE_OPTIONS,
        scales: {
          x: {
            grid: { color: 'rgba(48,54,61,0.6)' },
            ticks: { color: '#8b949e', font: { size: 10 }, maxTicksLimit: 12 }
          },
          y: {
            grid: { color: 'rgba(48,54,61,0.6)' },
            ticks: { color: '#8b949e', font: { size: 10 } },
            beginAtZero: true
          }
        },
        plugins: {
          ...CHART_BASE_OPTIONS.plugins,
          legend: { display: false }
        }
      }
    });
  });
}

// ── Top IPs ──────────────────────────────────────────────────────────
function loadTopIPs() {
  const sid = getSessionId();
  fetch(`/api/charts/top-ips${sid ? '?session_id=' + sid : ''}`)
    .then(r => r.json()).then(data => {
      destroyChart('topIpsChart');

      const colors = data.labels.map((_, i) => PALETTE[i % PALETTE.length]);
      charts['topIpsChart'] = new Chart(
        document.getElementById('topIpsChart').getContext('2d'), {
        type: 'bar',
        data: {
          labels: data.labels,
          datasets: [{
            label: 'Requests',
            data: data.data,
            backgroundColor: colors.map(c => c + 'bb'),
            borderColor: colors,
            borderWidth: 1,
            borderRadius: 4,
          }]
        },
        options: {
          ...CHART_BASE_OPTIONS,
          indexAxis: 'y',
          scales: {
            x: {
              grid: { color: 'rgba(48,54,61,0.6)' },
              ticks: { color: '#8b949e', font: { size: 10 } },
              beginAtZero: true
            },
            y: {
              grid: { display: false },
              ticks: {
                color: '#39c5cf',
                font: { family: 'JetBrains Mono', size: 11 }
              }
            }
          },
          plugins: { ...CHART_BASE_OPTIONS.plugins, legend: { display: false } }
        }
      });
    });
}

// ── Status Codes ─────────────────────────────────────────────────────
function loadStatusCodes() {
  const sid = getSessionId();
  fetch(`/api/charts/status-codes${sid ? '?session_id=' + sid : ''}`)
    .then(r => r.json()).then(data => {
      destroyChart('statusChart');

      const colorMap = s => {
        const code = parseInt(s);
        if (code >= 500) return CHART_COLORS.red;
        if (code >= 400) return CHART_COLORS.orange;
        if (code >= 300) return CHART_COLORS.blue;
        if (code >= 200) return CHART_COLORS.green;
        return CHART_COLORS.cyan;
      };

      const colors = data.labels.map(colorMap);
      charts['statusChart'] = new Chart(
        document.getElementById('statusChart').getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: data.labels.map(s => `${s} (${statusDesc(s)})`),
          datasets: [{
            data: data.data,
            backgroundColor: colors.map(c => c + 'cc'),
            borderColor: colors,
            borderWidth: 2,
            hoverOffset: 8,
          }]
        },
        options: {
          ...CHART_BASE_OPTIONS,
          cutout: '60%',
          plugins: {
            ...CHART_BASE_OPTIONS.plugins,
            legend: {
              position: 'right',
              labels: {
                color: '#8b949e', font: { size: 10 },
                padding: 8, usePointStyle: true, pointStyleWidth: 6
              }
            }
          }
        }
      });
    });
}

function statusDesc(code) {
  const m = { '200':'OK', '301':'Redirect', '302':'Found', '400':'Bad Req',
              '401':'Unauth', '403':'Forbidden', '404':'Not Found',
              '500':'Server Err', '502':'Bad Gateway', '503':'Unavailable' };
  return m[code] || '';
}

// ── Threat Types ─────────────────────────────────────────────────────
function loadThreatTypes() {
  const sid = getSessionId();
  fetch(`/api/charts/threat-types${sid ? '?session_id=' + sid : ''}`)
    .then(r => r.json()).then(data => {
      destroyChart('threatTypeChart');

      const colors = data.labels.map((_, i) => PALETTE[i % PALETTE.length]);
      charts['threatTypeChart'] = new Chart(
        document.getElementById('threatTypeChart').getContext('2d'), {
        type: 'bar',
        data: {
          labels: data.labels,
          datasets: [{
            label: 'Count',
            data: data.data,
            backgroundColor: colors.map(c => c + 'bb'),
            borderColor: colors,
            borderWidth: 1,
            borderRadius: 6,
          }]
        },
        options: {
          ...CHART_BASE_OPTIONS,
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 30 }
            },
            y: {
              grid: { color: 'rgba(48,54,61,0.6)' },
              ticks: { color: '#8b949e', font: { size: 10 } },
              beginAtZero: true
            }
          },
          plugins: { ...CHART_BASE_OPTIONS.plugins, legend: { display: false } }
        }
      });
    });
}

// ── Severity Donut ───────────────────────────────────────────────────
function loadSeverityChart() {
  const sid = getSessionId();
  fetch(`/api/threats/stats${sid ? '?session_id=' + sid : ''}`)
    .then(r => r.json()).then(data => {
      destroyChart('severityChart');

      const sev = data.by_severity || {};
      const labels = ['Critical', 'High', 'Medium', 'Low'].filter(s => sev[s]);
      const values  = labels.map(s => sev[s] || 0);
      const colors  = labels.map(s => SEVERITY_COLORS[s]);

      charts['severityChart'] = new Chart(
        document.getElementById('severityChart').getContext('2d'), {
        type: 'polarArea',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors.map(c => c + 'aa'),
            borderColor: colors,
            borderWidth: 2,
          }]
        },
        options: {
          ...CHART_BASE_OPTIONS,
          scales: {
            r: {
              grid: { color: 'rgba(48,54,61,0.4)' },
              ticks: { display: false },
              pointLabels: { color: '#8b949e', font: { size: 10 } }
            }
          },
          plugins: {
            ...CHART_BASE_OPTIONS.plugins,
            legend: {
              position: 'bottom',
              labels: { color: '#8b949e', font: { size: 11 }, padding: 12 }
            }
          }
        }
      });
    });
}

function destroyChart(id) {
  if (charts[id]) {
    charts[id].destroy();
    delete charts[id];
  }
}

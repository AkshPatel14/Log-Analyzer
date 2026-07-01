// dashboard.js — Dashboard charts and counter animations

document.addEventListener('DOMContentLoaded', () => {
  applyChartDefaults();

  // Animate counters
  document.querySelectorAll('[data-counter]').forEach(el => {
    const val = parseInt(el.dataset.counter, 10) || 0;
    animateCounter(el, val);
  });

  // Animate severity bars
  document.querySelectorAll('.severity-bar-fill').forEach(bar => {
    const w = bar.dataset.width || '0';
    bar.style.width = '0%';
    setTimeout(() => { bar.style.width = w + '%'; }, 200);
  });

  // Threat types donut chart
  if (typeof THREAT_TYPES_DATA !== 'undefined' && Object.keys(THREAT_TYPES_DATA).length > 0) {
    const labels = Object.keys(THREAT_TYPES_DATA);
    const data   = Object.values(THREAT_TYPES_DATA);
    const colors = [
      '#f85149', '#d29922', '#eab308', '#3fb950',
      '#58a6ff', '#bc8cff', '#39c5cf', '#ff7c7c',
    ];

    new Chart(document.getElementById('threatTypesChart'), {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: colors.slice(0, labels.length).map(c => c + 'cc'),
          borderColor:      colors.slice(0, labels.length),
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#8b949e',
              font: { size: 11 },
              padding: 12,
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
            padding: 10,
          }
        },
        cutout: '65%',
        animation: { animateRotate: true, duration: 800 }
      }
    });
  }
});

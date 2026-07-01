// Log Analyzer — Shared JS Utilities

// Flash message auto-dismiss
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.opacity = '0';
            a.style.transform = 'translateY(-10px)';
            setTimeout(() => a.remove(), 400);
        });
    }, 4000);

    // Animate stat cards on load
    document.querySelectorAll('.stat-card').forEach((card, i) => {
        card.style.animationDelay = `${i * 0.1}s`;
        card.classList.add('animate-in');
    });

    // Active nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

// Animated counter for stat numbers
function animateCounter(el, target, duration = 1200) {
    const start = 0;
    const startTime = performance.now();
    const update = (currentTime) => {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(eased * target).toLocaleString();
        if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
}

// Format timestamp
function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
}

// Severity badge HTML
function severityBadge(severity) {
    const map = {
        'Critical': 'badge-critical',
        'High': 'badge-high',
        'Medium': 'badge-medium',
        'Low': 'badge-low'
    };
    const cls = map[severity] || 'badge-low';
    return `<span class="badge ${cls}">${severity}</span>`;
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied!', 'success'));
}

// Toast notification
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Default Chart.js theme
const CHART_DEFAULTS = {
    colors: {
        blue: '#58a6ff',
        red: '#f85149',
        orange: '#d29922',
        green: '#3fb950',
        purple: '#bc8cff',
        cyan: '#39d353',
        grid: 'rgba(48, 54, 61, 0.6)',
        text: '#8b949e'
    }
};

function applyChartDefaults() {
    Chart.defaults.color = CHART_DEFAULTS.colors.text;
    Chart.defaults.borderColor = CHART_DEFAULTS.colors.grid;
    Chart.defaults.font.family = "'Inter', sans-serif";
}

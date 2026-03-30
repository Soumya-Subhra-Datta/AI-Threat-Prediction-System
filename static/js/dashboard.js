/**
 * Cybersecurity Dashboard JavaScript
 * Interactive charts, real-time threat feed, API integration
 */

class ThreatDashboard {
  constructor() {
    this.apiBase = '/api';
    this.init();
  }

  init() {
    this.loadCharts();
    this.startLiveFeed();
    this.loadStats();
    setInterval(() => this.loadStats(), 5000);
  }

  async apiCall(endpoint) {
    try {
      const response = await fetch(`${this.apiBase}${endpoint}`);
      return await response.json();
    } catch (error) {
      console.error('API Error:', error);
      return null;
    }
  }

  async loadCharts() {
    const data = await this.apiCall('/threats/analytics');
    if (!data) return;

    // Threat Distribution Pie Chart
    const ctx1 = document.getElementById('threatDistribution').getContext('2d');
    new Chart(ctx1, {
      type: 'pie',
      data: {
        labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        datasets: [{
          data: [data.threat_dist.low, data.threat_dist.medium, data.threat_dist.high, data.threat_dist.critical],
          backgroundColor: ['#36A2EB', '#FFCE56', '#FF6384', '#FF4444']
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' }}
      }
    });

    // Threat Timeline Line Chart
    const ctx2 = document.getElementById('threatTimeline').getContext('2d');
    new Chart(ctx2, {
      type: 'line',
      data: {
        labels: data.timeline.hours,
        datasets: [{
          label: 'Threat Events',
          data: data.timeline.counts,
          borderColor: '#36A2EB',
          backgroundColor: 'rgba(54, 162, 235, 0.1)',
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        scales: { y: { beginAtZero: true }}
      }
    });
  }

  async loadStats() {
    const stats = await this.apiCall('/stats');
    if (!stats) return;

    document.getElementById('total-threats').textContent = stats.total_threats;
    document.getElementById('blocked-ips').textContent = stats.blocked_ips;
    document.getElementById('model-accuracy').textContent = `${stats.model_accuracy}%`;
    document.getElementById('active-threats').textContent = stats.active_threats;
  }

  async startLiveFeed() {
    const feed = document.getElementById('live-feed');
    setInterval(async () => {
      const recent = await this.apiCall('/threats/recent?limit=5');
      if (recent) {
        feed.innerHTML = recent.threats.map(t => `
          <div class="threat-item severity-${t.severity.toLowerCase()}">
            <span class="ip">${t.ip}</span>
            <span class="severity">${t.severity}</span>
            <span class="action">${t.action}</span>
            <span class="time">${new Date(t.timestamp).toLocaleTimeString()}</span>
          </div>
        `).join('');
      }
    }, 3000);
  }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new ThreatDashboard();
});

<template>
  <div class="overview">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_projects }}</div>
        <div class="stat-label">总项目数</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.active_targets }}</div>
        <div class="stat-label">活跃目标</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_apis }}</div>
        <div class="stat-label">总API数</div>
      </div>
      <div class="stat-card danger">
        <div class="stat-value">{{ stats.critical_vulns }}</div>
        <div class="stat-label">严重漏洞</div>
      </div>
      <div class="stat-card warning">
        <div class="stat-value">{{ stats.high_vulns }}</div>
        <div class="stat-label">高危漏洞</div>
      </div>
      <div class="stat-card info">
        <div class="stat-value">{{ stats.medium_vulns }}</div>
        <div class="stat-label">中危漏洞</div>
      </div>
    </div>

    <div class="charts-section">
      <div class="chart-card">
        <h3>漏洞趋势</h3>
        <div class="chart" id="vulnTrendChart"></div>
      </div>
      <div class="chart-card">
        <h3>目标分布</h3>
        <div class="chart" id="targetDistChart"></div>
      </div>
    </div>

    <div class="recent-section">
      <h3>最近扫描</h3>
      <div class="recent-list">
        <div v-for="scan in recentScans" :key="scan.id" class="recent-item">
          <span class="recent-target">{{ scan.target }}</span>
          <span :class="['recent-status', scan.status]">{{ scan.status }}</span>
          <span class="recent-time">{{ scan.time }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Overview',
  data() {
    return {
      stats: {
        total_projects: 0,
        active_targets: 0,
        total_apis: 0,
        critical_vulns: 0,
        high_vulns: 0,
        medium_vulns: 0,
        low_vulns: 0
      },
      recentScans: []
    }
  },
  mounted() {
    this.fetchStats()
  },
  methods: {
    async fetchStats() {
      try {
        const response = await fetch('/api/overview')
        const data = await response.json()
        this.stats = data
      } catch (e) {
        console.error('Failed to fetch stats:', e)
      }
    }
  }
}
</script>

<style scoped>
.overview {
  padding: 20px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 36px;
  font-weight: 700;
  color: #00d4ff;
  margin-bottom: 8px;
}

.stat-card.danger .stat-value { color: #ff4757; }
.stat-card.warning .stat-value { color: #ffa500; }
.stat-card.info .stat-value { color: #00ff99; }

.stat-label {
  font-size: 14px;
  color: #888;
}

.charts-section {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.chart-card {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 20px;
}

.chart-card h3 {
  margin-bottom: 16px;
  color: #fff;
}

.chart {
  height: 200px;
  background: #16162a;
  border-radius: 8px;
}

.recent-section {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 20px;
}

.recent-section h3 {
  margin-bottom: 16px;
  color: #fff;
}

.recent-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.recent-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px;
  background: #16162a;
  border-radius: 8px;
}

.recent-target {
  flex: 1;
  color: #ccc;
}

.recent-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.recent-status.completed { background: #00ff9933; color: #00ff99; }
.recent-status.failed { background: #ff475733; color: #ff4757; }
.recent-status.pending { background: #ffa50033; color: #ffa500; }

.recent-time {
  color: #666;
  font-size: 12px;
}
</style>

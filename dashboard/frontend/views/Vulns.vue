<template>
  <div class="vulnerabilities">
    <div class="header">
      <h2>漏洞管理</h2>
    </div>

    <div class="filter-bar">
      <select v-model="filterSeverity" class="filter-select">
        <option value="">全部严重性</option>
        <option value="critical">严重</option>
        <option value="high">高危</option>
        <option value="medium">中危</option>
        <option value="low">低危</option>
      </select>
      <input v-model="filterVulnType" placeholder="按漏洞类型筛选" class="filter-input" />
    </div>

    <div class="vulns-table">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>漏洞类型</th>
            <th>严重性</th>
            <th>目标</th>
            <th>发现时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="vuln in filteredVulns" :key="vuln.id">
            <td>{{ vuln.id }}</td>
            <td class="vuln-type">{{ vuln.vuln_type }}</td>
            <td>
              <span :class="['severity-badge', vuln.severity]">{{ vuln.severity }}</span>
            </td>
            <td class="url-cell">{{ vuln.target }}</td>
            <td>{{ vuln.created_at }}</td>
            <td>
              <button @click="viewDetail(vuln)" class="btn-small btn-primary">详情</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="filteredVulns.length === 0" class="empty-state">
      暂无漏洞
    </div>

    <div v-if="selectedVuln" class="dialog-overlay">
      <div class="dialog vuln-detail">
        <h3>漏洞详情</h3>
        <div class="detail-row">
          <label>漏洞类型:</label>
          <span>{{ selectedVuln.vuln_type }}</span>
        </div>
        <div class="detail-row">
          <label>严重性:</label>
          <span :class="['severity-badge', selectedVuln.severity]">{{ selectedVuln.severity }}</span>
        </div>
        <div class="detail-row">
          <label>目标:</label>
          <span>{{ selectedVuln.target }}</span>
        </div>
        <div class="detail-row">
          <label>描述:</label>
          <p>{{ selectedVuln.description }}</p>
        </div>
        <div class="detail-row" v-if="selectedVuln.payload">
          <label>Payload:</label>
          <code>{{ selectedVuln.payload }}</code>
        </div>
        <div class="detail-row" v-if="selectedVuln.remediation">
          <label>修复建议:</label>
          <p>{{ selectedVuln.remediation }}</p>
        </div>
        <div class="dialog-actions">
          <button @click="selectedVuln = null" class="btn-secondary">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Vulns',
  data() {
    return {
      vulns: [],
      filterSeverity: '',
      filterVulnType: '',
      selectedVuln: null
    }
  },
  computed: {
    filteredVulns() {
      let result = this.vulns
      
      if (this.filterSeverity) {
        result = result.filter(v => v.severity === this.filterSeverity)
      }
      if (this.filterVulnType) {
        result = result.filter(v => v.vuln_type.includes(this.filterVulnType))
      }
      
      return result
    }
  },
  mounted() {
    this.fetchVulns()
  },
  methods: {
    async fetchVulns() {
      try {
        const response = await fetch('/api/reports/vulnerabilities')
        const data = await response.json()
        this.vulns = data.vulnerabilities || []
      } catch (e) {
        console.error('Failed to fetch vulns:', e)
      }
    },
    viewDetail(vuln) {
      this.selectedVuln = vuln
    }
  }
}
</script>

<style scoped>
.vulnerabilities {
  padding: 20px;
}

.header {
  margin-bottom: 20px;
}

.header h2 {
  color: #fff;
}

.filter-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
}

.filter-select, .filter-input {
  padding: 8px 12px;
  background: #1e1e2e;
  border: 1px solid #333;
  border-radius: 6px;
  color: #fff;
}

.filter-select {
  min-width: 120px;
}

.filter-input {
  flex: 1;
  max-width: 300px;
}

.vulns-table {
  background: #1e1e2e;
  border-radius: 8px;
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th, td {
  padding: 12px 16px;
  text-align: left;
  border-bottom: 1px solid #333;
}

th {
  background: #16162a;
  color: #888;
  font-weight: 500;
  font-size: 13px;
}

td {
  color: #ccc;
  font-size: 14px;
}

.vuln-type {
  color: #00d4ff;
  font-weight: 500;
}

.url-cell {
  max-width: 250px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.severity-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.severity-badge.critical {
  background: #ff475733;
  color: #ff4757;
}

.severity-badge.high {
  background: #ffa50033;
  color: #ffa500;
}

.severity-badge.medium {
  background: #ffbe0033;
  color: #ffbe00;
}

.severity-badge.low {
  background: #00d4ff33;
  color: #00d4ff;
}

.btn-small {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
}

.btn-primary {
  background: #00d4ff;
  color: #1a1a2e;
}

.btn-secondary {
  background: #333;
  color: #fff;
  padding: 8px 16px;
  border: none;
  border-radius: 6px;
  cursor: pointer;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}

.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.dialog {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 24px;
  width: 90%;
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
}

.dialog h3 {
  color: #fff;
  margin-bottom: 20px;
}

.detail-row {
  margin-bottom: 16px;
}

.detail-row label {
  display: block;
  color: #888;
  font-size: 12px;
  margin-bottom: 4px;
}

.detail-row span {
  color: #fff;
}

.detail-row p {
  color: #ccc;
  margin: 0;
  line-height: 1.6;
}

.detail-row code {
  display: block;
  background: #16162a;
  padding: 8px 12px;
  border-radius: 4px;
  color: #ff4757;
  font-family: monospace;
  overflow-x: auto;
}

.dialog-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: 20px;
}
</style>

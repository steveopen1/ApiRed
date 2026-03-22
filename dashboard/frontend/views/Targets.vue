<template>
  <div class="targets">
    <div class="header">
      <h2>目标管理</h2>
    </div>

    <div class="filter-bar">
      <select v-model="filterStatus" class="filter-select">
        <option value="">全部状态</option>
        <option value="pending">待扫描</option>
        <option value="scanning">扫描中</option>
        <option value="completed">已完成</option>
        <option value="failed">失败</option>
      </select>
      <input v-model="filterUrl" placeholder="按URL筛选" class="filter-input" />
    </div>

    <div class="targets-table">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>URL</th>
            <th>状态</th>
            <th>API数</th>
            <th>漏洞数</th>
            <th>最后扫描</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="target in filteredTargets" :key="target.id">
            <td>{{ target.id }}</td>
            <td class="url-cell">{{ target.url }}</td>
            <td>
              <span :class="['status-badge', target.status]">{{ target.status }}</span>
            </td>
            <td>{{ target.api_count }}</td>
            <td :class="{danger: target.vuln_count > 0}">{{ target.vuln_count }}</td>
            <td>{{ target.last_scan_at || '-' }}</td>
            <td>
              <button @click="scanTarget(target.id)" class="btn-small btn-primary">扫描</button>
              <button @click="deleteTarget(target.id)" class="btn-small btn-danger">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="filteredTargets.length === 0" class="empty-state">
      暂无目标
    </div>
  </div>
</template>

<script>
export default {
  name: 'Targets',
  data() {
    return {
      targets: [],
      filterStatus: '',
      filterUrl: ''
    }
  },
  computed: {
    filteredTargets() {
      let result = this.targets
      
      if (this.filterStatus) {
        result = result.filter(t => t.status === this.filterStatus)
      }
      if (this.filterUrl) {
        result = result.filter(t => t.url.includes(this.filterUrl))
      }
      
      return result
    }
  },
  mounted() {
    this.fetchTargets()
  },
  methods: {
    async fetchTargets() {
      try {
        const response = await fetch('/api/targets')
        const data = await response.json()
        this.targets = data.targets || []
      } catch (e) {
        console.error('Failed to fetch targets:', e)
      }
    },
    async scanTarget(targetId) {
      try {
        await fetch(`/api/targets/${targetId}/scan`, { method: 'POST' })
        this.fetchTargets()
      } catch (e) {
        console.error('Failed to scan target:', e)
      }
    },
    async deleteTarget(targetId) {
      if (!confirm('确定删除该目标?')) return
      try {
        await fetch(`/api/targets/${targetId}`, { method: 'DELETE' })
        this.fetchTargets()
      } catch (e) {
        console.error('Failed to delete target:', e)
      }
    }
  }
}
</script>

<style scoped>
.targets {
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

.targets-table {
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

.url-cell {
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.status-badge.pending {
  background: #ffa50033;
  color: #ffa500;
}

.status-badge.scanning {
  background: #00d4ff33;
  color: #00d4ff;
}

.status-badge.completed {
  background: #00ff9933;
  color: #00ff99;
}

.status-badge.failed {
  background: #ff475733;
  color: #ff4757;
}

.btn-small {
  padding: 6px 12px;
  border: none;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
  margin-right: 8px;
}

.btn-primary {
  background: #00d4ff;
  color: #1a1a2e;
}

.btn-danger {
  background: #ff4757;
  color: #fff;
}

.empty-state {
  text-align: center;
  padding: 60px 20px;
  color: #666;
}
</style>

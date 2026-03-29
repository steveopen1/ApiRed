<template>
  <div class="dashboard">
    <header class="header">
      <div class="header-title">
        <div class="logo">AR</div>
        <span>ApiRed Security Scanner</span>
      </div>
      <div class="header-actions">
        <el-button @click="refreshData">
          <span v-if="loading">刷新中...</span>
          <span v-else>刷新</span>
        </el-button>
        <el-dropdown @command="handleCommand">
          <el-button type="primary">
            {{ authStore.user?.username || '用户' }}
            <el-icon><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="profile">个人设置</el-dropdown-item>
              <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </header>

    <main class="main-container">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">{{ stats.total_apis || 0 }}</div>
          <div class="stat-label">API 端点</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-critical">{{ stats.critical || 0 }}</div>
          <div class="stat-label">严重漏洞</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-high">{{ stats.high || 0 }}</div>
          <div class="stat-label">高危漏洞</div>
        </div>
        <div class="stat-card">
          <div class="stat-value severity-medium">{{ stats.medium || 0 }}</div>
          <div class="stat-label">中危漏洞</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">{{ stats.scheduled || 0 }}</div>
          <div class="stat-label">定时任务</div>
        </div>
      </div>

      <el-tabs v-model="activeTab" class="main-tabs">
        <el-tab-pane label="扫描任务" name="scan">
          <scan-panel />
        </el-tab-pane>
        <el-tab-pane label="导入管理" name="import">
          <import-panel />
        </el-tab-pane>
        <el-tab-pane label="定时任务" name="schedule">
          <schedule-panel />
        </el-tab-pane>
        <el-tab-pane label="报告分析" name="report">
          <report-panel />
        </el-tab-pane>
      </el-tabs>
    </main>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, useTaskStore, useScheduleStore, api } from '../stores'
import { ElMessage } from 'element-plus'
import { ArrowDown } from '@element-plus/icons-vue'
import ScanPanel from '../components/ScanPanel.vue'
import ImportPanel from '../components/ImportPanel.vue'
import SchedulePanel from '../components/SchedulePanel.vue'
import ReportPanel from '../components/ReportPanel.vue'

const router = useRouter()
const authStore = useAuthStore()
const taskStore = useTaskStore()
const scheduleStore = useScheduleStore()

const activeTab = ref('scan')
const loading = ref(false)

const stats = reactive({
  total_apis: 0,
  critical: 0,
  high: 0,
  medium: 0,
  scheduled: 0
})

const refreshData = async () => {
  loading.value = true
  try {
    const response = await api.get('/stats')
    Object.assign(stats, response.data)
    taskStore.history = response.data.history || []
    await scheduleStore.fetchSchedules()
    stats.scheduled = scheduleStore.schedules.length
  } catch (error) {
    console.error('Refresh failed:', error)
  } finally {
    loading.value = false
  }
}

const handleCommand = async (command) => {
  if (command === 'logout') {
    await authStore.logout()
    router.push('/login')
  } else if (command === 'profile') {
    ElMessage.info('个人设置功能开发中')
  }
}

onMounted(() => {
  refreshData()
})
</script>

<style scoped>
.dashboard {
  min-height: 100vh;
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
}

.header {
  background: rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  padding: 15px 30px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-title {
  color: white;
  font-size: 1.3em;
  font-weight: bold;
  display: flex;
  align-items: center;
  gap: 12px;
}

.logo {
  width: 40px;
  height: 40px;
  background: linear-gradient(135deg, #667eea, #764ba2);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-weight: bold;
}

.header-actions {
  display: flex;
  gap: 10px;
}

.main-container {
  padding: 20px 30px;
  max-width: 1600px;
  margin: 0 auto;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 15px;
  margin-bottom: 20px;
}

.stat-card {
  background: white;
  border-radius: 10px;
  padding: 20px;
  text-align: center;
  box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);
}

.stat-value {
  font-size: 2.2em;
  font-weight: bold;
  background: linear-gradient(135deg, #667eea, #764ba2);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.severity-critical { color: #dc3545; }
.severity-high { color: #fd7e14; }
.severity-medium { color: #ffc107; }

.stat-label {
  color: #666;
  margin-top: 5px;
}

.main-tabs {
  background: white;
  border-radius: 12px;
  padding: 20px;
}
</style>

<template>
  <div class="scan-panel">
    <div class="card">
      <div class="card-header">新建扫描任务</div>
      <el-form :model="scanForm" label-width="100px">
        <el-form-item label="目标 URL">
          <el-input v-model="scanForm.target" placeholder="输入目标 URL (例如: https://api.example.com)" size="large" />
        </el-form-item>
        <el-form-item label="采集选项">
          <el-checkbox-group v-model="scanForm.collectors">
            <el-checkbox label="js">JS 采集</el-checkbox>
            <el-checkbox label="api">API 发现</el-checkbox>
            <el-checkbox label="swagger">Swagger</el-checkbox>
            <el-checkbox label="passive">被动源</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="行业测试">
          <el-select v-model="scanForm.industryTests" placeholder="选择行业测试用例" style="width: 100%">
            <el-option label="无" value="none" />
            <el-option label="金融行业" value="finance" />
            <el-option label="医疗行业" value="healthcare" />
            <el-option label="全部行业" value="all" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" size="large" :loading="scanning" @click="startScan">
            {{ scanning ? '扫描中...' : '开始扫描' }}
          </el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card" v-if="activeScan">
      <div class="card-header">扫描进行中</div>
      <el-progress :percentage="activeScan.progress" :status="activeScan.status === 'failed' ? 'exception' : undefined" />
      <div class="scan-status">
        <span>{{ activeScan.status }}</span>
        <span>{{ activeScan.phase }}</span>
      </div>
    </div>

    <div class="card">
      <div class="card-header">扫描历史</div>
      <el-table :data="scanHistory" stripe style="width: 100%">
        <el-table-column prop="target" label="目标" min-width="200" />
        <el-table-column prop="api_count" label="端点" width="80" />
        <el-table-column label="漏洞" width="150">
          <template #default="{ row }">
            <span v-if="row.critical > 0" class="badge badge-critical">{{ row.critical }} 严重</span>
            <span v-if="row.high > 0" class="badge badge-high">{{ row.high }} 高危</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status_class">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="time" label="时间" width="180" />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="viewReport(row)">报告</el-button>
            <el-button size="small" type="danger" @click="deleteScan(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useTaskStore, api } from '../stores'
import { ElMessage } from 'element-plus'

const taskStore = useTaskStore()

const scanForm = reactive({
  target: '',
  collectors: ['js', 'api'],
  industryTests: 'none'
})

const scanning = ref(false)
const activeScan = ref(null)
const scanHistory = ref([])

const startScan = async () => {
  if (!scanForm.target) {
    ElMessage.warning('请输入目标 URL')
    return
  }

  scanning.value = true
  activeScan.value = { progress: 0, status: '初始化...', phase: '' }

  try {
    const response = await api.post('/tasks', {
      target: scanForm.target,
      collectors: scanForm.collectors,
      industry_tests: scanForm.industryTests
    })

    if (response.data.task_id) {
      pollScanProgress(response.data.task_id)
    }
  } catch (error) {
    ElMessage.error('扫描启动失败: ' + error.message)
    scanning.value = false
    activeScan.value = null
  }
}

const pollScanProgress = async (taskId) => {
  const poll = async () => {
    if (!scanning.value) return
    try {
      const response = await api.get(`/tasks/${taskId}`)
      const task = response.data
      activeScan.value = {
        progress: task.progress || 0,
        status: task.status || '运行中',
        phase: task.phase || ''
      }

      if (task.status === 'completed' || task.status === 'failed') {
        scanning.value = false
        activeScan.value = null
        ElMessage.success('扫描完成')
        refreshHistory()
      } else {
        setTimeout(poll, 2000)
      }
    } catch (error) {
      console.error('Poll error:', error)
      setTimeout(poll, 5000)
    }
  }
  poll()
}

const refreshHistory = async () => {
  try {
    const response = await api.get('/stats')
    scanHistory.value = response.data.history || []
  } catch (error) {
    console.error('Failed to load history:', error)
  }
}

const viewReport = (scan) => {
  window.open(`/api/results/${scan.id}/report`, '_blank')
}

const deleteScan = async (scan) => {
  try {
    await api.delete(`/tasks/${scan.id}`)
    ElMessage.success('删除成功')
    refreshHistory()
  } catch (error) {
    ElMessage.error('删除失败')
  }
}
</script>

<style scoped>
.scan-panel {
  padding: 10px 0;
}

.card {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
}

.card-header {
  font-size: 1.1em;
  font-weight: bold;
  color: #333;
  margin-bottom: 15px;
  padding-bottom: 10px;
  border-bottom: 2px solid #667eea;
}

.scan-status {
  display: flex;
  justify-content: space-between;
  margin-top: 10px;
  color: #666;
}

.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 20px;
  font-size: 0.75em;
  font-weight: bold;
  margin-right: 5px;
}

.badge-critical { background: #dc3545; color: white; }
.badge-high { background: #fd7e14; color: white; }
</style>

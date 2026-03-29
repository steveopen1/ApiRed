<template>
  <div class="report-panel">
    <div class="card">
      <div class="card-header">安全态势评分</div>
      <div class="score-container">
        <div ref="scoreChartRef" class="chart-container"></div>
        <div class="score-details">
          <div v-for="(score, category) in postureScores" :key="category" class="score-item">
            <div class="score-label">
              <span>{{ category }}</span>
              <span>{{ score }}%</span>
            </div>
            <el-progress :percentage="score" :color="getScoreColor(score)" :show-text="false" />
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">漏洞分布</div>
      <div ref="vulnChartRef" class="chart-container"></div>
    </div>

    <div class="card">
      <div class="card-header">漏洞详情</div>
      <el-table :data="vulnerabilities" stripe style="width: 100%">
        <el-table-column label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)" :class="'badge-' + row.severity">
              {{ row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="150" />
        <el-table-column prop="path" label="路径" min-width="200">
          <template #default="{ row }">
            <code>{{ row.path }}</code>
          </template>
        </el-table-column>
        <el-table-column label="方法" width="100">
          <template #default="{ row }">
            <el-tag :class="'method-' + row.method.toLowerCase()">{{ row.method }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="描述" min-width="200" />
      </el-table>
      <div v-if="vulnerabilities.length === 0" class="empty-state">暂无漏洞数据</div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, nextTick } from 'vue'
import { api } from '../stores'
import * as echarts from 'echarts'

const scoreChartRef = ref(null)
const vulnChartRef = ref(null)

const postureScores = ref({})
const vulnerabilities = ref([])

const stats = reactive({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0
})

const getScoreColor = (score) => {
  if (score >= 80) return '#28a745'
  if (score >= 60) return '#17a2b8'
  if (score >= 40) return '#ffc107'
  if (score >= 20) return '#fd7e14'
  return '#dc3545'
}

const getSeverityType = (severity) => {
  const map = {
    critical: 'danger',
    high: 'warning',
    medium: 'warning',
    low: 'success',
    info: 'info'
  }
  return map[severity] || 'info'
}

const initCharts = async () => {
  await nextTick()
  
  if (scoreChartRef.value) {
    const scoreChart = echarts.init(scoreChartRef.value)
    scoreChart.setOption({
      tooltip: { trigger: 'item' },
      legend: { bottom: 0 },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        data: [
          { value: stats.critical, name: '严重', itemStyle: { color: '#dc3545' } },
          { value: stats.high, name: '高危', itemStyle: { color: '#fd7e14' } },
          { value: stats.medium, name: '中危', itemStyle: { color: '#ffc107' } },
          { value: stats.low, name: '低危', itemStyle: { color: '#28a745' } }
        ]
      }]
    })
  }

  if (vulnChartRef.value) {
    const vulnChart = echarts.init(vulnChartRef.value)
    vulnChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['漏洞数量'] },
      xAxis: { type: 'category', data: ['严重', '高危', '中危', '低危'] },
      yAxis: { type: 'value' },
      series: [{
        type: 'bar',
        data: [
          { value: stats.critical, itemStyle: { color: '#dc3545' } },
          { value: stats.high, itemStyle: { color: '#fd7e14' } },
          { value: stats.medium, itemStyle: { color: '#ffc107' } },
          { value: stats.low, itemStyle: { color: '#28a745' } }
        ]
      }]
    })
  }
}

const fetchData = async () => {
  try {
    const response = await api.get('/stats')
    stats.critical = response.data.critical || 0
    stats.high = response.data.high || 0
    stats.medium = response.data.medium || 0
    stats.low = response.data.low || 0
    postureScores.value = response.data.posture || {}
    vulnerabilities.value = response.data.vulnerabilities || []
    await initCharts()
  } catch (error) {
    console.error('Failed to load stats:', error)
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped>
.report-panel {
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

.score-container {
  display: flex;
  gap: 30px;
}

.chart-container {
  width: 300px;
  height: 300px;
}

.score-details {
  flex: 1;
}

.score-item {
  margin-bottom: 15px;
}

.score-label {
  display: flex;
  justify-content: space-between;
  margin-bottom: 5px;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #999;
}

.method-get { background: #61affe; color: white; }
.method-post { background: #49cc90; color: white; }
.method-put { background: #fca130; color: white; }
.method-delete { background: #f93e3e; color: white; }
</style>

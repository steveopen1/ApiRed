<template>
  <div class="schedule-panel">
    <div class="card">
      <div class="card-header">创建定时任务</div>
      <el-form :model="scheduleForm" label-width="100px">
        <el-form-item label="目标 URL">
          <el-input v-model="scheduleForm.target" placeholder="目标 URL" />
        </el-form-item>
        <el-form-item label="Cron 表达式">
          <el-input v-model="scheduleForm.cron" placeholder="0 2 * * *" />
        </el-form-item>
        <el-form-item>
          <div class="cron-hint">
            常用表达式: <code>0 2 * * *</code> 每天凌晨2点 | <code>0 */6 * * *</code> 每6小时 | <code>0 0 * * 1</code> 每周一
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="createSchedule">创建定时任务</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="card">
      <div class="card-header">定时任务列表</div>
      <div v-if="schedules.length > 0" class="schedule-list">
        <div v-for="task in schedules" :key="task.id" class="schedule-item">
          <div>
            <div class="task-name">{{ task.name }}</div>
            <div class="task-info">{{ task.target }} | {{ task.cron }}</div>
            <div v-if="task.nextRun" class="task-next">下次运行: {{ task.nextRun }}</div>
          </div>
          <div class="task-actions">
            <el-tag :type="task.enabled ? 'success' : 'info'">{{ task.enabled ? '启用' : '禁用' }}</el-tag>
            <el-button type="danger" size="small" @click="deleteSchedule(task.id)">删除</el-button>
          </div>
        </div>
      </div>
      <div v-else class="empty-state">暂无定时任务</div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useScheduleStore } from '../stores'
import { ElMessage } from 'element-plus'

const scheduleStore = useScheduleStore()

const scheduleForm = reactive({
  target: '',
  cron: '0 2 * * *'
})

const schedules = ref([])

const createSchedule = async () => {
  if (!scheduleForm.target || !scheduleForm.cron) {
    ElMessage.warning('请填写目标和定时表达式')
    return
  }

  const success = await scheduleStore.createSchedule(scheduleForm.target, scheduleForm.cron)
  if (success) {
    ElMessage.success('定时任务创建成功')
    scheduleForm.target = ''
    scheduleForm.cron = '0 2 * * *'
    await refreshSchedules()
  }
}

const refreshSchedules = async () => {
  schedules.value = await scheduleStore.fetchSchedules()
}

const deleteSchedule = async (id) => {
  const success = await scheduleStore.deleteSchedule(id)
  if (success) {
    ElMessage.success('删除成功')
    await refreshSchedules()
  }
}

onMounted(() => {
  refreshSchedules()
})
</script>

<style scoped>
.schedule-panel {
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

.cron-hint {
  color: #666;
  font-size: 0.85em;
}

.cron-hint code {
  background: #e9ecef;
  padding: 2px 6px;
  border-radius: 4px;
  margin: 0 3px;
}

.schedule-list {
  margin-top: 15px;
}

.schedule-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 15px;
  background: white;
  border-radius: 8px;
  margin-bottom: 10px;
}

.task-name {
  font-weight: bold;
  margin-bottom: 5px;
}

.task-info {
  color: #666;
  font-size: 0.9em;
}

.task-next {
  color: #999;
  font-size: 0.85em;
  margin-top: 5px;
}

.task-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #999;
}
</style>

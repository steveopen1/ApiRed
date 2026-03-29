<template>
  <div class="import-panel">
    <div class="card">
      <div class="card-header">导入 BurpSuite 流量</div>
      <el-upload
        ref="burpUpload"
        :auto-upload="false"
        :limit="1"
        accept=".csv,.json,.xml,.har"
        :on-change="handleBurpChange"
      >
        <template #trigger>
          <div class="upload-area">
            <el-icon class="upload-icon"><UploadFilled /></el-icon>
            <div>点击或拖拽文件到此处上传</div>
            <div class="upload-hint">支持 CSV/JSON/XML/HAR 格式</div>
          </div>
        </template>
      </el-upload>
    </div>

    <div class="card">
      <div class="card-header">导入 Postman Collection</div>
      <el-upload
        ref="postmanUpload"
        :auto-upload="false"
        :limit="1"
        accept=".json"
        :on-change="handlePostmanChange"
      >
        <template #trigger>
          <div class="upload-area">
            <el-icon class="upload-icon"><UploadFilled /></el-icon>
            <div>点击或拖拽文件到此处上传</div>
            <div class="upload-hint">支持 Postman Collection v2.0/v2.1</div>
          </div>
        </template>
      </el-upload>
    </div>

    <div class="card" v-if="importedEndpoints.length > 0">
      <div class="card-header">已导入端点 ({{ importedEndpoints.length }})</div>
      <el-table :data="importedEndpoints.slice(0, 50)" stripe style="width: 100%">
        <el-table-column label="方法" width="100">
          <template #default="{ row }">
            <el-tag :class="'method-' + row.method.toLowerCase()">{{ row.method }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="path" label="路径" min-width="300">
          <template #default="{ row }">
            <code>{{ row.path }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="120" />
      </el-table>
      <div v-if="importedEndpoints.length > 50" class="more-hint">
        还有 {{ importedEndpoints.length - 50 }} 个端点...
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useApiStore, api } from '../stores'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'

const apiStore = useApiStore()

const importedEndpoints = ref([])
const burpUpload = ref(null)
const postmanUpload = ref(null)

const handleBurpChange = async (file) => {
  const formData = new FormData()
  formData.append('file', file.raw)

  try {
    const response = await api.post('/import/burp', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    importedEndpoints.value = response.data.endpoints || []
    ElMessage.success(`导入成功: ${response.data.count} 个端点`)
  } catch (error) {
    ElMessage.error('导入失败: ' + error.message)
  }
}

const handlePostmanChange = async (file) => {
  const formData = new FormData()
  formData.append('file', file.raw)

  try {
    const response = await api.post('/import/postman', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    importedEndpoints.value = response.data.endpoints || []
    ElMessage.success(`导入成功: ${response.data.count} 个端点`)
  } catch (error) {
    ElMessage.error('导入失败: ' + error.message)
  }
}
</script>

<style scoped>
.import-panel {
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

.upload-area {
  border: 2px dashed #ddd;
  border-radius: 10px;
  padding: 40px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.3s;
}

.upload-area:hover {
  border-color: #667eea;
}

.upload-icon {
  font-size: 2em;
  color: #999;
  margin-bottom: 10px;
}

.upload-hint {
  color: #999;
  font-size: 0.9em;
  margin-top: 5px;
}

.more-hint {
  text-align: center;
  color: #666;
  margin-top: 10px;
}

.method-get { background: #61affe; color: white; }
.method-post { background: #49cc90; color: white; }
.method-put { background: #fca130; color: white; }
.method-delete { background: #f93e3e; color: white; }
</style>

<template>
  <div class="login-container">
    <div class="login-card">
      <div class="logo">
        <div class="logo-icon">AR</div>
        <h1>ApiRed Security Scanner</h1>
      </div>
      <el-form :model="form" class="login-form">
        <el-form-item>
          <el-input v-model="form.username" placeholder="用户名" size="large">
            <template #prefix>
              <el-icon><User /></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" placeholder="密码" size="large" @keyup.enter="handleLogin">
            <template #prefix>
              <el-icon><Lock /></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-button type="primary" size="large" :loading="loading" @click="handleLogin" class="login-btn">
          登录
        </el-button>
      </el-form>
      <div class="login-footer">
        <span>默认账号: admin / admin123</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useAuthStore } from '../stores'
import { ElMessage } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'

const emit = defineEmits(['login-success'])
const authStore = useAuthStore()

const form = ref({
  username: '',
  password: ''
})

const loading = ref(false)

const handleLogin = async () => {
  if (!form.value.username || !form.value.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }

  loading.value = true
  try {
    const success = await authStore.login(form.value.username, form.value.password)
    if (success) {
      ElMessage.success('登录成功')
      emit('login-success')
    } else {
      ElMessage.error('登录失败，请检查用户名和密码')
    }
  } catch (error) {
    ElMessage.error('登录失败: ' + error.message)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  padding: 20px;
}

.login-card {
  background: white;
  border-radius: 16px;
  padding: 40px;
  width: 100%;
  max-width: 400px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
}

.logo {
  text-align: center;
  margin-bottom: 30px;
}

.logo-icon {
  width: 60px;
  height: 60px;
  background: linear-gradient(135deg, #667eea, #764ba2);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 1.5em;
  font-weight: bold;
  margin: 0 auto 15px;
}

.logo h1 {
  color: #333;
  font-size: 1.3em;
  margin: 0;
}

.login-form {
  margin-top: 20px;
}

.login-btn {
  width: 100%;
  height: 45px;
  font-size: 1em;
}

.login-footer {
  margin-top: 20px;
  text-align: center;
  color: #999;
  font-size: 0.85em;
}
</style>

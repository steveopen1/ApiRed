<template>
  <div id="app" class="app-container">
    <router-view v-if="!showLogin" />
    <login-view v-else @login-success="onLoginSuccess" />
  </div>
</template>

<script setup>
import { ref, onMounted, provide } from 'vue'
import { useAuthStore } from './stores'
import LoginView from './views/LoginView.vue'

const authStore = useAuthStore()
const showLogin = ref(true)

provide('showLogin', showLogin)

const onLoginSuccess = () => {
  showLogin.value = false
}

onMounted(async () => {
  await authStore.checkAuth()
  showLogin.value = !authStore.isAuthenticated
})
</script>

<style>
.app-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
}
</style>

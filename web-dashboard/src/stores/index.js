import { defineStore } from 'pinia'
import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000
})

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    user: null,
    isAuthenticated: false
  }),

  actions: {
    async login(username, password) {
      try {
        const response = await api.post('/auth/login', { username, password })
        if (response.data.success) {
          this.token = response.data.token
          this.user = response.data.user
          this.isAuthenticated = true
          localStorage.setItem('token', this.token)
          return true
        }
        return false
      } catch (error) {
        console.error('Login failed:', error)
        return false
      }
    },

    async logout() {
      try {
        await api.post('/auth/logout')
      } catch (e) {
        console.error('Logout error:', e)
      }
      this.token = ''
      this.user = null
      this.isAuthenticated = false
      localStorage.removeItem('token')
    },

    async checkAuth() {
      if (!this.token) {
        this.isAuthenticated = false
        return false
      }
      try {
        const response = await api.get('/auth/user')
        if (response.data.success) {
          this.user = response.data.user
          this.isAuthenticated = true
          return true
        }
      } catch (e) {
        this.token = ''
        this.isAuthenticated = false
      }
      return false
    }
  }
})

export const useTaskStore = defineStore('tasks', {
  state: () => ({
    tasks: [],
    currentTask: null,
    history: [],
    isScanning: false
  }),

  actions: {
    async fetchTasks() {
      try {
        const response = await api.get('/tasks')
        this.tasks = response.data.tasks || []
        return this.tasks
      } catch (error) {
        console.error('Fetch tasks failed:', error)
        return []
      }
    },

    async createTask(target, collectors, industryTests) {
      try {
        const response = await api.post('/tasks', {
          target,
          collectors,
          industry_tests: industryTests
        })
        return response.data
      } catch (error) {
        console.error('Create task failed:', error)
        throw error
      }
    },

    async stopTask(taskId) {
      try {
        await api.post(`/tasks/${taskId}/stop`)
        return true
      } catch (error) {
        console.error('Stop task failed:', error)
        return false
      }
    },

    async deleteTask(taskId) {
      try {
        await api.delete(`/tasks/${taskId}`)
        return true
      } catch (error) {
        console.error('Delete task failed:', error)
        return false
      }
    }
  }
})

export const useScheduleStore = defineStore('schedule', {
  state: () => ({
    schedules: []
  }),

  actions: {
    async fetchSchedules() {
      try {
        const response = await api.get('/schedule')
        this.schedules = response.data.tasks || []
        return this.schedules
      } catch (error) {
        console.error('Fetch schedules failed:', error)
        return []
      }
    },

    async createSchedule(target, cron) {
      try {
        await api.post('/schedule', { target, cron })
        return true
      } catch (error) {
        console.error('Create schedule failed:', error)
        return false
      }
    },

    async deleteSchedule(taskId) {
      try {
        await api.delete(`/schedule/${taskId}`)
        return true
      } catch (error) {
        console.error('Delete schedule failed:', error)
        return false
      }
    }
  }
})

export { api }

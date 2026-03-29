import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('../views/DashboardView.vue')
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/LoginView.vue')
  },
  {
    path: '/scan',
    name: 'Scan',
    component: () => import('../views/ScanView.vue')
  },
  {
    path: '/import',
    name: 'Import',
    component: () => import('../views/ImportView.vue')
  },
  {
    path: '/schedule',
    name: 'Schedule',
    component: () => import('../views/ScheduleView.vue')
  },
  {
    path: '/report',
    name: 'Report',
    component: () => import('../views/ReportView.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

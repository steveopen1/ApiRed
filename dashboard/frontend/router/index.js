import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'Overview',
    component: () => import('../views/Overview.vue')
  },
  {
    path: '/projects',
    name: 'Projects',
    component: () => import('../views/Projects.vue')
  },
  {
    path: '/projects/:id',
    name: 'ProjectDetail',
    component: () => import('../views/Projects.vue')
  },
  {
    path: '/targets',
    name: 'Targets',
    component: () => import('../views/Targets.vue')
  },
  {
    path: '/vulns',
    name: 'Vulns',
    component: () => import('../views/Vulns.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router

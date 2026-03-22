<template>
  <div class="projects">
    <div class="header">
      <h2>项目管理</h2>
      <button @click="showCreateDialog = true" class="btn-primary">新建项目</button>
    </div>

    <div class="filter-bar">
      <input v-model="filterTag" placeholder="按标签筛选" class="filter-input" />
    </div>

    <div class="projects-grid">
      <div v-for="project in filteredProjects" :key="project.id" class="project-card">
        <div class="project-header">
          <h3>{{ project.name }}</h3>
          <div class="project-tags">
            <span v-for="tag in project.tags" :key="tag" class="tag">{{ tag }}</span>
          </div>
        </div>
        <p class="project-desc">{{ project.description || '暂无描述' }}</p>
        <div class="project-stats">
          <div class="stat">
            <span class="stat-value">{{ project.target_count }}</span>
            <span class="stat-label">目标</span>
          </div>
          <div class="stat">
            <span class="stat-value">{{ project.api_count }}</span>
            <span class="stat-label">API</span>
          </div>
          <div class="stat danger">
            <span class="stat-value">{{ project.vuln_count }}</span>
            <span class="stat-label">漏洞</span>
          </div>
        </div>
        <div class="project-actions">
          <button @click="viewProject(project.id)" class="btn-secondary">查看</button>
          <button @click="deleteProject(project.id)" class="btn-danger">删除</button>
        </div>
      </div>
    </div>

    <div v-if="showCreateDialog" class="dialog-overlay">
      <div class="dialog">
        <h3>新建项目</h3>
        <div class="form-group">
          <label>项目名称</label>
          <input v-model="newProject.name" placeholder="输入项目名称" />
        </div>
        <div class="form-group">
          <label>项目描述</label>
          <textarea v-model="newProject.description" placeholder="输入项目描述"></textarea>
        </div>
        <div class="form-group">
          <label>标签 (逗号分隔)</label>
          <input v-model="newProject.tagsStr" placeholder="标签1, 标签2" />
        </div>
        <div class="dialog-actions">
          <button @click="showCreateDialog = false" class="btn-secondary">取消</button>
          <button @click="createProject" class="btn-primary">创建</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'Projects',
  data() {
    return {
      projects: [],
      filterTag: '',
      showCreateDialog: false,
      newProject: {
        name: '',
        description: '',
        tagsStr: ''
      }
    }
  },
  computed: {
    filteredProjects() {
      if (!this.filterTag) return this.projects
      return this.projects.filter(p => p.tags.includes(this.filterTag))
    }
  },
  mounted() {
    this.fetchProjects()
  },
  methods: {
    async fetchProjects() {
      try {
        const response = await fetch('/api/projects')
        this.projects = await response.json()
      } catch (e) {
        console.error('Failed to fetch projects:', e)
      }
    },
    async createProject() {
      try {
        const tags = this.newProject.tagsStr.split(',').map(t => t.trim()).filter(Boolean)
        await fetch('/api/projects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...this.newProject, tags })
        })
        this.showCreateDialog = false
        this.fetchProjects()
      } catch (e) {
        console.error('Failed to create project:', e)
      }
    },
    async deleteProject(id) {
      if (!confirm('确定删除该项目?')) return
      try {
        await fetch(`/api/projects/${id}`, { method: 'DELETE' })
        this.fetchProjects()
      } catch (e) {
        console.error('Failed to delete project:', e)
      }
    },
    viewProject(id) {
      this.$router.push(`/projects/${id}`)
    }
  }
}
</script>

<style scoped>
.projects {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.btn-primary {
  background: #00d4ff;
  color: #1a1a2e;
  border: none;
  padding: 10px 20px;
  border-radius: 6px;
  cursor: pointer;
}

.btn-secondary {
  background: #333;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
}

.btn-danger {
  background: #ff4757;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 6px;
  cursor: pointer;
}

.projects-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.project-card {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 20px;
}

.project-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.project-tags {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.tag {
  background: #333;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  color: #00d4ff;
}

.project-desc {
  color: #888;
  font-size: 14px;
  margin-bottom: 16px;
}

.project-stats {
  display: flex;
  gap: 20px;
  margin-bottom: 16px;
}

.stat {
  text-align: center;
}

.stat-value {
  display: block;
  font-size: 24px;
  font-weight: 700;
  color: #00d4ff;
}

.stat.danger .stat-value {
  color: #ff4757;
}

.stat-label {
  font-size: 12px;
  color: #666;
}

.project-actions {
  display: flex;
  gap: 8px;
}
</style>

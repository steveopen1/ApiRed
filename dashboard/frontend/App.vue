<template>
  <div id="app">
    <nav class="sidebar">
      <div class="logo">
        <h1>ApiRed</h1>
        <span>v4.2</span>
      </div>
      <ul class="nav-menu">
        <li>
          <router-link to="/">
            <span class="icon">📊</span>
            <span>概览</span>
          </router-link>
        </li>
        <li>
          <router-link to="/projects">
            <span class="icon">📁</span>
            <span>项目</span>
          </router-link>
        </li>
        <li>
          <router-link to="/targets">
            <span class="icon">🎯</span>
            <span>目标</span>
          </router-link>
        </li>
        <li>
          <router-link to="/vulns">
            <span class="icon">🔓</span>
            <span>漏洞</span>
          </router-link>
        </li>
      </ul>
    </nav>
    <main class="content">
      <router-view />
    </main>
  </div>
</template>

<script>
export default {
  name: 'App'
}
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: #0f0f1a;
  color: #fff;
  min-height: 100vh;
}

#app {
  display: flex;
  min-height: 100vh;
}

.sidebar {
  width: 240px;
  background: #1a1a2e;
  border-right: 1px solid #333;
  padding: 20px 0;
  flex-shrink: 0;
}

.logo {
  padding: 0 20px 20px;
  border-bottom: 1px solid #333;
  margin-bottom: 20px;
}

.logo h1 {
  font-size: 24px;
  color: #00d4ff;
  margin-bottom: 4px;
}

.logo span {
  font-size: 12px;
  color: #666;
}

.nav-menu {
  list-style: none;
}

.nav-menu li {
  margin-bottom: 4px;
}

.nav-menu a {
  display: flex;
  align-items: center;
  padding: 12px 20px;
  color: #888;
  text-decoration: none;
  transition: all 0.2s;
}

.nav-menu a:hover,
.nav-menu a.router-link-active {
  background: #16162a;
  color: #00d4ff;
}

.nav-menu .icon {
  margin-right: 12px;
  font-size: 18px;
}

.content {
  flex: 1;
  overflow-x: hidden;
}
</style>

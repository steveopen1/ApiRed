<template>
  <div :class="['stat-card', variant]">
    <div class="stat-value">{{ value }}</div>
    <div class="stat-label">{{ label }}</div>
  </div>
</template>

<script>
export default {
  name: 'StatCard',
  props: {
    value: {
      type: [Number, String],
      default: 0
    },
    label: {
      type: String,
      required: true
    },
    variant: {
      type: String,
      default: ''
    }
  }
}
</script>

<style scoped>
.stat-card {
  background: #1e1e2e;
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 36px;
  font-weight: 700;
  color: #00d4ff;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 14px;
  color: #888;
}

.stat-card.danger .stat-value { color: #ff4757; }
.stat-card.warning .stat-value { color: #ffa500; }
.stat-card.success .stat-value { color: #00ff99; }
</style>

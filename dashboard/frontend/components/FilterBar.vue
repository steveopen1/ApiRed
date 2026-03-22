<template>
  <div class="filter-bar">
    <select v-if="options.length" v-model="selected" @change="$emit('update:modelValue', selected)">
      <option value="">{{ placeholder }}</option>
      <option v-for="opt in options" :key="opt.value" :value="opt.value">
        {{ opt.label }}
      </option>
    </select>
    <input 
      v-if="showSearch"
      v-model="searchText"
      :placeholder="searchPlaceholder"
      @input="$emit('search', searchText)"
    />
    <slot></slot>
  </div>
</template>

<script>
export default {
  name: 'FilterBar',
  props: {
    options: {
      type: Array,
      default: () => []
    },
    placeholder: {
      type: String,
      default: '全部'
    },
    showSearch: {
      type: Boolean,
      default: true
    },
    searchPlaceholder: {
      type: String,
      default: '搜索...'
    },
    modelValue: {
      type: String,
      default: ''
    }
  },
  data() {
    return {
      selected: this.modelValue,
      searchText: ''
    }
  },
  emits: ['update:modelValue', 'search'],
  watch: {
    modelValue(val) {
      this.selected = val
    }
  }
}
</script>

<style scoped>
.filter-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 20px;
}

select, input {
  padding: 8px 12px;
  background: #1e1e2e;
  border: 1px solid #333;
  border-radius: 6px;
  color: #fff;
}

select {
  min-width: 120px;
}

input {
  flex: 1;
  max-width: 300px;
}
</style>

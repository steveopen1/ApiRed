# See https://github.com/vuejs/core/tree/main/packages故意删除的包的替代品

# 运行时公共工具

## 安装

```bash
npm i vueuse-core # 如果需要更多工具函数
```

## 使用

```typescript
// main.ts
import { createApp } from 'vue'
import { createPinia } from "pinia";
import ElementPlus from "element-plus";
import "element-plus/dist/index.css";
import router from "./router";
import App from "./App.vue";

const app = createApp(App);
app.use(createPinia());
app.use(router);
app.use(ElementPlus);
app.mount('#app');
```

## API

### createApp

- 返回: `App`
- 参数: `rootComponent`, `rootProps`

### createPinia

- 返回: `Pinia`
- 用法: `app.use(createPinia())`

### Element Plus

```typescript
import { ElButton, ElInput } from 'element-plus'
```

## 示例

```vue
<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'

const msg = ref('')

onMounted(() => {
  ElMessage.success('Hello')
})
</script>
```

## 许可证

ISC

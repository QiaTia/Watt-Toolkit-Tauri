import { createApp } from 'vue';
import { createPinia } from 'pinia';
import dayjs from 'dayjs';
import 'dayjs/locale/zh-cn';
import App from './App.vue';
import router from './router';
import { i18n } from './locales';
// ant-design-vue v4 的全局 reset（组件样式由 CSS-in-JS 按需注入，这里只补全局基线）
import 'ant-design-vue/dist/reset.css';
import './assets/base.css';

dayjs.locale('zh-cn');

const app = createApp(App);
app.use(createPinia());
app.use(i18n);
app.use(router);
app.mount('#app');

import { createRouter, createWebHistory } from 'vue-router';
import { useProxyStore } from '@/stores/proxy';

/**
 * 路由：首页 / 网络加速 / 设置 / 关于
 */
const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'home',
      component: () => import('@/views/HomePage.vue'),
      meta: { title: '首页', icon: '🏠' },
    },
    {
      path: '/accelerator',
      name: 'accelerator',
      component: () => import('@/views/AcceleratorPage.vue'),
      meta: { title: '网络加速', icon: '🚀' },
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/SettingsPage.vue'),
      meta: { title: '设置', icon: '⚙️' },
    },
    {
      path: '/logs',
      name: 'logs',
      component: () => import('@/views/LogsPage.vue'),
      meta: { title: '日志', icon: '📄' },
    },
    {
      path: '/about',
      name: 'about',
      component: () => import('@/views/AboutPage.vue'),
      meta: { title: '关于', icon: 'ℹ️' },
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/',
    },
  ],
});

/**
 * 首次落地页策略：打开软件时若引擎未加速，默认进入网络加速页
 * （工具型应用的核心操作位；引擎运行中则保持首页总览）。
 * 仅影响首次导航——用户之后的手动切换不被拦截。
 */
let landingResolved = false;
router.beforeEach(async (to) => {
  if (landingResolved) return;
  landingResolved = true;
  if (to.path !== '/') return;
  let running = false;
  try {
    const proxy = useProxyStore();
    await proxy.refreshState();
    running = proxy.isRunning;
  } catch {
    // 状态获取失败：按未加速处理，落入加速页
    running = false;
  }
  if (!running) return '/accelerator';
});

router.afterEach((to) => {
  const title = to.meta['title'];
  if (typeof title === 'string') {
    document.title = `${title} - Watt Toolkit`;
  }
});

export default router;

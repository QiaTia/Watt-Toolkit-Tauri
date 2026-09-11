import { createRouter, createWebHistory } from 'vue-router';

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

router.afterEach((to) => {
  const title = to.meta['title'];
  if (typeof title === 'string') {
    document.title = `${title} - Watt Toolkit`;
  }
});

export default router;

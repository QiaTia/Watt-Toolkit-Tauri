<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { RouterView, useRoute, useRouter } from 'vue-router';
import zhCN from 'ant-design-vue/es/locale/zh_CN';
import theme from 'ant-design-vue/es/theme';
import { useProxyStore } from '@/stores/proxy';
import { useAppStore } from '@/stores/app';
import { useSettingsStore } from '@/stores/settings';
import { useCertStore } from '@/stores/cert';

const route = useRoute();
const router = useRouter();
const proxy = useProxyStore();
const appStore = useAppStore();
const settings = useSettingsStore();
const cert = useCertStore();

const collapsed = ref(false);

/** 主导航（path → 标题，用于顶栏面包屑标题） */
const navRoutes: ReadonlyArray<{ path: string; title: string }> = [
  { path: '/', title: '首页' },
  { path: '/accelerator', title: '网络加速' },
  { path: '/settings', title: '设置' },
  { path: '/about', title: '关于' },
];

const selectedKeys = computed<string[]>(() => [route.path]);
const currentTitle = computed(
  () => navRoutes.find((r) => r.path === route.path)?.title ?? 'Watt Toolkit',
);

function onMenuClick(info: { key: string | number }): void {
  void router.push(String(info.key));
}

/* 跟随系统深色模式；antd 通过 algorithm 切换整套色板 */
const prefersDark = ref(false);
const schemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
prefersDark.value = schemeQuery.matches;

function onSchemeChange(e: MediaQueryListEvent): void {
  prefersDark.value = e.matches;
}

const themeConfig = computed(() => ({
  algorithm: prefersDark.value ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: {
    colorPrimary: prefersDark.value ? '#4f8ef7' : '#3b82f6',
    borderRadius: 8,
  },
}));

/** 引擎状态徽标色 */
const engineTagColor = computed(() => {
  switch (proxy.state.type) {
    case 'running':
      return 'success';
    case 'error':
      return 'error';
    case 'starting':
    case 'stopping':
      return 'processing';
    default:
      return 'default';
  }
});

onMounted(() => {
  schemeQuery.addEventListener('change', onSchemeChange);
  void appStore.load();
  // ensureLoaded 幂等去重：子页面可能更早发起加载
  void settings.ensureLoaded();
  void cert.refresh();
  void proxy.refreshState();
});

onUnmounted(() => {
  schemeQuery.removeEventListener('change', onSchemeChange);
});
</script>

<template>
  <a-config-provider :locale="zhCN" :theme="themeConfig">
    <a-app>
      <a-layout class="shell">
        <a-layout-sider
          theme="light"
          :collapsed="collapsed"
          :width="208"
          :collapsed-width="64"
          :trigger="null"
          collapsible
          class="shell-sider"
        >
          <div class="brand">
            <span class="brand-mark">⚡</span>
            <span v-show="!collapsed" class="brand-text">Watt Toolkit</span>
          </div>

          <a-menu
            :selected-keys="selectedKeys"
            :inline-collapsed="collapsed"
            mode="inline"
            class="shell-menu"
            @click="onMenuClick"
          >
            <a-menu-item key="/">
              <template #icon><HomeOutlined /></template>
              <span>首页</span>
            </a-menu-item>
            <a-menu-item key="/accelerator">
              <template #icon><RocketOutlined /></template>
              <span>网络加速</span>
            </a-menu-item>
            <a-menu-item key="/settings">
              <template #icon><SettingOutlined /></template>
              <span>设置</span>
            </a-menu-item>
            <a-menu-item key="/about">
              <template #icon><InfoCircleOutlined /></template>
              <span>关于</span>
            </a-menu-item>
          </a-menu>

          <div class="sider-foot">
            <a-tag :color="engineTagColor">
              <span v-show="!collapsed">{{ proxy.stateLabel }}</span>
              <span v-show="collapsed">●</span>
            </a-tag>
          </div>
        </a-layout-sider>

        <a-layout class="shell-body">
          <a-layout-header class="shell-header">
            <a-button type="text" class="collapse-trigger" @click="collapsed = !collapsed">
              <template #icon>
                <MenuUnfoldOutlined v-if="collapsed" />
                <MenuFoldOutlined v-else />
              </template>
            </a-button>
            <span class="header-title">{{ currentTitle }}</span>
          </a-layout-header>

          <a-layout-content class="shell-content">
            <RouterView />
          </a-layout-content>
        </a-layout>
      </a-layout>
    </a-app>
  </a-config-provider>
</template>

<style scoped>
.shell {
  height: 100%;
  overflow: hidden;
}

.shell-sider {
  border-right: 1px solid var(--border);
}

/* antdv 会把内容包进 .ant-layout-sider-children，flex 布局必须落在这一层，
   否则底部的引擎状态徽标无法贴到侧栏最底部 */
.shell-sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 56px;
  padding: 0 18px;
  font-size: 16px;
  font-weight: 700;
  white-space: nowrap;
  overflow: hidden;
}

.brand-mark {
  font-size: 20px;
  line-height: 1;
}

.brand-text {
  letter-spacing: 0.2px;
}

.shell-menu {
  flex: 1;
  border-inline-end: none !important;
  overflow-y: auto;
  padding: 4px 0;
}

.sider-foot {
  padding: 12px 16px 16px;
  display: flex;
  justify-content: center;
}

.shell-body {
  height: 100%;
  min-width: 0;
}

.shell-header {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 56px;
  padding: 0 20px 0 8px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  line-height: normal;
}

.collapse-trigger {
  font-size: 16px;
}

.header-title {
  font-size: 16px;
  font-weight: 600;
}

.shell-content {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 20px 24px 28px;
}
</style>

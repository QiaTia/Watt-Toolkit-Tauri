<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { RouterView, useRoute, useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import zhCN from 'ant-design-vue/es/locale/zh_CN';
import zhTW from 'ant-design-vue/es/locale/zh_TW';
import jaJP from 'ant-design-vue/es/locale/ja_JP';
import enUS from 'ant-design-vue/es/locale/en_US';
import frFR from 'ant-design-vue/es/locale/fr_FR';
import theme from 'ant-design-vue/es/theme';
import { useProxyStore } from '@/stores/proxy';
import { useAppStore } from '@/stores/app';
import { useSettingsStore } from '@/stores/settings';
import { useCertStore } from '@/stores/cert';
import { useThemeStore } from '@/stores/theme';
import { i18n, type LocaleCode } from '@/locales';
import AppHeader from '@/components/AppHeader.vue';
import appIcon from '@/assets/app-icon.png';

const route = useRoute();
const router = useRouter();
const { t } = useI18n();
const proxy = useProxyStore();
const appStore = useAppStore();
const settings = useSettingsStore();
const cert = useCertStore();
const themeStore = useThemeStore();

const collapsed = ref(false);

/** 主导航（path → 标题 key，用于顶栏标题） */
const navRoutes: ReadonlyArray<{ path: string; titleKey: string }> = [
  { path: '/', titleKey: 'nav.home' },
  { path: '/accelerator', titleKey: 'nav.accelerator' },
  { path: '/settings', titleKey: 'nav.settings' },
  { path: '/about', titleKey: 'nav.about' },
];

const selectedKeys = computed<string[]>(() => [route.path]);
const currentTitle = computed(() => {
  const key = navRoutes.find((r) => r.path === route.path)?.titleKey;
  return key ? t(key) : 'Watt Toolkit';
});

/** antd 组件库文案（内置组件的内置文字）跟随语言切换 */
const antdLocales: Record<LocaleCode, typeof zhCN> = {
  'zh-Hans': zhCN,
  'zh-Hant': zhTW,
  ja: jaJP,
  en: enUS,
  fr: frFR,
};
const antdLocale = computed(() => antdLocales[i18n.global.locale.value as LocaleCode]);

function onMenuClick(info: { key: string | number }): void {
  void router.push(String(info.key));
}

/* 主题三态（浅色/深色/跟随系统）由 theme store 解析；antd 通过 algorithm 切换整套色板 */
const themeConfig = computed(() => ({
  algorithm: themeStore.isDark ? theme.darkAlgorithm : theme.defaultAlgorithm,
  token: {
    // 主色对齐应用图标渐变亮端（#247bc7）；暗色下提亮 25% 保证对比度
    colorPrimary: themeStore.isDark ? '#5a9cd5' : '#247bc7',
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
  void appStore.load();
  // ensureLoaded 幂等去重：子页面可能更早发起加载
  void settings.ensureLoaded();
  void cert.refresh();
  void proxy.refreshState();
});
</script>

<template>
  <a-config-provider :locale="antdLocale" :theme="themeConfig">
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
            <img :src="appIcon" :alt="$t('about.iconAlt')" class="brand-mark" />
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
              <span>{{ $t('nav.home') }}</span>
            </a-menu-item>
            <a-menu-item key="/accelerator">
              <template #icon><RocketOutlined /></template>
              <span>{{ $t('nav.accelerator') }}</span>
            </a-menu-item>
            <a-menu-item key="/settings">
              <template #icon><SettingOutlined /></template>
              <span>{{ $t('nav.settings') }}</span>
            </a-menu-item>
            <a-menu-item key="/about">
              <template #icon><InfoCircleOutlined /></template>
              <span>{{ $t('nav.about') }}</span>
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
          <AppHeader
            :title="currentTitle"
            :collapsed="collapsed"
            @toggle="collapsed = !collapsed"
          />

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
  width: 28px;
  height: 28px;
  border-radius: 7px;
  display: block;
  flex-shrink: 0;
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

.shell-content {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 20px 24px 28px;
}
</style>

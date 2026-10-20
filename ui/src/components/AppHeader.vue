<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useI18n } from 'vue-i18n';
import AntApp from 'ant-design-vue/es/app';
import { useSettingsStore } from '@/stores/settings';
import { useIpPoolStore } from '@/stores/ipPool';

defineProps<{ title: string; collapsed: boolean }>();

const emit = defineEmits<{ (e: 'toggle'): void }>();

const route = useRoute();
const { t } = useI18n();
const settings = useSettingsStore();
const pool = useIpPoolStore();
// 由 <a-app>（App.vue）提供的上下文创建，跟随全局主题
const { message } = AntApp.useApp();

/** 仅设置页在顶栏右上角显示保存入口（原页面底部保存栏已移除） */
const showSave = computed(() => route.path === '/settings');
/** IP 池管理页：顶栏右上角显示「刷新 IP 池」（原设置页 IP 池卡片迁移至此） */
const showPoolRefresh = computed(() => route.path === '/pool');

async function onSave(): Promise<void> {
  const ok = await settings.save();
  if (ok) {
    void message.success(t('common.saved'));
  } else {
    void message.error(t('common.saveFailed'));
  }
}

async function onRefreshPool(): Promise<void> {
  const results = await pool.refreshAll();
  // null = 命令失败，错误已进 store（页面顶部 alert 展示）
  if (results === null) {
    void message.error(pool.error ?? t('pool.refreshFailed'));
    return;
  }
  if (results.length === 0) {
    void message.info(t('pool.refreshEmpty'));
    return;
  }
  void message.success(
    t('pool.refreshDone', {
      hosts: results.length,
      ok: results.reduce((n, r) => n + r.ok, 0),
      candidates: results.reduce((n, r) => n + r.candidates, 0),
    }),
  );
}
</script>

<template>
  <a-layout-header class="shell-header">
    <a-button type="text" class="collapse-trigger" @click="emit('toggle')">
      <template #icon>
        <MenuUnfoldOutlined v-if="collapsed" />
        <MenuFoldOutlined v-else />
      </template>
    </a-button>
    <!-- 绝对定位居中，不随左右两侧宽度漂移 -->
    <span class="header-title">{{ title }}</span>
    <div class="header-right">
      <a-button v-if="showSave" type="primary" :loading="settings.saving" @click="onSave">
        {{ $t('common.save') }}
      </a-button>
      <a-button
        v-if="showPoolRefresh"
        type="primary"
        :loading="pool.refreshing"
        @click="onRefreshPool"
      >
        <template #icon><ReloadOutlined /></template>
        {{ $t('pool.refreshAll') }}
      </a-button>
    </div>
  </a-layout-header>
</template>

<style scoped>
.shell-header {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 20px 0 8px;
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  line-height: normal;
}

.collapse-trigger {
  font-size: 16px;
  /* 明确前景色：默认 text 按钮图标色可能随主题过浅，与头部背景混为一体 */
  color: var(--text);
}

.collapse-trigger:hover,
.collapse-trigger:focus-visible {
  color: var(--primary);
  background: color-mix(in srgb, var(--primary) 12%, transparent);
}

.header-title {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  font-size: 16px;
  font-weight: 600;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
}
</style>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useI18n } from 'vue-i18n';
import AntApp from 'ant-design-vue/es/app';
import { useSettingsStore } from '@/stores/settings';

defineProps<{ title: string; collapsed: boolean }>();

const emit = defineEmits<{ (e: 'toggle'): void }>();

const route = useRoute();
const { t } = useI18n();
const settings = useSettingsStore();
// 由 <a-app>（App.vue）提供的上下文创建，跟随全局主题
const { message } = AntApp.useApp();

/** 仅设置页在顶栏右上角显示保存入口（原页面底部保存栏已移除） */
const showSave = computed(() => route.path === '/settings');

async function onSave(): Promise<void> {
  const ok = await settings.save();
  if (ok) {
    void message.success(t('common.saved'));
  } else {
    void message.error(t('common.saveFailed'));
  }
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

<script setup lang="ts">
import { computed } from 'vue';
import { useI18n } from 'vue-i18n';
import { useAppStore } from '@/stores/app';
import { useUpdateStore, RELEASE_PAGE_URL } from '@/stores/update';
import { openExternal } from '@/api';
import appIcon from '@/assets/app-icon.png';

const app = useAppStore();
const update = useUpdateStore();
const { t } = useI18n();

/** 检查结果提示（自动检查静默，只有手动检查/失败才出现在这里） */
const hint = computed<string | null>(() => {
  switch (update.status) {
    case 'checking':
      return t('update.checking');
    case 'upToDate':
      return t('update.upToDate');
    case 'available':
      return t('update.availableHint', { version: update.info?.version ?? '' });
    case 'error':
      return update.error ?? t('update.failed');
    default:
      return null;
  }
});

function onCheck(): void {
  void update.check(true);
}

function onManualDownload(): void {
  void openExternal(RELEASE_PAGE_URL);
}

function onOpenSource(): void {
  void openExternal('https://github.com/WattToolkit/WattToolkit');
}
</script>

<template>
  <div class="page">
    <a-card :bordered="false" class="about-card">
      <div class="about">
        <img :src="appIcon" :alt="$t('about.iconAlt')" class="brand-avatar" />
        <a-typography-title :level="3" class="brand-name">Watt Toolkit</a-typography-title>
        <a-tag v-if="app.info" color="blue" class="brand-tag">
          v{{ app.info.version }} · Tauri
        </a-tag>
        <a-typography-paragraph type="secondary" class="desc">
          {{ $t('about.desc') }}
        </a-typography-paragraph>

        <div class="update-row">
          <a-button :loading="update.isChecking" @click="onCheck">
            {{ $t('update.checkNow') }}
          </a-button>
          <a-button v-if="update.hasUpdate" type="primary" @click="update.openModal()">
            {{ $t('update.viewDetail') }}
          </a-button>
          <a-button v-else type="text" @click="onManualDownload">
            {{ $t('update.manualDownload') }}
          </a-button>
        </div>
        <a-typography-text
          v-if="hint"
          :type="update.status === 'error' ? 'danger' : 'secondary'"
          class="update-hint"
        >
          {{ hint }}
        </a-typography-text>

        <a-descriptions v-if="app.info" :column="1" size="small" bordered class="meta">
          <a-descriptions-item :label="$t('about.platform')">{{ app.info.platform }}</a-descriptions-item>
          <a-descriptions-item :label="$t('about.dataDir')">
            <span class="mono">{{ app.info.dataDir }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <a-typography-paragraph type="secondary" class="license">
          {{ $t('about.license') }}
          {{ $t('about.sourceLabel') }}
          <a-typography-link @click="onOpenSource">WattToolkit/WattToolkit</a-typography-link>
        </a-typography-paragraph>
      </div>
    </a-card>
  </div>
</template>

<style scoped>
.about-card {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.about {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 24px 16px;
  text-align: center;
}

.brand-avatar {
  width: 72px;
  height: 72px;
  border-radius: 16px;
  display: block;
  /* 深浅两态下都与卡片背景有区分 */
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.18);
}

.brand-name {
  margin: 16px 0 8px !important;
}

.brand-tag {
  margin-bottom: 16px;
}

.desc {
  max-width: 420px;
  margin-bottom: 24px !important;
  line-height: 1.8;
}

.update-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.update-hint {
  font-size: 12px;
  margin-bottom: 16px;
  word-break: break-all;
  max-width: 480px;
}

.meta {
  width: 100%;
  max-width: 480px;
  margin-bottom: 24px;
  text-align: left;
}

.license {
  margin-bottom: 0 !important;
  font-size: 13px;
  line-height: 1.8;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  word-break: break-all;
}
</style>

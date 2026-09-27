<script setup lang="ts">
import { useAppStore } from '@/stores/app';
import appIcon from '@/assets/app-icon.png';

const app = useAppStore();
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

        <a-descriptions v-if="app.info" :column="1" size="small" bordered class="meta">
          <a-descriptions-item :label="$t('about.platform')">{{ app.info.platform }}</a-descriptions-item>
          <a-descriptions-item :label="$t('about.dataDir')">
            <span class="mono">{{ app.info.dataDir }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <a-typography-paragraph type="secondary" class="license">
          {{ $t('about.license') }}
          {{ $t('about.sourceLabel') }}
          <a href="https://github.com/WattToolkit/WattToolkit" target="_blank" rel="noopener">
            WattToolkit/WattToolkit
          </a>
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

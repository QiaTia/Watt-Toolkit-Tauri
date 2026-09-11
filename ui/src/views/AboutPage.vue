<script setup lang="ts">
import { useAppStore } from '@/stores/app';

const app = useAppStore();
</script>

<template>
  <div class="page">
    <a-card :bordered="false" class="about-card">
      <div class="about">
        <a-avatar :size="72" shape="square" class="brand-avatar">⚡</a-avatar>
        <a-typography-title :level="3" class="brand-name">Watt Toolkit</a-typography-title>
        <a-tag v-if="app.info" color="blue" class="brand-tag">
          v{{ app.info.version }} · Tauri
        </a-tag>
        <a-typography-paragraph type="secondary" class="desc">
          跨平台桌面应用，为 Steam 等游戏平台提供网络加速、脚本扩展等工具箱。
        </a-typography-paragraph>

        <a-descriptions v-if="app.info" :column="1" size="small" bordered class="meta">
          <a-descriptions-item label="平台">{{ app.info.platform }}</a-descriptions-item>
          <a-descriptions-item label="数据目录">
            <span class="mono">{{ app.info.dataDir }}</span>
          </a-descriptions-item>
        </a-descriptions>

        <a-typography-paragraph type="secondary" class="license">
          本项目基于 GPL-3.0 许可证开源。
          原项目：
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
  font-size: 40px;
  background: color-mix(in srgb, var(--primary) 15%, transparent);
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

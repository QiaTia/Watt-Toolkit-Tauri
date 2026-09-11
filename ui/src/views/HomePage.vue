<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { useProxyStore } from '@/stores/proxy';
import { useAppStore } from '@/stores/app';
import { useCertStore } from '@/stores/cert';

const proxy = useProxyStore();
const app = useAppStore();
const cert = useCertStore();

onMounted(() => {
  void proxy.refreshState();
  void cert.refresh();
});

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

const certHealthy = computed(() => cert.status !== null && !cert.status.expired);

/** 引擎状态 → antd Badge status */
const badgeStatus = computed(() => {
  switch (proxy.state.type) {
    case 'running':
      return 'success' as const;
    case 'error':
      return 'error' as const;
    case 'starting':
    case 'stopping':
      return 'processing' as const;
    default:
      return 'default' as const;
  }
});
</script>

<template>
  <div class="page">
    <a-card :bordered="false" class="hero-card">
      <div class="hero">
        <div class="hero-status">
          <a-badge :status="badgeStatus" />
          <div>
            <div class="status-text">{{ proxy.stateLabel }}</div>
            <a-typography-text v-if="proxy.state.type === 'error'" type="danger">
              {{ proxy.state.message }}
            </a-typography-text>
            <a-typography-text v-else type="secondary">
              {{
                proxy.isRunning
                  ? '流量正通过本地代理转发'
                  : '前往「网络加速」选择项目并一键加速'
              }}
            </a-typography-text>
          </div>
        </div>

        <a-row v-if="proxy.isRunning" :gutter="32" class="hero-stats">
          <a-col>
            <a-statistic title="上行" :value="formatBytes(proxy.stats.upBytes)" />
          </a-col>
          <a-col>
            <a-statistic title="下行" :value="formatBytes(proxy.stats.downBytes)" />
          </a-col>
        </a-row>
      </div>
    </a-card>

    <a-row :gutter="16" class="grid">
      <a-col :xs="24" :lg="12">
        <a-card :bordered="false" title="证书状态" class="info-card">
          <template #extra>
            <a-tag v-if="cert.status" :color="certHealthy ? 'success' : 'error'">
              {{ cert.status.expired ? '已过期' : '有效' }}
            </a-tag>
          </template>
          <a-descriptions v-if="cert.status" :column="1" size="small">
            <a-descriptions-item label="主题">{{ cert.status.subject }}</a-descriptions-item>
            <a-descriptions-item label="序列号">
              <span class="mono">{{ cert.status.serial }}</span>
            </a-descriptions-item>
            <a-descriptions-item label="剩余有效期">
              <a-typography-text :type="certHealthy ? 'success' : 'danger'">
                {{ cert.status.daysRemaining }} 天
              </a-typography-text>
            </a-descriptions-item>
          </a-descriptions>
          <a-skeleton v-else active :paragraph="{ rows: 3 }" />
        </a-card>
      </a-col>

      <a-col :xs="24" :lg="12">
        <a-card :bordered="false" title="应用信息" class="info-card">
          <a-descriptions v-if="app.info" :column="1" size="small">
            <a-descriptions-item label="版本">{{ app.info.version }}</a-descriptions-item>
            <a-descriptions-item label="平台">{{ app.info.platform }}</a-descriptions-item>
            <a-descriptions-item label="数据目录">
              <span class="mono">{{ app.info.dataDir }}</span>
            </a-descriptions-item>
          </a-descriptions>
          <a-skeleton v-else active :paragraph="{ rows: 3 }" />
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<style scoped>
.hero-card {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  flex-wrap: wrap;
}

.hero-status {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-text {
  font-size: 18px;
  font-weight: 600;
  line-height: 1.4;
}

.hero-stats {
  flex-shrink: 0;
}

.grid {
  margin-top: 16px;
}

.info-card {
  height: 100%;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  word-break: break-all;
}
</style>

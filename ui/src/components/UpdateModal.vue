<script setup lang="ts">
import { computed, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useUpdateStore, RELEASE_PAGE_URL } from '@/stores/update';
import { openExternal } from '@/api';
import { formatBytes } from '@/utils/format';

const update = useUpdateStore();
const { t } = useI18n();

/** Gatekeeper 脚本是否已复制（按钮文案反馈） */
const copied = ref(false);

/** 后端脚本加载失败时的兜底命令（默认安装路径）；显示与复制共用，避免不一致 */
const FALLBACK_SCRIPT = 'sudo xattr -cr "/Applications/Watt Toolkit.app"';
const scriptText = computed(() => update.gatekeeperScript || FALLBACK_SCRIPT);

const title = computed(() =>
  update.info
    ? t('update.modalTitle', { version: update.info.version })
    : t('update.title'),
);

const publishedAt = computed(() => {
  const raw = update.info?.date;
  if (!raw) return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? raw : d.toLocaleString();
});

const speedText = computed(() =>
  update.speed > 0 ? `${formatBytes(update.speed)}/s` : null,
);

const etaText = computed(() => {
  const s = update.etaSeconds;
  if (s === null || s <= 0) return null;
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
});

const percent = computed(() => update.percent ?? 0);

function onOpenChange(open: boolean): void {
  update.modalOpen = open;
}

/** 复制 Gatekeeper 脚本到剪贴板（失败时界面仍展示脚本供手动选择） */
async function copyScript(): Promise<void> {
  try {
    await navigator.clipboard.writeText(scriptText.value);
    copied.value = true;
  } catch {
    copied.value = false;
  }
}

/** 自动更新：macOS 先复制绕过脚本（确保重启前进剪贴板）再安装，照样替换 .app */
async function onAutoInstall(): Promise<void> {
  if (update.needsGatekeeperBypass) await copyScript();
  void update.install();
}

/** 错误态重新检查：版本漂移后刷新 info，再行安装 */
function onRecheck(): void {
  void update.check(true);
}

function onManualDownload(): void {
  void openExternal(RELEASE_PAGE_URL);
}
</script>

<template>
  <a-modal
    :open="update.modalOpen"
    :title="title"
    :mask-closable="!update.busy"
    :closable="!update.busy"
    :width="620"
    centered
    @update:open="onOpenChange"
  >
    <template v-if="update.info">
      <div class="version-row">
        <a-tag>{{ `v${update.info.currentVersion}` }}</a-tag>
        <span class="arrow">→</span>
        <a-tag color="blue">{{ `v${update.info.version}` }}</a-tag>
        <a-typography-text v-if="publishedAt" type="secondary" class="published">
          {{ $t('update.publishedAt', { time: publishedAt }) }}
        </a-typography-text>
      </div>

      <a-typography-text type="secondary" class="source">
        {{ $t('update.source') }}：{{ update.info.endpoint ?? $t('update.sourceDefault') }}
      </a-typography-text>

      <!-- macOS 未签名：自动更新照样替换 .app，提前告知 Gatekeeper 绕过方法并提供脚本 -->
      <a-alert
        v-if="update.needsGatekeeperBypass"
        type="warning"
        show-icon
        class="mac-hint"
      >
        <template #message>{{ $t('update.gatekeeperTitle') }}</template>
        <template #description>
          <div class="gk-hint">{{ $t('update.gatekeeperHint') }}</div>
          <div class="script-row">
            <code class="script">{{ scriptText }}</code>
            <a-button size="small" @click="copyScript">
              {{ copied ? $t('update.copied') : $t('update.copyScript') }}
            </a-button>
          </div>
          <div class="gk-steps">{{ $t('update.gatekeeperSteps') }}</div>
        </template>
      </a-alert>

      <div class="notes-label">{{ $t('update.notes') }}</div>
      <div class="notes">{{ update.info.body || $t('update.noNotes') }}</div>

      <div v-if="update.busy" class="progress-block">
        <a-progress
          :percent="update.status === 'installing' ? 100 : update.percent === null ? 99 : percent"
          :status="update.status === 'installing' ? 'success' : 'active'"
          :show-info="update.percent !== null"
        />
        <div class="progress-meta">
          <span v-if="update.status === 'installing'">{{ $t('update.installing') }}</span>
          <template v-else>
            <span>{{ $t('update.downloading') }}</span>
            <span v-if="update.total !== null">
              {{ formatBytes(update.downloaded) }} / {{ formatBytes(update.total) }}
            </span>
            <span v-else>{{ formatBytes(update.downloaded) }}</span>
            <span v-if="speedText">{{ speedText }}</span>
            <span v-if="etaText">{{ $t('update.remaining', { time: etaText }) }}</span>
          </template>
        </div>
        <a-typography-paragraph type="warning" class="stop-hint">
          {{ $t('update.stopHint') }}
        </a-typography-paragraph>
      </div>

      <a-alert v-if="update.status === 'error' && update.error" type="error" show-icon class="err">
        <template #message>{{ $t('update.failed') }}</template>
        <template #description>
          <div class="err-detail">{{ update.error }}</div>
          <a-button type="link" size="small" class="err-link" @click="onRecheck">
            {{ $t('update.checkNow') }}
          </a-button>
          <a-button type="link" size="small" class="err-link" @click="onManualDownload">
            {{ $t('update.manualDownload') }}
          </a-button>
        </template>
      </a-alert>
    </template>

    <template #footer>
      <div class="footer">
        <a-button v-if="!update.busy" @click="update.dismiss()">
          {{ $t('update.later') }}
        </a-button>
        <a-button v-if="!update.busy && update.info" @click="update.skipCurrent()">
          {{ $t('update.skipVersion') }}
        </a-button>
        <!-- macOS：与自动更新并列的手动下载选项 -->
        <a-button
          v-if="!update.busy && update.needsGatekeeperBypass"
          @click="onManualDownload"
        >
          {{ $t('update.manualDownload') }}
        </a-button>
        <!-- 自动安装（macOS 点击时先复制 Gatekeeper 脚本，再替换 .app） -->
        <a-button
          v-if="!update.busy && update.status !== 'error'"
          type="primary"
          @click="onAutoInstall"
        >
          {{ update.needsGatekeeperBypass ? $t('update.autoInstall') : $t('update.installNow') }}
        </a-button>
        <a-button
          v-if="!update.busy && update.status === 'error'"
          type="primary"
          @click="onAutoInstall"
        >
          {{ $t('update.retry') }}
        </a-button>
        <a-button v-if="update.busy" type="primary" loading>
          {{ update.status === 'installing' ? $t('update.installing') : $t('update.downloading') }}
        </a-button>
      </div>
    </template>
  </a-modal>
</template>

<style scoped>
.version-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.arrow {
  color: var(--text-secondary, #888);
}

.published {
  font-size: 12px;
  margin-left: auto;
}

.source {
  display: block;
  font-size: 12px;
  margin-top: 6px;
  word-break: break-all;
}

.mac-hint {
  margin-top: 12px;
}

.gk-hint {
  margin-bottom: 8px;
}

.script-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.script {
  flex: 1;
  padding: 6px 10px;
  border-radius: 6px;
  background: color-mix(in srgb, var(--border) 45%, transparent);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
  /* 单击即全选，自动复制失败时便于手动拷贝 */
  user-select: all;
}

.gk-steps {
  font-size: 12px;
}

.notes-label {
  margin: 16px 0 6px;
  font-weight: 600;
}

.notes {
  max-height: 240px;
  overflow-y: auto;
  padding: 12px 14px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--border) 35%, transparent);
  font-size: 13px;
  line-height: 1.7;
  /* Release body 是 Markdown 原文：保留换行与列表层级，不做富文本渲染 */
  white-space: pre-wrap;
  word-break: break-word;
}

.progress-block {
  margin-top: 16px;
}

.progress-meta {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--text-secondary, #888);
}

.stop-hint {
  margin: 8px 0 0;
  font-size: 12px;
}

.err {
  margin-top: 16px;
}

.err-detail {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
}

.err-link {
  padding-left: 0;
}

.footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}
</style>

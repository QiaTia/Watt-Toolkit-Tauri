<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import dayjs from 'dayjs';
import {
  proxyAccessLogs,
  proxyAccessLogsClear,
  runtimeLogs,
  runtimeLogsClear,
} from '@/api';
import type {
  AccessLogEntry,
  Disposition,
  RuntimeLogEntry,
} from '@/types/ipc';

const { t } = useI18n();

const activeTab = ref<'access' | 'runtime'>('access');

/* ===================== 访问日志 ===================== */

const accessRows = ref<AccessLogEntry[]>([]);
const accessLoading = ref(false);
const accessAutoRefresh = ref(true);
const accessFilter = reactive({
  keyword: '',
  method: undefined as string | undefined,
  statusClass: undefined as string | undefined,
  disposition: undefined as Disposition | undefined,
});
const accessPage = reactive({ current: 1, pageSize: 50, total: 0 });

const methodOptions = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
const statusOptions = [
  { value: '2xx', min: 200, max: 299 },
  { value: '3xx', min: 300, max: 399 },
  { value: '4xx', min: 400, max: 499 },
  { value: '5xx', min: 500, max: 599 },
];

async function loadAccess(): Promise<void> {
  accessLoading.value = true;
  try {
    const sc = statusOptions.find((o) => o.value === accessFilter.statusClass);
    const page = await proxyAccessLogs(
      {
        keyword: accessFilter.keyword.trim() || null,
        method: accessFilter.method || null,
        statusMin: sc ? sc.min : null,
        statusMax: sc ? sc.max : null,
        disposition: accessFilter.disposition || null,
      },
      accessPage.current,
      accessPage.pageSize,
    );
    accessRows.value = page.items;
    accessPage.total = page.total;
  } catch (e) {
    console.error('加载访问日志失败', e);
  } finally {
    accessLoading.value = false;
  }
}

function applyAccessFilter(): void {
  accessPage.current = 1;
  void loadAccess();
}

function onAccessTableChange(pag: { current?: number; pageSize?: number }): void {
  accessPage.current = pag.current ?? 1;
  accessPage.pageSize = pag.pageSize ?? accessPage.pageSize;
  void loadAccess();
}

async function clearAccess(): Promise<void> {
  await proxyAccessLogsClear();
  accessPage.current = 1;
  await loadAccess();
}

/* ===================== 运行日志 ===================== */

const runtimeRows = ref<RuntimeLogEntry[]>([]);
const runtimeLoading = ref(false);
const runtimeAutoRefresh = ref(true);
const runtimeFilter = reactive({
  keyword: '',
  minLevel: undefined as string | undefined,
});
const runtimePage = reactive({ current: 1, pageSize: 50, total: 0 });

const levelOptions = ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];

async function loadRuntime(): Promise<void> {
  runtimeLoading.value = true;
  try {
    const page = await runtimeLogs(
      {
        keyword: runtimeFilter.keyword.trim() || null,
        minLevel: runtimeFilter.minLevel || null,
      },
      runtimePage.current,
      runtimePage.pageSize,
    );
    runtimeRows.value = page.items;
    runtimePage.total = page.total;
  } catch (e) {
    console.error('加载运行日志失败', e);
  } finally {
    runtimeLoading.value = false;
  }
}

function applyRuntimeFilter(): void {
  runtimePage.current = 1;
  void loadRuntime();
}

function onRuntimeTableChange(pag: { current?: number; pageSize?: number }): void {
  runtimePage.current = pag.current ?? 1;
  runtimePage.pageSize = pag.pageSize ?? runtimePage.pageSize;
  void loadRuntime();
}

async function clearRuntime(): Promise<void> {
  await runtimeLogsClear();
  runtimePage.current = 1;
  await loadRuntime();
}

/* ===================== 公共 ===================== */

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatTime(tsMs: number): string {
  return dayjs(tsMs).format('MM-DD HH:mm:ss.SSS');
}

function statusColor(status: number): string {
  if (status >= 500) return 'error';
  if (status >= 400) return 'warning';
  if (status >= 300) return 'processing';
  if (status >= 200) return 'success';
  return 'default';
}

function levelColor(level: string): string {
  switch (level) {
    case 'ERROR':
      return 'error';
    case 'WARN':
      return 'warning';
    case 'INFO':
      return 'success';
    case 'DEBUG':
      return 'processing';
    default:
      return 'default';
  }
}

const dispositionLabel = computed<Record<Disposition, string>>(() => ({
  matched: t('logs.dispMatched'),
  default: t('logs.dispDefault'),
  unmatched: t('logs.dispUnmatched'),
  local: t('logs.dispLocal'),
}));

const accessPagination = computed(() => ({
  current: accessPage.current,
  pageSize: accessPage.pageSize,
  total: accessPage.total,
  showSizeChanger: true,
  pageSizeOptions: ['20', '50', '100', '200'],
  showTotal: (total: number) => t('logs.total', { total }),
  size: 'small' as const,
}));

const runtimePagination = computed(() => ({
  current: runtimePage.current,
  pageSize: runtimePage.pageSize,
  total: runtimePage.total,
  showSizeChanger: true,
  pageSizeOptions: ['20', '50', '100', '200'],
  showTotal: (total: number) => t('logs.total', { total }),
  size: 'small' as const,
}));

/* 自动刷新：每 2s 重载当前激活标签页 */
let timer: ReturnType<typeof setInterval> | null = null;
function ensureTimer(): void {
  if (timer !== null) return;
  timer = setInterval(() => {
    if (activeTab.value === 'access' && accessAutoRefresh.value) {
      void loadAccess();
    } else if (activeTab.value === 'runtime' && runtimeAutoRefresh.value) {
      void loadRuntime();
    }
  }, 2000);
}

onMounted(() => {
  void loadAccess();
  void loadRuntime();
  ensureTimer();
});

onUnmounted(() => {
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }
});
</script>

<template>
  <div class="page">
    <a-card :bordered="false" class="log-card">
      <a-tabs v-model:activeKey="activeTab">
        <!-- 访问日志 -->
        <a-tab-pane key="access" :tab="$t('logs.accessTab')">
          <div class="toolbar">
            <a-input-search
              v-model:value="accessFilter.keyword"
              :placeholder="$t('logs.keywordPlaceholder')"
              class="kw"
              allow-clear
              @search="applyAccessFilter"
            />
            <a-select
              v-model:value="accessFilter.method"
              :placeholder="$t('logs.method')"
              class="sel-sm"
              allow-clear
              :options="methodOptions.map((m) => ({ value: m, label: m }))"
              @change="applyAccessFilter"
            />
            <a-select
              v-model:value="accessFilter.statusClass"
              :placeholder="$t('logs.status')"
              class="sel-sm"
              allow-clear
              :options="statusOptions.map((o) => ({ value: o.value, label: o.value }))"
              @change="applyAccessFilter"
            />
            <a-select
              v-model:value="accessFilter.disposition"
              :placeholder="$t('logs.disposition')"
              class="sel"
              allow-clear
              :options="[
                { value: 'matched', label: $t('logs.dispMatched') },
                { value: 'default', label: $t('logs.dispDefault') },
                { value: 'unmatched', label: $t('logs.dispUnmatched') },
                { value: 'local', label: $t('logs.dispLocal') },
              ]"
              @change="applyAccessFilter"
            />
            <div class="spacer" />
            <span class="auto">
              {{ $t('logs.autoRefresh') }}
              <a-switch v-model:checked="accessAutoRefresh" size="small" />
            </span>
            <a-button size="small" @click="loadAccess">{{ $t('logs.refresh') }}</a-button>
            <a-button size="small" danger @click="clearAccess">{{ $t('logs.clear') }}</a-button>
          </div>

          <a-table
            :data-source="accessRows"
            :loading="accessLoading"
            :pagination="accessPagination"
            :scroll="{ x: 1000 }"
            size="small"
            row-key="tsMs"
            :locale="{ emptyText: $t('logs.empty') }"
            @change="onAccessTableChange"
          >
            <a-table-column :title="$t('logs.colTime')" data-index="tsMs" :width="170">
              <template #default="{ record }">
                <span class="mono">{{ formatTime(record.tsMs) }}</span>
              </template>
            </a-table-column>
            <a-table-column :title="$t('logs.colMethod')" data-index="method" :width="90" />
            <a-table-column :title="$t('logs.colHost')" data-index="host" :width="220" ellipsis />
            <a-table-column :title="$t('logs.colPath')" data-index="path" ellipsis />
            <a-table-column :title="$t('logs.colStatus')" data-index="status" :width="90">
              <template #default="{ record }">
                <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
              </template>
            </a-table-column>
            <a-table-column :title="$t('logs.colDown')" data-index="downBytes" :width="100">
              <template #default="{ record }">{{ formatBytes(record.downBytes) }}</template>
            </a-table-column>
            <a-table-column :title="$t('logs.colLatency')" data-index="latencyMs" :width="100">
              <template #default="{ record }">{{ record.latencyMs }} ms</template>
            </a-table-column>
            <a-table-column :title="$t('logs.colDisposition')" data-index="disposition" :width="110">
              <template #default="{ record }">
                <a-tag>{{ dispositionLabel[record.disposition as Disposition] }}</a-tag>
              </template>
            </a-table-column>
          </a-table>
        </a-tab-pane>

        <!-- 运行日志 -->
        <a-tab-pane key="runtime" :tab="$t('logs.runtimeTab')">
          <div class="toolbar">
            <a-input-search
              v-model:value="runtimeFilter.keyword"
              :placeholder="$t('logs.runtimeKeywordPlaceholder')"
              class="kw"
              allow-clear
              @search="applyRuntimeFilter"
            />
            <a-select
              v-model:value="runtimeFilter.minLevel"
              :placeholder="$t('logs.level')"
              class="sel-sm"
              allow-clear
              :options="levelOptions.map((l) => ({ value: l, label: l }))"
              @change="applyRuntimeFilter"
            />
            <div class="spacer" />
            <span class="auto">
              {{ $t('logs.autoRefresh') }}
              <a-switch v-model:checked="runtimeAutoRefresh" size="small" />
            </span>
            <a-button size="small" @click="loadRuntime">{{ $t('logs.refresh') }}</a-button>
            <a-button size="small" danger @click="clearRuntime">{{ $t('logs.clear') }}</a-button>
          </div>

          <a-table
            :data-source="runtimeRows"
            :loading="runtimeLoading"
            :pagination="runtimePagination"
            :scroll="{ x: 900 }"
            size="small"
            row-key="tsMs"
            :locale="{ emptyText: $t('logs.empty') }"
            @change="onRuntimeTableChange"
          >
            <a-table-column :title="$t('logs.colTime')" data-index="tsMs" :width="170">
              <template #default="{ record }">
                <span class="mono">{{ formatTime(record.tsMs) }}</span>
              </template>
            </a-table-column>
            <a-table-column :title="$t('logs.colLevel')" data-index="level" :width="90">
              <template #default="{ record }">
                <a-tag :color="levelColor(record.level)">{{ record.level }}</a-tag>
              </template>
            </a-table-column>
            <a-table-column :title="$t('logs.colTarget')" data-index="target" :width="220" ellipsis />
            <a-table-column :title="$t('logs.colMessage')" data-index="message">
              <template #default="{ record }">
                <span class="mono msg">{{ record.message }}</span>
              </template>
            </a-table-column>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </a-card>
  </div>
</template>

<style scoped>
.log-card {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.toolbar .kw {
  width: 240px;
}

.toolbar .sel {
  width: 140px;
}

.toolbar .sel-sm {
  width: 110px;
}

.toolbar .spacer {
  flex: 1;
}

.toolbar .auto {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: var(--text-secondary, #666);
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
}

.msg {
  word-break: break-all;
  white-space: pre-wrap;
}
</style>

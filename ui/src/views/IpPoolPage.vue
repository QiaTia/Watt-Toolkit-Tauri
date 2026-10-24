<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import AntApp from 'ant-design-vue/es/app';
import dayjs from 'dayjs';
import { ipPoolBuiltinList, ipPoolDomainOverview } from '@/api';
import { useIpPoolStore } from '@/stores/ipPool';
import type { BuiltinPoolGroup, DomainPoolOverview, IpPoolDomain } from '@/types/ipc';

const { t } = useI18n();
const pool = useIpPoolStore();
// 由 <a-app>（App.vue）提供的上下文创建，跟随全局主题
const { message } = AntApp.useApp();

/** 版本内置备用池（编译期常量，只读）：动态池无命中时的兜底候选 */
const builtin = ref<BuiltinPoolGroup[]>([]);
const builtinIpTotal = computed(() => builtin.value.reduce((n, g) => n + g.ips.length, 0));

/* ===================== 加速域名 IP 总览 ===================== */

/** 已勾选加速项目的全部域名 + 每个域名实际可用的 IP 来源 */
const overview = ref<DomainPoolOverview[]>([]);
const overviewKeyword = ref('');
const overviewSource = ref<'all' | 'override' | 'dynamic' | 'builtin' | 'dns'>('all');

const overviewWithIp = computed(() => overview.value.filter((d) => d.sources.length > 1).length);
const overviewDnsOnly = computed(() => overview.value.filter((d) => d.sources.length === 1).length);

const overviewFiltered = computed(() => {
  const kw = overviewKeyword.value.trim().toLowerCase();
  return overview.value.filter((d) => {
    if (kw && !d.pattern.toLowerCase().includes(kw)) return false;
    // dns 筛选项为「仅 DNS」：没有任何静态 / 池 IP，全靠解析
    if (overviewSource.value === 'all') return true;
    if (overviewSource.value === 'dns') return d.sources.length === 1;
    return d.sources.includes(overviewSource.value);
  });
});

const sourceOptions = computed(() => [
  { value: 'all', label: t('pool.srcAll') },
  { value: 'override', label: t('pool.srcOverride') },
  { value: 'dynamic', label: t('pool.srcDynamic') },
  { value: 'builtin', label: t('pool.srcBuiltin') },
  { value: 'dns', label: t('pool.srcDnsOnly') },
]);

const overviewColumns = computed(() => [
  { key: 'pattern', title: t('pool.colHost') },
  { key: 'sources', title: t('pool.colSource'), width: 250 },
  { key: 'count', title: t('pool.colIps'), width: 100, align: 'right' as const },
]);

const SOURCE_COLOR: Record<string, string> = {
  override: 'purple',
  dynamic: 'blue',
  builtin: 'orange',
  dns: 'default',
};

function sourceLabel(src: string): string {
  switch (src) {
    case 'override':
      return t('pool.srcOverride');
    case 'dynamic':
      return t('pool.srcDynamic');
    case 'builtin':
      return t('pool.srcBuiltin');
    default:
      return t('pool.srcDns');
  }
}

/** 该域名可用的静态 / 池 IP 总数（不含 DNS 动态解析结果） */
function ipCount(d: DomainPoolOverview): number {
  return d.overrideIps.length + d.dynamicIps.length + d.builtinIps.length;
}

async function loadBuiltin(): Promise<void> {
  try {
    builtin.value = await ipPoolBuiltinList();
  } catch {
    // 旧二进制没有该命令时保持隐藏，不打断页面其余功能
    builtin.value = [];
  }
}

async function loadOverview(): Promise<void> {
  try {
    overview.value = await ipPoolDomainOverview();
  } catch {
    overview.value = [];
  }
}

onMounted(() => {
  void pool.load();
  void loadOverview();
  void loadBuiltin();
});

// 动态池变化（刷新/保存/删除）后「来源」列会变，总览需同步重算。
// 连续操作（如批量删除）在 150ms 内合并为一次 IPC。
let overviewTimer: ReturnType<typeof setTimeout> | null = null;
watch(
  () => pool.domains,
  () => {
    if (overviewTimer !== null) clearTimeout(overviewTimer);
    overviewTimer = setTimeout(() => {
      overviewTimer = null;
      void loadOverview();
    }, 150);
  },
);
onUnmounted(() => {
  if (overviewTimer !== null) clearTimeout(overviewTimer);
});

/* ===================== 列表 ===================== */

const columns = computed(() => [
  { key: 'host', title: t('pool.colHost') },
  { key: 'count', title: t('pool.colIps'), width: 100 },
  { key: 'refreshed', title: t('pool.colRefreshed'), width: 170 },
  { key: 'actions', title: t('pool.colActions'), width: 260, align: 'right' as const },
]);

/** 内置备用池列表列（只读） */
const builtinColumns = computed(() => [
  { key: 'pattern', title: t('pool.colPattern'), width: 300 },
  { key: 'count', title: t('pool.colIps'), width: 100 },
  { key: 'note', title: t('pool.colNote') },
]);

function formatTime(ms: number): string {
  return ms > 0 ? dayjs(ms).format('YYYY-MM-DD HH:mm:ss') : '—';
}

/** 该 IP 的本次探测结果（未探测 = undefined） */
function probeOf(host: string, ip: string) {
  return pool.probes[host]?.find((p) => p.ip === ip);
}

/** 探测结果 → 展示态（未探测 / 不可用 / RTT） */
function probeState(host: string, ip: string): {
  type: 'secondary' | 'danger' | 'success';
  text: string;
} {
  const p = probeOf(host, ip);
  if (!p) return { type: 'secondary', text: t('pool.notProbed') };
  if (p.rttMs === null) return { type: 'danger', text: t('pool.unreachable') };
  return { type: 'success', text: t('pool.rtt', { ms: p.rttMs }) };
}

function hasProbe(host: string): boolean {
  return Array.isArray(pool.probes[host]);
}

function unreachableCount(host: string): number {
  return pool.probes[host]?.filter((p) => p.rttMs === null).length ?? 0;
}

/* ===================== 行操作 ===================== */

async function probeHost(host: string): Promise<void> {
  const items = await pool.probeHost(host);
  if (items === null) return;
  const ok = items.filter((i) => i.rttMs !== null).length;
  if (ok === 0) {
    void message.warning(t('pool.probeAllFailed', { total: items.length }));
    return;
  }
  void message.success(t('pool.probeOk', { ok, total: items.length }));
}

async function refreshHost(host: string): Promise<void> {
  const r = await pool.refreshHost(host);
  if (r === null) return;
  if (r.ok === 0) {
    void message.warning(t('pool.refreshHostEmpty', { host }));
    return;
  }
  void message.success(t('pool.refreshedHost', { host, ok: r.ok, total: r.candidates }));
}

async function pruneHost(host: string): Promise<void> {
  try {
    const n = await pool.pruneUnreachable(host);
    if (n > 0) void message.success(t('pool.pruneDone', { n }));
  } catch {
    // 错误已由 store 写入 error（页面顶部 alert）
  }
}

async function removeHost(host: string): Promise<void> {
  const ok = await pool.removeDomain(host);
  if (ok) void message.success(t('pool.removed'));
}

/** 移除单个 IP（保存剩余列表；全部移除时退化为删除域名条目） */
async function removeIp(host: string, ip: string): Promise<void> {
  const entry = pool.domains.find((d) => d.host === host);
  const rest = (entry?.ips ?? []).filter((x) => x !== ip);
  if (rest.length === 0) {
    await removeHost(host);
    return;
  }
  try {
    await pool.saveDomain(host, rest);
    void message.success(t('pool.removed'));
  } catch {
    // 错误已由 store 写入 error（页面顶部 alert）
  }
}

async function clearAll(): Promise<void> {
  const ok = await pool.clearAll();
  if (ok) void message.success(t('pool.cleared'));
}

/* ===================== 编辑弹窗 ===================== */

const editorOpen = ref(false);
/** 正在编辑的域名（null = 新增） */
const editingHost = ref<string | null>(null);
const draftHost = ref('');
const draftIps = ref('');
const saving = ref(false);

const editorTitle = computed(() =>
  editingHost.value ? t('pool.editTitleEdit', { host: editingHost.value }) : t('pool.editTitleNew'),
);

function openCreate(): void {
  editingHost.value = null;
  draftHost.value = '';
  draftIps.value = '';
  editorOpen.value = true;
}

function openEdit(record: IpPoolDomain): void {
  editingHost.value = record.host;
  draftHost.value = record.host;
  draftIps.value = record.ips.join('\n');
  editorOpen.value = true;
}

async function submitEditor(): Promise<void> {
  const host = draftHost.value.trim();
  if (!host) {
    void message.error(t('pool.hostRequired'));
    return;
  }
  saving.value = true;
  try {
    await pool.saveDomain(host, [draftIps.value]);
    editorOpen.value = false;
    void message.success(t('pool.saved'));
  } catch (e) {
    // 弹窗遮住页面顶部 alert，保存失败必须就地提示（无效 IP / 空列表等）
    void message.error(e instanceof Error ? e.message : String(e));
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <div class="page">
    <a-card :bordered="false" class="panel">
      <div class="pool-head">
        <div class="pool-summary">
          <span class="pool-count">
            {{ $t('pool.summary', { hosts: pool.domains.length, ips: pool.ipTotal }) }}
          </span>
          <a-typography-text v-if="pool.lastRefresh" type="secondary" class="pool-sub">
            {{ $t('pool.lastRefreshSummary', pool.lastRefresh) }}
          </a-typography-text>
        </div>
        <a-space :size="8">
          <a-button size="small" @click="openCreate">
            <template #icon><PlusOutlined /></template>
            {{ $t('pool.addDomain') }}
          </a-button>
          <a-popconfirm
            v-if="pool.domains.length"
            :title="$t('pool.clearConfirm')"
            :ok-text="$t('pool.clearAll')"
            :cancel-text="$t('pool.cancel')"
            @confirm="clearAll"
          >
            <a-button danger type="text" size="small">{{ $t('pool.clearAll') }}</a-button>
          </a-popconfirm>
        </a-space>
      </div>

      <a-typography-paragraph type="secondary" class="pool-hint">
        {{ $t('pool.hint') }}
      </a-typography-paragraph>

      <a-alert v-if="pool.error" type="error" show-icon class="pool-error">
        <template #message>{{ pool.error }}</template>
      </a-alert>

      <a-table
        v-if="pool.domains.length"
        size="small"
        row-key="host"
        :loading="pool.loading"
        :pagination="false"
        :columns="columns"
        :data-source="pool.domains"
        class="pool-table"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'host'">
            <span class="mono host">{{ record.host }}</span>
          </template>
          <template v-else-if="column.key === 'count'">
            <a-tag :color="record.ips.length ? 'blue' : 'default'">{{ record.ips.length }}</a-tag>
          </template>
          <template v-else-if="column.key === 'refreshed'">
            <span class="refreshed">{{ formatTime(record.refreshedAtMs) }}</span>
          </template>
          <template v-else-if="column.key === 'actions'">
            <a-space :size="4">
              <a-button size="small" type="link" @click="openEdit(record as IpPoolDomain)">
                {{ $t('pool.edit') }}
              </a-button>
              <a-button
                size="small"
                type="link"
                :loading="pool.isBusy(record.host)"
                @click="probeHost(record.host)"
              >
                {{ $t('pool.probe') }}
              </a-button>
              <a-button
                size="small"
                type="link"
                :loading="pool.isBusy(record.host)"
                @click="refreshHost(record.host)"
              >
                {{ $t('pool.refreshHost') }}
              </a-button>
              <a-popconfirm
                :title="$t('pool.removeConfirm', { host: record.host })"
                :ok-text="$t('pool.remove')"
                :cancel-text="$t('pool.cancel')"
                @confirm="removeHost(record.host)"
              >
                <a-button size="small" type="link" danger>{{ $t('pool.remove') }}</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>

        <template #expandedRowRender="{ record }">
          <div class="ips">
            <div v-for="ip in record.ips" :key="ip" class="ip-row">
              <span class="mono ip">{{ ip }}</span>
              <a-typography-text :type="probeState(record.host, ip).type" class="ip-status">
                {{ probeState(record.host, ip).text }}
              </a-typography-text>
              <a-popconfirm
                :title="$t('pool.removeIpConfirm', { ip })"
                :ok-text="$t('pool.remove')"
                :cancel-text="$t('pool.cancel')"
                @confirm="removeIp(record.host, ip)"
              >
                <a-button size="small" type="link" danger>
                  {{ $t('pool.removeIp') }}
                </a-button>
              </a-popconfirm>
            </div>

            <div v-if="hasProbe(record.host) && unreachableCount(record.host) > 0" class="prune">
              <a-button size="small" @click="pruneHost(record.host)">
                {{ $t('pool.prune', { n: unreachableCount(record.host) }) }}
              </a-button>
            </div>
          </div>
        </template>
      </a-table>

      <a-empty v-else-if="!pool.loading" :description="$t('pool.empty')" class="pool-empty">
        <a-button type="primary" @click="openCreate">{{ $t('pool.addDomain') }}</a-button>
      </a-empty>
    </a-card>

    <a-card v-if="overview.length" :bordered="false" class="panel">
      <div class="pool-head">
        <div class="pool-summary">
          <span class="pool-count">{{ $t('pool.overviewTitle') }}</span>
          <a-typography-text type="secondary" class="pool-sub">
            {{
              $t('pool.overviewSummary', {
                hosts: overview.length,
                withIp: overviewWithIp,
                dnsOnly: overviewDnsOnly,
              })
            }}
          </a-typography-text>
        </div>
        <a-input
          v-model:value="overviewKeyword"
          :placeholder="$t('pool.searchPlaceholder')"
          size="small"
          allow-clear
          class="search"
        />
      </div>

      <a-typography-paragraph type="secondary" class="pool-hint">
        {{ $t('pool.overviewHint') }}
      </a-typography-paragraph>

      <a-segmented
        v-model:value="overviewSource"
        :options="sourceOptions"
        size="small"
        class="src-filter"
      />

      <a-table
        size="small"
        row-key="host"
        :pagination="{ pageSize: 15, size: 'small', showSizeChanger: false }"
        :columns="overviewColumns"
        :data-source="overviewFiltered"
        class="pool-table"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'pattern'">
            <span class="mono host">{{ record.pattern }}</span>
          </template>
          <template v-else-if="column.key === 'sources'">
            <a-space :size="4" wrap>
              <a-tag
                v-for="s in record.sources"
                :key="s"
                :color="SOURCE_COLOR[s] ?? 'default'"
                class="src-tag"
              >
                {{ sourceLabel(s) }}
              </a-tag>
            </a-space>
          </template>
          <template v-else-if="column.key === 'count'">
            <a-tag v-if="ipCount(record as DomainPoolOverview) > 0" color="blue">
              {{ ipCount(record as DomainPoolOverview) }}
            </a-tag>
            <a-typography-text v-else type="secondary">{{ $t('pool.ipCountDns') }}</a-typography-text>
          </template>
        </template>

        <template #expandedRowRender="{ record }">
          <div class="ips">
            <div v-if="record.overrideIps.length" class="ip-group">
              <a-tag color="purple">{{ $t('pool.srcOverride') }}</a-tag>
              <span class="mono ip ip-inline">{{ record.overrideIps.join('   ') }}</span>
            </div>
            <div v-if="record.dynamicIps.length" class="ip-group">
              <a-tag color="blue">{{ $t('pool.srcDynamic') }}</a-tag>
              <span class="mono ip ip-inline">{{ record.dynamicIps.join('   ') }}</span>
            </div>
            <div v-if="record.builtinIps.length" class="ip-group">
              <a-tag color="orange">{{ $t('pool.srcBuiltin') }}</a-tag>
              <span class="mono ip ip-inline">{{ record.builtinIps.join('   ') }}</span>
            </div>
            <div class="ip-row">
              <a-tag>{{ $t('pool.srcDns') }}</a-tag>
              <span class="refreshed">{{ $t('pool.dnsAlwaysHint') }}</span>
            </div>
          </div>
        </template>
      </a-table>
    </a-card>

    <a-card v-if="builtin.length" :bordered="false" class="panel">
      <div class="pool-head">
        <div class="pool-summary">
          <span class="pool-count">{{ $t('pool.builtinTitle') }}</span>
          <a-typography-text type="secondary" class="pool-sub">
            {{ $t('pool.builtinSummary', { groups: builtin.length, ips: builtinIpTotal }) }}
          </a-typography-text>
        </div>
        <a-tag color="default">{{ $t('pool.readonly') }}</a-tag>
      </div>

      <a-typography-paragraph type="secondary" class="pool-hint">
        {{ $t('pool.builtinHint') }}
      </a-typography-paragraph>

      <a-table
        size="small"
        row-key="pattern"
        :pagination="false"
        :columns="builtinColumns"
        :data-source="builtin"
        class="pool-table"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'pattern'">
            <span class="mono host">{{ record.pattern }}</span>
          </template>
          <template v-else-if="column.key === 'count'">
            <a-tag color="default">{{ record.ips.length }}</a-tag>
          </template>
          <template v-else-if="column.key === 'note'">
            <span class="refreshed">{{ record.note }}</span>
          </template>
        </template>

        <template #expandedRowRender="{ record }">
          <div class="ips">
            <div v-for="ip in record.ips" :key="ip" class="ip-row">
              <span class="mono ip">{{ ip }}</span>
            </div>
          </div>
        </template>
      </a-table>
    </a-card>

    <a-modal
      v-model:open="editorOpen"
      :title="editorTitle"
      :ok-text="$t('pool.save')"
      :cancel-text="$t('pool.cancel')"
      :confirm-loading="saving"
      @ok="submitEditor"
    >
      <a-form layout="vertical" class="editor">
        <a-form-item :label="$t('pool.hostLabel')">
          <a-input
            v-model:value="draftHost"
            :disabled="editingHost !== null"
            :placeholder="$t('pool.hostPlaceholder')"
            class="mono"
          />
        </a-form-item>
        <a-form-item :label="$t('pool.ipsLabel')">
          <a-textarea
            v-model:value="draftIps"
            :rows="9"
            :placeholder="$t('pool.ipsPlaceholder')"
            class="mono"
          />
        </a-form-item>
      </a-form>
      <a-typography-paragraph type="secondary" class="editor-hint">
        {{ $t('pool.ipsHint') }}
      </a-typography-paragraph>
    </a-modal>
  </div>
</template>

<style scoped>
.panel {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.panel + .panel {
  margin-top: 16px;
}

.pool-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.pool-summary {
  display: flex;
  align-items: baseline;
  gap: 8px;
  flex-wrap: wrap;
}

.pool-count {
  font-size: 15px;
  font-weight: 600;
}

.pool-sub {
  font-size: 12px;
}

.pool-hint {
  margin: 8px 0 0;
  font-size: 13px;
  line-height: 1.7;
}

.pool-error {
  margin-top: 12px;
}

.pool-table {
  margin-top: 14px;
}

.pool-empty {
  margin: 28px 0 16px;
}

.host {
  font-weight: 600;
}

.refreshed {
  font-size: 12px;
  color: var(--text-secondary, rgba(0, 0, 0, 0.45));
}

.ips {
  padding: 2px 0 2px 8px;
}

.ip-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 3px 0;
  border-bottom: 1px dashed var(--border, rgba(0, 0, 0, 0.06));
}

.ip-row:last-of-type {
  border-bottom: none;
}

.ip {
  min-width: 190px;
}

.ip-inline {
  min-width: 0;
}

.ip-group {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 3px 0;
}

.search {
  width: 220px;
}

.src-filter {
  margin-top: 10px;
}

.src-tag {
  margin-inline-end: 0;
}

.ip-status {
  font-size: 12px;
}

.prune {
  margin-top: 8px;
}

.editor {
  margin-bottom: -8px;
}

.editor-hint {
  margin: 0;
  font-size: 12px;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
}
</style>

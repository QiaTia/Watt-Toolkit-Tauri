<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import AntApp from 'ant-design-vue/es/app';
import { useProxyStore } from '@/stores/proxy';
import { useSettingsStore } from '@/stores/settings';
import { useAccelerateStore } from '@/stores/accelerate';
import type {
  AccelerateProject,
  AccelerateProjectGroup,
  EngineStartParams,
  ProxyMode,
} from '@/types/ipc';

const proxy = useProxyStore();
const settings = useSettingsStore();
const accel = useAccelerateStore();
const { t } = useI18n();
const { message } = AntApp.useApp();

// 必须在 setup 顶层调用：放到 onMounted 里会因没有活跃组件实例而注册失败，
// 导致离开页面后 1s 统计轮询永不停止。
proxy.useAutoClean();

onMounted(async () => {
  void proxy.refreshState();
  // 关键顺序：先等设置从磁盘加载完成，再初始化勾选集合。
  // 若直接读 settings.settings.enabled_accelerate_ids（默认 []），
  // 持久化的勾选会被云端默认值覆盖，表现为「下次打开不恢复选择」。
  await settings.ensureLoaded();
  void accel.load(false, settings.settings.enabled_accelerate_ids);
});

/** 正向代理实际端口（0 = 默认 26501） */
const forwardPort = computed(() => settings.settings.system_proxy_port || 26501);

const modeOptions = computed<ReadonlyArray<{ value: ProxyMode; label: string; description: string }>>(
  () => [
    {
      value: 'Hosts',
      label: t('accel.modes.hosts.label'),
      description: t('accel.modes.hosts.desc'),
    },
    {
      value: 'System',
      label: t('accel.modes.system.label'),
      description: t('accel.modes.system.desc', { port: forwardPort.value }),
    },
    {
      value: 'Pac',
      label: t('accel.modes.pac.label'),
      description: t('accel.modes.pac.desc', { port: forwardPort.value }),
    },
    {
      value: 'ProxyOnly',
      label: t('accel.modes.proxyOnly.label'),
      description: t('accel.modes.proxyOnly.desc', { port: forwardPort.value }),
    },
  ],
);

const selectedMode = computed({
  get: () => settings.settings.proxy_mode,
  set: (mode: ProxyMode) => {
    if (settings.settings.proxy_mode === mode) return;
    settings.settings.proxy_mode = mode;
    // 持久化：引擎按下发的 mode 运行，而 mode 又决定接入面（Hosts/PAC/系统代理），
    // 只改内存会导致「磁盘写 A 模式、引擎跑 B 模式」，重启后行为悄悄漂移。
    // 运行中 segmented 已禁用（先停止加速才能切换），模式变更必然发生在停止态。
    void settings.save();
  },
});

const currentModeDescription = computed(
  () => modeOptions.value.find((opt) => opt.value === selectedMode.value)?.description ?? '',
);

/* ========== 加速项目检索过滤（仅影响展示，不影响勾选与持久化） ========== */

const keyword = ref('');
const normKeyword = computed(() => keyword.value.trim().toLowerCase());
const searching = computed(() => normKeyword.value.length > 0);

function matchProject(p: AccelerateProject): AccelerateProject | null {
  const kw = normKeyword.value;
  if (!kw) return p;
  const kids = p.items
    .map(matchProject)
    .filter((x): x is AccelerateProject => x !== null);
  // 命中自身 → 保留整棵子树；仅子项命中 → 保留过滤后的子树
  if (p.name.toLowerCase().includes(kw)) return { ...p, items: p.items };
  if (kids.length > 0) return { ...p, items: kids };
  return null;
}

/** 全部分组（按关键词过滤后的视图） */
const visibleGroups = computed<AccelerateProjectGroup[]>(() => {
  const kw = normKeyword.value;
  if (!kw) return accel.groups;
  const out: AccelerateProjectGroup[] = [];
  for (const g of accel.groups) {
    if (g.name.toLowerCase().includes(kw)) {
      out.push(g);
      continue;
    }
    const items = g.items.map(matchProject).filter((x): x is AccelerateProject => x !== null);
    if (items.length > 0) out.push({ ...g, items });
  }
  return out;
});

/* ========== 分组展开（a-collapse 受控，持久化到 localStorage） ========== */

const activeKeys = ref<Array<string | number>>([]);
const COLLAPSE_KEY = 'accel.active_groups';

function readSavedCollapse(): string[] | null {
  try {
    const raw = localStorage.getItem(COLLAPSE_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : null;
  } catch {
    return null;
  }
}

function saveCollapse(): void {
  try {
    localStorage.setItem(COLLAPSE_KEY, JSON.stringify(activeKeys.value.map(String)));
  } catch {
    // 容量/隐私模式异常不影响功能
  }
}

watch(activeKeys, saveCollapse, { deep: true });

watch(
  () => accel.catalog,
  (c) => {
    if (!c) return;
    // 已有持久化的展开状态 → 恢复（用户手动折叠/展开优先于默认值）
    const saved = readSavedCollapse();
    if (saved) {
      activeKeys.value = saved;
      return;
    }
    // 默认展开：云端标记 show 或已含勾选项
    const next: string[] = [];
    for (const g of accel.groups) {
      if (g.show || accel.groupState(g) !== 'none') next.push(g.id);
    }
    activeKeys.value = next;
  },
  { immediate: true },
);

// 检索时自动展开所有命中分组，避免「搜到了但折叠着」；退出检索恢复持久化状态
watch(searching, (on) => {
  if (on) {
    activeKeys.value = visibleGroups.value.map((g) => g.id);
  } else {
    const saved = readSavedCollapse();
    if (saved) activeKeys.value = saved;
  }
});

/** 勾选项目数 */
const checkedCount = computed(() => accel.checkedIds.size);

/** 目录内项目总数（含子项目） */
const totalCount = computed(() => accel.allProjectIds.length);

/** 目录是否已全选 */
const isAllSelected = computed(
  () => totalCount.value > 0 && checkedCount.value === totalCount.value,
);

/** 分组勾选计数：x / y */
function groupCount(g: AccelerateProjectGroup): { hit: number; total: number } {
  const ids = collectAll(g.items);
  let hit = 0;
  for (const id of ids) if (accel.checkedIds.has(id)) hit++;
  return { hit, total: ids.length };
}

/** 递归收集项目树全部 Id */
function collectAll(items: AccelerateProject[], out: string[] = []): string[] {
  for (const p of items) {
    out.push(p.id);
    collectAll(p.items, out);
  }
  return out;
}

const refreshing = ref(false);

async function refreshCatalog(): Promise<void> {
  refreshing.value = true;
  try {
    accel.clearProbes();
    await accel.load(true, settings.settings.enabled_accelerate_ids);
  } finally {
    refreshing.value = false;
  }
}

/* ========== 连通性测试（对齐原版「连通性测试」按钮） ========== */

/** 分组连通性测试：展开面板展示结果，全失败时弹警告（对齐原版 Toast 语义） */
async function runGroupTest(group: AccelerateProjectGroup): Promise<void> {
  if (!activeKeys.value.includes(group.id)) {
    activeKeys.value = [...activeKeys.value, group.id];
  }
  const res = await accel.testGroup(group);
  if (res === 'empty') {
    message.warning(t('accel.testEmpty'));
    return;
  }
  if (res === 'fail-all') {
    message.error(t('accel.testAllFailed'));
  }
}

/** 延迟文本配色（对齐原版：≤1000ms 绿 / >1000ms 橙 / Timeout·error 红） */
function delayClass(text: string | undefined): string {
  if (!text) return 'delay-ok';
  if (text === 'Timeout' || text === 'error') return 'delay-bad';
  const ms = Number.parseInt(text, 10);
  return Number.isFinite(ms) && ms > 1000 ? 'delay-mid' : 'delay-ok';
}

function isChecked(p: AccelerateProject): boolean {
  return accel.checkedIds.has(p.id);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

async function toggleEngine(): Promise<void> {
  if (proxy.isRunning) {
    await proxy.stop();
    return;
  }
  const s = settings.settings;
  // 勾选项目 → 引擎规则（后端按 Id 集合展平）
  const { rules } = await accel.buildEngineAssets();
  const params: EngineStartParams = {
    mode: s.proxy_mode,
    listenIp: null,
    httpsPort: null,
    httpPort: s.enable_http_proxy_to_https ? 80 : null,
    forwardProxyPort: s.system_proxy_port,
    socks5Port: s.socks5_proxy_enable ? s.socks5_proxy_port : null,
    enableHttpToHttps: s.enable_http_proxy_to_https,
    twoLevelAgent: s.two_level_agent,
    dns: s.dns,
    serverSideProxyToken: null,
    rules,
  };
  await proxy.start(params);
}
</script>

<template>
  <div class="page">
    <a-card :bordered="false" :title="$t('accel.modeTitle')" class="panel">
      <a-segmented
        v-model:value="selectedMode"
        :options="modeOptions.map((o) => ({ value: o.value, label: o.label }))"
        :disabled="proxy.isRunning"
        size="large"
        block
      />
      <a-typography-paragraph v-if="proxy.isRunning" type="warning" class="mode-desc">
        {{ $t('accel.runningSwitchHint') }}
      </a-typography-paragraph>
      <a-typography-paragraph v-else type="secondary" class="mode-desc">
        {{ currentModeDescription }}
      </a-typography-paragraph>
    </a-card>

    <a-card :bordered="false" class="panel">
      <div class="operate">
        <div class="operate-status">
          <a-badge :status="proxy.isRunning ? 'success' : proxy.state.type === 'error' ? 'error' : 'default'" />
          <span class="status-text">{{ proxy.stateLabel }}</span>
          <a-typography-text v-if="proxy.state.type === 'error'" type="danger">
            {{ proxy.state.message }}
          </a-typography-text>
        </div>
        <a-button
          type="primary"
          size="large"
          :danger="proxy.isRunning"
          :loading="proxy.isBusy"
          @click="toggleEngine"
        >
          {{ proxy.isRunning ? $t('accel.stop') : $t('accel.start') }}
        </a-button>
      </div>
      <a-row v-if="proxy.isRunning" :gutter="32" class="stats-row">
        <a-col>
          <a-statistic :title="$t('common.up')" :value="formatBytes(proxy.stats.upBytes)" />
        </a-col>
        <a-col>
          <a-statistic :title="$t('common.down')" :value="formatBytes(proxy.stats.downBytes)" />
        </a-col>
      </a-row>
    </a-card>

    <a-card :bordered="false" class="panel">
      <template #title>
        <a-space :size="8">
          {{ $t('accel.projectsTitle') }}
          <a-tag v-if="accel.source" :color="accel.source === 'cloud' ? 'success' : 'warning'">
            {{ accel.source === 'cloud' ? $t('accel.sourceCloud') : $t('accel.sourceCache') }}
          </a-tag>
        </a-space>
      </template>
      <template #extra>
        <a-space :size="8">
          <a-input-search
            v-model:value="keyword"
            :placeholder="$t('accel.searchPlaceholder')"
            allow-clear
            class="search-input"
          />
          <a-button v-if="!isAllSelected" :disabled="accel.loading" @click="accel.setAll(true)">
            {{ $t('accel.selectAll') }}
          </a-button>
          <a-button v-else :disabled="accel.loading" @click="accel.setAll(false)">
            {{ $t('accel.clearAll') }}
          </a-button>
          <a-button :loading="refreshing || accel.loading" @click="refreshCatalog">
            {{ $t('accel.refresh') }}
          </a-button>
        </a-space>
      </template>

      <a-alert v-if="accel.error" type="error" show-icon class="catalog-alert">
        <template #message>{{ $t('accel.loadFailed', { error: accel.error }) }}</template>
      </a-alert>

      <a-skeleton v-if="accel.loading && !accel.catalog" active :paragraph="{ rows: 5 }" />

      <template v-else>
        <a-typography-paragraph type="secondary" class="catalog-hint">
          {{ $t('accel.checkedSummary', { checked: checkedCount, total: totalCount }) }}
        </a-typography-paragraph>

        <a-empty v-if="visibleGroups.length === 0" :description="$t('accel.noMatch')" />

        <a-collapse v-else v-model:active-key="activeKeys" :bordered="false" class="groups">
          <a-collapse-panel v-for="group in visibleGroups" :key="group.id">
            <template #header>
              <div class="group-header">
                <a-checkbox
                  :checked="accel.groupState(group) === 'all'"
                  :indeterminate="accel.groupState(group) === 'some'"
                  class="group-check"
                  @click.stop
                  @change="accel.toggleGroup(group)"
                />
                <span class="group-title">{{ group.name }}</span>
                <a-tag>
                  {{ groupCount(group).hit }}/{{ groupCount(group).total }}
                </a-tag>
                <a-button
                  size="small"
                  class="group-test-btn"
                  :loading="accel.testingGroups.has(group.id)"
                  @click.stop="runGroupTest(group)"
                >
                  {{ $t('accel.connectivityTest') }}
                </a-button>
              </div>
            </template>

            <div class="project-list">
              <div v-for="project in group.items" :key="project.id" class="project">
                <label class="project-row">
                  <a-checkbox :checked="isChecked(project)" @change="accel.toggle(project)" />
                  <span class="project-name">{{ project.name }}</span>
                  <a-tag v-if="project.serverSide" color="blue">{{ $t('accel.serverSide') }}</a-tag>
                  <span
                    v-if="accel.probeResults[project.id]"
                    class="delay"
                    :class="delayClass(accel.probeResults[project.id])"
                  >
                    {{ accel.probeResults[project.id] }}
                  </span>
                </label>
                <div v-if="project.items.length" class="sub-list">
                  <label v-for="sub in project.items" :key="sub.id" class="project-row sub">
                    <a-checkbox :checked="isChecked(sub)" @change="accel.toggle(sub)" />
                    <span class="project-name">{{ sub.name }}</span>
                    <span
                      v-if="accel.probeResults[sub.id]"
                      class="delay"
                      :class="delayClass(accel.probeResults[sub.id])"
                    >
                      {{ accel.probeResults[sub.id] }}
                    </span>
                  </label>
                </div>
              </div>
            </div>
          </a-collapse-panel>
        </a-collapse>
      </template>
    </a-card>

    <a-card :bordered="false" :title="$t('accel.hintTitle')" class="panel">
      <a-typography-paragraph type="secondary" class="hint">
        {{ $t('accel.hint', { port: forwardPort }) }}
      </a-typography-paragraph>
    </a-card>
  </div>
</template>

<style scoped>
.panel {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.panel + .panel {
  margin-top: 16px;
}

.mode-desc {
  margin: 14px 2px 0;
}

.operate {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

.operate-status {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-text {
  font-size: 16px;
  font-weight: 600;
}

.stats-row {
  margin-top: 16px;
}

.search-input {
  width: 200px;
}

.catalog-alert {
  margin-bottom: 12px;
}

.catalog-hint {
  margin: 0 0 8px;
}

.groups :deep(.ant-collapse-header) {
  align-items: center !important;
}

.group-header {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.group-title {
  font-weight: 600;
  font-size: 14px;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.project-list {
  padding: 2px 0 4px;
}

.project-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 10px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.15s;
}

.project-row:hover {
  background: var(--bg);
}

.project-row.sub {
  padding-left: 32px;
}

.project-name {
  font-size: 13px;
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sub-list {
  margin: 2px 0 4px;
}

.group-test-btn {
  margin-left: auto;
}

/* 延迟配色（对齐原版 DelayColor：≤1000 绿 / >1000 橙 / 失败红） */
.delay {
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.delay-ok {
  color: #52c41a;
}

.delay-mid {
  color: #faad14;
}

.delay-bad {
  color: #ff4d4f;
}

.hint {
  margin-bottom: 0;
  line-height: 1.8;
}
</style>

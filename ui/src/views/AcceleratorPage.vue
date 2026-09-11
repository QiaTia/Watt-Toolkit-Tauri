<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
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
      label: 'Hosts 模式',
      description: '修改 hosts 指向本地 443 反代（需 443 端口空闲，写入 hosts 可能需要管理员权限）',
    },
    {
      value: 'System',
      label: '系统代理',
      description: `设置系统代理走本地端口 ${forwardPort.value}，全局生效，无需占用 443`,
    },
    {
      value: 'Pac',
      label: 'PAC 模式',
      description: `自动配置脚本按域名分流，仅加速域名走代理（端口 ${forwardPort.value}）`,
    },
    {
      value: 'ProxyOnly',
      label: '仅代理端口',
      description: `不修改系统设置，手动将浏览器/客户端代理指向 127.0.0.1:${forwardPort.value}`,
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
    void settings.save();
    // 运行中切换模式：接入面需重建才会生效（规则相同，但监听/系统设置不同），
    // 故停掉再按新模式拉起，避免用户以为切换无效。
    if (proxy.isRunning) {
      void (async () => {
        await proxy.stop();
        await toggleEngine();
      })();
    }
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

/* ========== 分组展开（a-collapse 受控） ========== */

const activeKeys = ref<Array<string | number>>([]);

watch(
  () => accel.catalog,
  (c) => {
    if (!c) return;
    // 默认展开：云端标记 show 或已含勾选项
    const next: string[] = [];
    for (const g of accel.groups) {
      if (g.show || accel.groupState(g) !== 'none') next.push(g.id);
    }
    activeKeys.value = next;
  },
  { immediate: true },
);

// 检索时自动展开所有命中分组，避免「搜到了但折叠着」
watch(searching, (on) => {
  if (on) activeKeys.value = visibleGroups.value.map((g) => g.id);
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
    await accel.load(true, settings.settings.enabled_accelerate_ids);
  } finally {
    refreshing.value = false;
  }
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
    <a-card :bordered="false" title="加速模式" class="panel">
      <a-segmented
        v-model:value="selectedMode"
        :options="modeOptions.map((o) => ({ value: o.value, label: o.label }))"
        size="large"
        block
      />
      <a-typography-paragraph type="secondary" class="mode-desc">
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
          {{ proxy.isRunning ? '停止加速' : '一键加速' }}
        </a-button>
      </div>
      <a-row v-if="proxy.isRunning" :gutter="32" class="stats-row">
        <a-col>
          <a-statistic title="上行" :value="formatBytes(proxy.stats.upBytes)" />
        </a-col>
        <a-col>
          <a-statistic title="下行" :value="formatBytes(proxy.stats.downBytes)" />
        </a-col>
      </a-row>
    </a-card>

    <a-card :bordered="false" class="panel">
      <template #title>
        <a-space :size="8">
          加速项目
          <a-tag v-if="accel.source" :color="accel.source === 'cloud' ? 'success' : 'warning'">
            {{ accel.source === 'cloud' ? '云端' : '本地缓存' }}
          </a-tag>
        </a-space>
      </template>
      <template #extra>
        <a-space :size="8">
          <a-input-search
            v-model:value="keyword"
            placeholder="搜索加速项目"
            allow-clear
            class="search-input"
          />
          <a-button v-if="!isAllSelected" :disabled="accel.loading" @click="accel.setAll(true)">
            全选
          </a-button>
          <a-button v-else :disabled="accel.loading" @click="accel.setAll(false)">
            清空
          </a-button>
          <a-button :loading="refreshing || accel.loading" @click="refreshCatalog">
            刷新列表
          </a-button>
        </a-space>
      </template>

      <a-alert v-if="accel.error" type="error" show-icon class="catalog-alert">
        <template #message>加速项目加载失败：{{ accel.error }}</template>
      </a-alert>

      <a-skeleton v-if="accel.loading && !accel.catalog" active :paragraph="{ rows: 5 }" />

      <template v-else>
        <a-typography-paragraph type="secondary" class="catalog-hint">
          已勾选 {{ checkedCount }} / {{ totalCount }} 项
        </a-typography-paragraph>

        <a-empty v-if="visibleGroups.length === 0" description="没有匹配的加速项目" />

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
              </div>
            </template>

            <div class="project-list">
              <div v-for="project in group.items" :key="project.id" class="project">
                <label class="project-row">
                  <a-checkbox :checked="isChecked(project)" @change="accel.toggle(project)" />
                  <span class="project-name">{{ project.name }}</span>
                  <a-tag v-if="project.serverSide" color="blue">服务端加速</a-tag>
                </label>
                <div v-if="project.items.length" class="sub-list">
                  <label v-for="sub in project.items" :key="sub.id" class="project-row sub">
                    <a-checkbox :checked="isChecked(sub)" @change="accel.toggle(sub)" />
                    <span class="project-name">{{ sub.name }}</span>
                  </label>
                </div>
              </div>
            </div>
          </a-collapse-panel>
        </a-collapse>
      </template>
    </a-card>

    <a-card :bordered="false" title="说明" class="panel">
      <a-typography-paragraph type="secondary" class="hint">
        System / PAC / ProxyOnly 模式监听本地正向代理端口 {{ forwardPort }}，
        PAC 脚本地址为 http://127.0.0.1:{{ forwardPort }}/pac；
        Hosts 模式将加速域名写入 hosts 并在本地 443 做 TLS 反代（停止时自动还原）。
        代理端口可在「设置 → 代理设置」中修改。
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

.hint {
  margin-bottom: 0;
  line-height: 1.8;
}
</style>

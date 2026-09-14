/**
 * 加速项目 store：云端目录加载 + 勾选状态持久化 + 引擎参数构建。
 *
 * 勾选语义（对齐旧版 ProxyService）：
 * - 首次运行（本地无勾选记录，enabled_accelerate_ids 为空）→ 回退云端 Checked 默认值；
 * - 此后勾选集合整体持久化到 ProxySettings.enabled_accelerate_ids；
 * - 引擎启动时由后端按勾选 Id 集合展平为 DomainRule 列表。
 */
import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import {
  accelerateConnectivityTest,
  accelerateGetProjects,
  accelerateGetRules,
  accelerateRefresh,
  accelerateSetEnabled,
} from '@/api';
import { useSettingsStore } from '@/stores/settings';
import type {
  AccelerateCatalog,
  AccelerateProject,
  AccelerateProjectGroup,
  ConnectivityTestItem,
  DomainRule,
} from '@/types/ipc';

export const useAccelerateStore = defineStore('accelerate', () => {
  const catalog = ref<AccelerateCatalog | null>(null);
  /** 数据来源：'cloud' | 'cache' | null（未加载） */
  const source = ref<string | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);
  /** 勾选的项目 Id 集合（含子项目） */
  const checkedIds = ref<Set<string>>(new Set());

  const groups = computed(() => catalog.value?.groups ?? []);

  /** 收集项目及全部子孙 Id */
  function collectIds(project: AccelerateProject, out: string[] = []): string[] {
    out.push(project.id);
    for (const child of project.items) collectIds(child, out);
    return out;
  }

  /** 目录内全部项目 Id */
  const allProjectIds = computed(() =>
    groups.value.flatMap((g) => g.items.flatMap((p) => collectIds(p))),
  );

  /** 云端默认勾选 Id 集合 */
  const defaultCheckedIds = computed(() => {
    const ids: string[] = [];
    const walk = (p: AccelerateProject): void => {
      if (p.defaultChecked) ids.push(p.id);
      p.items.forEach(walk);
    };
    groups.value.forEach((g) => g.items.forEach(walk));
    return ids;
  });

  /** 加载目录（force=true 时强制走云端刷新） */
  async function load(force = false, fallbackIds: string[] = []): Promise<void> {
    if (loading.value) return;
    loading.value = true;
    error.value = null;
    try {
      const dto = force ? await accelerateRefresh() : await accelerateGetProjects();
      catalog.value = dto.catalog;
      source.value = dto.source;
      initChecked(fallbackIds);
    } catch (e) {
      error.value = e instanceof Error ? e.message : String(e);
    } finally {
      loading.value = false;
    }
  }

  /** 初始化勾选：持久化集合非空则用它，否则回退云端默认值 */
  function initChecked(persistedIds: string[]): void {
    const valid = new Set(allProjectIds.value);
    const persisted = persistedIds.filter((id) => valid.has(id));
    checkedIds.value = new Set(persisted.length > 0 ? persisted : defaultCheckedIds.value);
  }

  /** 切换单个项目勾选（含子项目联动：父勾选带动未勾选子项，父取消则整树取消） */
  function toggle(project: AccelerateProject): void {
    const next = new Set(checkedIds.value);
    if (next.has(project.id)) {
      for (const id of collectIds(project)) next.delete(id);
    } else {
      for (const id of collectIds(project)) {
        // 简化语义：勾选父项即启用整树（旧版行为）
        next.add(id);
      }
    }
    checkedIds.value = next;
    void persist();
  }

  /** 分组内全部项目 Id（含子项目） */
  function groupIds(group: { items: AccelerateProject[] }): string[] {
    return group.items.flatMap((p) => collectIds(p));
  }

  /** 分组勾选状态：'all' 全选 / 'some' 部分勾选 / 'none' 未勾选 */
  function groupState(group: { items: AccelerateProject[] }): 'all' | 'some' | 'none' {
    const ids = groupIds(group);
    if (ids.length === 0) return 'none';
    let hit = 0;
    for (const id of ids) if (checkedIds.value.has(id)) hit++;
    if (hit === 0) return 'none';
    return hit === ids.length ? 'all' : 'some';
  }

  /** 切换分组勾选：全选 ↔ 全不选（部分勾选时点击 → 全不选） */
  function toggleGroup(group: { items: AccelerateProject[] }): void {
    const next = new Set(checkedIds.value);
    const ids = groupIds(group);
    if (groupState(group) === 'all') {
      for (const id of ids) next.delete(id);
    } else {
      for (const id of ids) next.add(id);
    }
    checkedIds.value = next;
    void persist();
  }

  /** 全选 / 清空整个目录 */
  function setAll(checked: boolean): void {
    checkedIds.value = checked ? new Set(allProjectIds.value) : new Set();
    void persist();
  }

  /** 持久化勾选集合 */
  async function persist(): Promise<void> {
    const ids = [...checkedIds.value];
    try {
      await accelerateSetEnabled(ids);
      // 同步内存态：后端该命令是「读-改-写」磁盘 JSON，而设置页/加速模式切换走的是
      // settings.save()（整对象保存）。若不回写内存，后续一次 settings.save() 会用
      // 加载时的旧集合覆盖磁盘，表现为「切换模式后勾选被重置」。
      useSettingsStore().settings.enabled_accelerate_ids = ids;
    } catch (e) {
      console.warn('勾选状态保存失败', e);
    }
  }

  /** 构建引擎启动规则 */
  async function buildEngineAssets(): Promise<{ rules: DomainRule[] }> {
    if (checkedIds.value.size === 0) return { rules: [] };
    const rules = await accelerateGetRules([...checkedIds.value]);
    return { rules };
  }

  /* ========== 连通性测试（对齐原版 ProxyDomainGroupViewModel.ConnectTestCommand） ========== */

  /** 项目 Id → 延迟显示文本（'123 ms' | 'Timeout' | 'error'） */
  const probeResults = ref<Record<string, string>>({});
  /** 正在测试的分组 Id 集合 */
  const testingGroups = ref<Set<string>>(new Set());

  /** 项目的探测主机：第一个监听域名，回退匹配域名（剥 URL 前缀/通配符/端口） */
  function projectHost(project: AccelerateProject): string {
    const raw = project.rule.listening_domain_names[0] ?? project.rule.match_domain_names[0] ?? '';
    const noScheme = raw.replace(/^https?:\/\//i, '');
    const host = (noScheme.split('/')[0] ?? '').split(':')[0] ?? '';
    return host.replace(/^\*\./, '').toLowerCase();
  }

  /** 结果格式化：失败区分超时/错误，成功 >20s 判 Timeout（对齐原版阈值） */
  function formatProbeResult(r: ConnectivityTestItem): string {
    if (!r.ok) return r.error?.includes('超时') === true ? 'Timeout' : 'error';
    if (r.latencyMs > 20_000) return 'Timeout';
    return `${r.latencyMs} ms`;
  }

  /**
   * 分组连通性测试：仅测当前勾选项，同 host 去重，后端全并发探测。
   * 返回 'empty'（无可测试项）/ 'ok' / 'fail-all'（全部失败，供页面弹警告）。
   */
  async function testGroup(group: AccelerateProjectGroup): Promise<'empty' | 'ok' | 'fail-all'> {
    if (testingGroups.value.has(group.id)) return 'empty';
    const targets: Array<{ id: string; host: string }> = [];
    const walk = (p: AccelerateProject): void => {
      if (checkedIds.value.has(p.id)) {
        const host = projectHost(p);
        if (host) targets.push({ id: p.id, host });
      }
      p.items.forEach(walk);
    };
    group.items.forEach(walk);
    if (targets.length === 0) return 'empty';

    testingGroups.value = new Set(testingGroups.value).add(group.id);
    try {
      const hosts = [...new Set(targets.map((t) => t.host))];
      const results = await accelerateConnectivityTest(hosts);
      const byHost = new Map(results.map((r) => [r.host, r]));
      const next = { ...probeResults.value };
      let failAll = true;
      for (const t of targets) {
        const r = byHost.get(t.host);
        if (!r) continue;
        const text = formatProbeResult(r);
        next[t.id] = text;
        if (text !== 'Timeout' && text !== 'error') failAll = false;
      }
      probeResults.value = next;
      return failAll ? 'fail-all' : 'ok';
    } finally {
      const rest = new Set(testingGroups.value);
      rest.delete(group.id);
      testingGroups.value = rest;
    }
  }

  /** 清空探测结果（刷新列表时结果已过期） */
  function clearProbes(): void {
    probeResults.value = {};
  }

  return {
    catalog,
    source,
    loading,
    error,
    checkedIds,
    groups,
    allProjectIds,
    defaultCheckedIds,
    probeResults,
    testingGroups,
    load,
    toggle,
    toggleGroup,
    groupState,
    setAll,
    persist,
    buildEngineAssets,
    testGroup,
    projectHost,
    clearProbes,
  };
});

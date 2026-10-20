import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import {
  ipPoolClear,
  ipPoolList,
  ipPoolProbeDomain,
  ipPoolRefresh,
  ipPoolRefreshHost,
  ipPoolRemoveDomain,
  ipPoolSaveDomain,
} from '@/api';
import type { IpPoolDomain, IpPoolHostResult, IpPoolProbeItem } from '@/types/ipc';

/**
 * IP 池管理状态。
 *
 * 抽成 store 的原因：右上角的「刷新 IP 池 / 新增域名」按钮位于 AppHeader（全局顶栏），
 * 而列表与编辑弹窗在 IP 池管理页——两处必须共享同一份数据与忙碌态，
 * 否则顶栏刷新不会驱动页面表格更新（历史上设置页的池卡片只在自己页面里持有状态）。
 */
export const useIpPoolStore = defineStore('ipPool', () => {
  /** 池内全部域名条目（后端按域名升序返回） */
  const domains = ref<IpPoolDomain[]>([]);
  const loading = ref(false);
  /** 全量刷新进行中（顶栏按钮 loading） */
  const refreshing = ref(false);
  /** 单域名刷新/探测进行中的 host 集合 */
  const busyHosts = ref<Set<string>>(new Set());
  /** 命令层错误（页面顶部 alert） */
  const error = ref<string | null>(null);
  /** 本次会话最近一次全量刷新结果（下拉汇总展示，null = 未刷新过） */
  const lastRefresh = ref<{ hosts: number; ok: number; candidates: number } | null>(null);
  /** 逐域名探测结果（host → 逐 IP RTT），由「探测」按钮写入 */
  const probes = ref<Record<string, IpPoolProbeItem[]>>({});

  const ipTotal = computed(() => domains.value.reduce((n, d) => n + d.ips.length, 0));

  function isBusy(host: string): boolean {
    return busyHosts.value.has(host);
  }

  function setBusy(host: string, busy: boolean): void {
    const next = new Set(busyHosts.value);
    if (busy) next.add(host);
    else next.delete(host);
    busyHosts.value = next;
  }

  function errText(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  /** 拉取池内容（页面挂载 / 任意变更后调用） */
  async function load(): Promise<void> {
    loading.value = true;
    try {
      domains.value = await ipPoolList();
    } catch (e) {
      error.value = errText(e);
    } finally {
      loading.value = false;
    }
  }

  /** 全量刷新：按当前勾选的加速项目域名重新解析 + 探测（原设置页入口迁移至此） */
  async function refreshAll(): Promise<IpPoolHostResult[] | null> {
    refreshing.value = true;
    error.value = null;
    try {
      const results = await ipPoolRefresh();
      lastRefresh.value = {
        hosts: results.length,
        ok: results.reduce((n, r) => n + r.ok, 0),
        candidates: results.reduce((n, r) => n + r.candidates, 0),
      };
      await load();
      return results;
    } catch (e) {
      error.value = errText(e);
      return null;
    } finally {
      refreshing.value = false;
    }
  }

  /** 保存某域名的 IP 列表（新增或覆盖） */
  async function saveDomain(host: string, ips: string[]): Promise<void> {
    error.value = null;
    try {
      await ipPoolSaveDomain(host, ips);
      await load();
    } catch (e) {
      error.value = errText(e);
      throw e;
    }
  }

  /** 删除某域名的池 */
  async function removeDomain(host: string): Promise<boolean> {
    setBusy(host, true);
    error.value = null;
    try {
      await ipPoolRemoveDomain(host);
      delete probes.value[host];
      await load();
      return true;
    } catch (e) {
      error.value = errText(e);
      return false;
    } finally {
      setBusy(host, false);
    }
  }

  /** 清空全部 */
  async function clearAll(): Promise<boolean> {
    error.value = null;
    try {
      await ipPoolClear();
      probes.value = {};
      await load();
      return true;
    } catch (e) {
      error.value = errText(e);
      return false;
    }
  }

  /** 单域名从 DNS 重新解析并探测 */
  async function refreshHost(host: string): Promise<IpPoolHostResult | null> {
    setBusy(host, true);
    error.value = null;
    try {
      const result = await ipPoolRefreshHost(host);
      delete probes.value[host];
      await load();
      return result;
    } catch (e) {
      error.value = errText(e);
      return null;
    } finally {
      setBusy(host, false);
    }
  }

  /** 探测单域名池内全部 IP（只读） */
  async function probeHost(host: string): Promise<IpPoolProbeItem[] | null> {
    setBusy(host, true);
    error.value = null;
    try {
      const items = await ipPoolProbeDomain(host);
      probes.value = { ...probes.value, [host]: items };
      return items;
    } catch (e) {
      error.value = errText(e);
      return null;
    } finally {
      setBusy(host, false);
    }
  }

  /** 移除不可用 IP（探测后一键清理）：保留本次探测通过的 IP */
  async function pruneUnreachable(host: string): Promise<number> {
    const items = probes.value[host];
    if (!items) return 0;
    const alive = items.filter((i) => i.rttMs !== null).map((i) => i.ip);
    const before = domains.value.find((d) => d.host === host)?.ips.length ?? 0;
    if (alive.length === before) return 0;
    if (alive.length === 0) {
      await removeDomain(host);
      return before;
    }
    await saveDomain(host, alive);
    delete probes.value[host];
    return before - alive.length;
  }

  return {
    domains,
    loading,
    refreshing,
    busyHosts,
    error,
    lastRefresh,
    probes,
    ipTotal,
    isBusy,
    load,
    refreshAll,
    saveDomain,
    removeDomain,
    clearAll,
    refreshHost,
    probeHost,
    pruneUnreachable,
  };
});

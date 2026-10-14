import { defineStore } from 'pinia';
import { computed, onUnmounted, ref } from 'vue';
import { listen } from '@tauri-apps/api/event';
import { engineGetState, engineGetStats, engineStart, engineStop } from '@/api';
import { i18n } from '@/locales';
import type { EngineStartParams, EngineStateDto, FlowStatsDto } from '@/types/ipc';

/** 后端托盘/命令启停引擎后广播的状态变更事件（与 Rust tray::ENGINE_STATE_EVENT 对齐） */
const ENGINE_STATE_EVENT = 'watt://engine-state-changed';

/** 代理引擎状态 store */
export const useProxyStore = defineStore('proxy', () => {
  const state = ref<EngineStateDto>({ type: 'stopped' });
  const stats = ref<FlowStatsDto>({ upBytes: 0, downBytes: 0 });
  const operating = ref(false);
  const error = ref<string | null>(null);

  /** 1s 统计轮询句柄 */
  let statsTimer: ReturnType<typeof setInterval> | null = null;

  const isRunning = computed(() => state.value.type === 'running');
  const isBusy = computed(
    () => state.value.type === 'starting' || state.value.type === 'stopping' || operating.value,
  );

  const stateLabel = computed(() => {
    const t = i18n.global.t;
    switch (state.value.type) {
      case 'stopped':
        return t('state.stopped');
      case 'starting':
        return t('state.starting');
      case 'running':
        return t('state.running');
      case 'stopping':
        return t('state.stopping');
      case 'error':
        return t('state.error');
    }
  });

  async function refreshState(): Promise<void> {
    state.value = await engineGetState();
  }

  async function start(params: EngineStartParams): Promise<boolean> {
    operating.value = true;
    error.value = null;
    try {
      state.value = await engineStart(params);
      startStatsLoop();
      return state.value.type === 'running';
    } catch (e) {
      error.value = String(e);
      state.value = { type: 'error', message: String(e) };
      return false;
    } finally {
      operating.value = false;
    }
  }

  async function stop(): Promise<boolean> {
    operating.value = true;
    error.value = null;
    try {
      state.value = await engineStop();
      stopStatsLoop();
      stats.value = { upBytes: 0, downBytes: 0 };
      return true;
    } catch (e) {
      error.value = String(e);
      return false;
    } finally {
      operating.value = false;
    }
  }

  async function refreshStats(): Promise<void> {
    try {
      stats.value = await engineGetStats();
    } catch {
      // 引擎停止时轮询静默失败
    }
  }

  function startStatsLoop(): void {
    stopStatsLoop();
    statsTimer = setInterval(() => void refreshStats(), 1000);
  }

  function stopStatsLoop(): void {
    if (statsTimer !== null) {
      clearInterval(statsTimer);
      statsTimer = null;
    }
  }

  /** 组件内使用：自动清理轮询 */
  function useAutoClean(): void {
    onUnmounted(stopStatsLoop);
  }

  /**
   * 外部（托盘菜单 / 其他入口）触发的引擎状态变更：
   * 重新拉取状态并同步统计轮询，使面板与后台服务保持一致。
   */
  async function syncFromExternal(): Promise<void> {
    await refreshState();
    if (isRunning.value) {
      startStatsLoop();
    } else {
      stopStatsLoop();
      stats.value = { upBytes: 0, downBytes: 0 };
    }
  }

  // 订阅后端状态广播（store 为应用级单例，随应用生命周期常驻，无需手动解绑）
  void listen(ENGINE_STATE_EVENT, () => {
    void syncFromExternal();
  });

  return {
    state,
    stats,
    operating,
    error,
    isRunning,
    isBusy,
    stateLabel,
    start,
    stop,
    refreshState,
    refreshStats,
    useAutoClean,
    syncFromExternal,
  };
});

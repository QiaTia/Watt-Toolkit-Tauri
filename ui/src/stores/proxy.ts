import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  engineGetState,
  engineGetStats,
  engineProbeSummary,
  engineStart,
  engineStop,
} from '@/api';
import { i18n } from '@/locales';
import type { EngineStartParams, EngineStateDto, FlowStatsDto, ProbeSummaryDto } from '@/types/ipc';

/** 后端托盘/命令启停引擎后广播的状态变更事件（与 Rust tray::ENGINE_STATE_EVENT 对齐） */
const ENGINE_STATE_EVENT = 'watt://engine-state-changed';

/** 探测摘要轮询上限（启动预探测整体预算 12s + 余量；拿到摘要或超时即停） */
const PROBE_POLL_TIMEOUT_MS = 15_000;
const PROBE_POLL_INTERVAL_MS = 1000;

/** 代理引擎状态 store */
export const useProxyStore = defineStore('proxy', () => {
  const state = ref<EngineStateDto>({ type: 'stopped' });
  const stats = ref<FlowStatsDto>({ upBytes: 0, downBytes: 0 });
  const operating = ref(false);
  const error = ref<string | null>(null);
  /** 最近一次候选探测摘要（null = 尚未拿到；UI 显示「探测中」） */
  const probeSummary = ref<ProbeSummaryDto | null>(null);

  /** 1s 统计轮询句柄 */
  let statsTimer: ReturnType<typeof setInterval> | null = null;
  /** 探测摘要轮询句柄 */
  let probeTimer: ReturnType<typeof setInterval> | null = null;

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
    // 轮询归属 store：引擎运行中时无论当前在哪个页面都持续统计
    if (isRunning.value) {
      if (statsTimer === null) startStatsLoop();
    } else {
      stopStatsLoop();
      stopProbePolling();
      stats.value = { upBytes: 0, downBytes: 0 };
      probeSummary.value = null;
    }
  }

  async function start(params: EngineStartParams): Promise<boolean> {
    operating.value = true;
    error.value = null;
    try {
      state.value = await engineStart(params);
      startStatsLoop();
      startProbePolling();
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
      stopProbePolling();
      stats.value = { upBytes: 0, downBytes: 0 };
      probeSummary.value = null;
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

  /**
   * 探测摘要轮询：启动预探测整体预算 8s，1s 一拉；
   * 拿到摘要（或超上限）即停——周期刷新（60s）的下次结果不追，
   * 避免常驻轮询。
   */
  function startProbePolling(): void {
    stopProbePolling();
    const deadline = Date.now() + PROBE_POLL_TIMEOUT_MS;
    const tick = async (): Promise<void> => {
      try {
        probeSummary.value = await engineProbeSummary();
      } catch {
        // 查询失败静默（引擎刚启动 / IPC 抖动），下个 tick 重试
      }
      if (probeSummary.value !== null || Date.now() >= deadline) {
        stopProbePolling();
      }
    };
    void tick();
    probeTimer = setInterval(() => void tick(), PROBE_POLL_INTERVAL_MS);
  }

  function stopProbePolling(): void {
    if (probeTimer !== null) {
      clearInterval(probeTimer);
      probeTimer = null;
    }
  }

  /**
   * 外部（托盘菜单 / 其他入口）触发的引擎状态变更：
   * 重新拉取状态并同步统计轮询，使面板与后台服务保持一致。
   */
  async function syncFromExternal(): Promise<void> {
    await refreshState();
    if (isRunning.value) {
      startStatsLoop();
      startProbePolling();
    }
  }

  // 订阅后端状态广播（store 为应用级单例；HMR 时释放旧监听避免叠加）
  let unlistenState: UnlistenFn | null = null;
  void listen(ENGINE_STATE_EVENT, () => {
    void syncFromExternal();
  }).then((fn) => {
    unlistenState = fn;
  });
  if (import.meta.hot) {
    import.meta.hot.dispose(() => {
      unlistenState?.();
      unlistenState = null;
      stopStatsLoop();
      stopProbePolling();
    });
  }

  return {
    state,
    stats,
    operating,
    error,
    probeSummary,
    isRunning,
    isBusy,
    stateLabel,
    start,
    stop,
    refreshState,
    refreshStats,
    syncFromExternal,
  };
});

import { defineStore } from 'pinia';
import { computed, onUnmounted, ref } from 'vue';
import { engineGetState, engineGetStats, engineStart, engineStop } from '@/api';
import type { EngineStartParams, EngineStateDto, FlowStatsDto } from '@/types/ipc';

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
    switch (state.value.type) {
      case 'stopped':
        return '已停止';
      case 'starting':
        return '启动中…';
      case 'running':
        return '加速运行中';
      case 'stopping':
        return '停止中…';
      case 'error':
        return '错误';
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
  };
});

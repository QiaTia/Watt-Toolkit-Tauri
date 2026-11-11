import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  updateCheck,
  updateGatekeeperScript,
  updateGetSettings,
  updateInstall,
  updateSaveSettings,
} from '@/api';
import { isMacOS } from '@/utils/platform';
import type { UpdateInfoDto, UpdateProgressDto, UpdateSettings } from '@/types/ipc';

/** 后端进度事件（与 Rust UPDATE_PROGRESS_EVENT 对齐） */
const PROGRESS_EVENT = 'watt://update-progress';
/** 上次检查时间（运行态时间戳，不写进设置文件） */
const LAST_CHECK_KEY = 'update.lastCheckAt';

/** 手动下载兜底地址（更新检查全部失败时的出口） */
export const RELEASE_PAGE_URL = 'https://github.com/QiaTia/Watt-Toolkit-Tauri/releases/latest';

/**
 * macOS 未签名 / 未公证：自动更新照样替换 .app，但首次打开可能被 Gatekeeper 拦截
 * （「已损坏」/「无法验证开发者」）。更新前向用户展示「手动 / 自动」选择，选自动时
 * 提前给出清除隔离属性的脚本（复制到「终端」运行）。具备 Apple 签名 + 公证后可改为 false。
 */
export const NEEDS_GATEKEEPER_BYPASS = isMacOS();

export type UpdateStatus =
  | 'idle'
  | 'checking'
  | 'upToDate'
  | 'available'
  | 'downloading'
  | 'installing'
  | 'error';

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function readLastCheck(): number {
  try {
    const raw = localStorage.getItem(LAST_CHECK_KEY);
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) ? n : 0;
  } catch {
    return 0;
  }
}

function writeLastCheck(ms: number): void {
  try {
    localStorage.setItem(LAST_CHECK_KEY, String(ms));
  } catch {
    // 写入失败只影响下一次自动检查的频率判断
  }
}

/**
 * 自动更新状态机：
 *
 *   idle → checking → (upToDate | available | error)
 *   available → downloading → installing →（进程被安装器接管）
 *   error → idle（可重试）
 *
 * 检查与安装的实际网络动作都在 Rust 侧（多源顺序回退 + 引擎代理 + 安装前停引擎），
 * 这里只维护状态与进度展示。
 */
export const useUpdateStore = defineStore('update', () => {
  const status = ref<UpdateStatus>('idle');
  const info = ref<UpdateInfoDto | null>(null);
  const error = ref<string | null>(null);

  const settings = ref<UpdateSettings>({
    autoCheck: true,
    checkIntervalHours: 24,
    endpoint: null,
    skippedVersion: null,
  });
  const settingsLoaded = ref(false);
  const savingSettings = ref(false);

  /* 下载进度 */
  const downloaded = ref(0);
  const total = ref<number | null>(null);
  const speed = ref(0);
  const etaSeconds = ref<number | null>(null);

  /** 弹窗开关由 store 统一管理（顶栏 / 横幅 / 关于页都能唤起） */
  const modalOpen = ref(false);
  /** 「稍后」：本次会话不再横幅提示，下次启动重新检查 */
  const dismissed = ref(false);
  /** macOS Gatekeeper 绕过脚本（清除 .app 隔离属性）；非 macOS 为空 */
  const gatekeeperScript = ref('');

  let inflight: Promise<UpdateInfoDto | null> | null = null;
  /** 检查请求世代号：并发时仅最新一次请求可写状态，避免过期结果覆盖 */
  let checkSeq = 0;
  let lastSampleAt = 0;
  let lastSampleBytes = 0;

  const isChecking = computed(() => status.value === 'checking');
  const hasUpdate = computed(() => status.value === 'available' && info.value !== null);
  const busy = computed(
    () => status.value === 'downloading' || status.value === 'installing',
  );
  /** 进度百分比；总大小未知时为 null（用 indeterminate 展示） */
  const percent = computed<number | null>(() => {
    if (total.value === null || total.value <= 0) return null;
    return Math.min(100, Math.round((downloaded.value / total.value) * 100));
  });

  /** 有未跳过的新版本时，界面显示入口（顶栏红点 / 首页横幅） */
  const shouldNotify = computed(
    () =>
      hasUpdate.value &&
      !dismissed.value &&
      info.value!.version !== settings.value.skippedVersion,
  );

  function applyProgress(p: UpdateProgressDto): void {
    if (p.stage === 'installing') {
      status.value = 'installing';
      return;
    }
    downloaded.value = p.downloaded;
    total.value = p.total;
    const now = Date.now();
    if (lastSampleAt > 0 && now - lastSampleAt >= 500) {
      const dt = (now - lastSampleAt) / 1000;
      speed.value = Math.max(0, (p.downloaded - lastSampleBytes) / dt);
      etaSeconds.value =
        p.total !== null && speed.value > 1
          ? Math.max(0, Math.round((p.total - p.downloaded) / speed.value))
          : null;
      lastSampleAt = now;
      lastSampleBytes = p.downloaded;
    } else if (lastSampleAt === 0) {
      lastSampleAt = now;
      lastSampleBytes = p.downloaded;
    }
  }

  async function loadSettings(): Promise<void> {
    try {
      settings.value = await updateGetSettings();
      settingsLoaded.value = true;
    } catch (e) {
      console.error('读取更新设置失败', e);
      settingsLoaded.value = false;
    }
  }

  async function saveSettings(): Promise<boolean> {
    savingSettings.value = true;
    try {
      await updateSaveSettings(settings.value);
      settingsLoaded.value = true;
      return true;
    } catch (e) {
      error.value = errorText(e);
      return false;
    } finally {
      savingSettings.value = false;
    }
  }

  /** 加载 macOS Gatekeeper 绕过脚本（仅 macOS、仅一次）；失败不阻断更新流程 */
  async function ensureGatekeeperScript(): Promise<void> {
    if (!NEEDS_GATEKEEPER_BYPASS || gatekeeperScript.value) return;
    try {
      gatekeeperScript.value = await updateGatekeeperScript();
    } catch (e) {
      console.error('获取 Gatekeeper 脚本失败', e);
    }
  }

  /**
   * 检查更新。`manual = true` 时不做间隔/跳过判断，失败也返回错误供界面提示；
   * 自动检查则完全静默（不打扰用户）。
   */
  function check(manual = false): Promise<UpdateInfoDto | null> {
    // 并发去重：自动检查复用同一请求；手动检查不复用自动请求
    //（自动请求可能因「跳过此版本」抑制结果，手动应始终展示最新版本）
    if (inflight && !manual) return inflight;

    const seq = ++checkSeq;
    const task = (async () => {
      // 仅最新一次请求可写状态：并发时过期请求的结果丢弃，避免覆盖手动结果
      const current = () => seq === checkSeq;
      if (current()) {
        status.value = 'checking';
        error.value = null;
      }
      try {
        const result = await updateCheck(settings.value.endpoint);
        writeLastCheck(Date.now());
        if (!current()) return result;
        if (!result) {
          info.value = null;
          status.value = 'upToDate';
          return null;
        }
        if (!manual && result.version === settings.value.skippedVersion) {
          info.value = null;
          status.value = 'idle';
          return null;
        }
        info.value = result;
        status.value = 'available';
        dismissed.value = false;
        void ensureGatekeeperScript();
        return result;
      } catch (e) {
        if (current()) {
          error.value = errorText(e);
          status.value = 'error';
        }
        return null;
      }
    })();

    inflight = task;
    // 仅当 inflight 仍是本请求时才清空，避免手动请求覆盖句柄后被自动请求误清
    void task.finally(() => {
      if (inflight === task) inflight = null;
    });
    return task;
  }

  /** 启动后延迟调用：按设置与间隔决定要不要真的发请求 */
  async function maybeAutoCheck(): Promise<void> {
    if (!settingsLoaded.value) await loadSettings();
    if (!settings.value.autoCheck) return;
    const intervalMs = settings.value.checkIntervalHours * 3600_000;
    // 0 小时 = 每次启动都查
    if (intervalMs > 0 && Date.now() - readLastCheck() < intervalMs) return;
    await check(false);
  }

  /** 下载并安装。停引擎由 Rust 侧在「重检更新源之后、下载之前」统一执行
   *  （还原 hosts / 系统代理 / 终端代理），并经 ENGINE_STATE_EVENT 同步 proxy store；
   *  前端不再预停，以免让 Rust 重检失去引擎代理出口。 */
  async function install(): Promise<void> {
    const target = info.value;
    if (!target || busy.value) return;

    status.value = 'downloading';
    downloaded.value = 0;
    total.value = null;
    speed.value = 0;
    etaSeconds.value = null;
    lastSampleAt = 0;
    lastSampleBytes = 0;
    error.value = null;

    try {
      await updateInstall(target.endpoint, target.version);
      status.value = 'installing';
    } catch (e) {
      error.value = errorText(e);
      status.value = 'error';
    }
  }

  /** 跳过此版本（持久化，直到出现更高版本） */
  async function skipCurrent(): Promise<void> {
    if (!info.value) return;
    settings.value.skippedVersion = info.value.version;
    await saveSettings();
    modalOpen.value = false;
    dismissed.value = true;
    status.value = 'idle';
    info.value = null;
  }

  /** 清除「跳过」，让该版本重新参与提示 */
  async function clearSkip(): Promise<void> {
    settings.value.skippedVersion = null;
    await saveSettings();
  }

  /** 稍后：本次会话不再自动提示 */
  function dismiss(): void {
    modalOpen.value = false;
    dismissed.value = true;
  }

  function openModal(): void {
    modalOpen.value = true;
    // 复用已有 info 打开弹窗时也确保脚本就绪（首次加载失败可在此重试）
    void ensureGatekeeperScript();
  }

  /** 手动检查并直接打开弹窗（顶栏入口用） */
  async function checkAndOpen(): Promise<'available' | 'upToDate' | 'error'> {
    if (info.value && status.value === 'available') {
      modalOpen.value = true;
      return 'available';
    }
    const result = await check(true);
    if (result) {
      modalOpen.value = true;
      return 'available';
    }
    return status.value === 'error' ? 'error' : 'upToDate';
  }

  // 订阅进度事件（store 为应用级单例；HMR 时释放旧监听避免叠加）
  let unlisten: UnlistenFn | null = null;
  void listen<UpdateProgressDto>(PROGRESS_EVENT, (event) => {
    applyProgress(event.payload);
  }).then((fn) => {
    unlisten = fn;
  });
  if (import.meta.hot) {
    import.meta.hot.dispose(() => {
      unlisten?.();
      unlisten = null;
    });
  }

  return {
    status,
    info,
    error,
    settings,
    settingsLoaded,
    savingSettings,
    downloaded,
    total,
    speed,
    etaSeconds,
    modalOpen,
    dismissed,
    isChecking,
    hasUpdate,
    busy,
    percent,
    shouldNotify,
    needsGatekeeperBypass: NEEDS_GATEKEEPER_BYPASS,
    gatekeeperScript,
    loadSettings,
    saveSettings,
    ensureGatekeeperScript,
    check,
    checkAndOpen,
    maybeAutoCheck,
    install,
    skipCurrent,
    clearSkip,
    dismiss,
    openModal,
  };
});

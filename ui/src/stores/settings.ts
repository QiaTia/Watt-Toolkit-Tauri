import { defineStore } from 'pinia';
import { ref } from 'vue';
import { settingsGetProxy, settingsSaveProxy } from '@/api';
import { isMacOS } from '@/utils/platform';
import type { ProxySettings } from '@/types/ipc';

/** 默认设置（与 Rust ProxySettings::default 对齐） */
export function defaultProxySettings(): ProxySettings {
  return {
    // 与 Rust ProxyMode::default 对齐：macOS 默认 PAC（Hosts 需 root 绑 443）
    proxy_mode: isMacOS() ? 'Pac' : 'Hosts',
    system_proxy_ip: null,
    system_proxy_port: 26501,
    socks5_proxy_enable: false,
    socks5_proxy_port: 8868,
    enable_http_proxy_to_https: false,
    two_level_agent: {
      enable: false,
      proxy_type: null,
      ip: null,
      port: 0,
      username: null,
      password: null,
    },
    dns: {
      before_dns_check: false,
      master_dns: null,
      use_doh: false,
      custom_doh_address: null,
    },
    is_proxy_gog: false,
    enabled_accelerate_ids: [],
    enabled_accelerate_ids_initialized: false,
    terminal_proxy_enable: true,
  };
}

export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<ProxySettings>(defaultProxySettings());
  const loaded = ref(false);
  const saving = ref(false);
  /** 最近一次加载错误（非 null 时禁止保存，避免默认值覆盖磁盘配置） */
  const loadError = ref<string | null>(null);
  /** 进行中的加载请求（并发去重用） */
  let inflight: Promise<void> | null = null;

  async function load(): Promise<void> {
    try {
      settings.value = await settingsGetProxy();
      // macOS 上 Hosts 模式不可用（443 是特权端口，非 root 无法监听）：磁盘里若残留
      // Hosts（旧配置 / 从 Windows 搬来的配置），就地降级为 PAC —— 只改内存不改磁盘，
      // 避免悄悄重写用户配置；否则用户点一次加速只会收到「端口绑定被拒绝」。
      if (isMacOS() && settings.value.proxy_mode === 'Hosts') {
        settings.value.proxy_mode = 'Pac';
      }
      loadError.value = null;
      loaded.value = true;
    } catch (e) {
      // 读取失败不能标记 loaded：否则保存会用默认值覆盖磁盘上的真实配置
      loadError.value = e instanceof Error ? e.message : String(e);
      loaded.value = false;
      throw e;
    }
  }

  /**
   * 确保设置已从磁盘加载完成（幂等、并发去重）。
   *
   * 必须 await 之后再读取 settings.value：`load()` 是异步的，而子组件的 onMounted
   * 先于父组件执行，直接读会拿到默认值（例如 enabled_accelerate_ids 为 []），
   * 造成「持久化的用户选择被默认值覆盖」。
   */
  function ensureLoaded(): Promise<void> {
    if (loaded.value) return Promise.resolve();
    inflight ??= load().finally(() => {
      inflight = null;
    });
    return inflight;
  }

  async function save(): Promise<boolean> {
    if (!loaded.value) {
      console.error('设置尚未成功加载，拒绝保存以避免覆盖磁盘配置');
      return false;
    }
    saving.value = true;
    try {
      await settingsSaveProxy(settings.value);
      return true;
    } catch (e) {
      console.error('保存设置失败', e);
      return false;
    } finally {
      saving.value = false;
    }
  }

  return { settings, loaded, loadError, saving, load, ensureLoaded, save };
});

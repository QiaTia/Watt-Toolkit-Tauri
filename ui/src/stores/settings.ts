import { defineStore } from 'pinia';
import { ref } from 'vue';
import { settingsGetProxy, settingsSaveProxy } from '@/api';
import type { ProxySettings } from '@/types/ipc';

/** 默认设置（与 Rust ProxySettings::default 对齐） */
export function defaultProxySettings(): ProxySettings {
  return {
    proxy_mode: 'Hosts',
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
  };
}

export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<ProxySettings>(defaultProxySettings());
  const loaded = ref(false);
  const saving = ref(false);
  /** 进行中的加载请求（并发去重用） */
  let inflight: Promise<void> | null = null;

  async function load(): Promise<void> {
    try {
      settings.value = await settingsGetProxy();
    } catch {
      settings.value = defaultProxySettings();
    } finally {
      loaded.value = true;
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

  return { settings, loaded, saving, load, ensureLoaded, save };
});

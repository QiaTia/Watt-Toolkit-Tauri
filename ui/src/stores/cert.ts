import { defineStore } from 'pinia';
import { ref } from 'vue';
import {
  certExportCa,
  certGetInfo,
  certGetStatus,
  certInstall,
  certRegenerate,
  certUninstall,
} from '@/api';
import type { CertificateInfo, CertStatusDto } from '@/types/ipc';

export const useCertStore = defineStore('cert', () => {
  const status = ref<CertStatusDto | null>(null);
  const info = ref<CertificateInfo | null>(null);
  const loading = ref(false);
  /** 安装/卸载/重生成进行中（阻塞按钮） */
  const busy = ref(false);

  async function refresh(): Promise<void> {
    loading.value = true;
    try {
      status.value = await certGetStatus();
      if (status.value.installed) {
        info.value = await certGetInfo();
      } else {
        info.value = null;
      }
    } finally {
      loading.value = false;
    }
  }

  /** 导出 CA PEM 并触发浏览器下载 */
  async function exportCa(): Promise<void> {
    const pem = await certExportCa();
    const blob = new Blob([pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'watt-toolkit-ca.pem';
    a.click();
    URL.revokeObjectURL(url);
  }

  /** 安装到系统信任存储（Windows 触发 UAC，可能耗时较长） */
  async function install(): Promise<void> {
    busy.value = true;
    try {
      await certInstall();
      await refresh();
    } finally {
      busy.value = false;
    }
  }

  /** 移除系统信任（引擎运行时后端会拒绝） */
  async function uninstall(): Promise<void> {
    busy.value = true;
    try {
      await certUninstall();
      await refresh();
    } finally {
      busy.value = false;
    }
  }

  async function regenerate(): Promise<void> {
    busy.value = true;
    try {
      status.value = await certRegenerate();
      info.value = null;
    } finally {
      busy.value = false;
    }
  }

  return {
    status,
    info,
    loading,
    busy,
    refresh,
    exportCa,
    install,
    uninstall,
    regenerate,
  };
});

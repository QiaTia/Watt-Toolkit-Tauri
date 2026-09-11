import { defineStore } from 'pinia';
import { ref } from 'vue';
import { getAppInfo } from '@/api';
import type { AppInfo } from '@/types/ipc';

export const useAppStore = defineStore('app', () => {
  const info = ref<AppInfo | null>(null);
  const loaded = ref(false);

  async function load(): Promise<void> {
    info.value = await getAppInfo();
    loaded.value = true;
  }

  return { info, loaded, load };
});

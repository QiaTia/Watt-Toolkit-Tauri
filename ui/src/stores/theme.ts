import { defineStore } from 'pinia';
import { computed, ref, watch } from 'vue';
import { getCurrentWindow } from '@tauri-apps/api/window';

export type ThemeMode = 'light' | 'dark' | 'auto';

const STORAGE_KEY = 'app.theme_mode';

/**
 * 同步原生窗口主题：Windows 标题栏（DWMWA_USE_IMMERSIVE_DARK_MODE）、
 * macOS 外观都靠它，否则深色界面会顶一条白色原生标题栏。
 */
async function syncNativeTheme(dark: boolean): Promise<void> {
  try {
    await getCurrentWindow().setTheme(dark ? 'dark' : 'light');
  } catch {
    // 纯浏览器预览或权限缺失时只影响原生标题栏，不影响界面主题
  }
}

function readStoredMode(): ThemeMode {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === 'light' || raw === 'dark' || raw === 'auto') return raw;
  } catch {
    // 隐私模式等读取异常 → 默认跟随系统
  }
  return 'auto';
}

/**
 * 全局主题（浅色 / 深色 / 跟随系统），持久化到 localStorage。
 *
 * 双通道同步：
 * - antd 组件：App.vue 读取 isDark 切换 algorithm（CSS-in-JS，自成体系）
 * - 非 antd 部分（--bg/--border 等自定义属性、原生滚动条、color-scheme）：
 *   把解析结果落到 <html class="dark">，base.css 据此切换令牌
 */
export const useThemeStore = defineStore('theme', () => {
  const mode = ref<ThemeMode>(readStoredMode());

  const schemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
  const systemDark = ref(schemeQuery.matches);
  // store 与应用同生命周期，监听无需注销
  schemeQuery.addEventListener('change', (e) => {
    systemDark.value = e.matches;
  });

  /** 实际生效的深色状态（auto 展开为系统偏好） */
  const isDark = computed(() => (mode.value === 'auto' ? systemDark.value : mode.value === 'dark'));

  watch(
    mode,
    (m) => {
      try {
        localStorage.setItem(STORAGE_KEY, m);
      } catch {
        // 写入异常不影响功能
      }
    },
    { immediate: true },
  );

  watch(
    isDark,
    (dark) => {
      document.documentElement.classList.toggle('dark', dark);
      // 原生标题栏与界面保持同一套明暗（「跟随系统」时随 matchMedia 变化重新同步）
      void syncNativeTheme(dark);
    },
    { immediate: true },
  );

  return { mode, isDark };
});

import { createI18n } from 'vue-i18n';
import zhHans from './zh-Hans';
import zhHant from './zh-Hant';
import ja from './ja';
import en from './en';
import fr from './fr';

export type LocaleCode = 'zh-Hans' | 'zh-Hant' | 'ja' | 'en' | 'fr';

const STORAGE_KEY = 'app.locale';

export const localeOptions: ReadonlyArray<{ value: LocaleCode; label: string }> = [
  { value: 'zh-Hans', label: '简体中文' },
  { value: 'zh-Hant', label: '繁體中文' },
  { value: 'ja', label: '日本語' },
  { value: 'en', label: 'English' },
  { value: 'fr', label: 'Français' },
];

function readStoredLocale(): LocaleCode {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (localeOptions.some((o) => o.value === raw)) return raw as LocaleCode;
  } catch {
    // 读取异常 → 默认简体中文
  }
  return 'zh-Hans';
}

/**
 * 全局 i18n 实例（组合式 API）。
 * - 模板内直接用 $t（globalInjection）
 * - 脚本/店铺内用 i18n.global.t（引用 global.locale ref，语言切换自动响应）
 */
export const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: readStoredLocale(),
  fallbackLocale: 'zh-Hans',
  messages: {
    'zh-Hans': zhHans,
    'zh-Hant': zhHant,
    ja,
    en,
    fr,
  },
});

/** 切换语言并持久化（所有视图即时响应） */
export function setLocale(locale: LocaleCode): void {
  i18n.global.locale.value = locale;
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    // 写入异常不影响本次会话
  }
}

export function getLocale(): LocaleCode {
  return i18n.global.locale.value as LocaleCode;
}

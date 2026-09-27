<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useSettingsStore } from '@/stores/settings';
import { useCertStore } from '@/stores/cert';
import { useThemeStore, type ThemeMode } from '@/stores/theme';
import { getLocale, localeOptions, setLocale, type LocaleCode } from '@/locales';
import type { ProxyMode } from '@/types/ipc';

const settings = useSettingsStore();
const cert = useCertStore();
// 主题/语言即时生效（localStorage 持久化），不走「保存设置」
const theme = useThemeStore();
const { t } = useI18n();

/** 语言选择器双向绑定（写 localStorage + 切 i18n locale） */
const language = computed<LocaleCode>({
  get: () => getLocale(),
  set: (v) => setLocale(v),
});

/** 证书操作错误（UAC 取消 / 引擎运行中等） */
const certError = ref<string | null>(null);

onMounted(() => {
  if (!settings.loaded) void settings.load();
  if (cert.status === null) void cert.refresh();
});

/**
 * 后端字段为 `string | null`，而 antd 表单组件的 v-model 只接受
 * `string` / `string | number`（且 exactOptionalPropertyTypes 下连 undefined 都不行）。
 * 这里做一层映射：null ↔ ''，空串写回时还原为 null。
 */
function nullableString(get: () => string | null, set: (v: string | null) => void) {
  return computed<string>({
    get: () => get() ?? '',
    set: (v: unknown) => {
      const s = v === null || v === undefined ? '' : String(v);
      set(s === '' ? null : s);
    },
  });
}

/**
 * 端口类字段：a-input-number 清空时会发出 null，直接写进 `number` 字段
 * 会让 JSON 里出现 null、Rust 侧 u16 反序列化失败 —— 兜底为 0（0 = 使用默认端口）。
 */
function portNumber(get: () => number, set: (v: number) => void) {
  return computed<number>({
    get: () => get(),
    set: (v: unknown) => set(typeof v === 'number' && Number.isFinite(v) ? v : 0),
  });
}

const proxyType = computed<string>({
  get: () => settings.settings.two_level_agent.proxy_type ?? '',
  set: (v: unknown) => {
    settings.settings.two_level_agent.proxy_type =
      v === null || v === undefined || v === '' ? null : String(v);
  },
});

const systemProxyPort = portNumber(
  () => settings.settings.system_proxy_port,
  (v) => (settings.settings.system_proxy_port = v),
);
const socks5ProxyPort = portNumber(
  () => settings.settings.socks5_proxy_port,
  (v) => (settings.settings.socks5_proxy_port = v),
);
const twoLevelPort = portNumber(
  () => settings.settings.two_level_agent.port,
  (v) => (settings.settings.two_level_agent.port = v),
);
const twoLevelIp = nullableString(
  () => settings.settings.two_level_agent.ip,
  (v) => (settings.settings.two_level_agent.ip = v),
);
const twoLevelUsername = nullableString(
  () => settings.settings.two_level_agent.username,
  (v) => (settings.settings.two_level_agent.username = v),
);
const twoLevelPassword = nullableString(
  () => settings.settings.two_level_agent.password,
  (v) => (settings.settings.two_level_agent.password = v),
);
const masterDns = nullableString(
  () => settings.settings.dns.master_dns,
  (v) => (settings.settings.dns.master_dns = v),
);
const customDohAddress = nullableString(
  () => settings.settings.dns.custom_doh_address,
  (v) => (settings.settings.dns.custom_doh_address = v),
);

const modeOptions = computed<Array<{ value: ProxyMode; label: string }>>(() => [
  { value: 'Hosts', label: t('accel.modes.hosts.label') },
  { value: 'System', label: t('accel.modes.system.label') },
  { value: 'Pac', label: t('accel.modes.pac.label') },
  { value: 'ProxyOnly', label: t('accel.modes.proxyOnly.label') },
]);

const themeOptions = computed<Array<{ value: ThemeMode; label: string }>>(() => [
  { value: 'light', label: t('settings.themeLight') },
  { value: 'dark', label: t('settings.themeDark') },
  { value: 'auto', label: t('settings.themeAuto') },
]);

const proxyTypeOptions: Array<{ value: string; label: string }> = [
  { value: 'HTTP', label: 'HTTP' },
  { value: 'SOCKS4', label: 'SOCKS4' },
  { value: 'SOCKS5', label: 'SOCKS5' },
];

/** 包装证书操作：统一错误提示 */
async function withCertError(action: () => Promise<void>): Promise<void> {
  certError.value = null;
  try {
    await action();
  } catch (e) {
    certError.value = e instanceof Error ? e.message : String(e);
  }
}

async function exportCa(): Promise<void> {
  await withCertError(() => cert.exportCa());
}

async function installCa(): Promise<void> {
  await withCertError(() => cert.install());
}

async function uninstallCa(): Promise<void> {
  await withCertError(() => cert.uninstall());
}

async function regenerateCa(): Promise<void> {
  await withCertError(() => cert.regenerate());
}

/** 格式化指纹为每组两字符的可读形式 */
function groupFingerprint(hex: string): string {
  return hex.replace(/(..)/g, '$1 ').trim();
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}
</script>

<template>
  <div class="page">
    <a-card :bordered="false" :title="$t('settings.generalTitle')" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.appearance')">
              <a-segmented v-model:value="theme.mode" :options="themeOptions" />
              <a-typography-paragraph type="secondary" class="field-hint">
                {{ $t('settings.themeHint') }}
              </a-typography-paragraph>
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.language')">
              <a-select
                v-model:value="language"
                :options="localeOptions.map((o) => ({ value: o.value, label: o.label }))"
              />
              <a-typography-paragraph type="secondary" class="field-hint">
                {{ $t('settings.languageHint') }}
              </a-typography-paragraph>
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <a-card :bordered="false" :title="$t('settings.proxyTitle')" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.proxyMode')">
              <a-select
                v-model:value="settings.settings.proxy_mode"
                :options="modeOptions"
                :placeholder="$t('settings.proxyModePlaceholder')"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.forwardPort')">
              <a-input-number
                v-model:value="systemProxyPort"
                :min="0"
                :max="65535"
                class="w-full"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.httpRedirect')">
              <a-switch v-model:checked="settings.settings.enable_http_proxy_to_https" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.socks5Enable')">
              <a-switch v-model:checked="settings.settings.socks5_proxy_enable" />
            </a-form-item>
          </a-col>
          <a-col v-if="settings.settings.socks5_proxy_enable" :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.socks5Port')">
              <a-input-number
                v-model:value="socks5ProxyPort"
                :min="0"
                :max="65535"
                class="w-full"
              />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <a-card :bordered="false" :title="$t('settings.twoLevelTitle')" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.twoLevelEnable')">
              <a-switch v-model:checked="settings.settings.two_level_agent.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row v-if="settings.settings.two_level_agent.enable" :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.protocol')">
              <a-select
                v-model:value="proxyType"
                :options="proxyTypeOptions"
                :placeholder="$t('settings.protocolPlaceholder')"
                allow-clear
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.serverAddr')">
              <a-input v-model:value="twoLevelIp" placeholder="127.0.0.1" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.port')">
              <a-input-number
                v-model:value="twoLevelPort"
                :min="0"
                :max="65535"
                class="w-full"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.username')">
              <a-input v-model:value="twoLevelUsername" :placeholder="$t('settings.optional')" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.password')">
              <a-input-password v-model:value="twoLevelPassword" :placeholder="$t('settings.optional')" />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <a-card :bordered="false" :title="$t('settings.dnsTitle')" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.masterDns')">
              <a-input v-model:value="masterDns" placeholder="223.5.5.5" allow-clear />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.useDoh')">
              <a-switch v-model:checked="settings.settings.dns.use_doh" />
            </a-form-item>
          </a-col>
          <a-col v-if="settings.settings.dns.use_doh" :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.dohAddr')">
              <a-input
                v-model:value="customDohAddress"
                placeholder="https://dns.alidns.com/dns-query"
                allow-clear
              />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <a-card v-if="cert.status" :bordered="false" :title="$t('settings.certTitle')" class="panel">
      <a-descriptions :column="{ xs: 1, sm: 2 }" size="small" bordered class="cert-desc">
        <a-descriptions-item :label="$t('settings.trustStatus')">
          <a-tag :color="cert.status.installed ? 'success' : 'warning'">
            {{ cert.status.installed ? $t('settings.trusted') : $t('settings.untrusted') }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="$t('settings.daysRemaining')">
          <a-typography-text :type="cert.status.expired ? 'danger' : 'success'">
            {{ cert.status.daysRemaining }} {{ $t('common.daysUnit') }}
          </a-typography-text>
        </a-descriptions-item>
      </a-descriptions>

      <a-descriptions v-if="cert.info" :column="1" size="small" bordered class="cert-desc">
        <a-descriptions-item :label="$t('settings.subject')">{{ cert.info.subject }}</a-descriptions-item>
        <a-descriptions-item :label="$t('settings.serial')">
          <span class="mono">{{ cert.info.serial }}</span>
        </a-descriptions-item>
        <a-descriptions-item :label="$t('settings.notBefore')">{{ formatTime(cert.info.not_before) }}</a-descriptions-item>
        <a-descriptions-item :label="$t('settings.notAfter')">{{ formatTime(cert.info.not_after) }}</a-descriptions-item>
        <a-descriptions-item label="SHA-1">
          <span class="mono fp">{{ groupFingerprint(cert.info.sha1) }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="SHA-256">
          <span class="mono fp">{{ groupFingerprint(cert.info.sha256) }}</span>
        </a-descriptions-item>
      </a-descriptions>

      <a-alert v-if="certError" type="error" show-icon class="cert-error">
        <template #message>{{ certError }}</template>
      </a-alert>

      <a-space :size="12" wrap>
        <a-button v-if="!cert.status.installed" type="primary" :loading="cert.busy" @click="installCa">
          {{ $t('settings.install') }}
        </a-button>
        <a-popconfirm
          v-else
          :title="$t('settings.uninstallConfirm')"
          :ok-text="$t('settings.okRemove')"
          :cancel-text="$t('settings.cancel')"
          @confirm="uninstallCa"
        >
          <a-button danger :loading="cert.busy">{{ $t('settings.uninstall') }}</a-button>
        </a-popconfirm>
        <a-button :loading="cert.busy" @click="exportCa">
          {{ $t('settings.exportCert') }}
        </a-button>
        <a-popconfirm
          :title="$t('settings.regenerateConfirm')"
          :ok-text="$t('settings.okRegenerate')"
          :cancel-text="$t('settings.cancel')"
          @confirm="regenerateCa"
        >
          <a-button danger :loading="cert.busy">{{ $t('settings.regenerate') }}</a-button>
        </a-popconfirm>
      </a-space>

      <a-typography-paragraph type="secondary" class="hint">
        {{ $t('settings.certHint') }}
      </a-typography-paragraph>
    </a-card>
  </div>
</template>

<style scoped>
.panel {
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.panel + .panel {
  margin-top: 16px;
}

.w-full {
  width: 100%;
}

.cert-desc {
  margin-bottom: 16px;
}

.cert-error {
  margin-bottom: 12px;
}

.hint {
  margin: 16px 0 0;
  line-height: 1.8;
  font-size: 13px;
}

.field-hint {
  margin: 10px 0 0;
  font-size: 13px;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  word-break: break-all;
}

.fp {
  font-size: 12px;
  letter-spacing: 0.5px;
}
</style>

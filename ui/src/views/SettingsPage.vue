<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import AntApp from 'ant-design-vue/es/app';
import { useSettingsStore } from '@/stores/settings';
import { useProxyStore } from '@/stores/proxy';
import { useCertStore } from '@/stores/cert';
import { useAppStore } from '@/stores/app';
import { useThemeStore, type ThemeMode } from '@/stores/theme';
import { useUpdateStore, RELEASE_PAGE_URL } from '@/stores/update';
import { certDiagnose, dnsProbeDoh, openExternal } from '@/api';
import { getLocale, localeOptions, setLocale, type LocaleCode } from '@/locales';
import { isMacOS } from '@/utils/platform';
import type { ProxyMode, TrustDiagnostics } from '@/types/ipc';

const settings = useSettingsStore();
const proxy = useProxyStore();
const cert = useCertStore();
const app = useAppStore();
// 主题/语言即时生效（localStorage 持久化），不走「保存设置」
const theme = useThemeStore();
const update = useUpdateStore();
const { t } = useI18n();
const { message } = AntApp.useApp();

/** macOS 提权提示（钥匙串写入弹管理员密码框） */
const isMac = isMacOS();

/** 语言选择器双向绑定（写 localStorage + 切 i18n locale） */
const language = computed<LocaleCode>({
  get: () => getLocale(),
  set: (v) => setLocale(v),
});

/** 证书操作错误（UAC 取消 / 引擎运行中等） */
const certError = ref<string | null>(null);

/** 信任存储诊断结果（点击「诊断」后出现） */
const certDiagnostics = ref<TrustDiagnostics | null>(null);
/** 诊断进行中 */
const diagnosing = ref(false);

/** DoH 连通性测试中（防止重复点击） */
const dohTesting = ref(false);

onMounted(() => {
  if (!settings.loaded) void settings.ensureLoaded().catch(() => {});
  if (cert.status === null) void cert.refresh().catch(() => {});
  if (!update.settingsLoaded) void update.loadSettings();
});

/* 软件更新卡片：独立于代理设置保存，避免两处整对象写入互相覆盖 */
const updateEndpoint = nullableString(
  () => update.settings.endpoint,
  (v) => (update.settings.endpoint = v),
);
const updateInterval = computed<number>({
  get: () => update.settings.checkIntervalHours,
  set: (v: unknown) => {
    update.settings.checkIntervalHours =
      typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 24;
  },
});

async function saveUpdateSettings(): Promise<void> {
  const ok = await update.saveSettings();
  if (ok) void message.success(t('common.saved'));
  else void message.error(update.error ?? t('common.saveFailed'));
}

async function checkUpdateNow(): Promise<void> {
  const result = await update.checkAndOpen();
  if (result === 'upToDate') void message.info(t('update.upToDate'));
  else if (result === 'error') void message.error(update.error ?? t('update.failed'));
}

function openManualDownload(): void {
  void openExternal(RELEASE_PAGE_URL);
}

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
/** 默认 DoH 端点（与 Rust DEFAULT_DOH_ADDRESS 一致） */
const DEFAULT_DOH = 'https://doh.pub/dns-query';
/** 内置服务器预设（顺序即优先级，对齐 Rust DEFAULT_DOH_SERVERS / DEFAULT_DNS_SERVERS） */
const PRESET_DNS_SERVERS = [
  'https://doh.pub/dns-query',
  'https://dns.alidns.com/dns-query',
  'https://dns.google/dns-query',
  '223.5.5.5',
  '119.29.29.29',
  '114.114.114.114',
];

/**
 * 有序解析服务器列表。
 *
 * 列表为空时按旧字段（DoH 开关 / 主 DNS）临时合成用于展示——只在用户编辑后
 * 才写回 `resolver_servers`，避免打开设置页就悄悄改写磁盘配置。
 */
const dnsServers = computed<string[]>({
  get: () => {
    const list = settings.settings.dns.resolver_servers;
    if (list && list.length > 0) return list;
    const legacy: string[] = [];
    if (settings.settings.dns.use_doh) {
      legacy.push(settings.settings.dns.custom_doh_address || DEFAULT_DOH);
    }
    if (settings.settings.dns.master_dns) legacy.push(settings.settings.dns.master_dns);
    return legacy;
  },
  set: (v) => {
    settings.settings.dns.resolver_servers = v;
  },
});

function updateDnsServer(index: number, value: string): void {
  const next = [...dnsServers.value];
  next[index] = value;
  dnsServers.value = next;
}

function addDnsServer(): void {
  dnsServers.value = [...dnsServers.value, ''];
}

function removeDnsServer(index: number): void {
  dnsServers.value = dnsServers.value.filter((_, i) => i !== index);
}

/** 上移/下移：顺序即优先级，必须立即落数组顺序 */
function moveDnsServer(index: number, delta: number): void {
  const target = index + delta;
  const next = [...dnsServers.value];
  if (target < 0 || target >= next.length) return;
  const current = next[index] ?? '';
  const other = next[target] ?? '';
  next[index] = other;
  next[target] = current;
  dnsServers.value = next;
}

function fillDefaultDns(): void {
  dnsServers.value = [...PRESET_DNS_SERVERS];
}

const modeOptions = computed<Array<{ value: ProxyMode; label: string; disabled: boolean }>>(() => [
  // macOS：Hosts 需要监听 443（特权端口），非 root 不可用，直接置灰
  { value: 'Hosts', label: t('accel.modes.hosts.label'), disabled: isMac },
  { value: 'System', label: t('accel.modes.system.label'), disabled: false },
  { value: 'Pac', label: t('accel.modes.pac.label'), disabled: false },
  { value: 'ProxyOnly', label: t('accel.modes.proxyOnly.label'), disabled: false },
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

/** 包装证书操作：统一错误提示 + 成功反馈 */
async function withCertError(action: () => Promise<void>): Promise<void> {
  certError.value = null;
  try {
    await action();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // 提权取消：后端错误含"取消" / osascript 的 -128 文案
    const cancelled = msg.includes('取消') || msg.toLowerCase().includes('cancel') || msg.includes('-128');
    certError.value = cancelled ? t('settings.elevateCancelled') : msg;
  }
}

async function exportCa(): Promise<void> {
  await withCertError(() => cert.exportCa());
}

/** 信任存储诊断：旧根残留 / 已导入未信任 / 未提权，一次查清 */
async function diagnoseCa(): Promise<void> {
  if (diagnosing.value) return;
  diagnosing.value = true;
  try {
    certDiagnostics.value = await certDiagnose();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    message.error(msg);
  } finally {
    diagnosing.value = false;
  }
}

async function installCa(): Promise<void> {
  await withCertError(async () => {
    await cert.install();
    if (cert.status?.installed) {
      message.success(t('settings.certInstalled'));
    } else {
      // 命令成功但安装后校验未通过：明确提示，而不是静默停在「未安装」
      message.warning(t('settings.certInstallVerifyFailed'));
    }
  });
}

async function uninstallCa(): Promise<void> {
  await withCertError(async () => {
    await cert.uninstall();
    message.success(t('settings.certUninstalled'));
  });
}

async function regenerateCa(): Promise<void> {
  await withCertError(async () => {
    const status = await cert.regenerate();
    message.warning(t('settings.certRegenerated'));
    // 旧信任清理失败是非致命告警：必须显式提示，避免用户误以为旧根已移除
    if (status.warning) message.warning(status.warning);
  });
}

/**
 * DoH 连通性测试：显式验证 TLS 握手 + 真实解析。
 * 引擎启动时若端点配置无效会回退系统 DNS，这里给用户一个「不静默」的检查入口。
 */
/** 正在测试的行下标（仅该行按钮转圈） */
const probingIndex = ref<number | null>(null);

/** 该行是否为可测试的 DoH 端点 */
function isDohServer(server: string): boolean {
  return /^https:\/\//i.test(server.trim());
}

/** 单行 DoH 连通性测试（严格单端点，不做回退，失败即报错） */
async function probeDohServer(index: number): Promise<void> {
  if (dohTesting.value) return;
  const endpoint = (dnsServers.value[index] ?? '').trim();
  if (!isDohServer(endpoint)) return;
  dohTesting.value = true;
  probingIndex.value = index;
  try {
    const r = await dnsProbeDoh(endpoint);
    message.success(
      t('settings.dohTestOk', {
        host: r.host,
        ips: r.ips.join(', '),
        ms: r.elapsedMs,
      }),
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    message.error(t('settings.dohTestFail', { error: msg }));
  } finally {
    dohTesting.value = false;
    probingIndex.value = null;
  }
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
                :disabled="proxy.isRunning"
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
                :disabled="proxy.isRunning"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.httpRedirect')">
              <a-switch
                v-model:checked="settings.settings.enable_http_proxy_to_https"
                :disabled="proxy.isRunning"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.socks5Enable')">
              <a-switch
                v-model:checked="settings.settings.socks5_proxy_enable"
                :disabled="proxy.isRunning"
              />
            </a-form-item>
          </a-col>
          <a-col v-if="settings.settings.socks5_proxy_enable" :xs="24" :md="12" :lg="8">
            <a-form-item :label="$t('settings.socks5Port')">
              <a-input-number
                v-model:value="socks5ProxyPort"
                :min="0"
                :max="65535"
                class="w-full"
                :disabled="proxy.isRunning"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-typography-paragraph v-if="proxy.isRunning" type="warning">
          {{ t('settings.runningLockedHint') }}
        </a-typography-paragraph>

        <a-row :gutter="16">
          <a-col :xs="24" :md="16" :lg="12">
            <a-form-item :label="$t('settings.terminalProxy')">
              <a-switch
                v-model:checked="settings.settings.terminal_proxy_enable"
                :disabled="proxy.isRunning"
              />
              <a-typography-paragraph type="secondary" class="field-hint">
                {{ $t('settings.terminalProxyHint') }}
              </a-typography-paragraph>
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
        <a-form-item :label="$t('settings.dnsServers')">
          <template #extra>
            <span class="dns-hint">{{ $t('settings.dnsServersHint') }}</span>
          </template>
          <div class="dns-list">
            <div v-for="(server, i) in dnsServers" :key="i" class="dns-row">
              <span class="dns-index">{{ i + 1 }}</span>
              <a-input
                :value="server"
                :placeholder="isDohServer(server) || i === 0 ? 'https://doh.pub/dns-query' : '223.5.5.5'"
                allow-clear
                @update:value="(v: string) => updateDnsServer(i, v)"
              />
              <a-button
                v-if="isDohServer(server)"
                size="small"
                :loading="probingIndex === i"
                :disabled="dohTesting && probingIndex !== i"
                @click="probeDohServer(i)"
              >
                {{ $t('settings.dohTest') }}
              </a-button>
              <a-tooltip :title="$t('settings.dnsMoveUp')">
                <a-button size="small" :disabled="i === 0" @click="moveDnsServer(i, -1)">↑</a-button>
              </a-tooltip>
              <a-tooltip :title="$t('settings.dnsMoveDown')">
                <a-button size="small" :disabled="i === dnsServers.length - 1" @click="moveDnsServer(i, 1)">
                  ↓
                </a-button>
              </a-tooltip>
              <a-tooltip :title="$t('settings.dnsRemove')">
                <a-button size="small" danger @click="removeDnsServer(i)">✕</a-button>
              </a-tooltip>
            </div>
            <a-empty v-if="dnsServers.length === 0" :description="$t('settings.dnsEmpty')" />
            <div class="dns-actions">
              <a-button size="small" @click="addDnsServer">{{ $t('settings.dnsAdd') }}</a-button>
              <a-button size="small" @click="fillDefaultDns">{{ $t('settings.dnsPreset') }}</a-button>
            </div>
          </div>
        </a-form-item>
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item>
              <a-checkbox v-model:checked="settings.settings.dns.before_dns_check">
                {{ $t('settings.beforeDnsCheck') }}
              </a-checkbox>
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

      <a-typography-paragraph v-if="isMac" type="secondary" class="cert-elevate-hint">
        {{ $t('settings.elevateMacHint') }}
      </a-typography-paragraph>

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
        <a-button :loading="diagnosing" @click="diagnoseCa">
          {{ $t('settings.certDiagnose') }}
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

      <a-alert
        v-if="certDiagnostics"
        :type="certDiagnostics.installed ? 'success' : 'warning'"
        show-icon
        closable
        class="cert-error"
        @close="certDiagnostics = null"
      >
        <template #message>{{ $t('settings.certDiagnoseTitle') }}</template>
        <template #description>
          <ul class="diag-list">
            <li v-for="(line, i) in certDiagnostics.advice" :key="i">{{ line }}</li>
          </ul>
        </template>
      </a-alert>

      <a-typography-paragraph type="secondary" class="hint">
        {{ $t('settings.certHint') }}
      </a-typography-paragraph>
    </a-card>

    <a-card :bordered="false" :title="$t('update.settingsTitle')" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="8">
            <a-form-item :label="$t('update.autoCheck')">
              <a-switch v-model:checked="update.settings.autoCheck" />
              <template #extra>{{ $t('update.autoCheckHint') }}</template>
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="8">
            <a-form-item :label="$t('update.interval')">
              <a-input-number v-model:value="updateInterval" :min="0" :max="720" class="w-full" />
              <template #extra>{{ $t('update.intervalHint') }}</template>
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item :label="$t('update.endpoint')">
          <a-input
            v-model:value="updateEndpoint"
            allow-clear
            :placeholder="$t('update.endpointPlaceholder')"
          />
          <template #extra>{{ $t('update.endpointHint') }}</template>
        </a-form-item>

        <a-form-item v-if="update.settings.skippedVersion" :label="$t('update.skippedVersion')">
          <a-space>
            <a-tag>{{ update.settings.skippedVersion }}</a-tag>
            <a-button size="small" @click="update.clearSkip()">
              {{ $t('update.clearSkip') }}
            </a-button>
          </a-space>
        </a-form-item>
      </a-form>

      <a-space wrap>
        <a-button type="primary" :loading="update.savingSettings" @click="saveUpdateSettings">
          {{ $t('update.saveSettings') }}
        </a-button>
        <a-button :loading="update.isChecking" @click="checkUpdateNow">
          {{ $t('update.checkNow') }}
        </a-button>
        <a-button v-if="update.hasUpdate" type="link" @click="update.openModal()">
          {{ $t('update.viewDetail') }}
        </a-button>
        <a-button type="link" @click="openManualDownload">
          {{ $t('update.manualDownload') }}
        </a-button>
      </a-space>

      <a-alert v-if="update.status === 'error' && update.error" type="error" show-icon class="update-error">
        <template #message>{{ $t('update.failed') }}</template>
        <template #description>
          <span class="mono">{{ update.error }}</span>
        </template>
      </a-alert>
      <a-typography-paragraph v-else type="secondary" class="hint">
        {{ $t('update.currentVersion', { version: app.info?.version ?? '—' }) }}
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

.doh-row {
  display: flex;
  gap: 8px;
}

.dns-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
}

.dns-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.dns-row :deep(.ant-input-affix-wrapper),
.dns-row :deep(.ant-input) {
  flex: 1;
}

.dns-index {
  width: 18px;
  color: rgba(0, 0, 0, 0.45);
  text-align: right;
  flex: none;
}

.dns-actions {
  display: flex;
  gap: 8px;
}

.dns-hint {
  color: rgba(0, 0, 0, 0.45);
  font-size: 12px;
}

.cert-desc {
  margin-bottom: 16px;
}

.cert-error {
  margin-bottom: 12px;
  /* 后端的失败指引是多行（含可复制的手动命令），保留换行 */
  white-space: pre-line;
}

/* 诊断结论列表：默认 ul 缩进过大且无间距，压紧以贴合卡片的行距 */
.diag-list {
  margin: 0;
  padding-left: 18px;
  white-space: normal;
}

.diag-list li + li {
  margin-top: 4px;
}

.hint {
  margin: 16px 0 0;
  line-height: 1.8;
  font-size: 13px;
}

.update-error {
  margin-top: 16px;
  white-space: pre-wrap;
  word-break: break-all;
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
.cert-elevate-hint {
  margin-bottom: 4px;
}
</style>

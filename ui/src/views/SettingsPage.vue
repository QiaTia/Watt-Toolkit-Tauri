<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import AntApp from 'ant-design-vue/es/app';
import { useSettingsStore } from '@/stores/settings';
import { useCertStore } from '@/stores/cert';
import type { ProxyMode } from '@/types/ipc';

const settings = useSettingsStore();
const cert = useCertStore();
// 由 <a-app>（App.vue）提供的上下文创建，跟随全局主题
const { message } = AntApp.useApp();

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

const modeOptions: Array<{ value: ProxyMode; label: string }> = [
  { value: 'Hosts', label: 'Hosts 模式' },
  { value: 'System', label: '系统代理' },
  { value: 'Pac', label: 'PAC 模式' },
  { value: 'ProxyOnly', label: '仅代理端口' },
];

const proxyTypeOptions: Array<{ value: string; label: string }> = [
  { value: 'HTTP', label: 'HTTP' },
  { value: 'SOCKS4', label: 'SOCKS4' },
  { value: 'SOCKS5', label: 'SOCKS5' },
];

async function save(): Promise<void> {
  const ok = await settings.save();
  if (ok) {
    void message.success('设置已保存');
  } else {
    void message.error('保存失败，请查看日志');
  }
}

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
    <a-card :bordered="false" title="代理设置" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="代理模式">
              <a-select
                v-model:value="settings.settings.proxy_mode"
                :options="modeOptions"
                placeholder="选择加速模式"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="正向代理端口">
              <a-input-number
                v-model:value="systemProxyPort"
                :min="0"
                :max="65535"
                class="w-full"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="HTTP→HTTPS 重定向 (80)">
              <a-switch v-model:checked="settings.settings.enable_http_proxy_to_https" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="启用 SOCKS5">
              <a-switch v-model:checked="settings.settings.socks5_proxy_enable" />
            </a-form-item>
          </a-col>
          <a-col v-if="settings.settings.socks5_proxy_enable" :xs="24" :md="12" :lg="8">
            <a-form-item label="SOCKS5 端口">
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

    <a-card :bordered="false" title="二级代理（上游）" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="启用二级代理">
              <a-switch v-model:checked="settings.settings.two_level_agent.enable" />
            </a-form-item>
          </a-col>
        </a-row>

        <a-row v-if="settings.settings.two_level_agent.enable" :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="协议类型">
              <a-select
                v-model:value="proxyType"
                :options="proxyTypeOptions"
                placeholder="默认 SOCKS5"
                allow-clear
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="服务器地址">
              <a-input v-model:value="twoLevelIp" placeholder="127.0.0.1" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="端口">
              <a-input-number
                v-model:value="twoLevelPort"
                :min="0"
                :max="65535"
                class="w-full"
              />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="用户名">
              <a-input v-model:value="twoLevelUsername" placeholder="可选" />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="密码">
              <a-input-password v-model:value="twoLevelPassword" placeholder="可选" />
            </a-form-item>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <a-card :bordered="false" title="DNS 设置" class="panel">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="自定义主 DNS">
              <a-input v-model:value="masterDns" placeholder="223.5.5.5" allow-clear />
            </a-form-item>
          </a-col>
          <a-col :xs="24" :md="12" :lg="8">
            <a-form-item label="使用 DoH">
              <a-switch v-model:checked="settings.settings.dns.use_doh" />
            </a-form-item>
          </a-col>
          <a-col v-if="settings.settings.dns.use_doh" :xs="24" :md="12" :lg="8">
            <a-form-item label="自定义 DoH 地址">
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

    <a-card v-if="cert.status" :bordered="false" title="CA 证书" class="panel">
      <a-descriptions :column="{ xs: 1, sm: 2 }" size="small" bordered class="cert-desc">
        <a-descriptions-item label="信任状态">
          <a-tag :color="cert.status.installed ? 'success' : 'warning'">
            {{ cert.status.installed ? '已安装并信任' : '未安装' }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="剩余有效期">
          <a-typography-text :type="cert.status.expired ? 'danger' : 'success'">
            {{ cert.status.daysRemaining }} 天
          </a-typography-text>
        </a-descriptions-item>
      </a-descriptions>

      <a-descriptions v-if="cert.info" :column="1" size="small" bordered class="cert-desc">
        <a-descriptions-item label="主题">{{ cert.info.subject }}</a-descriptions-item>
        <a-descriptions-item label="序列号">
          <span class="mono">{{ cert.info.serial }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="生效时间">{{ formatTime(cert.info.not_before) }}</a-descriptions-item>
        <a-descriptions-item label="过期时间">{{ formatTime(cert.info.not_after) }}</a-descriptions-item>
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
          安装到系统信任存储
        </a-button>
        <a-popconfirm
          v-else
          title="确定从系统信任存储移除 Watt Toolkit 根证书？"
          ok-text="移除"
          cancel-text="取消"
          @confirm="uninstallCa"
        >
          <a-button danger :loading="cert.busy">移除信任</a-button>
        </a-popconfirm>
        <a-button :loading="cert.busy" @click="exportCa">导出证书 (PEM)</a-button>
        <a-popconfirm
          title="重新生成 CA 证书将使所有已签发证书失效，确定继续？"
          ok-text="重新生成"
          cancel-text="取消"
          @confirm="regenerateCa"
        >
          <a-button danger :loading="cert.busy">重新生成</a-button>
        </a-popconfirm>
      </a-space>

      <a-typography-paragraph type="secondary" class="hint">
        安装到系统信任存储是 HTTPS 加速（MITM）的前提，Windows 下安装会弹出 UAC 提权确认。
        也可导出 PEM 后手动导入到「受信任的根证书颁发机构」。
      </a-typography-paragraph>
    </a-card>

    <div class="save-bar">
      <a-button type="primary" :loading="settings.saving" @click="save">保存设置</a-button>
    </div>
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

.save-bar {
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px 0;
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

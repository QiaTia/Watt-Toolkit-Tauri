import type { Schema } from './zh-Hans';

const en: Schema = {
  nav: {
    home: 'Home',
    accelerator: 'Network Boost',
    settings: 'Settings',
    about: 'About',
  },
  state: {
    stopped: 'Stopped',
    starting: 'Starting…',
    running: 'Boosting',
    stopping: 'Stopping…',
    error: 'Error',
  },
  common: {
    save: 'Save Settings',
    saved: 'Settings saved',
    saveFailed: 'Save failed, check the logs',
    up: 'Up',
    down: 'Down',
    daysUnit: 'days',
  },
  home: {
    runningHint: 'Traffic is being forwarded through the local proxy',
    idleHint: 'Pick projects in "Network Boost" and start with one click',
    certTitle: 'Certificate Status',
    appTitle: 'App Info',
    subject: 'Subject',
    serial: 'Serial',
    daysRemaining: 'Days Remaining',
    valid: 'Valid',
    expired: 'Expired',
    version: 'Version',
    platform: 'Platform',
    dataDir: 'Data Directory',
  },
  accel: {
    modeTitle: 'Boost Mode',
    runningSwitchHint: 'Boost is running — stop it before switching modes',
    start: 'One-Click Boost',
    stop: 'Stop Boost',
    projectsTitle: 'Boost Projects',
    sourceCloud: 'Cloud',
    sourceCache: 'Local Cache',
    searchPlaceholder: 'Search boost projects',
    selectAll: 'Select All',
    clearAll: 'Clear',
    refresh: 'Refresh List',
    checkedSummary: '{checked} / {total} selected',
    noMatch: 'No matching boost projects',
    loadFailed: 'Failed to load boost projects: {error}',
    connectivityTest: 'Connectivity Test',
    testEmpty: 'Nothing to test: check some projects in this group first',
    testAllFailed:
      'All tests failed. Check your network connection and the proxy settings.',
    serverSide: 'Server-side Boost',
    hintTitle: 'Notes',
    hint:
      'System / PAC / ProxyOnly modes listen on the local forward proxy port {port}; the PAC ' +
      'script is served at http://127.0.0.1:{port}/pac. Hosts mode writes boosted domains into ' +
      'the hosts file and serves a TLS reverse proxy on local 443 (restored automatically on ' +
      'stop). The proxy port can be changed in "Settings → Proxy".',
    modes: {
      hosts: {
        label: 'Hosts Mode',
        desc:
          'Points hosts at the local 443 reverse proxy (port 443 must be free; writing hosts ' +
          'may require admin rights)',
      },
      system: {
        label: 'System Proxy',
        desc:
          'Sets the system proxy to local port {port}; system-wide, no need to occupy 443',
      },
      pac: {
        label: 'PAC Mode',
        desc:
          'Auto-config script routes by domain — only boosted domains go through the proxy ' +
          '(port {port})',
      },
      proxyOnly: {
        label: 'Proxy Port Only',
        desc:
          'No system changes; point your browser/client at 127.0.0.1:{port} manually',
      },
    },
  },
  settings: {
    generalTitle: 'General',
    appearance: 'Theme',
    themeLight: 'Light',
    themeDark: 'Dark',
    themeAuto: 'Follow System',
    themeHint: 'Changes apply immediately; "Follow System" tracks the OS dark mode',
    language: 'Language',
    languageHint: 'Changes apply immediately',
    proxyTitle: 'Proxy Settings',
    proxyMode: 'Proxy Mode',
    proxyModePlaceholder: 'Choose a boost mode',
    forwardPort: 'Forward Proxy Port',
    httpRedirect: 'HTTP→HTTPS Redirect (80)',
    socks5Enable: 'Enable SOCKS5',
    socks5Port: 'SOCKS5 Port',
    twoLevelTitle: 'Upstream (Two-level Proxy)',
    twoLevelEnable: 'Enable Upstream Proxy',
    protocol: 'Protocol',
    protocolPlaceholder: 'Default SOCKS5',
    serverAddr: 'Server Address',
    port: 'Port',
    username: 'Username',
    password: 'Password',
    optional: 'Optional',
    dnsTitle: 'DNS Settings',
    masterDns: 'Custom Primary DNS',
    useDoh: 'Use DoH',
    dohAddr: 'Custom DoH Address',
    certTitle: 'CA Certificate',
    trustStatus: 'Trust Status',
    trusted: 'Installed & Trusted',
    untrusted: 'Not Installed',
    daysRemaining: 'Days Remaining',
    valid: 'Valid',
    expired: 'Expired',
    subject: 'Subject',
    serial: 'Serial',
    notBefore: 'Valid From',
    notAfter: 'Valid Until',
    install: 'Install to System Trust Store',
    uninstall: 'Remove Trust',
    exportCert: 'Export Certificate (PEM)',
    regenerate: 'Regenerate',
    uninstallConfirm: 'Remove the Watt Toolkit root certificate from the system trust store?',
    regenerateConfirm:
      'Regenerating the CA will invalidate all issued certificates. Continue?',
    okRemove: 'Remove',
    okRegenerate: 'Regenerate',
    cancel: 'Cancel',
    certHint:
      'Installing to the system trust store is required for HTTPS boost (MITM). On Windows an ' +
      'UAC prompt will appear. You can also export the PEM and import it into "Trusted Root ' +
      'Certification Authorities" manually.',
  },
  about: {
    iconAlt: 'Watt Toolkit icon',
    desc:
      'A cross-platform desktop toolbox providing network boost, script extensions and more ' +
      'for Steam and other game platforms.',
    platform: 'Platform',
    dataDir: 'Data Directory',
    license: 'This project is open source under the GPL-3.0 license.',
    sourceLabel: 'Original project:',
  },
};

export default en;

import type { Schema } from './zh-Hans';

const en: Schema = {
  nav: {
    home: 'Home',
    accelerator: 'Network Boost',
    pool: 'IP Pools',
    settings: 'Settings',
    about: 'About',
    logs: 'Logs',
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
        descMac:
          'On macOS, writing /etc/hosts requires administrator rights: one password prompt each ' +
          'when starting and stopping the engine.',
        descWin:
          'On Windows the app runs as administrator (one UAC prompt at launch) so it can write ' +
          'and restore the hosts file.',
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
    probe: {
      running: 'Probing network nodes and ranking by latency…',
      done: 'Optimized {ok}/{total} nodes, fastest {ms}ms',
      failed: 'Probing incomplete; racing in default order',
      partial: 'Probing truncated by budget; using partial results',
    },
    noCheckedHint: 'Select at least one acceleration project before starting.',
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
    terminalProxy: 'Terminal proxy (CLI)',
    terminalProxyHint:
      'Injects HTTP(S)_PROXY and CA certificate variables for git / curl / npm / pip so '
      + 'terminal traffic is accelerated too (already-open terminals must be restarted). '
      + 'System / PAC / proxy-port-only modes point at the local forward proxy; Hosts mode '
      + 'only injects the certificate.',
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
    certHint: 'Installing to the system trust store is required for HTTPS boost (MITM): Windows shows a UAC prompt, macOS shows a system trust confirmation (enter your login password). You can also export the PEM and import it manually.',
    elevateMacHint: 'On macOS, installing the root certificate shows a one-time system trust confirmation (enter your login password). It applies to the current user - no administrator password needed.',
    elevateCancelled: 'Administrator authorization was cancelled. The operation was not completed.',
    runningLockedHint: 'Acceleration is running; proxy mode and ports are locked. Stop acceleration before changing them.',
    certInstalled: 'Root certificate installed and trusted.',
    certInstallVerifyFailed: 'The install command ran but verification failed. Check the system trust settings or export the PEM and install it manually.',
    certUninstalled: 'Root certificate trust removed.',
    certRegenerated: 'CA regenerated and old trust cleaned up. Reinstall the root certificate before enabling HTTPS acceleration.',
  },
  pool: {
    summary: '{hosts} domains, {ips} IPs',
    lastRefreshSummary: 'Last refresh: {hosts} domains, {ok}/{candidates} candidates usable',
    hint:
      'IP pools are kept per domain: acceleration picks the fastest reachable IP from the pool ' +
      '(shortest TLS handshake RTT wins). “Refresh IP Pools” at the top right resolves the ' +
      'domains of enabled projects via healthy DNS and probes them locally; single domains ' +
      'can also be edited or re-resolved individually.',
    refreshAll: 'Refresh IP Pools',
    refreshDone: 'Refresh done: {hosts} domains, {ok}/{candidates} candidates usable',
    refreshEmpty: 'Nothing to refresh: enable acceleration projects on the Boost page first',
    refreshFailed: 'Failed to refresh IP pools',
    addDomain: 'Add Domain',
    clearAll: 'Clear All',
    clearConfirm: 'Clear all IP pools? Acceleration falls back to built-in backups and system DNS.',
    colHost: 'Domain',
    colIps: 'IPs',
    colRefreshed: 'Last Refresh',
    colActions: 'Actions',
    builtinTitle: 'Built-in Backup Pools',
    builtinSummary: '{groups} groups / {ips} IPs',
    builtinHint:
      'Shipped with each release and read-only: a domain tries its dynamic pool first; when the ' +
      'dynamic pool has no match or every candidate fails, these IPs back up the outbound race ' +
      '(failed candidates are skipped automatically, so the successful path is not slowed down). ' +
      'This covers only the few services that genuinely need a hand-curated backup (three GitHub ' +
      'groups / Google Translate / three Figma groups) — it is not the domain list; see “Accelerated ' +
      'Domain IP Overview” above for every domain.',
    overviewTitle: 'Accelerated Domain IP Overview',
    overviewSummary:
      '{hosts} domains: {withIp} have static/pool IPs, {dnsOnly} rely on DNS only',
    overviewHint:
      'Every domain of the currently enabled acceleration projects (built-in groups included) and ' +
      'where its IPs come from. “Override IP” is a pinned first-choice IP baked into the built-in ' +
      'service; “Dynamic pool” comes from the refresh action; “Built-in backup pool” is the ' +
      'release-shipped fallback list. Domains with none of these are resolved by the ' +
      'anti-poisoning DNS plus racing.',
    searchPlaceholder: 'Search domain',
    colSource: 'Sources',
    srcAll: 'All',
    srcOverride: 'Override IP',
    srcDynamic: 'Dynamic pool',
    srcBuiltin: 'Built-in backup',
    srcDns: 'DNS',
    srcDnsOnly: 'DNS only',
    dnsAlwaysHint: 'DNS resolution is always one of the candidates (anti-poisoning DNS + racing)',
    ipCountDns: 'DNS only',
    readonly: 'Read-only',
    colPattern: 'Pattern',
    colNote: 'Notes',
    edit: 'Edit',
    probe: 'Probe',
    refreshHost: 'Re-resolve',
    remove: 'Delete',
    removeConfirm: 'Delete the IP pool of {host}? It falls back to built-in backups and system DNS.',
    removeIp: 'Remove',
    removeIpConfirm: 'Remove {ip}?',
    unreachable: 'Unreachable',
    notProbed: 'Not probed',
    rtt: '{ms} ms',
    prune: 'Remove {n} unreachable IPs',
    pruneDone: 'Removed {n} unreachable IPs',
    probeOk: '{ok}/{total} IPs usable',
    probeAllFailed: 'All {total} IPs are unreachable — try re-resolving from DNS',
    refreshHostEmpty: 'No usable IP resolved for {host}; its pool entry was cleared',
    refreshedHost: '{host} updated: {ok}/{total} candidates usable',
    removed: 'Deleted',
    saved: 'Saved',
    cleared: 'IP pools cleared',
    empty: 'No domain pools yet — add a domain or use “Refresh IP Pools” at the top right',
    editTitleNew: 'Add Domain IP Pool',
    editTitleEdit: 'Edit IP pool of {host}',
    hostLabel: 'Domain',
    hostPlaceholder: 'example.com (no scheme or path)',
    ipsLabel: 'IP list',
    ipsPlaceholder: 'One IP per line, e.g.\n18.65.14.118\n13.35.190.56',
    ipsHint: 'IPv4 / IPv6, one per line (commas or spaces also work); duplicates are dropped on save.',
    hostRequired: 'Please enter a domain',
    save: 'Save',
    cancel: 'Cancel',
  },
  logs: {
    accessTab: 'Access Log',
    runtimeTab: 'Runtime Log',
    refresh: 'Refresh',
    clear: 'Clear',
    autoRefresh: 'Auto refresh',
    keywordPlaceholder: 'Search host / path',
    runtimeKeywordPlaceholder: 'Search message / target',
    method: 'Method',
    status: 'Status',
    disposition: 'Disposition',
    level: 'Level',
    colTime: 'Time',
    colMethod: 'Method',
    colHost: 'Host',
    colPath: 'Path',
    colStatus: 'Status',
    colDown: 'Down',
    colLatency: 'Latency',
    colDisposition: 'Disposition',
    colLevel: 'Level',
    colTarget: 'Target',
    colMessage: 'Message',
    dispMatched: 'Matched',
    dispDefault: 'Default',
    dispUnmatched: 'Unmatched',
    dispLocal: 'Local',
    empty: 'No logs yet',
    total: '{total} entries',
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

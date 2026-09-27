import type { Schema } from './zh-Hans';

const ja: Schema = {
  nav: {
    home: 'ホーム',
    accelerator: 'ネットワーク加速',
    settings: '設定',
    about: '情報',
  },
  state: {
    stopped: '停止中',
    starting: '起動中…',
    running: '加速中',
    stopping: '停止処理中…',
    error: 'エラー',
  },
  common: {
    save: '設定を保存',
    saved: '保存しました',
    saveFailed: '保存に失敗しました。ログを確認してください',
    up: 'アップロード',
    down: 'ダウンロード',
    daysUnit: '日',
  },
  home: {
    runningHint: 'トラフィックはローカルプロキシ経由で転送されています',
    idleHint: '「ネットワーク加速」で項目を選択してワンクリック加速',
    certTitle: '証明書の状態',
    appTitle: 'アプリ情報',
    subject: 'サブジェクト',
    serial: 'シリアル番号',
    daysRemaining: '残り有効期間',
    valid: '有効',
    expired: '期限切れ',
    version: 'バージョン',
    platform: 'プラットフォーム',
    dataDir: 'データディレクトリ',
  },
  accel: {
    modeTitle: '加速モード',
    runningSwitchHint: '加速中のため、先に加速を停止してからモードを切り替えてください',
    start: 'ワンクリック加速',
    stop: '加速を停止',
    projectsTitle: '加速項目',
    sourceCloud: 'クラウド',
    sourceCache: 'ローカルキャッシュ',
    searchPlaceholder: '加速項目を検索',
    selectAll: 'すべて選択',
    clearAll: 'クリア',
    refresh: 'リストを更新',
    checkedSummary: '{checked} / {total} 件を選択中',
    noMatch: '一致する加速項目がありません',
    loadFailed: '加速項目の読み込みに失敗しました：{error}',
    connectivityTest: '接続テスト',
    testEmpty: 'テスト可能な項目がありません：先にこのグループ内の加速項目にチェックを入れてください',
    testAllFailed:
      'テスト項目がすべて失敗しました。ネットワーク接続と、プロキシ設定の内容を確認してください。',
    serverSide: 'サーバー側加速',
    hintTitle: '説明',
    hint:
      'System / PAC / ProxyOnly モードはローカルのフォワードプロキシポート {port} で待ち受け、' +
      'PAC スクリプトのアドレスは http://127.0.0.1:{port}/pac です。Hosts モードは加速ドメインを ' +
      'hosts に書き込み、ローカル 443 で TLS リバースプロキシを行います（停止時に自動復元）。' +
      'プロキシポートは「設定 → プロキシ設定」で変更できます。',
    modes: {
      hosts: {
        label: 'Hosts モード',
        desc:
          'hosts をローカル 443 のリバースプロキシに向ける（443 ポートが空いている必要あり。' +
          'hosts への書き込みには管理者権限が必要な場合があります）',
      },
      system: {
        label: 'システムプロキシ',
        desc: 'システムプロキシをローカルポート {port} に設定。全体に有効で 443 を占有しません',
      },
      pac: {
        label: 'PAC モード',
        desc:
          '自動設定スクリプトでドメイン別に振り分け、加速ドメインのみプロキシ経由（ポート {port}）',
      },
      proxyOnly: {
        label: 'ポートのみ',
        desc:
          'システム設定を変更せず、ブラウザ/クライアントのプロキシを手動で 127.0.0.1:{port} に向ける',
      },
    },
  },
  settings: {
    generalTitle: '全般',
    appearance: 'テーマ',
    themeLight: 'ライト',
    themeDark: 'ダーク',
    themeAuto: 'システムに従う',
    themeHint: '切り替えは即時反映。「システムに従う」は OS のダークモードに連動します',
    language: '言語',
    languageHint: '切り替えは即時反映',
    proxyTitle: 'プロキシ設定',
    proxyMode: 'プロキシモード',
    proxyModePlaceholder: '加速モードを選択',
    forwardPort: 'フォワードプロキシポート',
    httpRedirect: 'HTTP→HTTPS リダイレクト (80)',
    socks5Enable: 'SOCKS5 を有効化',
    socks5Port: 'SOCKS5 ポート',
    twoLevelTitle: '上位プロキシ（二次プロキシ）',
    twoLevelEnable: '二次プロキシを有効化',
    protocol: 'プロトコル種別',
    protocolPlaceholder: 'デフォルト SOCKS5',
    serverAddr: 'サーバーアドレス',
    port: 'ポート',
    username: 'ユーザー名',
    password: 'パスワード',
    optional: '任意',
    dnsTitle: 'DNS 設定',
    masterDns: 'カスタム メイン DNS',
    useDoh: 'DoH を使用',
    dohAddr: 'カスタム DoH アドレス',
    certTitle: 'CA 証明書',
    trustStatus: '信頼状態',
    trusted: 'インストール済み（信頼済み）',
    untrusted: '未インストール',
    daysRemaining: '残り有効期間',
    valid: '有効',
    expired: '期限切れ',
    subject: 'サブジェクト',
    serial: 'シリアル番号',
    notBefore: '発行日時',
    notAfter: '有効期限',
    install: 'システムの信頼ストアにインストール',
    uninstall: '信頼を解除',
    exportCert: '証明書をエクスポート (PEM)',
    regenerate: '再生成',
    uninstallConfirm: 'Watt Toolkit のルート証明書をシステムの信頼ストアから削除しますか？',
    regenerateConfirm:
      'CA 証明書を再生成すると発行済みの全証明書が無効になります。続行しますか？',
    okRemove: '削除',
    okRegenerate: '再生成',
    cancel: 'キャンセル',
    certHint:
      'システムの信頼ストアへのインストールは HTTPS 加速（MITM）の前提です。Windows では ' +
      'インストール時に UAC 昇格の確認が表示されます。PEM をエクスポートして' +
      '「信頼されたルート証明機関」に手動でインポートすることもできます。',
  },
  about: {
    iconAlt: 'Watt Toolkit アイコン',
    desc:
      'Steam などのゲームプラットフォーム向けのクロスプラットフォームデスクトップアプリ。' +
      'ネットワーク加速やスクリプト拡張などのツールボックスを提供します。',
    platform: 'プラットフォーム',
    dataDir: 'データディレクトリ',
    license: '本プロジェクトは GPL-3.0 ライセンスでオープンソースとして公開されています。',
    sourceLabel: '元プロジェクト：',
  },
};

export default ja;

import type { Schema } from './zh-Hans';

const fr: Schema = {
  nav: {
    home: 'Accueil',
    accelerator: 'Accélération réseau',
    settings: 'Paramètres',
    about: 'À propos',
  },
  state: {
    stopped: 'Arrêté',
    starting: 'Démarrage…',
    running: 'Accélération en cours',
    stopping: 'Arrêt en cours…',
    error: 'Erreur',
  },
  common: {
    save: 'Enregistrer',
    saved: 'Paramètres enregistrés',
    saveFailed: "Échec de l'enregistrement, consultez les journaux",
    up: 'Montant',
    down: 'Descendant',
    daysUnit: 'jours',
  },
  home: {
    runningHint: 'Le trafic transite par le proxy local',
    idleHint: 'Sélectionnez des projets dans « Accélération réseau » et lancez en un clic',
    certTitle: 'État du certificat',
    appTitle: 'Infos de l’app',
    subject: 'Sujet',
    serial: 'Numéro de série',
    daysRemaining: 'Validité restante',
    valid: 'Valide',
    expired: 'Expiré',
    version: 'Version',
    platform: 'Plateforme',
    dataDir: 'Répertoire de données',
  },
  accel: {
    modeTitle: "Mode d'accélération",
    runningSwitchHint:
      "L'accélération est en cours — arrêtez-la avant de changer de mode",
    start: 'Accélérer en un clic',
    stop: "Arrêter l'accélération",
    projectsTitle: "Projets d'accélération",
    sourceCloud: 'Cloud',
    sourceCache: 'Cache local',
    searchPlaceholder: 'Rechercher des projets',
    selectAll: 'Tout sélectionner',
    clearAll: 'Vider',
    refresh: 'Actualiser la liste',
    checkedSummary: '{checked} / {total} sélectionnés',
    noMatch: 'Aucun projet correspondant',
    loadFailed: "Échec du chargement des projets : {error}",
    connectivityTest: 'Test de connectivité',
    testEmpty: "Rien à tester : cochez d'abord des projets de ce groupe",
    testAllFailed:
      'Tous les tests ont échoué. Vérifiez votre connexion réseau et les réglages du proxy.',
    serverSide: 'Accélération côté serveur',
    hintTitle: 'Notes',
    hint:
      "Les modes System / PAC / ProxyOnly écoutent sur le port local {port} ; le script PAC " +
      "est servi à l'adresse http://127.0.0.1:{port}/pac. Le mode Hosts écrit les domaines " +
      'accélérés dans le fichier hosts et sert un proxy inverse TLS sur le port 443 local ' +
      "(restauré automatiquement à l'arrêt). Le port se modifie dans « Paramètres → Proxy ».",
    modes: {
      hosts: {
        label: 'Mode Hosts',
        desc:
          'Pointe hosts vers le proxy inverse local 443 (le port 443 doit être libre ; ' +
          'écrire hosts peut nécessiter les droits administrateur)',
      },
      system: {
        label: 'Proxy système',
        desc:
          'Définit le proxy système sur le port local {port} ; global, sans occuper le 443',
      },
      pac: {
        label: 'Mode PAC',
        desc:
          'Script de configuration automatique : seuls les domaines accélérés passent par le ' +
          'proxy (port {port})',
      },
      proxyOnly: {
        label: 'Port proxy seul',
        desc:
          'Aucune modification système ; pointez manuellement le navigateur/client vers ' +
          '127.0.0.1:{port}',
      },
    },
  },
  settings: {
    generalTitle: 'Général',
    appearance: 'Thème',
    themeLight: 'Clair',
    themeDark: 'Sombre',
    themeAuto: 'Suivre le système',
    themeHint:
      'Effet immédiat ; « Suivre le système » suit le mode sombre du système',
    language: 'Langue',
    languageHint: 'Effet immédiat',
    proxyTitle: 'Paramètres du proxy',
    proxyMode: 'Mode de proxy',
    proxyModePlaceholder: "Choisir un mode d'accélération",
    forwardPort: 'Port du proxy local',
    httpRedirect: 'Redirection HTTP→HTTPS (80)',
    socks5Enable: 'Activer SOCKS5',
    socks5Port: 'Port SOCKS5',
    twoLevelTitle: 'Proxy amont (secondaire)',
    twoLevelEnable: 'Activer le proxy amont',
    protocol: 'Protocole',
    protocolPlaceholder: 'SOCKS5 par défaut',
    serverAddr: 'Adresse du serveur',
    port: 'Port',
    username: "Nom d'utilisateur",
    password: 'Mot de passe',
    optional: 'Facultatif',
    dnsTitle: 'Paramètres DNS',
    masterDns: 'DNS principal personnalisé',
    useDoh: 'Utiliser DoH',
    dohAddr: 'Adresse DoH personnalisée',
    certTitle: 'Certificat CA',
    trustStatus: 'État de confiance',
    trusted: 'Installé et approuvé',
    untrusted: 'Non installé',
    daysRemaining: 'Validité restante',
    valid: 'Valide',
    expired: 'Expiré',
    subject: 'Sujet',
    serial: 'Numéro de série',
    notBefore: 'Valide depuis',
    notAfter: "Valide jusqu'au",
    install: 'Installer dans le magasin de confiance système',
    uninstall: 'Retirer la confiance',
    exportCert: 'Exporter le certificat (PEM)',
    regenerate: 'Régénérer',
    uninstallConfirm:
      'Retirer le certificat racine Watt Toolkit du magasin de confiance système ?',
    regenerateConfirm:
      "Régénérer l'AC invalidera tous les certificats émis. Continuer ?",
    okRemove: 'Retirer',
    okRegenerate: 'Régénérer',
    cancel: 'Annuler',
    certHint:
      "L'installation dans le magasin de confiance système est requise pour l'accélération " +
      'HTTPS (MITM). Sous Windows, une invite UAC apparaîtra. Vous pouvez aussi exporter le ' +
      'PEM et l’importer manuellement dans « Autorités de certification racines de confiance ».',
  },
  about: {
    iconAlt: 'Icône Watt Toolkit',
    desc:
      'Boîte à outils multiplateforme offrant accélération réseau, extensions de script et ' +
      'plus, pour Steam et autres plateformes de jeu.',
    platform: 'Plateforme',
    dataDir: 'Répertoire de données',
    license: 'Ce projet est open source sous licence GPL-3.0.',
    sourceLabel: 'Projet d’origine :',
  },
};

export default fr;

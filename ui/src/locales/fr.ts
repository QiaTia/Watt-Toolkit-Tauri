import type { Schema } from './zh-Hans';

const fr: Schema = {
  nav: {
    home: 'Accueil',
    accelerator: 'Accélération réseau',
    pool: 'Pools d’IP',
    settings: 'Paramètres',
    about: 'À propos',
    logs: 'Journaux',
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
        descMac:
          'Sur macOS, écrire /etc/hosts nécessite les droits administrateur : une invite de ' +
          'mot de passe au démarrage et à l’arrêt du moteur.',
        descWin:
          'Sur Windows, l’application s’exécute en tant qu’administrateur (une invite UAC au ' +
          'lancement) afin d’écrire et de restaurer le fichier hosts.',
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
    probe: {
      running: 'Détection des nœuds et classement par latence…',
      done: '{ok}/{total} nœuds optimisés, plus rapide {ms}ms',
      failed: 'Détection incomplète ; course dans l’ordre par défaut',
      partial: 'Détection tronquée par le budget ; résultats partiels utilisés',
    },
    noCheckedHint: "Sélectionnez au moins un projet d'accélération avant de démarrer.",
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
    terminalProxy: 'Proxy terminal (CLI)',
    terminalProxyHint:
      'Injecte HTTP(S)_PROXY et les variables de certificat CA pour git / curl / npm / pip '
      + 'afin d’accélérer aussi le trafic du terminal (les terminaux déjà ouverts doivent être '
      + 'redémarrés). Les modes System / PAC / port proxy uniquement pointent vers le proxy '
      + 'local ; le mode Hosts n’injecte que le certificat.',
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
    certHint: 'HTTPS (MITM) : Windows affiche une invite UAC, macOS une confirmation de confiance système (mot de passe de session). Vous pouvez aussi exporter le PEM et l’importer manuellement.',
    elevateMacHint: "Sur macOS, l'installation affiche une confirmation de confiance (mot de passe de session) et s’applique à l’utilisateur courant, sans mot de passe administrateur.",
    elevateCancelled: "Autorisation administrateur annulée. L'opération n'a pas été effectuée.",
    runningLockedHint: "L'accélération est en cours ; le mode proxy et les ports sont verrouillés. Arrêtez l'accélération avant de les modifier.",
    certInstalled: 'Certificat racine installé et approuvé.',
    certInstallVerifyFailed: "La commande d'installation a été exécutée mais la vérification a échoué. Vérifiez les réglages de confiance du système ou exportez le PEM pour l'installer manuellement.",
    certUninstalled: 'Confiance du certificat racine supprimée.',
    certRegenerated: "CA régénérée et ancienne confiance nettoyée. Réinstallez le certificat racine avant d'activer l'accélération HTTPS.",
  },
  pool: {
    summary: '{hosts} domaines, {ips} IP',
    lastRefreshSummary: 'Dernier rafraîchissement : {hosts} domaines, {ok}/{candidates} candidats utilisables',
    hint:
      'Les pools d’IP sont gérés par domaine : l’accélération choisit l’IP la plus rapide du ' +
      'pool (RTT de handshake TLS le plus court). Le bouton « Rafraîchir les pools d’IP » en ' +
      'haut à droite résout les domaines des projets cochés via un DNS sain et les teste ' +
      'localement ; un domaine peut aussi être modifié ou re-résolu individuellement.',
    refreshAll: 'Rafraîchir les pools d’IP',
    refreshDone: 'Rafraîchissement terminé : {hosts} domaines, {ok}/{candidates} candidats utilisables',
    refreshEmpty: 'Rien à rafraîchir : cochez d’abord des projets sur la page d’accélération',
    refreshFailed: 'Échec du rafraîchissement des pools d’IP',
    addDomain: 'Ajouter un domaine',
    clearAll: 'Tout effacer',
    clearConfirm:
      'Effacer tous les pools d’IP ? L’accélération reviendra aux sauvegardes intégrées et au DNS système.',
    colHost: 'Domaine',
    colIps: 'IP',
    colRefreshed: 'Dernier rafraîchissement',
    colActions: 'Actions',
    builtinTitle: 'Pools de secours intégrés',
    builtinSummary: '{groups} groupes / {ips} IP',
    builtinHint:
      'Livrés avec chaque version et en lecture seule : un domaine utilise d’abord son pool ' +
      'dynamique ; si celui-ci n’a aucune correspondance ou si tous les candidats échouent, ces ' +
      'IP servent de secours à la course sortante (les candidats en échec sont ignorés, donc le ' +
      'chemin réussi n’est pas ralenti). Cela ne couvre que les rares services nécessitant un ' +
      'secours manuel (trois groupes GitHub / Google Traduction / trois groupes Figma) — ce n’est ' +
      'pas la liste des domaines, voir « Aperçu IP des domaines accélérés » ci-dessus.',
    overviewTitle: 'Aperçu IP des domaines accélérés',
    overviewSummary:
      '{hosts} domaines : {withIp} avec IP statiques/pool, {dnsOnly} via DNS seulement',
    overviewHint:
      'Tous les domaines des projets d’accélération cochés (groupes intégrés compris) et l’origine ' +
      'de leurs IP. « IP imposée » est l’IP prioritaire fixée par le service intégré ; « Pool ' +
      'dynamique » provient du rafraîchissement ; « Pool de secours intégré » est la liste livrée ' +
      'avec la version. Les domaines sans aucune de ces sources passent par le DNS anti-empoisonnement ' +
      'et la course de candidats.',
    searchPlaceholder: 'Rechercher un domaine',
    colSource: 'Sources',
    srcAll: 'Tout',
    srcOverride: 'IP imposée',
    srcDynamic: 'Pool dynamique',
    srcBuiltin: 'Secours intégré',
    srcDns: 'DNS',
    srcDnsOnly: 'DNS seul',
    dnsAlwaysHint:
      'La résolution DNS reste toujours candidate (DNS anti-empoisonnement + course de candidats)',
    ipCountDns: 'DNS seul',
    readonly: 'Lecture seule',
    colPattern: 'Motif',
    colNote: 'Notes',
    edit: 'Modifier',
    probe: 'Tester',
    refreshHost: 'Re-résoudre',
    remove: 'Supprimer',
    removeConfirm:
      'Supprimer le pool d’IP de {host} ? Il reviendra aux sauvegardes intégrées et au DNS système.',
    removeIp: 'Retirer',
    removeIpConfirm: 'Supprimer {ip} ?',
    unreachable: 'Injoignable',
    notProbed: 'Non testé',
    rtt: '{ms} ms',
    prune: 'Retirer {n} IP injoignables',
    pruneDone: '{n} IP injoignables retirées',
    probeOk: '{ok}/{total} IP utilisables',
    probeAllFailed: 'Les {total} IP sont injoignables — relancez une résolution DNS',
    refreshHostEmpty: 'Aucune IP utilisable pour {host} ; son entrée de pool a été supprimée',
    refreshedHost: '{host} mis à jour : {ok}/{total} candidats utilisables',
    removed: 'Supprimé',
    saved: 'Enregistré',
    cleared: 'Pools d’IP effacés',
    empty:
      'Aucun pool de domaine — ajoutez un domaine ou utilisez « Rafraîchir les pools d’IP » en haut à droite',
    editTitleNew: 'Ajouter un pool d’IP de domaine',
    editTitleEdit: 'Modifier le pool d’IP de {host}',
    hostLabel: 'Domaine',
    hostPlaceholder: 'example.com (sans schéma ni chemin)',
    ipsLabel: 'Liste d’IP',
    ipsPlaceholder: 'Une IP par ligne, par ex.\n18.65.14.118\n13.35.190.56',
    ipsHint:
      'IPv4 / IPv6, une par ligne (virgules ou espaces acceptés) ; les doublons sont supprimés à l’enregistrement.',
    hostRequired: 'Veuillez saisir un domaine',
    save: 'Enregistrer',
    cancel: 'Annuler',
  },
  logs: {
    accessTab: 'Journal des accès',
    runtimeTab: 'Journal des exécutions',
    refresh: 'Actualiser',
    clear: 'Vider',
    autoRefresh: 'Actualisation auto',
    keywordPlaceholder: 'Rechercher hôte / chemin',
    runtimeKeywordPlaceholder: 'Rechercher message / cible',
    method: 'Méthode',
    status: 'Statut',
    disposition: 'Traitement',
    level: 'Niveau',
    colTime: 'Heure',
    colMethod: 'Méthode',
    colHost: 'Hôte',
    colPath: 'Chemin',
    colStatus: 'Statut',
    colDown: 'Descendant',
    colLatency: 'Latence',
    colDisposition: 'Traitement',
    colLevel: 'Niveau',
    colTarget: 'Cible',
    colMessage: 'Message',
    dispMatched: 'Règle correspondante',
    dispDefault: 'Par défaut',
    dispUnmatched: 'Non correspondant',
    dispLocal: 'Local',
    empty: 'Aucun journal',
    total: '{total} entrées',
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

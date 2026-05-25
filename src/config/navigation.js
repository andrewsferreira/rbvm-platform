// =============================================================================
// RBVM Platform — Navigation Configuration
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// Navegação por domínio de produto — sem labels de sprint.
// =============================================================================

export const NAVIGATION = [
  {
    section: 'executive',
    labelKey: 'nav.executive',
    items: [
      { id: 'dashboard',  labelKey: 'nav.dashboard',        icon: 'ti-layout-dashboard', badgeId: null },
      { id: 'execintel',  labelKey: 'nav.execIntelligence',  icon: 'ti-brain',            badgeId: null },
      { id: 'rptexport',  labelKey: 'nav.reportsEvidence',   icon: 'ti-file-analytics',   badgeId: 'sb-rpt', badgeCls: 'ni' },
    ],
  },
  {
    section: 'exposure',
    labelKey: 'nav.exposureManagement',
    items: [
      { id: 'threatintel', labelKey: 'nav.threatIntelligence', icon: 'ti-radar-2',           badgeId: 'sb-kev', badgeCls: 'nc' },
      { id: 'asm',         labelKey: 'nav.attackSurface',       icon: 'ti-radar',             badgeId: 'sb-asm', badgeCls: 'nc' },
      { id: 'crownj',      labelKey: 'nav.crownJewels',         icon: 'ti-crown',             badgeId: null },
      { id: 'warroom',     labelKey: 'nav.warRoom',             icon: 'ti-alert-hexagon',     badgeId: 'sb-wr',  badgeCls: 'nc' },
    ],
  },
  {
    section: 'vulnops',
    labelKey: 'nav.vulnerabilityOps',
    items: [
      { id: 'vulns',      labelKey: 'nav.vulnerabilities',      icon: 'ti-bug',                       badgeId: 'sb-tot', badgeCls: 'nc' },
      { id: 'lifecycle',  labelKey: 'nav.remediationLifecycle', icon: 'ti-route',                     badgeId: null },
      { id: 'sla',        labelKey: 'nav.slaManagement',        icon: 'ti-clock',                     badgeId: 'sb-sla', badgeCls: 'nc' },
      { id: 'smartgroup', labelKey: 'nav.smartGrouping',        icon: 'ti-stack-2',                   badgeId: null },
      { id: 'patch',      labelKey: 'nav.patchManagement',      icon: 'ti-package',                   badgeId: 'sb-patch', badgeCls: 'nh' },
      { id: 'metrics',    labelKey: 'nav.metrics',              icon: 'ti-chart-line',                badgeId: null },
      { id: 'reclassify', labelKey: 'nav.reclassification',     icon: 'ti-adjustments-horizontal',   badgeId: null },
    ],
  },
  {
    section: 'appsec',
    labelKey: 'nav.applicationSecurity',
    items: [
      { id: 'cicd',     labelKey: 'nav.cicdSecurity',  icon: 'ti-git-branch',   badgeId: 'sb-cicd', badgeCls: 'nc' },
      { id: 'sbom',     labelKey: 'nav.sbom',           icon: 'ti-box-multiple', badgeId: 'sb-sbom', badgeCls: 'nh' },
      { id: 'bugbounty',labelKey: 'nav.bugBounty',      icon: 'ti-bug-off',      badgeId: 'sb-bb',   badgeCls: 'nh',
        alias: { view: 'offensive', tab: 'bugbounty', tabState: 'OFT_TAB' } },
      { id: 'fpw',      labelKey: 'nav.falsePositives', icon: 'ti-shield-question', badgeId: 'sb-fp', badgeCls: 'nh' },
    ],
  },
  {
    section: 'offensive',
    labelKey: 'nav.offensiveRisk',
    items: [
      { id: 'offensive',   labelKey: 'nav.offensiveFindings',    icon: 'ti-shield-exclamation', badgeId: 'sb-off', badgeCls: 'nc' },
      { id: 'redteam',     labelKey: 'nav.redTeamFindings',      icon: 'ti-sword',              badgeId: null,
        alias: { view: 'offensive', tab: 'redteam', tabState: 'OFT_TAB' } },
      { id: 'gaps',        labelKey: 'nav.controlDetectionGaps', icon: 'ti-eye-off',            badgeId: null,
        alias: { view: 'offensive', tab: 'gaps', tabState: 'OFT_TAB' } },
      { id: 'retestqueue', labelKey: 'nav.retestQueue',          icon: 'ti-refresh',            badgeId: null,
        alias: { view: 'offensive', tab: 'retest', tabState: 'OFT_TAB' } },
    ],
  },
  {
    section: 'governance',
    labelKey: 'nav.governance',
    items: [
      { id: 'assets',     labelKey: 'nav.assets',       icon: 'ti-server',                 badgeId: null },
      { id: 'suppliers',  labelKey: 'nav.suppliers',    icon: 'ti-building-factory-2',      badgeId: 'sb-sup', badgeCls: 'nh' },
      { id: 'compliance', labelKey: 'nav.complianceGrc',icon: 'ti-certificate',             badgeId: null },
      { id: 'exceptions', labelKey: 'nav.exceptions',   icon: 'ti-shield-x',               badgeId: 'sb-exc', badgeCls: 'nh' },
      { id: 'dataquality',labelKey: 'nav.dataQuality',  icon: 'ti-shield-half',            badgeId: null },
      { id: 'playbooks',  labelKey: 'nav.playbooks',    icon: 'ti-player-play',             badgeId: 'sb-pb',  badgeCls: 'ni' },
      { id: 'risk',       labelKey: 'nav.riskAnalysis', icon: 'ti-chart-area',             badgeId: null },
    ],
  },
  {
    section: 'platform',
    labelKey: 'nav.platform',
    items: [
      { id: 'integrations', labelKey: 'nav.integrations',   icon: 'ti-plug',     badgeId: null },
      { id: 'agent',        labelKey: 'nav.aiAgent',        icon: 'ti-robot',    badgeId: null },
      { id: 'comms',        labelKey: 'nav.communications', icon: 'ti-send',     badgeId: null },
      { id: 'settings',     labelKey: 'nav.settings',       icon: 'ti-settings', badgeId: null },
    ],
  },
];

// Route aliases: nav ID → { view, OFT_TAB value }
export const ROUTE_ALIASES = {
  bugbounty:   { view: 'offensive', tabKey: 'OFT_TAB', tabVal: 'bugbounty' },
  redteam:     { view: 'offensive', tabKey: 'OFT_TAB', tabVal: 'redteam'   },
  gaps:        { view: 'offensive', tabKey: 'OFT_TAB', tabVal: 'gaps'      },
  retestqueue: { view: 'offensive', tabKey: 'OFT_TAB', tabVal: 'retest'    },
};

// Hash-friendly route IDs (nav-id → hash segment)
export const HASH_ROUTES = {
  dashboard:    'dashboard',
  execintel:    'exec-intelligence',
  rptexport:    'reports-evidence',
  threatintel:  'threat-intelligence',
  asm:          'attack-surface',
  crownj:       'crown-jewels',
  warroom:      'zero-day-war-room',
  vulns:        'vulnerabilities',
  lifecycle:    'remediation-lifecycle',
  sla:          'sla-management',
  smartgroup:   'smart-grouping',
  patch:        'patch-management',
  metrics:      'metrics',
  reclassify:   'reclassification',
  cicd:         'cicd-security',
  sbom:         'sbom',
  bugbounty:    'bug-bounty',
  fpw:          'false-positives',
  offensive:    'offensive-findings',
  redteam:      'red-team',
  gaps:         'control-detection-gaps',
  retestqueue:  'retest-queue',
  assets:       'assets',
  suppliers:    'suppliers',
  compliance:   'compliance-grc',
  exceptions:   'exceptions',
  dataquality:  'data-quality',
  playbooks:    'playbooks',
  risk:         'risk-analysis',
  integrations: 'integrations',
  agent:        'ai-agent',
  comms:        'communications',
  settings:     'settings',
};

// Reverse map: hash segment → nav ID
export const HASH_TO_VIEW = Object.fromEntries(
  Object.entries(HASH_ROUTES).map(([k, v]) => [v, k])
);

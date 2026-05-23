// =============================================================================
// RBVM Platform — Historical Trends (6 months)
// =============================================================================

export const MONTHLY_TRENDS = [
  { month:'Dez/23', label:'Dez', opened:45, closed:38, kev:3, critical:8,  high:15, med:16, low:6,  mttr_crit:14.2, mttr_high:28.5, sla_compliance:0.72, new_exploits:5 },
  { month:'Jan/24', label:'Jan', opened:52, closed:44, kev:5, critical:11, high:18, med:17, low:6,  mttr_crit:12.1, mttr_high:26.1, sla_compliance:0.74, new_exploits:7 },
  { month:'Fev/24', label:'Fev', opened:38, closed:47, kev:2, critical:7,  high:14, med:13, low:4,  mttr_crit:10.8, mttr_high:23.4, sla_compliance:0.78, new_exploits:4 },
  { month:'Mar/24', label:'Mar', opened:61, closed:42, kev:8, critical:14, high:21, med:20, low:6,  mttr_crit:13.5, mttr_high:30.2, sla_compliance:0.69, new_exploits:9 },
  { month:'Abr/24', label:'Abr', opened:44, closed:51, kev:4, critical:9,  high:16, med:14, low:5,  mttr_crit:9.7,  mttr_high:22.8, sla_compliance:0.82, new_exploits:6 },
  { month:'Mai/24', label:'Mai', opened:35, closed:48, kev:3, critical:7,  high:13, med:11, low:4,  mttr_crit:7.4,  mttr_high:20.1, sla_compliance:0.85, new_exploits:4 },
];

export const MTTR_BY_TEAM = [
  { team:'AppSec',         mttr_crit:6.2,  mttr_high:18.5, mttr_med:52.1, sla_rate:0.88, vulns:8 },
  { team:'CloudOps',       mttr_crit:9.1,  mttr_high:22.3, mttr_med:61.4, sla_rate:0.79, vulns:7 },
  { team:'Infrastructure', mttr_crit:11.4, mttr_high:28.7, mttr_med:74.2, sla_rate:0.71, vulns:5 },
  { team:'Network',        mttr_crit:4.8,  mttr_high:15.2, mttr_med:48.6, sla_rate:0.92, vulns:2 },
  { team:'DevOps',         mttr_crit:13.2, mttr_high:31.4, mttr_med:82.3, sla_rate:0.68, vulns:3 },
];

export const COVERAGE_METRICS = {
  assets_total:     { value: 210, label: 'Ativos cadastrados' },
  assets_scanned:   { value: 187, label: 'Com scan recente (<30d)', pct: 89 },
  assets_no_owner:  { value: 14,  label: 'Sem owner definido', critical: true },
  assets_eol:       { value: 8,   label: 'EOL/EOS em produção', critical: true },
  apps_covered:     { value: 42,  label: 'Aplicações cobertas', pct: 91 },
  pipelines_gated:  { value: 28,  label: 'Pipelines com security gate', pct: 74 },
  cloud_accounts:   { value: 6,   label: 'Cloud accounts monitoradas', pct: 100 },
  repos_scanned:    { value: 89,  label: 'Repositórios com SAST/SCA', pct: 81 },
};

export const KRI_ALERTS = [
  { id:'KRI-001', label:'Críticos vencidos',           value:3,  threshold:0,  status:'breach', unit:'vulns' },
  { id:'KRI-002', label:'KEVs em produção',            value:5,  threshold:0,  status:'breach', unit:'vulns' },
  { id:'KRI-003', label:'Ativos críticos sem scan',    value:4,  threshold:2,  status:'breach', unit:'ativos' },
  { id:'KRI-004', label:'Aplicações sem owner',        value:7,  threshold:5,  status:'warn',   unit:'apps' },
  { id:'KRI-005', label:'Sistemas EOL expostos',       value:3,  threshold:0,  status:'breach', unit:'sistemas' },
  { id:'KRI-006', label:'Pipelines sem security gate', value:10, threshold:5,  status:'warn',   unit:'pipelines' },
  { id:'KRI-007', label:'Exceções com risco crítico',  value:2,  threshold:0,  status:'breach', unit:'exceções' },
  { id:'KRI-008', label:'Secrets expostos ativos',     value:1,  threshold:0,  status:'breach', unit:'secrets' },
];

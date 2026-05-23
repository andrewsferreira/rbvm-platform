// =============================================================================
// RBVM Platform — Audit Trail Data
// Eventos pré-populados para as vulnerabilidades principais do demo
// =============================================================================

export const AUDIT_BASE = {
  'CVE-2024-23897': [
    { ts:'2024-05-16 08:42', actor:'system', name:'Tenable VM',          icon:'ti-radar',          action:'Finding ingerido',                    before:null,           after:'New',            detail:'Plugin 85555 · CRITICAL · jenkins-prod-01 · agentless',              src:'Tenable' },
    { ts:'2024-05-16 08:43', actor:'system', name:'RBVM Normalizer',     icon:'ti-transform',      action:'Normalizado e deduplicado',            before:null,           after:'New',            detail:'CVE-2024-23897 · Hash único · Sem duplicata encontrada',              src:'Internal' },
    { ts:'2024-05-16 08:44', actor:'system', name:'Enrichment Engine',   icon:'ti-database',       action:'Enriquecido com Threat Intelligence',  before:null,           after:null,             detail:'CISA KEV=true · EPSS=97% · exploit=true · MITRE T1190 (Initial Access)', src:'CISA/FIRST' },
    { ts:'2024-05-16 08:44', actor:'system', name:'Risk Scoring Engine', icon:'ti-chart-bar',      action:'Risk Score calculado: 97',             before:null,           after:null,             detail:'KEV(+15) RCE(+5) EPSS(+10) Internet(+10) LGPD(+3) DataSensitive(+3)', src:'Internal' },
    { ts:'2024-05-16 08:45', actor:'system', name:'CMDB Integration',    icon:'ti-server',         action:'Owner e squad identificados via CMDB', before:null,           after:null,             detail:'Owner: carlos.silva@corp.example · Squad: Platform Engineering · BU: Technology', src:'CMDB' },
    { ts:'2024-05-16 08:46', actor:'system', name:'Jira Integration',    icon:'ti-ticket',         action:'Ticket criado: SEC-1001',              before:'New',          after:'Ticket Created', detail:'Prioridade: P1 · Due: 2024-05-23 · SLA: 7 dias · Tipo: Security Finding', src:'Jira' },
    { ts:'2024-05-16 08:46', actor:'system', name:'SLA Engine',          icon:'ti-clock',          action:'SLA iniciado: 7 dias corridos',        before:null,           after:null,             detail:'Due: 2024-05-23 · Política: Crítico Internet-Facing', src:'Internal' },
    { ts:'2024-05-16 09:00', actor:'system', name:'Notification Engine', icon:'ti-send',           action:'Alerta enviado — 7 dias para vencer',  before:null,           after:null,             detail:'Slack #sec-critical + carlos.silva@corp.example · Teams #plataforma', src:'Slack/Teams' },
    { ts:'2024-05-22 06:00', actor:'system', name:'Escalation Engine',   icon:'ti-arrow-up',       action:'SLA vencendo em 1 dia — escalonamento preventivo', before:null, after:null,           detail:'CISO + GRC + Gerente de Technology notificados via PagerDuty', src:'PagerDuty' },
  ],
  'CVE-2024-21762': [
    { ts:'2024-05-19 06:12', actor:'system', name:'Tenable VM',          icon:'ti-radar',          action:'Finding ingerido',                    before:null,           after:'New',            detail:'Plugin 192777 · FortiOS SSL-VPN · CRITICAL · fw-perimeter-01',        src:'Tenable' },
    { ts:'2024-05-19 06:13', actor:'system', name:'Enrichment Engine',   icon:'ti-database',       action:'Enriquecido — CISA KEV emergencial',  before:null,           after:null,             detail:'KEV=true · EPSS=95% · RCE=true · internet-facing · PCI scope', src:'CISA' },
    { ts:'2024-05-19 06:14', actor:'system', name:'Risk Scoring Engine', icon:'ti-chart-bar',      action:'Risk Score calculado: 98',            before:null,           after:null,             detail:'CRÍTICO EMERGENCIAL · Score máximo quase atingido', src:'Internal' },
    { ts:'2024-05-19 06:15', actor:'system', name:'Jira Integration',    icon:'ti-ticket',         action:'Ticket emergencial criado: SEC-1002', before:'New',          after:'Ticket Created', detail:'P0 · Due: 2024-05-22 · SLA: 3 dias (KEV+internet+PCI)', src:'Jira' },
    { ts:'2024-05-19 06:15', actor:'system', name:'Notification Engine', icon:'ti-send',           action:'Alerta P0 enviado — ação imediata',   before:null,           after:null,             detail:'PagerDuty wake-up + CISO + SOC + ana.oliveira@corp.example', src:'PagerDuty' },
    { ts:'2024-05-22 03:00', actor:'system', name:'SLA Engine',          icon:'ti-clock-x',        action:'SLA VENCIDO — escalonamento máximo',  before:'In Progress',  after:'In Progress',    detail:'Diretoria + Comitê de Risco notificados. Decisão formal solicitada.', src:'Internal' },
  ],
  'SCA-2024-LOG4J': [
    { ts:'2024-04-07 10:15', actor:'system', name:'Snyk',                icon:'ti-code',           action:'Finding ingerido — SCA scan',          before:null,          after:'New',            detail:'Log4j 1.x EOL · CVE múltiplas · app-legacy-payments · dependência direta', src:'Snyk' },
    { ts:'2024-04-07 10:16', actor:'system', name:'Enrichment Engine',   icon:'ti-database',       action:'Enriquecido — componente EOL',         before:null,           after:null,             detail:'PCI scope=true · LGPD scope=true · exploit=true · patch=unavailable (EOL)', src:'CISA/NVD' },
    { ts:'2024-04-07 10:17', actor:'system', name:'Jira Integration',    icon:'ti-ticket',         action:'Ticket criado: SEC-1007',              before:'New',          after:'Ticket Created', detail:'P1 · Due: 2024-05-07 · SLA: 30 dias (Alto PCI)', src:'Jira' },
    { ts:'2024-04-08 09:00', actor:'user',   name:'fernanda.rocha',      icon:'ti-user',           action:'Exceção de risco solicitada',          before:'In Progress',  after:'In Progress',    detail:'Justificativa: migração planejada Q3/2024. Controles: WAF + Network isolation', src:'User' },
    { ts:'2024-04-08 14:30', actor:'user',   name:'ciso@corp.example',   icon:'ti-user-check',     action:'Exceção EXC-001 aprovada',             before:null,           after:null,             detail:'Aprovada com validade até 2024-07-08. Revalidação obrigatória.', src:'Governance' },
    { ts:'2024-05-07 00:01', actor:'system', name:'SLA Engine',          icon:'ti-clock-x',        action:'SLA VENCIDO — 30 dias esgotados',      before:'In Progress',  after:'In Progress',    detail:'Exceção ativa mas SLA base venceu. Risco remanescente registrado.', src:'Internal' },
    { ts:'2024-05-07 08:00', actor:'system', name:'Escalation Engine',   icon:'ti-arrow-up',       action:'SLA vencido há 15 dias — reescalonado',before:null,           after:null,             detail:'GRC + Auditoria notificados. Evidência do SLA vencido registrada.', src:'Internal' },
  ],
  'CICD-2024-001': [
    { ts:'2024-05-22 07:34', actor:'system', name:'GitHub Secret Scanning',icon:'ti-brand-github',  action:'Secret exposto detectado — PR #842',  before:null,           after:'New',            detail:'AWS_ACCESS_KEY_ID válida detectada · branch feature/auth-refactor', src:'GitHub GHAS' },
    { ts:'2024-05-22 07:34', actor:'system', name:'RBVM CI/CD Gate',     icon:'ti-git-branch',     action:'Pipeline BLOQUEADO — merge impedido',  before:null,           after:'New',            detail:'corp/backend-api bloqueado · nenhum merge permitido até resolução', src:'GitHub Actions' },
    { ts:'2024-05-22 07:35', actor:'system', name:'Notification Engine', icon:'ti-send',           action:'Alerta CRÍTICO enviado — secret exposto',before:null,          after:null,             detail:'PagerDuty P0 + gabriel.ferreira@corp.example + DevSecOps squad + CISO', src:'PagerDuty' },
    { ts:'2024-05-22 07:35', actor:'system', name:'Jira Integration',    icon:'ti-ticket',         action:'Incidente SEC-1010 criado automaticamente',before:'New',        after:'Ticket Created', detail:'Tipo: Security Incident · P0 · SLA: 1 dia · Ação: revogar chave imediatamente', src:'Jira' },
  ],
  'AD-2024-001': [
    { ts:'2024-05-20 14:22', actor:'system', name:'BloodHound',          icon:'ti-users-group',    action:'Attack path detectado via análise de AD',before:null,          after:'New',            detail:'Domain Users → Domain Admins via Kerberoasting · 3 passos · T1558.003', src:'BloodHound' },
    { ts:'2024-05-20 14:23', actor:'system', name:'RBVM Enrichment',     icon:'ti-database',       action:'Enriquecido — caminho de ataque crítico', before:null,         after:null,             detail:'MITRE T1558.003 · PCI scope · LGPD scope · Crown jewel: Active Directory', src:'MITRE' },
    { ts:'2024-05-20 14:24', actor:'system', name:'Risk Scoring Engine', icon:'ti-chart-bar',      action:'Risk Score calculado: 86',              before:null,           after:null,             detail:'ALTO — sem exploit público mas caminho confirmado pelo BloodHound', src:'Internal' },
    { ts:'2024-05-20 14:25', actor:'system', name:'Jira Integration',    icon:'ti-ticket',         action:'Ticket criado: SEC-1009',               before:'New',          after:'Ticket Created', detail:'P1 · Due: 2024-06-19 · SLA: 30 dias (Alto Interno)', src:'Jira' },
  ],
};

export function getAuditTrail(vulnId, lsEvents = {}) {
  const base = AUDIT_BASE[vulnId] || [];
  const added = lsEvents[vulnId] || [];
  return [...base, ...added].sort((a, b) => a.ts.localeCompare(b.ts));
}

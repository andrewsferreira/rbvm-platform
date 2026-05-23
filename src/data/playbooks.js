// =============================================================================
// RBVM Platform — Compliance Controls & Playbooks
// =============================================================================

// ── COMPLIANCE CONTROLS ──────────────────────────────────────────────────────
export const COMPLIANCE_CONTROLS = [
  // NIST CSF 2.0
  { fw:'NIST CSF 2.0', control:'GV.RM-03', desc:'Enterprise risk strategy',                 status:'implemented', evidence:'Risk scoring engine + exception workflow',              gap:'' },
  { fw:'NIST CSF 2.0', control:'ID.AM-01', desc:'Inventário de ativos',                     status:'partial',     evidence:'Asset module com 210 ativos',                          gap:'CMDB integration pendente — 14 ativos sem owner' },
  { fw:'NIST CSF 2.0', control:'ID.AM-02', desc:'Inventário de software / dependências',    status:'partial',     evidence:'SCA via Snyk e Dependabot',                            gap:'SBOM formal não gerado para todos os sistemas' },
  { fw:'NIST CSF 2.0', control:'DE.CM-08', desc:'Vulnerability scanning contínuo',           status:'implemented', evidence:'Tenable + Qualys + AWS Inspector + Wiz — diário',      gap:'' },
  { fw:'NIST CSF 2.0', control:'RS.MA-01', desc:'Incident response plan',                   status:'implemented', evidence:'Playbooks automatizados + war room',                   gap:'' },
  { fw:'NIST CSF 2.0', control:'PR.PS-04', desc:'Security controls no desenvolvimento',      status:'partial',     evidence:'28/38 pipelines com security gates (74%)',             gap:'10 pipelines críticos sem gate configurado' },
  // PCI DSS 4.0
  { fw:'PCI DSS 4.0',  control:'6.3.1',   desc:'Security vulnerabilities identified',       status:'implemented', evidence:'Scan semanal em todos os ativos PCI',                  gap:'' },
  { fw:'PCI DSS 4.0',  control:'6.3.3',   desc:'All system components protected from CVEs', status:'partial',     evidence:'SLA de 7 dias para críticas PCI',                      gap:'Log4j EOL em app-legacy-payments — exceção aprovada' },
  { fw:'PCI DSS 4.0',  control:'11.3.1',  desc:'Internal vuln scan quarterly',              status:'implemented', evidence:'Scan quinzenal com Tenable + Qualys',                  gap:'' },
  { fw:'PCI DSS 4.0',  control:'11.3.2',  desc:'External vuln scan quarterly (ASV)',        status:'implemented', evidence:'Tenable ASM + Censys — mensal',                        gap:'' },
  { fw:'PCI DSS 4.0',  control:'11.4.4',  desc:'Pentest annually',                          status:'implemented', evidence:'Pentest externo anual — último: Mar/2024',             gap:'' },
  { fw:'PCI DSS 4.0',  control:'12.3.4',  desc:'Hardware and software technologies reviewed', status:'partial',   evidence:'EOL/EOS tracking no módulo de ativos',                 gap:'3 sistemas EOL em produção PCI' },
  // ISO 27001:2022
  { fw:'ISO 27001:2022',control:'A.8.8',  desc:'Management of technical vulnerabilities',   status:'implemented', evidence:'RBVM Platform — ciclo completo de gestão',             gap:'' },
  { fw:'ISO 27001:2022',control:'A.8.9',  desc:'Configuration management',                  status:'partial',     evidence:'Checkov + tfsec em IaC',                               gap:'CIS Benchmarks não totalmente implementados' },
  { fw:'ISO 27001:2022',control:'A.8.32', desc:'Change management',                          status:'partial',     evidence:'Integração com Jira para change requests',            gap:'Integração com ServiceNow pendente' },
  { fw:'ISO 27001:2022',control:'A.5.30', desc:'ICT continuity planning',                    status:'implemented', evidence:'Plano de resposta a zero-day documentado',            gap:'' },
  // LGPD
  { fw:'LGPD',          control:'Art.46', desc:'Medidas de segurança técnicas e administrativas', status:'partial',evidence:'Controles técnicos parcialmente implementados',      gap:'DPIA não realizado para todos os sistemas com dados pessoais' },
  { fw:'LGPD',          control:'Art.48', desc:'Comunicação de incidentes',                  status:'implemented', evidence:'Processo de notificação ao encarregado em 72h',       gap:'' },
  { fw:'LGPD',          control:'Art.50', desc:'Boas práticas — programa de governança',     status:'partial',     evidence:'Programa em implementação',                           gap:'Treinamento de todos os times pendente' },
  // CMN 4.893/2021
  { fw:'CMN 4.893/2021',control:'Art.6',  desc:'Gestão de vulnerabilidades',                status:'implemented', evidence:'RBVM Platform — gestão contínua',                     gap:'' },
  { fw:'CMN 4.893/2021',control:'Art.14', desc:'Resposta a incidentes — prazo 72h BACEN',   status:'implemented', evidence:'Playbook de zero-day com SLA de 24h-72h',            gap:'' },
  { fw:'CMN 4.893/2021',control:'Art.16', desc:'Relatórios de risco para diretoria',         status:'partial',     evidence:'Dashboard executivo disponível',                      gap:'Relatório trimestral formal não automatizado' },
];

// ── PLAYBOOKS ─────────────────────────────────────────────────────────────────
export const PLAYBOOKS = [
  {
    id:'PB-001', name:'CVE Crítica com CISA KEV', icon:'ti-alert-octagon', color:'var(--crit)',
    trigger:'KEV = true AND severity = CRITICAL AND status = New AND internet_facing = true',
    sla:'72h', status:'active', triggered:'2024-05-21', vulns:['CVE-2024-6387','CVE-2024-21762'],
    steps:[
      { n:1,  label:'Identificar ativos afetados via CMDB e inventário', auto:true,  done:true  },
      { n:2,  label:'Cruzar com exposição externa (internet-facing)',      auto:true,  done:true  },
      { n:3,  label:'Criar tickets emergenciais (P1 no Jira/ServiceNow)', auto:true,  done:true  },
      { n:4,  label:'Notificar SOC e owners via Slack + Teams',           auto:true,  done:true  },
      { n:5,  label:'Verificar IoCs no SIEM',                             auto:false, done:true  },
      { n:6,  label:'Acionar war room se exploração confirmada',          auto:false, done:false },
      { n:7,  label:'Aplicar mitigação temporária (WAF/network rule)',     auto:false, done:false },
      { n:8,  label:'Aplicar patch e validar por rescan',                 auto:false, done:false },
      { n:9,  label:'Gerar relatório executivo pós-correção',             auto:true,  done:false },
    ]
  },
  {
    id:'PB-002', name:'Dependência Vulnerável em Pipeline', icon:'ti-code', color:'var(--high)',
    trigger:'type = SCA AND exploit = true AND environment in [production, staging]',
    sla:'24h (build bloqueado)', status:'active', triggered:'2024-05-22', vulns:['CICD-SCA-001'],
    steps:[
      { n:1, label:'Detectar via Snyk/Dependabot no pipeline',          auto:true,  done:true  },
      { n:2, label:'Verificar se dependência é direta ou transitiva',   auto:true,  done:true  },
      { n:3, label:'Verificar EPSS e exploit disponível',               auto:true,  done:true  },
      { n:4, label:'Comentar automaticamente no Pull Request',          auto:true,  done:true  },
      { n:5, label:'Bloquear merge se risco crítico',                   auto:true,  done:true  },
      { n:6, label:'Abrir card no backlog do squad',                    auto:true,  done:true  },
      { n:7, label:'Desenvolvedor atualiza dependência',                auto:false, done:false },
      { n:8, label:'Rescan confirma correção — liberar pipeline',       auto:true,  done:false },
    ]
  },
  {
    id:'PB-003', name:'SLA Vencido — Escalonamento', icon:'ti-clock-x', color:'var(--high)',
    trigger:'sla_used >= sla_max AND status != Resolved',
    sla:'Imediato', status:'active', triggered:'2024-05-20', vulns:['AI-2025-001','SCA-2024-LOG4J'],
    steps:[
      { n:1, label:'Confirmar vulnerabilidade ainda ativa',              auto:true,  done:true  },
      { n:2, label:'Calcular dias de atraso e impacto de negócio',       auto:true,  done:true  },
      { n:3, label:'Notificar gestor da área + GRC',                    auto:true,  done:true  },
      { n:4, label:'Escalar para CISO se crítica ou KEV',               auto:true,  done:true  },
      { n:5, label:'Solicitar plano de ação ou aceite formal de risco',  auto:false, done:false },
      { n:6, label:'Registrar no dashboard executivo',                  auto:true,  done:false },
    ]
  },
  {
    id:'PB-004', name:'Zero-Day / Vulnerabilidade Sem Patch', icon:'ti-bomb', color:'var(--crit)',
    trigger:'patch_available = false AND severity = CRITICAL AND internet_facing = true',
    sla:'24h (mitigação)', status:'standby', triggered:null, vulns:[],
    steps:[
      { n:1, label:'Monitorar feeds: CISA, NVD, GreyNoise, Mandiant',  auto:true,  done:false },
      { n:2, label:'Identificar ativos afetados',                       auto:true,  done:false },
      { n:3, label:'Acionar war room e IR team',                        auto:false, done:false },
      { n:4, label:'Isolar ativos críticos se exploração confirmada',   auto:false, done:false },
      { n:5, label:'Implementar virtual patch (WAF/IPS rule)',           auto:false, done:false },
      { n:6, label:'Notificar CISO e diretoria em até 2h',              auto:true,  done:false },
      { n:7, label:'Aplicar patch assim que disponível',                auto:false, done:false },
      { n:8, label:'Rescan e relatório pós-incidente',                  auto:true,  done:false },
    ]
  },
  {
    id:'PB-005', name:'Cloud Misconfiguration Crítica', icon:'ti-cloud-exclamation', color:'var(--high)',
    trigger:'asset_type in [cloud, iac] AND severity = HIGH AND data_sensitive = true',
    sla:'7 dias', status:'active', triggered:'2024-05-18', vulns:['CLOUD-2024-S3'],
    steps:[
      { n:1, label:'Detectar via Wiz/Orca/Checkov',                     auto:true,  done:true  },
      { n:2, label:'Avaliar dados expostos — LGPD/PCI escopo',          auto:true,  done:true  },
      { n:3, label:'Corrigir configuração imediatamente',               auto:false, done:true  },
      { n:4, label:'Rescan confirma correção',                          auto:true,  done:true  },
      { n:5, label:'Verificar se houve acesso indevido (CloudTrail)',   auto:false, done:false },
      { n:6, label:'Notificar DPO se dados pessoais expostos (LGPD)',   auto:false, done:false },
    ]
  },
];

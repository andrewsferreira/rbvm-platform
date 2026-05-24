// =============================================================================
// RBVM Platform — Patch Management
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const PATCH_CAMPAIGNS = [
  {
    id:'PC-001', name:'Operação regreSSHion — Emergency OpenSSH',
    type:'emergency', priority:'P0',
    trigger:'CVE-2024-6387 · CISA KEV · RCE sem autenticação',
    lead:'marcos.costa@corp.example', squad:'Linux SRE',
    vuln_ids:['CVE-2024-6387'], asset_count:8, patched:3, validated:1,
    status:'in_progress', created:'2024-05-21', due:'2024-05-22',
    window_id:'MW-001',
    steps:[
      {n:1,label:'Identificar todos os ativos afetados via Qualys',done:true,auto:true},
      {n:2,label:'Preparar pacote openssh-server 9.8p1',done:true,auto:false},
      {n:3,label:'Aplicar workaround LoginGraceTime 0 em todos',done:true,auto:false},
      {n:4,label:'Patch em 6 ativos internos (non-internet-facing)',done:true,auto:false},
      {n:5,label:'Patch em ssh-bastion-01 (internet-facing)',done:false,auto:false},
      {n:6,label:'Patch em jenkins-prod-01 (internet-facing)',done:false,auto:false},
      {n:7,label:'Rescan Qualys confirma patch aplicado',done:false,auto:true},
      {n:8,label:'Fechar CVE-2024-6387 com evidência de rescan',done:false,auto:true},
    ],
    rollback:'apt-get install openssh-server=1:9.2p1 && systemctl restart sshd',
    change_id:'CHG-4821', approved_by:'ciso@corp.example',
    notes:'Janela emergencial 22/05 02:00–04:00 aprovada pelo CAB em regime de urgência.',
  },
  {
    id:'PC-002', name:'FortiOS SSL-VPN Emergency Patch',
    type:'emergency', priority:'P0',
    trigger:'CVE-2024-21762 · CISA KEV · RCE Out-of-Bounds',
    lead:'ana.oliveira@corp.example', squad:'Network Security',
    vuln_ids:['CVE-2024-21762'], asset_count:2, patched:1, validated:1,
    status:'in_progress', created:'2024-05-19', due:'2024-05-20',
    window_id:'MW-002',
    steps:[
      {n:1,label:'Identificar firewalls FortiOS afetados',done:true,auto:true},
      {n:2,label:'Download FortiOS 7.4.3 do Fortinet support',done:true,auto:false},
      {n:3,label:'Workaround: desabilitar SSL-VPN temporariamente',done:true,auto:false},
      {n:4,label:'Patch fw-perimeter-01 em janela emergencial',done:true,auto:false},
      {n:5,label:'Validar SSL-VPN funcional pós-patch',done:true,auto:false},
      {n:6,label:'Patch fw-backup-01',done:false,auto:false},
      {n:7,label:'Rescan Tenable confirma patch',done:false,auto:true},
    ],
    rollback:'Downgrade FortiOS para 7.2.x via backup de configuração + Fortinet TP',
    change_id:'CHG-4818', approved_by:'ciso@corp.example',
    notes:'fw-perimeter-01 patched com sucesso. fw-backup-01 aguardando janela.',
  },
  {
    id:'PC-003', name:'Patch Tuesday — Windows Servers (Maio/2024)',
    type:'patch_tuesday', priority:'P1',
    trigger:'KB5041773 (CVE-2024-38063) + 14 outros bulletins Microsoft',
    lead:'patricia.lima@corp.example', squad:'Windows SRE',
    vuln_ids:['CVE-2024-38063'], asset_count:47, patched:31, validated:28,
    status:'in_progress', created:'2024-05-14', due:'2024-05-29',
    window_id:'MW-003',
    steps:[
      {n:1,label:'Download e staging de todos os patches WSUS',done:true,auto:true},
      {n:2,label:'Testar em ambiente de homologação (5 VMs)',done:true,auto:false},
      {n:3,label:'Deploy em servidores de desenvolvimento (15 hosts)',done:true,auto:false},
      {n:4,label:'Deploy em servidores de produção grupo A (20 hosts)',done:true,auto:false},
      {n:5,label:'Deploy em servidores de produção grupo B (12 hosts)',done:false,auto:false},
      {n:6,label:'Validação Microsoft Defender — scan pós-patch',done:false,auto:true},
    ],
    rollback:'WSUS: approve rollback do KB5041773. Reboot em modo seguro se necessário.',
    change_id:'CHG-4799', approved_by:'infra-manager@corp.example',
    notes:'31/47 concluídos. Grupo B programado para 25/05. 3 hosts com issues de compatibilidade isolados.',
  },
  {
    id:'PC-004', name:'SCA Update Campaign — Dependências Vulneráveis Q2',
    type:'sca_update', priority:'P2',
    trigger:'lodash 4.17.15 (CVE-2021-23337) · axios 0.21.1 · PyYAML 5.4 · numpy 1.22',
    lead:'gabriel.ferreira@corp.example', squad:'DevSecOps',
    vuln_ids:['CICD-SCA-001','CICD-SCA-002','CICD-SCA-003'], asset_count:8, patched:2, validated:1,
    status:'in_progress', created:'2024-05-10', due:'2024-06-10',
    window_id:'MW-004',
    steps:[
      {n:1,label:'Gerar lista de dependências vulneráveis (Snyk)',done:true,auto:true},
      {n:2,label:'Criar PRs automáticos via Dependabot/Snyk Fix',done:true,auto:true},
      {n:3,label:'Revisão e merge: lodash → 4.17.21 (corp/frontend)',done:true,auto:false},
      {n:4,label:'Revisão e merge: axios → 1.6.8 (corp/frontend)',done:false,auto:false},
      {n:5,label:'Revisão e merge: PyYAML → 6.0 (corp/ml-service)',done:false,auto:false},
      {n:6,label:'Revisão e merge: numpy → 1.26.4 (corp/data-pipeline)',done:false,auto:false},
      {n:7,label:'Re-build e re-deploy de todas as imagens',done:false,auto:true},
      {n:8,label:'Snyk scan pós-merge confirma resolução',done:false,auto:true},
    ],
    rollback:'git revert do commit de update + npm/pip install da versão anterior.',
    change_id:'CHG-4805', approved_by:null,
    notes:'PRs abertos para todos os repos. Aguardando aprovação dos respectivos squads.',
  },
  {
    id:'PC-005', name:'Log4j EOL Migration — Legacy Payments',
    type:'eol_migration', priority:'P2',
    trigger:'SCA-2024-LOG4J · Log4j 1.x EOL desde 2015 · Múltiplas CVEs sem patch',
    lead:'fernanda.rocha@corp.example', squad:'Backend Platform',
    vuln_ids:['SCA-2024-LOG4J'], asset_count:1, patched:0, validated:0,
    status:'planned', created:'2024-04-07', due:'2024-08-30',
    window_id:null,
    steps:[
      {n:1,label:'Análise de impacto: mapear uso de Log4j 1.x no código',done:true,auto:false},
      {n:2,label:'Avaliar Log4j 2.x vs Logback — escolher alternativa',done:true,auto:false},
      {n:3,label:'Criar branch de migração no repositório',done:false,auto:false},
      {n:4,label:'Migrar configurações log4j.properties → log4j2.xml',done:false,auto:false},
      {n:5,label:'Atualizar dependência pom.xml: log4j-core 1.x → 2.23.1',done:false,auto:false},
      {n:6,label:'Testes de regressão completos (suite de 480 testes)',done:false,auto:false},
      {n:7,label:'Deploy em homologação + aprovação de QA',done:false,auto:false},
      {n:8,label:'Deploy em produção em janela de manutenção dedicada',done:false,auto:false},
      {n:9,label:'Snyk confirma ausência de Log4j 1.x',done:false,auto:true},
    ],
    rollback:'Manter Log4j 1.x com exceção formal (EXC-001) como contingência.',
    change_id:null, approved_by:null,
    notes:'Estimativa: 3 sprints de desenvolvimento. Budget aprovado para Q3. Exceção EXC-001 cobre o período.',
  },
];

export const MAINTENANCE_WINDOWS = [
  {
    id:'MW-001', name:'Janela Emergencial — OpenSSH regreSSHion',
    type:'emergency', squad:'Linux SRE',
    systems:['ssh-bastion-01','linux-prod-*','jenkins-prod-01','k8s-node-*'],
    date:'2024-05-22', start:'02:00', end:'04:00', duration_h:2,
    recurrence:'one-time', approved_by:'ciso@corp.example',
    campaign_id:'PC-001', status:'upcoming',
    impact:'Breve indisponibilidade SSH (< 3 min por host)',
    rollback_time_min:15,
  },
  {
    id:'MW-002', name:'Janela Emergencial — FortiOS Patch',
    type:'emergency', squad:'Network Security',
    systems:['fw-backup-01'],
    date:'2024-05-23', start:'01:00', end:'02:30', duration_h:1.5,
    recurrence:'one-time', approved_by:'ciso@corp.example',
    campaign_id:'PC-002', status:'upcoming',
    impact:'VPN indisponível durante upgrade (< 20 min)',
    rollback_time_min:30,
  },
  {
    id:'MW-003', name:'Patch Tuesday Standard — Windows Infrastructure',
    type:'standard', squad:'Windows SRE',
    systems:['win-servers-pool','win-prod-grupo-b-*'],
    date:'2024-05-25', start:'22:00', end:'02:00', duration_h:4,
    recurrence:'monthly', approved_by:'infra-manager@corp.example',
    campaign_id:'PC-003', status:'upcoming',
    impact:'Reboots programados. HA garante continuidade.',
    rollback_time_min:45,
  },
  {
    id:'MW-004', name:'Self-Service Dev — SCA Dependency Updates',
    type:'self_service', squad:'DevSecOps',
    systems:['corp/frontend','corp/ml-service','corp/data-pipeline','corp/api-gateway'],
    date:'2024-05-27', start:'14:00', end:'18:00', duration_h:4,
    recurrence:'bi-weekly', approved_by:'devops-lead@corp.example',
    campaign_id:'PC-004', status:'upcoming',
    impact:'Pipelines CI/CD com rebuild. Zero downtime (blue/green).',
    rollback_time_min:10,
  },
];

export const PATCH_RECORDS = [
  {id:'PR-001',vuln_id:'CVE-2024-6387',asset:'linux-prod-01',  patch:'openssh-server 9.8p1', status:'validated', scheduled:'2024-05-21 22:00',deployed:'2024-05-21 22:14',validated_at:'2024-05-22 06:00',mttr_days:1,deployed_by:'marcos.costa@corp.example',validated_by:'Qualys VMDR (auto)',rollback:false},
  {id:'PR-002',vuln_id:'CVE-2024-6387',asset:'linux-prod-02',  patch:'openssh-server 9.8p1', status:'validated', scheduled:'2024-05-21 22:00',deployed:'2024-05-21 22:28',validated_at:'2024-05-22 06:00',mttr_days:1,deployed_by:'marcos.costa@corp.example',validated_by:'Qualys VMDR (auto)',rollback:false},
  {id:'PR-003',vuln_id:'CVE-2024-6387',asset:'linux-prod-03',  patch:'openssh-server 9.8p1', status:'validated', scheduled:'2024-05-21 22:00',deployed:'2024-05-21 22:41',validated_at:'2024-05-22 06:00',mttr_days:1,deployed_by:'marcos.costa@corp.example',validated_by:'Qualys VMDR (auto)',rollback:false},
  {id:'PR-004',vuln_id:'CVE-2024-6387',asset:'ssh-bastion-01', patch:'openssh-server 9.8p1', status:'scheduled',  scheduled:'2024-05-22 02:00',deployed:null,validated_at:null,mttr_days:null,deployed_by:null,validated_by:null,rollback:false},
  {id:'PR-005',vuln_id:'CVE-2024-21762',asset:'fw-perimeter-01',patch:'FortiOS 7.4.3',       status:'validated', scheduled:'2024-05-19 06:45',deployed:'2024-05-19 10:12',validated_at:'2024-05-19 12:00',mttr_days:0,deployed_by:'ana.oliveira@corp.example',validated_by:'Tenable VM (auto)',rollback:false},
  {id:'PR-006',vuln_id:'CVE-2024-21762',asset:'fw-backup-01',  patch:'FortiOS 7.4.3',       status:'scheduled',  scheduled:'2024-05-23 01:00',deployed:null,validated_at:null,mttr_days:null,deployed_by:null,validated_by:null,rollback:false},
  {id:'PR-007',vuln_id:'CVE-2024-38063',asset:'win-servers-pool (grupo-a)',patch:'KB5041773', status:'deployed',  scheduled:'2024-05-18 22:00',deployed:'2024-05-19 02:30',validated_at:null,mttr_days:null,deployed_by:'WSUS Auto Deploy',validated_by:null,rollback:false},
  {id:'PR-008',vuln_id:'CVE-2024-38063',asset:'win-servers-pool (grupo-b)',patch:'KB5041773', status:'scheduled',  scheduled:'2024-05-25 22:00',deployed:null,validated_at:null,mttr_days:null,deployed_by:null,validated_by:null,rollback:false},
  {id:'PR-009',vuln_id:'CICD-SCA-001',  asset:'corp/frontend',           patch:'lodash 4.17.21',status:'validated',scheduled:'2024-05-20 14:00',deployed:'2024-05-20 15:30',validated_at:'2024-05-20 16:00',mttr_days:10,deployed_by:'Dependabot PR merge',validated_by:'Snyk (auto)',rollback:false},
  {id:'PR-010',vuln_id:'CICD-SCA-002',  asset:'corp/frontend',           patch:'axios 1.6.8', status:'scheduled',  scheduled:'2024-05-27 14:00',deployed:null,validated_at:null,mttr_days:null,deployed_by:null,validated_by:null,rollback:false},
  {id:'PR-011',vuln_id:'CLOUD-2024-S3', asset:'aws-s3-analytics-prod',   patch:'Block Public Access enabled',status:'validated',scheduled:'2024-05-18 14:00',deployed:'2024-05-18 14:15',validated_at:'2024-05-18 15:00',mttr_days:0,deployed_by:'thiago.nunes@corp.example',validated_by:'Wiz (auto)',rollback:false},
  {id:'PR-012',vuln_id:'SCA-2024-LOG4J',asset:'app-legacy-payments',     patch:'log4j-core 2.23.1',status:'planned',scheduled:null,deployed:null,validated_at:null,mttr_days:null,deployed_by:null,validated_by:null,rollback:false},
];

export const PATCH_VELOCITY = [
  {week:'S1/Mai', deployed:8,  validated:7,  failed:1},
  {week:'S2/Mai', deployed:14, validated:12, failed:2},
  {week:'S3/Mai', deployed:6,  validated:5,  failed:0},
  {week:'S4/Mai', deployed:11, validated:9,  failed:1},
  {week:'S1/Jun', deployed:3,  validated:2,  failed:0},
];

export function getPatchDebt(records, vulns) {
  let debt = 0;
  const unpatched = records.filter(r => r.status !== 'validated' && r.status !== 'deployed');
  unpatched.forEach(r => {
    const v = vulns?.find(x => x.id === r.vuln_id);
    const age = v?.sla_used || 10;
    const mult = v?.sev === 'CRITICAL' ? 4 : v?.sev === 'HIGH' ? 2 : 1;
    debt += age * mult;
  });
  return debt;
}

export function getCampaignTypeLabel(t) {
  return {
    emergency:     { label:'EMERGENCIAL',    color:'var(--crit)',    cls:'pc' },
    patch_tuesday: { label:'PATCH TUESDAY',  color:'var(--high)',   cls:'ph' },
    sca_update:    { label:'SCA UPDATE',     color:'var(--accent)', cls:'pi' },
    eol_migration: { label:'EOL MIGRATION',  color:'#a084ff',       cls:'pnist' },
    hardening:     { label:'HARDENING',      color:'var(--med)',     cls:'pm' },
  }[t] || { label:t.toUpperCase(), color:'var(--text3)', cls:'pn' };
}

export function getPatchStatusMeta(s) {
  return {
    planned:    { label:'Planejado',    cls:'pn',   color:'var(--text3)' },
    scheduled:  { label:'Agendado',     cls:'pi',   color:'var(--accent)' },
    in_progress:{ label:'Em Progresso', cls:'ph',   color:'var(--high)' },
    deployed:   { label:'Deployado',    cls:'pm',   color:'var(--med)' },
    validated:  { label:'Validado ✓',  cls:'pd',   color:'var(--success)' },
    failed:     { label:'FALHOU',       cls:'pc',   color:'var(--crit)' },
  }[s] || { label:s, cls:'pn', color:'var(--text3)' };
}

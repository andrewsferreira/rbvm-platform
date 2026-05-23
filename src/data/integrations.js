// =============================================================================
// RBVM Platform — Integrations Config
// =============================================================================

export const INTEGRATIONS = [
  // ── SCANNERS DE INFRAESTRUTURA ─────────────────────────────────────────────
  { id:'tenable',   name:'Tenable VM',       type:'Infrastructure Scanner', status:'connected', icon:'ti-radar',        color:'#1a9aef', last_sync:'2024-05-22 06:00', findings:5,  freq:'Diário', api:'REST', note:'' },
  { id:'qualys',    name:'Qualys VMDR',       type:'Infrastructure Scanner', status:'connected', icon:'ti-radar',        color:'#e35f1e', last_sync:'2024-05-22 04:00', findings:3,  freq:'Diário', api:'REST', note:'' },
  { id:'rapid7',    name:'Rapid7 InsightVM',  type:'Infrastructure Scanner', status:'partial',   icon:'ti-radar',        color:'#ff5722', last_sync:'2024-05-21 22:00', findings:2,  freq:'Semanal', api:'REST', note:'Credenciais a renovar' },
  { id:'ms_def',    name:'Microsoft Defender',type:'EDR / Infrastructure',   status:'connected', icon:'ti-shield',       color:'#0078d4', last_sync:'2024-05-22 05:00', findings:1,  freq:'Real-time', api:'REST', note:'' },
  // ── APPSEC ────────────────────────────────────────────────────────────────
  { id:'snyk',      name:'Snyk',              type:'SCA / SAST',             status:'connected', icon:'ti-code',         color:'4c4aed',  last_sync:'2024-05-22 07:00', findings:4,  freq:'Por commit', api:'REST', note:'' },
  { id:'sonar',     name:'SonarQube',         type:'SAST',                   status:'connected', icon:'ti-code',         color:'#cb3032', last_sync:'2024-05-21 20:00', findings:2,  freq:'Por PR', api:'REST', note:'' },
  { id:'veracode',  name:'Veracode',          type:'SAST / DAST',            status:'partial',   icon:'ti-code',         color:'#5e35b1', last_sync:'2024-05-20 18:00', findings:1,  freq:'Semanal', api:'REST', note:'Scan agendado' },
  { id:'ghas',      name:'GitHub Adv. Security',type:'SAST / Secret Scanning',status:'connected',icon:'ti-brand-github', color:'#24292e', last_sync:'2024-05-22 08:00', findings:1,  freq:'Por commit', api:'Webhook', note:'' },
  // ── CLOUD / CNAPP ─────────────────────────────────────────────────────────
  { id:'wiz',       name:'Wiz',               type:'CNAPP / Cloud',          status:'connected', icon:'ti-cloud',        color:'#6e40c9', last_sync:'2024-05-22 06:30', findings:2,  freq:'Contínuo', api:'GraphQL', note:'' },
  { id:'checkov',   name:'Checkov',           type:'IaC Scanner',            status:'connected', icon:'ti-file-code',    color:'#7c4dff', last_sync:'2024-05-22 07:30', findings:1,  freq:'Por PR', api:'CLI/Webhook', note:'' },
  { id:'trivy',     name:'Trivy',             type:'Container Scanner',      status:'connected', icon:'ti-box',          color:'#00b4d8', last_sync:'2024-05-22 08:00', findings:1,  freq:'Por build', api:'CLI/API', note:'' },
  // ── IDENTITY ──────────────────────────────────────────────────────────────
  { id:'bloodhound',name:'BloodHound',        type:'Active Directory',       status:'partial',   icon:'ti-users-group',  color:'#e63946', last_sync:'2024-05-20 14:00', findings:1,  freq:'Semanal', api:'API', note:'Scan agendado' },
  // ── TICKETING ─────────────────────────────────────────────────────────────
  { id:'jira',      name:'Jira',              type:'Ticketing / ITSM',       status:'connected', icon:'ti-ticket',       color:'#0052cc', last_sync:'2024-05-22 09:00', findings:null, freq:'Real-time', api:'REST', note:'' },
  { id:'servicenow',name:'ServiceNow',        type:'Ticketing / ITSM',       status:'off',       icon:'ti-ticket',       color:'#62d84e', last_sync:null, findings:null, freq:'—', api:'REST', note:'Não configurado' },
  // ── COMUNICAÇÃO ───────────────────────────────────────────────────────────
  { id:'slack',     name:'Slack',             type:'Comunicação',            status:'connected', icon:'ti-brand-slack',  color:'#4a154b', last_sync:'2024-05-22 09:00', findings:null, freq:'Real-time', api:'Webhook', note:'' },
  { id:'teams',     name:'Microsoft Teams',   type:'Comunicação',            status:'connected', icon:'ti-brand-teams',  color:'#5059c9', last_sync:'2024-05-22 09:00', findings:null, freq:'Real-time', api:'Webhook', note:'' },
];

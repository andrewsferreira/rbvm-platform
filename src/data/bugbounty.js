// =============================================================================
// RBVM Platform — Bug Bounty Management
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const BB_PROGRAMS = [
  {
    id:'BB-CORP-001', name:'Corp Security Bug Bounty Program',
    platform:'HackerOne', status:'active',
    launched:'2023-01-10', managed_by:'security-team@corp.example',
    scope:['app.corp.com','api.corp.com','auth.corp.com','admin.corp.com'],
    out_of_scope:['cdn.corp.com','mail.corp.com','staging.*','corp.com.br','Ataques DoS/DDoS','Engenharia social'],
    bounty_table:{
      critical:'R$ 10.000 – R$ 25.000',
      high:    'R$ 2.500 – R$ 10.000',
      medium:  'R$ 500 – R$ 2.500',
      low:     'R$ 100 – R$ 500',
      info:    'Hall da Fama',
    },
    stats:{
      total_reports:147, valid:38, duplicate:24, invalid:35, oos:22, triaging:28,
      unique_vulns:31, total_paid_brl:128500, avg_bounty_brl:3382,
      avg_resolution_days:18, top_severity:'HIGH',
    },
    safe_harbor:true, response_sla_h:72, resolution_sla_days:90,
  },
];

export const BB_REPORTS = [
  // ── TRIAGING (needs review) ─────────────────────────────────────────────────
  {
    id:'BBR-001', program:'BB-CORP-001',
    researcher:'h4cker_zero', researcher_rep:1840,
    title:'Stored XSS em comentários do perfil — bypass via SVG',
    severity:'HIGH', category:'XSS',
    submitted:'2024-05-20', status:'triaging',
    vuln_id:null, bounty_brl:null,
    disclosure_deadline:null, resolution_days:null,
    description:'É possível injetar SVG com onload handler no campo de bio do perfil. O XSS persiste e executa para todos que visitam o perfil.',
    impact:'Roubo de sessão de outros usuários, incluindo administradores.',
    steps_to_reproduce:'1. Acessar /profile/edit\n2. Inserir: <svg onload="alert(document.cookie)">\n3. Salvar e visitar o perfil com outro browser.',
    poc_attachment:true,
  },
  {
    id:'BBR-002', program:'BB-CORP-001',
    researcher:'sec_researcher_br', researcher_rep:920,
    title:'IDOR em endpoint /api/v1/invoices/:id permite ver faturas de outros usuários',
    severity:'HIGH', category:'IDOR / Access Control',
    submitted:'2024-05-18', status:'triaging',
    vuln_id:null, bounty_brl:null,
    disclosure_deadline:null, resolution_days:null,
    description:'O endpoint de faturas não valida se o usuário autenticado é dono do recurso. Qualquer user ID pode acessar qualquer invoice ID.',
    impact:'Exposição de dados financeiros de todos os clientes. PCI DSS violation.',
    steps_to_reproduce:'1. Autenticar como user A\n2. GET /api/v1/invoices/12345 (invoice de user B)\n3. Retorna dados completos da fatura.',
    poc_attachment:true,
  },
  // ── ACCEPTED (valid, bounty determined) ─────────────────────────────────────
  {
    id:'BBR-003', program:'BB-CORP-001',
    researcher:'null_pwner', researcher_rep:3200,
    title:'SSRF em API Gateway permite requisições à rede interna',
    severity:'HIGH', category:'SSRF',
    submitted:'2024-05-05', status:'accepted',
    vuln_id:null, bounty_brl:7500,
    disclosure_deadline:'2024-08-03', resolution_days:null,
    description:'O parâmetro ?redirect_url= em /api/gateway não sanitiza URLs internas. É possível fazer requisições para serviços internos como metadata AWS e serviços na faixa 10.0.0.0/8.',
    impact:'Acesso ao metadata AWS (IAM credentials), possível SSRF para serviços internos.',
    steps_to_reproduce:'GET /api/gateway?redirect_url=http://169.254.169.254/latest/meta-data/',
    poc_attachment:true,
  },
  {
    id:'BBR-004', program:'BB-CORP-001',
    researcher:'pwn_or_nothing', researcher_rep:2150,
    title:'Auth Bypass em reset de senha via manipulação de token JWT',
    severity:'CRITICAL', category:'Authentication Bypass',
    submitted:'2024-04-22', status:'accepted',
    vuln_id:null, bounty_brl:18000,
    disclosure_deadline:'2024-07-21', resolution_days:null,
    description:'O token de reset de senha usa HS256 com secret fraco. É possível assinar tokens arbitrários e resetar a senha de qualquer conta incluindo admins.',
    impact:'Account takeover total. Qualquer conta incluindo CISO e admins pode ser comprometida.',
    steps_to_reproduce:'1. Solicitar reset de senha\n2. Decodificar JWT\n3. Assinar novamente com secret "secret123"\n4. Usar para resetar senha de admin@corp.example.',
    poc_attachment:true,
  },
  {
    id:'BBR-005', program:'BB-CORP-001',
    researcher:'recon_ninja', researcher_rep:680,
    title:'Subdomain takeover em dev.corp.com (CNAME para recurso Azure deletado)',
    severity:'MEDIUM', category:'Subdomain Takeover',
    submitted:'2024-05-10', status:'accepted',
    vuln_id:null, bounty_brl:1200,
    disclosure_deadline:'2024-08-08', resolution_days:null,
    description:'O CNAME de dev.corp.com aponta para um Azure Static Site que foi deletado. Qualquer pessoa pode criar o recurso e servir conteúdo sob dev.corp.com.',
    impact:'Phishing de alta credibilidade, roubo de cookies via domínio legítimo.',
    steps_to_reproduce:'dig dev.corp.com → CNAME para recurso Azure 404. Registrar recurso e servir conteúdo.',
    poc_attachment:false,
  },
  // ── RESOLVED ─────────────────────────────────────────────────────────────────
  {
    id:'BBR-006', program:'BB-CORP-001',
    researcher:'null_pwner', researcher_rep:3200,
    title:'Broken Object Level Authorization em /api/users/:id/profile',
    severity:'HIGH', category:'BOLA / IDOR',
    submitted:'2024-04-01', status:'resolved',
    vuln_id:null, bounty_brl:6000,
    disclosure_deadline:'2024-06-30', resolution_days:15,
    description:'Endpoint retornava dados de perfil de qualquer usuário sem validar ownership.',
    impact:'Exposição de dados pessoais. LGPD violation.',
    steps_to_reproduce:'GET /api/users/1234/profile sem ser o dono da conta.',
    poc_attachment:true,
  },
  {
    id:'BBR-007', program:'BB-CORP-001',
    researcher:'infosec_caue', researcher_rep:1340,
    title:'Missing CSRF protection em ação de transferência',
    severity:'MEDIUM', category:'CSRF',
    submitted:'2024-04-10', status:'resolved',
    vuln_id:null, bounty_brl:1800,
    disclosure_deadline:'2024-07-09', resolution_days:22,
    description:'Endpoint de transferência não valida CSRF token. Possível via imagem em email.',
    impact:'Transferências não autorizadas via página maliciosa.',
    steps_to_reproduce:'Criar form com action=/api/transfer sem CSRF token.',
    poc_attachment:true,
  },
  // ── DUPLICATE ────────────────────────────────────────────────────────────────
  {
    id:'BBR-008', program:'BB-CORP-001',
    researcher:'xss_hunter', researcher_rep:440,
    title:'Reflected XSS no parâmetro de busca (duplicata de BBR-001)',
    severity:'MEDIUM', category:'XSS',
    submitted:'2024-05-21', status:'duplicate',
    vuln_id:null, bounty_brl:0,
    disclosure_deadline:null, resolution_days:null,
    description:'XSS no campo de busca — mas é variante da BBR-001 já em triage.',
    impact:'Similar ao BBR-001.',
    steps_to_reproduce:'/?q=<script>alert(1)</script>',
    poc_attachment:false,
  },
  // ── INVALID ──────────────────────────────────────────────────────────────────
  {
    id:'BBR-009', program:'BB-CORP-001',
    researcher:'noob_hunter', researcher_rep:120,
    title:'Clickjacking na página principal (sem autenticação)',
    severity:'LOW', category:'Clickjacking',
    submitted:'2024-05-19', status:'invalid',
    vuln_id:null, bounty_brl:0,
    disclosure_deadline:null, resolution_days:null,
    description:'A página principal não tem X-Frame-Options.',
    impact:'Nenhum impacto real — página pública sem ação sensível.',
    poc_attachment:false,
    triage_note:'Inválido: página pública sem ação sensível não é escopo de clickjacking.',
  },
  // ── OUT OF SCOPE ─────────────────────────────────────────────────────────────
  {
    id:'BBR-010', program:'BB-CORP-001',
    researcher:'boundary_buster', researcher_rep:890,
    title:'Rate limiting ausente no endpoint de login',
    severity:'MEDIUM', category:'Rate Limiting',
    submitted:'2024-05-15', status:'oos',
    vuln_id:null, bounty_brl:0,
    disclosure_deadline:null, resolution_days:null,
    description:'É possível fazer brute force no login sem ser bloqueado.',
    impact:'Brute force de senhas.',
    poc_attachment:false,
    triage_note:'Fora de escopo: rate limiting em login é known issue sendo resolvido via Cloudflare WAF.',
  },
];

export function getBBStatusMeta(s) {
  return {
    triaging:  { label:'Em Triagem',  cls:'ph',  color:'var(--high)',    icon:'ti-eye' },
    accepted:  { label:'Aceito',      cls:'pi',  color:'var(--accent)',  icon:'ti-check' },
    resolved:  { label:'Resolvido',   cls:'pd',  color:'var(--success)', icon:'ti-lock' },
    duplicate: { label:'Duplicado',   cls:'pn',  color:'var(--text3)',   icon:'ti-copy' },
    invalid:   { label:'Inválido',    cls:'pn',  color:'var(--text3)',   icon:'ti-x' },
    oos:       { label:'Fora Escopo', cls:'pm',  color:'var(--med)',     icon:'ti-minus' },
  }[s] || { label:s, cls:'pn', color:'var(--text3)', icon:'ti-circle' };
}

export function getDisclosureDays(report) {
  if (!report.disclosure_deadline) return null;
  const diff = Math.ceil((new Date(report.disclosure_deadline) - new Date('2024-05-22')) / 86400000);
  return diff;
}

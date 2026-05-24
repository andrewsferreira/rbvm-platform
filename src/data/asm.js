// =============================================================================
// RBVM Platform — Attack Surface Management (ASM)
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const EXTERNAL_ASSETS = [
  // ── WEB APPLICATIONS ───────────────────────────────────────────────────────
  {
    id:'EXT-001', hostname:'app.corp.com',           ip:'200.0.0.10', type:'web_app',
    category:'Aplicação Web', shadow:false, in_cmdb:true,
    ports:[443,80], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'nginx/1.24.0',tech:['React 18','nginx 1.24']}],
    ssl:{valid:true,grade:'A',expires:'2024-09-15',days:116,issuer:"Let's Encrypt",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:true,csp:false,xfo:true,xcto:true,referrer:true,score:60},
    dns:{spf:true,dkim:true,dmarc:false,dnssec:false},
    risk_score:38, last_scan:'2024-05-22', vuln_ids:['LOW-2024-001'],
    owner:'vitor.carvalho@corp.example', squad:'Frontend Platform',
    notes:'CSP ausente — risco de XSS. DMARC não configurado.',
  },
  {
    id:'EXT-002', hostname:'api.corp.com',           ip:'200.0.0.11', type:'api',
    category:'API Pública', shadow:false, in_cmdb:true,
    ports:[443,8080], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'',tech:['node:18','Express 4.18']},{port:8080,service:'HTTP',banner:'Express',tech:['Express 4.18']}],
    ssl:{valid:true,grade:'B',expires:'2024-07-10',days:49,issuer:"DigiCert",protocols:['TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3']},
    headers:{hsts:false,csp:false,xfo:false,xcto:true,referrer:false,score:20},
    dns:{spf:true,dkim:false,dmarc:false,dnssec:false},
    risk_score:72, last_scan:'2024-05-22', vuln_ids:['CONTAINER-2024-001'],
    owner:'rafael.moura@corp.example', squad:'Kubernetes Platform',
    notes:'Grade SSL B — TLS 1.0/1.1 ativo. Porta 8080 exposta sem HTTPS. Headers inseguros.',
  },
  {
    id:'EXT-003', hostname:'admin.corp.com',         ip:'200.0.0.12', type:'web_app',
    category:'Painel Administrativo', shadow:false, in_cmdb:true,
    ports:[443,22], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'Apache/2.4.57',tech:['PHP 8.1','Apache 2.4']},{port:22,service:'SSH',banner:'OpenSSH_8.9p1',tech:['OpenSSH 8.9']}],
    ssl:{valid:true,grade:'A+',expires:'2025-01-20',days:244,issuer:"Sectigo",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:true,csp:true,xfo:true,xcto:true,referrer:true,score:95},
    dns:{spf:true,dkim:true,dmarc:true,dnssec:false},
    risk_score:55, last_scan:'2024-05-22', vuln_ids:['CVE-2024-4577'],
    owner:'rodrigo.melo@corp.example', squad:'Web Platform',
    notes:'PHP CGI vulnerável (CVE-2024-4577). SSL A+ mas aplicação com vuln crítica.',
  },
  {
    id:'EXT-004', hostname:'auth.corp.com',          ip:'200.0.0.13', type:'api',
    category:'API de Autenticação', shadow:false, in_cmdb:true,
    ports:[443], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'',tech:['Java 17','Spring Boot 3.2']}],
    ssl:{valid:true,grade:'A+',expires:'2024-12-31',days:223,issuer:"Let's Encrypt",protocols:['TLS 1.3']},
    headers:{hsts:true,csp:true,xfo:true,xcto:true,referrer:true,score:100},
    dns:{spf:true,dkim:true,dmarc:true,dnssec:true},
    risk_score:22, last_scan:'2024-05-22', vuln_ids:[],
    owner:'beatriz.alves@corp.example', squad:'Identity & Access',
    notes:'Bem configurado. Único com DNSSEC ativo. Referência de hardening.',
  },
  // ── VPN / NETWORK ──────────────────────────────────────────────────────────
  {
    id:'EXT-005', hostname:'vpn.corp.com',           ip:'200.0.0.1', type:'vpn',
    category:'VPN / Acesso Remoto', shadow:false, in_cmdb:true,
    ports:[443,10443,4433], redirect_http:false,
    services:[{port:443,service:'SSL-VPN',banner:'FortiGate',tech:['FortiOS 7.2']},{port:10443,service:'HTTPS',banner:'FortiGate',tech:['FortiOS 7.2']}],
    ssl:{valid:true,grade:'A',expires:'2024-11-30',days:191,issuer:"DigiCert",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:true,csp:false,xfo:false,xcto:false,referrer:false,score:30},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:95, last_scan:'2024-05-22', vuln_ids:['CVE-2024-21762'],
    owner:'ana.oliveira@corp.example', squad:'Network Security',
    notes:'CVE-2024-21762 CRÍTICA — FortiOS SSL-VPN vulnerável. CISA KEV. Patch em andamento.',
  },
  {
    id:'EXT-006', hostname:'ssh-bastion.corp.com',   ip:'200.0.0.2', type:'bastion',
    category:'Bastion / Jump Host', shadow:false, in_cmdb:true,
    ports:[22,2222], redirect_http:false,
    services:[{port:22,service:'SSH',banner:'OpenSSH_9.2p1',tech:['OpenSSH 9.2']},{port:2222,service:'SSH (alt)',banner:'OpenSSH_9.2p1',tech:['OpenSSH 9.2']}],
    ssl:{valid:false,grade:'N/A',expires:null,days:null,issuer:null,protocols:[]},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:0},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:82, last_scan:'2024-05-22', vuln_ids:['CVE-2024-6387'],
    owner:'marcos.costa@corp.example', squad:'Linux SRE',
    notes:'OpenSSH regreSSHion (CVE-2024-6387). Porta 22 e 2222 expostas. War Room WR-001 ativo.',
  },
  // ── MAIL / COMMUNICATION ───────────────────────────────────────────────────
  {
    id:'EXT-007', hostname:'mail.corp.com',          ip:'200.0.0.20', type:'mail',
    category:'Mail Server', shadow:false, in_cmdb:true,
    ports:[25,465,587,993,143], redirect_http:false,
    services:[{port:465,service:'SMTPS',banner:'Postfix 3.7',tech:['Postfix 3.7']},{port:993,service:'IMAPS',banner:'Dovecot 2.3',tech:['Dovecot 2.3']}],
    ssl:{valid:true,grade:'A',expires:'2024-08-01',days:71,issuer:"Let's Encrypt",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:0},
    dns:{spf:true,dkim:true,dmarc:true,dnssec:false},
    risk_score:44, last_scan:'2024-05-21', vuln_ids:[],
    owner:'infra@corp.example', squad:'Linux SRE',
    notes:'Porta 25 (SMTP relay) exposta sem auth — risco de relay abuse. Cert expira em 71 dias.',
  },
  // ── CDN / CLOUD ────────────────────────────────────────────────────────────
  {
    id:'EXT-008', hostname:'cdn.corp.com',           ip:'104.21.0.1', type:'cdn',
    category:'CDN / Edge', shadow:false, in_cmdb:true,
    ports:[443,80], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'cloudflare',tech:['Cloudflare','React 18']}],
    ssl:{valid:true,grade:'A+',expires:'2025-05-22',days:365,issuer:"Cloudflare",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:true,csp:true,xfo:true,xcto:true,referrer:true,score:100},
    dns:{spf:true,dkim:true,dmarc:true,dnssec:false},
    risk_score:12, last_scan:'2024-05-22', vuln_ids:[],
    owner:'thiago.nunes@corp.example', squad:'Cloud Security',
    notes:'Melhor configuração de headers da superfície. Cloudflare WAF ativo.',
  },
  {
    id:'EXT-009', hostname:'s3.corp-public.com',     ip:'52.92.0.0', type:'cloud_storage',
    category:'Cloud Storage', shadow:false, in_cmdb:true,
    ports:[443,80], redirect_http:true,
    services:[{port:443,service:'HTTPS',banner:'AmazonS3',tech:['AWS S3']}],
    ssl:{valid:true,grade:'A',expires:'2025-05-22',days:365,issuer:"Amazon",protocols:['TLS 1.2','TLS 1.3']},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:10},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:28, last_scan:'2024-05-22', vuln_ids:['CLOUD-2024-S3'],
    owner:'thiago.nunes@corp.example', squad:'Cloud Security',
    notes:'S3 bucket resolvido (CLOUD-2024-S3). Monitorando para não reabrir.',
  },
  // ── SHADOW IT (discovered, not in CMDB) ────────────────────────────────────
  {
    id:'EXT-010', hostname:'dev-staging.corp-test.com', ip:'200.0.1.50', type:'web_app',
    category:'Shadow IT', shadow:true, in_cmdb:false,
    ports:[80,8080,3000,22], redirect_http:false,
    services:[{port:80,service:'HTTP',banner:'Apache/2.2.34',tech:['Apache 2.2','PHP 5.6']},{port:3000,service:'Node Dev',banner:'',tech:['Node.js']},{port:22,service:'SSH',banner:'OpenSSH_7.4',tech:['OpenSSH 7.4']}],
    ssl:{valid:false,grade:'F',expires:null,days:null,issuer:null,protocols:[]},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:0},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:91, last_scan:'2024-05-10', vuln_ids:[],
    owner:null, squad:null,
    discovery:'Subdomain enumeration (Amass) · Cert transparency log',
    notes:'Servidor desconhecido pelo CMDB. Apache 2.2 EOL + PHP 5.6 EOL. OpenSSH 7.4 vulnerável. Node dev server exposto publicamente.',
  },
  {
    id:'EXT-011', hostname:'test-api.corp.internal.com', ip:'200.0.1.51', type:'api',
    category:'Shadow IT', shadow:true, in_cmdb:false,
    ports:[8000,8001,9000,22], redirect_http:false,
    services:[{port:8000,service:'HTTP API',banner:'uvicorn',tech:['FastAPI','Python 3.11']},{port:9000,service:'Debug Port',banner:'debugpy',tech:['Python debugger']}],
    ssl:{valid:false,grade:'F',expires:null,days:null,issuer:null,protocols:[]},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:0},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:88, last_scan:'2024-05-15', vuln_ids:[],
    owner:null, squad:null,
    discovery:'Shodan scan · Port scan via ASM engine',
    notes:'API FastAPI exposta sem autenticação. PORTA 9000 = debugpy ativo = execução remota de código trivial. Crítico.',
  },
  {
    id:'EXT-012', hostname:'old-portal.corp.com.br',    ip:'200.0.1.52', type:'web_app',
    category:'Shadow IT', shadow:true, in_cmdb:false,
    ports:[80,443,3306], redirect_http:false,
    services:[{port:80,service:'HTTP',banner:'Apache/2.4.6',tech:['WordPress 5.2','Apache']},{port:3306,service:'MySQL',banner:'MySQL 5.7',tech:['MySQL 5.7']}],
    ssl:{valid:false,grade:'C',expires:'2023-11-15',days:-189,issuer:"Let's Encrypt",protocols:['TLS 1.0','TLS 1.1','TLS 1.2']},
    headers:{hsts:false,csp:false,xfo:false,xcto:false,referrer:false,score:0},
    dns:{spf:false,dkim:false,dmarc:false,dnssec:false},
    risk_score:96, last_scan:'2024-05-12', vuln_ids:[],
    owner:null, squad:null,
    discovery:'DNS brute-force · Google dork: site:corp.com.br',
    notes:'Portal WordPress 5.2 ALTAMENTE DESATUALIZADO. Certificado EXPIRADO há 189 dias. MySQL 3306 EXPOSTO PUBLICAMENTE sem auth verificada. Maior risco da superfície.',
  },
];

export const ASM_CATEGORIES = [
  { id:'web_app',       label:'Aplicações Web',     icon:'ti-world',             color:'var(--accent)',   count:3 },
  { id:'api',           label:'APIs Públicas',       icon:'ti-api',               color:'var(--high)',     count:2 },
  { id:'vpn',           label:'VPN / Acesso Remoto', icon:'ti-shield-lock',       color:'var(--crit)',     count:1 },
  { id:'bastion',       label:'Bastion Hosts',       icon:'ti-server',            color:'var(--crit)',     count:1 },
  { id:'mail',          label:'Mail Servers',        icon:'ti-mail',              color:'var(--med)',      count:1 },
  { id:'cdn',           label:'CDN / Edge',          icon:'ti-cloud',             color:'var(--success)',  count:1 },
  { id:'cloud_storage', label:'Cloud Storage',       icon:'ti-brand-aws',         color:'var(--accent)',   count:1 },
  { id:'shadow_it',     label:'Shadow IT',           icon:'ti-ghost',             color:'var(--crit)',     count:3 },
];

export const ASM_TIMELINE = [
  { date:'2024-05-22', event:'ASM scan completo', assets_found:12, new_assets:0, changes:['api.corp.com: TLS 1.0 ainda ativo'] },
  { date:'2024-05-15', event:'Shadow IT descoberto', assets_found:11, new_assets:2, changes:['test-api.corp.internal.com: nova descoberta via Shodan','dev-staging.corp-test.com: nova descoberta via Amass'] },
  { date:'2024-05-10', event:'old-portal.corp.com.br descoberto', assets_found:9, new_assets:1, changes:['old-portal.corp.com.br: cert expirado há 189 dias, MySQL exposto'] },
  { date:'2024-04-30', event:'Scan mensal', assets_found:8, new_assets:0, changes:['Nenhuma mudança significativa'] },
];

export function getAsmScore(assets) {
  const scored = assets.filter(a=>!a.shadow);
  if (!scored.length) return 0;
  return Math.round(scored.reduce((s,a)=>s+a.risk_score,0)/scored.length);
}

export function getCertStatus(days) {
  if (days === null) return { label:'Sem SSL', cls:'pc', color:'var(--crit)', priority:0 };
  if (days < 0)  return { label:'EXPIRADO', cls:'pc', color:'var(--crit)', priority:1 };
  if (days < 30) return { label:`${days}d`, cls:'pc', color:'var(--crit)', priority:2 };
  if (days < 90) return { label:`${days}d`, cls:'ph', color:'var(--high)', priority:3 };
  return { label:`${days}d`, cls:'pd', color:'var(--success)', priority:4 };
}

export function getHeadersGrade(score) {
  if (score >= 90) return { grade:'A', color:'var(--success)' };
  if (score >= 70) return { grade:'B', color:'var(--low)' };
  if (score >= 50) return { grade:'C', color:'var(--med)' };
  if (score >= 25) return { grade:'D', color:'var(--high)' };
  return { grade:'F', color:'var(--crit)' };
}

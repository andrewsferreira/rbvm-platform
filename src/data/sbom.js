// =============================================================================
// RBVM Platform — Software Bill of Materials (SBOM)
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const SBOM_APPS = [
  { id:'APP-001', name:'Payment API',        type:'java',   squad:'Backend Platform',  repo:'corp/payment-api',   scanner:'Snyk',      last_scan:'2024-05-15', components_total:142, components_vuln:8,  license_risk:0 },
  { id:'APP-002', name:'Frontend Dashboard', type:'node',   squad:'Frontend Platform', repo:'corp/frontend',      scanner:'Snyk',      last_scan:'2024-05-22', components_total:892, components_vuln:4,  license_risk:2 },
  { id:'APP-003', name:'ML Service',         type:'python', squad:'AI Security',       repo:'corp/ml-service',    scanner:'Snyk',      last_scan:'2024-05-12', components_total:218, components_vuln:5,  license_risk:1 },
  { id:'APP-004', name:'API Gateway',        type:'node',   squad:'Platform Engineering',repo:'corp/api-gateway', scanner:'Dependabot',last_scan:'2024-05-20', components_total:441, components_vuln:3,  license_risk:0 },
  { id:'APP-005', name:'Data Pipeline',      type:'python', squad:'Data Engineering',  repo:'corp/data-pipeline', scanner:'Snyk',      last_scan:'2024-05-18', components_total:176, components_vuln:2,  license_risk:0 },
];

export const SBOM_COMPONENTS = [
  // ── CRÍTICOS ─────────────────────────────────────────────────────────────────
  { id:'COMP-001', name:'log4j-core',       version:'1.2.17',  latest:'2.23.1',  ecosystem:'maven',  dep_type:'direct',     apps:['APP-001'], license:'Apache-2.0', license_risk:'none', eol:true,  eol_date:'2015-08-06', cves:['CVE-2019-17571','CVE-2020-9488','CVE-2022-23302'], vuln_ids:['SCA-2024-LOG4J'], can_upgrade:true,  upgrade_note:'Migrar para log4j-core 2.23.1+. Requer ajustes de API.' },
  { id:'COMP-002', name:'lodash',           version:'4.17.15', latest:'4.17.21', ecosystem:'npm',    dep_type:'direct',     apps:['APP-002'], license:'MIT',         license_risk:'none', eol:false, eol_date:null,         cves:['CVE-2021-23337'],                               vuln_ids:['CICD-SCA-001'], can_upgrade:true,  upgrade_note:'npm update lodash. Compatível com versão atual da API.' },
  { id:'COMP-003', name:'PyYAML',           version:'5.4.1',   latest:'6.0.1',   ecosystem:'pypi',   dep_type:'direct',     apps:['APP-003'], license:'MIT',         license_risk:'none', eol:false, eol_date:null,         cves:['CVE-2020-14343'],                               vuln_ids:['CICD-SCA-003'], can_upgrade:true,  upgrade_note:'pip install PyYAML>=6.0. Substituir yaml.load() por yaml.safe_load().' },
  { id:'COMP-004', name:'axios',            version:'0.21.1',  latest:'1.6.8',   ecosystem:'npm',    dep_type:'direct',     apps:['APP-002','APP-004'], license:'MIT', license_risk:'none', eol:false, eol_date:null, cves:['CVE-2021-3749','CVE-2023-45857'],           vuln_ids:['CICD-SCA-002'], can_upgrade:true,  upgrade_note:'npm install axios@1.6.8. Breaking changes na API de interceptors.' },
  { id:'COMP-005', name:'numpy',            version:'1.22.0',  latest:'1.26.4',  ecosystem:'pypi',   dep_type:'direct',     apps:['APP-003','APP-005'], license:'BSD-3-Clause', license_risk:'none', eol:false, eol_date:null, cves:['CVE-2021-34141'],                vuln_ids:[],               can_upgrade:true,  upgrade_note:'pip install numpy>=1.26. Compatível.' },
  // ── ALTOS ─────────────────────────────────────────────────────────────────────
  { id:'COMP-006', name:'spring-boot',      version:'2.5.14',  latest:'3.2.5',   ecosystem:'maven',  dep_type:'direct',     apps:['APP-001'], license:'Apache-2.0', license_risk:'none', eol:true,  eol_date:'2023-05-18', cves:['CVE-2022-22965','CVE-2023-34035'],              vuln_ids:[],               can_upgrade:false, upgrade_note:'Migração 2.x → 3.x tem breaking changes significativos. Requer sprint dedicado.' },
  { id:'COMP-007', name:'jsonwebtoken',     version:'8.5.1',   latest:'9.0.2',   ecosystem:'npm',    dep_type:'direct',     apps:['APP-004'], license:'MIT',         license_risk:'none', eol:false, eol_date:null,         cves:['CVE-2022-23529'],                               vuln_ids:[],               can_upgrade:true,  upgrade_note:'npm install jsonwebtoken@9. Verificar formato de tokens.' },
  { id:'COMP-008', name:'requests',         version:'2.26.0',  latest:'2.31.0',  ecosystem:'pypi',   dep_type:'direct',     apps:['APP-003','APP-005'], license:'Apache-2.0', license_risk:'none', eol:false, eol_date:null, cves:['CVE-2023-32681'],               vuln_ids:[],               can_upgrade:true,  upgrade_note:'pip install requests>=2.31.0.' },
  // ── RISCO DE LICENÇA ─────────────────────────────────────────────────────────
  { id:'COMP-009', name:'ffmpeg',           version:'6.0',     latest:'6.1',     ecosystem:'system', dep_type:'direct',     apps:['APP-003'], license:'GPL-2.0',     license_risk:'high',  eol:false, eol_date:null,         cves:[],                                               vuln_ids:[],               can_upgrade:false, upgrade_note:'GPL-2.0 é copyleft. Uso em produto comercial requer análise jurídica e possível substituição.' },
  { id:'COMP-010', name:'gpt4all',          version:'0.1.0',   latest:'2.1.0',   ecosystem:'pypi',   dep_type:'direct',     apps:['APP-003'], license:'GPL-3.0',     license_risk:'critical', eol:false, eol_date:null, cves:[],                                          vuln_ids:[],               can_upgrade:false, upgrade_note:'GPL-3.0 é copyleft forte. Não pode ser usado em produto proprietário sem liberação do código fonte.' },
  // ── MÉDIOS / TRANSITIVOS ──────────────────────────────────────────────────────
  { id:'COMP-011', name:'moment',           version:'2.29.1',  latest:'2.30.1',  ecosystem:'npm',    dep_type:'transitive', apps:['APP-002'], license:'MIT',         license_risk:'none', eol:true,  eol_date:'2020-09-13', cves:['CVE-2022-24785'],                               vuln_ids:[],               can_upgrade:true,  upgrade_note:'Substituir por Day.js ou date-fns (sem vulnerabilidades, menor bundle).' },
  { id:'COMP-012', name:'minimist',         version:'1.2.5',   latest:'1.2.8',   ecosystem:'npm',    dep_type:'transitive', apps:['APP-002','APP-004'], license:'MIT', license_risk:'none', eol:false, eol_date:null, cves:['CVE-2021-44906'],                    vuln_ids:[],               can_upgrade:true,  upgrade_note:'npm update minimist. Dependência transitiva — verificar dependência pai.' },
  { id:'COMP-013', name:'python-jose',      version:'3.3.0',   latest:'3.3.0',   ecosystem:'pypi',   dep_type:'direct',     apps:['APP-003'], license:'MIT',         license_risk:'none', eol:false, eol_date:null,         cves:['CVE-2024-33663'],                               vuln_ids:[],               can_upgrade:false, upgrade_note:'CVE recente sem fix. Avaliar substituição por PyJWT.' },
  { id:'COMP-014', name:'celery',           version:'5.2.7',   latest:'5.3.6',   ecosystem:'pypi',   dep_type:'direct',     apps:['APP-005'], license:'BSD-3-Clause', license_risk:'none', eol:false, eol_date:null, cves:[],                                           vuln_ids:[],               can_upgrade:true,  upgrade_note:'pip install celery>=5.3. Compatível.' },
  { id:'COMP-015', name:'node:18-alpine',   version:'18.0.0',  latest:'20.12.2', ecosystem:'docker', dep_type:'direct',     apps:['APP-004'], license:'MIT',         license_risk:'none', eol:false, eol_date:'2025-04-30', cves:['CVE-2024-22019','CVE-2023-44487'],              vuln_ids:['CONTAINER-2024-001'], can_upgrade:true, upgrade_note:'Atualizar para node:20-alpine (LTS). Reconstruir imagem.' },
];

export const LICENSE_RISKS = {
  'GPL-3.0':     { level:'critical', label:'GPL v3 — Copyleft Forte',  desc:'Produto derivado deve ser open source. Não pode usar em produto proprietário.' },
  'GPL-2.0':     { level:'high',     label:'GPL v2 — Copyleft',        desc:'Análise jurídica obrigatória. Pode impedir uso em produto comercial fechado.' },
  'AGPL-3.0':    { level:'critical', label:'AGPL v3 — Copyleft Forte', desc:'Mais restritivo que GPL. Uso em SaaS também exige release do código.' },
  'LGPL-2.1':    { level:'medium',   label:'LGPL — Copyleft Fraco',    desc:'Permite uso dinâmico sem exigir release. Verificar forma de linkagem.' },
  'MIT':         { level:'none',     label:'MIT — Permissiva',          desc:'Sem restrições de uso em software proprietário.' },
  'Apache-2.0':  { level:'none',     label:'Apache 2.0 — Permissiva',  desc:'Sem restrições. Requer manter notices de copyright.' },
  'BSD-3-Clause':{ level:'none',     label:'BSD 3-Clause — Permissiva',desc:'Sem restrições de uso.' },
};

export function getSbomStats() {
  const totalComps = SBOM_COMPONENTS.length;
  const withCves   = SBOM_COMPONENTS.filter(c=>c.cves.length>0).length;
  const eolComps   = SBOM_COMPONENTS.filter(c=>c.eol).length;
  const licRisk    = SBOM_COMPONENTS.filter(c=>c.license_risk!=='none').length;
  const directVuln = SBOM_COMPONENTS.filter(c=>c.dep_type==='direct'&&c.cves.length>0).length;
  const totalCves  = SBOM_COMPONENTS.reduce((s,c)=>s+c.cves.length,0);
  return { totalComps, withCves, eolComps, licRisk, directVuln, totalCves };
}

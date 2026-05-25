
import { VULNS }        from './data/vulns.js';
import { ASSETS }       from './data/assets.js';
import { INTEGRATIONS } from './data/integrations.js';
import { CICD_FINDINGS, PIPELINE_GATES }  from './data/cicd.js';
import { SUPPLIERS, SUPPLIER_VULNS }      from './data/suppliers.js';
import { COMPLIANCE_CONTROLS, PLAYBOOKS } from './data/playbooks.js';
import { MONTHLY_TRENDS, MTTR_BY_TEAM, KRI_ALERTS } from './data/trends.js';
import { computeRiskScore, getRiskColor, explainScore, getRiskLabel } from './utils/scoring.js';
import { getSlaRemaining, getEscalationLevel }          from './utils/sla.js';
import { sevPill, statusPill, slaBar, envPill, formatDate } from './utils/helpers.js';
import { estimateFinancialImpact, totalFinancialExposure, formatBRL } from './utils/financial.js';
import { AUDIT_BASE, getAuditTrail } from './data/audit.js';
import { RT_FINDINGS, RT_ENGAGEMENTS, getRTTypeLabel, computeRTScore } from './data/redteam.js';
import { BB_FINDINGS, BB_PROGRAM, getBBStatusMeta, getDisclosureDays }  from './data/bugbounty.js';
import { CONTROL_GAPS, getGapTypeMeta }                                 from './data/gaps.js';
import { PATCH_CAMPAIGNS, MAINTENANCE_WINDOWS, PATCH_RECORDS, PATCH_VELOCITY, getPatchDebt, getCampaignTypeLabel, getPatchStatusMeta } from './data/patches.js';
import { EXTERNAL_ASSETS, ASM_CATEGORIES, ASM_TIMELINE, getAsmScore, getCertStatus, getHeadersGrade } from './data/asm.js';
import { SBOM_APPS, SBOM_COMPONENTS, LICENSE_RISKS, getSbomStats } from './data/sbom.js';
import { FP_RECORDS, FP_SCANNER_STATS, getFPStats }                    from './data/fpw.js';
import { WAR_ROOM_INCIDENTS }              from './data/warroom.js';
import { CROWN_JEWELS, getProtectionColor, getDifficultyLabel } from './data/crownj.js';

import { NAVIGATION, ROUTE_ALIASES, HASH_ROUTES, HASH_TO_VIEW } from './config/navigation.js';
import { t, setLang, getLang } from './config/i18n.js';
import { loadPreferences, savePreference, loadReportHistory, saveReportHistory, loadFPRecords, resetAllPreferences } from './state/persistence.js';

// ── INIT ──────────────────────────────────────────────────────────────────────
VULNS.forEach(v => {
  if (!v.final_score) v.final_score = computeRiskScore(v);
  v._fin = estimateFinancialImpact(v);
});
const RC = s => getRiskColor(s), FMT = formatBRL;

// ── STATE ─────────────────────────────────────────────────────────────────────
let VIEW='dashboard', FS='ALL', FST='ALL', FSQ='';
let EXCS = [
  {id:'EXC-001',vid:'SCA-2024-LOG4J',st:'approved', owner:'fernanda.rocha@corp.com',appr:'ciso@corp.com',ctrl:'WAF + Network isolation',just:'Migração Q3/2024 planejada.',cr:'2024-04-08',exp:'2024-07-08'},
  {id:'EXC-002',vid:'CVE-2024-27198',st:'approved', owner:'camila.gomes@corp.com',appr:'infra-mgr@corp.com',ctrl:'Network isolation + MFA',just:'TeamCity isolado + MFA.',cr:'2024-04-23',exp:'2024-06-23'},
  {id:'EXC-003',vid:'LOW-2024-002',  st:'pending',  owner:'juliana.campos@corp.com',appr:null,ctrl:'',just:'Budget Q2 pendente.',cr:'2024-05-15',exp:'2024-08-15'},
];
let AH = [{role:'ai',text:'Olá! Sou o **Agente RBVM** com acesso completo à plataforma.\n\nVisibilidade: vulnerabilidades, ativos, SLAs, compliance (NIST, PCI, ISO, LGPD, CMN 4.893), CI/CD, fornecedores, MTTR e KRIs.\n\n**Como posso ajudar?**'}];

// ── HELPERS ───────────────────────────────────────────────────────────────────
const filt = () => VULNS.filter(v => {
  if (FS !=='ALL' && v.sev!==FS) return false;
  if (FST!=='ALL' && v.status!==FST) return false;
  if (FSQ) { const s=FSQ.toLowerCase(); if(![v.id,v.title,v.team,v.asset,v.owner,v.ticket||'',v.source].join(' ').toLowerCase().includes(s)) return false; }
  return true;
});

const q = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
function upd() {
  const a=VULNS.filter(v=>v.status!=='Resolved');
  q('pc-n',a.filter(v=>v.sev==='CRITICAL').length); q('ps-n',a.filter(v=>v.sla_used>=v.sla_max).length);
  q('pb-n',PIPELINE_GATES.filter(g=>g.status==='blocked').length);
  q('sb-kev',a.filter(v=>v.kev).length); q('sb-tot',a.length);
  q('sb-sla',a.filter(v=>v.sla_used>=v.sla_max).length);
  q('sb-exc',EXCS.filter(e=>e.st==='pending').length);
  q('sb-cicd',CICD_FINDINGS.filter(f=>f.status==='open').length);
  q('sb-sup',SUPPLIER_VULNS.filter(v=>v.status==='Overdue'||v.status==='New').length);
  q('sb-pb',PLAYBOOKS.filter(p=>p.status==='active').length);
  const sbomSt=getSbomStats(); q('sb-sbom',sbomSt.withCves);
  const fpSt=getFPStats();     q('sb-fp',fpSt.pending);
  const shadowCount=EXTERNAL_ASSETS.filter(a=>a.shadow).length;
  q('sb-asm',shadowCount>0?shadowCount+'!':EXTERNAL_ASSETS.length);
  const urgentPatches=PATCH_CAMPAIGNS.filter(c=>c.status==='in_progress'&&c.priority==='P0').length;
  q('sb-patch',urgentPatches>0?urgentPatches+'!':PATCH_CAMPAIGNS.filter(c=>c.status!=='completed').length);
  q('sb-rpt',RPT_HISTORY.length||'NEW');
  const offCrit=RT_FINDINGS.filter(f=>f.severity==='CRITICAL').length+BB_FINDINGS.filter(f=>f.severity==='CRITICAL').length;
  const offRetest=RT_FINDINGS.filter(f=>f.retest_status==='Scheduled'||f.retest_status==='Failed').length;
  q('sb-off',offCrit>0?offCrit+'!':RT_FINDINGS.length+BB_FINDINGS.length);
}

// ── NAVIGATION ────────────────────────────────────────────────────────────────
window.setView = (v, pushHash=true) => {
  // Handle route aliases (bugbounty→offensive/bugbounty tab, etc.)
  if (ROUTE_ALIASES[v]) {
    const alias = ROUTE_ALIASES[v];
    VIEW = alias.view;
    if (alias.tabKey === 'OFT_TAB') OFT_TAB = alias.tabVal;
  } else {
    VIEW = v;
  }
  FS='ALL'; FST='ALL'; FSQ='';
  if (pushHash) {
    const hash = HASH_ROUTES[v] || v;
    if (window.location.hash !== '#/' + hash) {
      window.history.pushState(null, '', '#/' + hash);
    }
  }
  closeDov();
  render();
};
window.fBySev = s => { FS=s; setView('vulns'); };
window.gS = s => { FSQ=s; if(s.length>1) render(); };
window.sf  = s => { FS=s;  render(); };
window.sft = s => { FST=s; render(); };

// ── RENDER ────────────────────────────────────────────────────────────────────
function renderSidebar() {
  return NAVIGATION.map(section => `
    <div class="sb-lbl">${t(section.labelKey)}</div>
    <div class="sb-sec">
      ${section.items.map(item => {
        const effectiveView = item.alias ? item.alias.view : item.id;
        const tabMatch = !item.alias || (
          item.alias.tabKey === 'OFT_TAB' ? OFT_TAB === item.alias.tab : true
        );
        const isActive = VIEW === effectiveView && tabMatch;
        return `<div class="sb-it ${isActive ? 'active' : ''}" id="nav-${item.id}" onclick="setView('${item.id}')">
          <i class="ti ${item.icon}"></i>${t(item.labelKey)}
          ${item.badgeId ? `<span class="sb-n ${item.badgeCls || 'ni'}" id="${item.badgeId}">—</span>` : ''}
        </div>`;
      }).join('')}
    </div>
  `).join('');
}

function render() {
  upd();
  // Rebuild sidebar (reflects current view, language, badge counts)
  const sb = document.getElementById('sidebar-inner');
  if (sb) sb.innerHTML = renderSidebar();
  const M={dashboard,threatintel,metrics,vulns,assets,suppliers,playbooks,reclassify,exceptions,sla,cicd,compliance,comms,risk,integrations,agent,settings,lifecycle,dataquality,execintel,smartgroup,warroom,crownj,sbom,fpw,asm,patch,rptexport,offensive};
  document.getElementById('main').innerHTML=(M[VIEW]||dashboard)();
  if(VIEW==='agent') rMsgs(false);
}

// ── SHARED HTML HELPERS ───────────────────────────────────────────────────────
const SP  = s => sevPill(s);
const STP = s => statusPill(s);
const SB  = v => slaBar(v);
const EP  = e => envPill(e);
const FD  = d => formatDate(d);
const rpill = (cls,txt) => `<span class="pill ${cls}" style="font-size:9px">${txt}</span>`;
const kevBadge = v => v.kev ? rpill('pc','KEV') : v.exploit ? rpill('ph','EXPLOIT') : '<span style="color:var(--text3)">—</span>';
const epss = v => v.epss!=null ? `<span style="color:${v.epss>=.9?'var(--crit)':v.epss>=.7?'var(--high)':'var(--text3)'};font-weight:700">${(v.epss*100).toFixed(0)}%</span>` : '—';

// ── SVG BAR CHART ─────────────────────────────────────────────────────────────
function barChart(data,h=60){
  const mx=Math.max(...data.map(m=>m.opened)),bw=32,gap=8,tot=data.length*(bw*2+gap+4);
  const bars=data.map((m,i)=>{
    const x=i*(bw*2+gap+4),h1=Math.max(2,(m.opened/mx)*h),h2=Math.max(2,(m.closed/mx)*h);
    return `<rect x="${x}" y="${h-h1}" width="${bw-2}" height="${h1}" rx="2" fill="var(--crit)" opacity=".75"/>
            <rect x="${x+bw+2}" y="${h-h2}" width="${bw-2}" height="${h2}" rx="2" fill="var(--success)" opacity=".75"/>
            <text x="${x+bw}" y="${h+14}" text-anchor="middle" font-size="9" fill="var(--text3)">${m.label}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${tot} ${h+18}" style="width:100%" xmlns="http://www.w3.org/2000/svg">${bars}</svg>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 1 — DASHBOARD EXECUTIVO
// ══════════════════════════════════════════════════════════════════════════════
function dashboard() {
  const a=VULNS.filter(v=>v.status!=='Resolved');
  const crit=a.filter(v=>v.sev==='CRITICAL').length, kev=a.filter(v=>v.kev).length;
  const br=a.filter(v=>v.sla_used>=v.sla_max).length, expl=a.filter(v=>v.exploit).length;
  const res=VULNS.filter(v=>v.status==='Resolved').length, rc=VULNS.filter(v=>v.reclassify_reason).length;
  const totalFin=FMT(totalFinancialExposure(VULNS));
  const byBU={}; a.forEach(v=>{byBU[v.bu]=(byBU[v.bu]||0)+1;});
  const blk=PIPELINE_GATES.filter(g=>g.status==='blocked').length;
  return `<div class="content">
  <div class="g6">
    <div class="mt"><div class="mt-l">Exposição Financeira</div><div class="mt-v vc" style="font-size:18px">${totalFin}</div><div class="mt-s">Risco ativo estimado</div></div>
    <div class="mt"><div class="mt-l">Críticas Ativas</div><div class="mt-v vc">${crit}</div><div class="mt-t tu">↑ 3 esta semana</div></div>
    <div class="mt"><div class="mt-l">CISA KEV</div><div class="mt-v vc">${kev}</div><div class="mt-s">Exploração confirmada</div></div>
    <div class="mt"><div class="mt-l">SLA Vencido</div><div class="mt-v vc">${br}</div><div class="mt-t tu">Ação imediata</div></div>
    <div class="mt"><div class="mt-l">Exploit Ativo</div><div class="mt-v vh">${expl}</div><div class="mt-s">Prioridade máxima</div></div>
    <div class="mt"><div class="mt-l">Resolvidas</div><div class="mt-v vk">${res}</div><div class="mt-t td2">↑ 2 esta semana</div></div>
  </div>
  ${kev>0?`<div class="nt nc-"><i class="ti ti-alert-octagon" style="font-size:16px;flex-shrink:0"></i><strong>${kev} CISA KEV ativas</strong> — exploração confirmada. SLA emergencial 72h.<button class="btn btn-s btn-d" style="margin-left:auto" onclick="setView('threatintel')">Threat Intel →</button></div>`:''}
  ${blk>0?`<div class="nt nw"><i class="ti ti-git-branch" style="font-size:16px;flex-shrink:0"></i><strong>${blk} pipelines bloqueados</strong> por vulnerabilidades críticas.<button class="btn btn-s" style="margin-left:auto" onclick="setView('cicd')">CI/CD →</button></div>`:''}
  <div class="g2">
    <div class="card">
      <div class="card-hd"><i class="ti ti-route" style="color:var(--accent)"></i><div><div class="card-t">Pipeline RBVM</div><div class="card-s">Ciclo de vida das vulnerabilidades</div></div></div>
      <div class="card-bd">
        <div class="pv">
          <div class="pvs"><div class="pvi done"><i class="ti ti-radar"></i></div><div class="pvn">Descoberta</div><div class="pvc">${ASSETS.length} ativos</div></div>
          <div class="pva"><i class="ti ti-chevron-right"></i></div>
          <div class="pvs"><div class="pvi done"><i class="ti ti-chart-bar"></i></div><div class="pvn">Risk Scoring</div><div class="pvc">Multicritério</div></div>
          <div class="pva"><i class="ti ti-chevron-right"></i></div>
          <div class="pvs"><div class="pvi ${rc>0?'act_':'done'}"><i class="ti ti-adjustments"></i></div><div class="pvn">Enriquecimento</div><div class="pvc">${rc} ajustes</div></div>
          <div class="pva"><i class="ti ti-chevron-right"></i></div>
          <div class="pvs"><div class="pvi ${br>0?'wrn':'done'}"><i class="ti ti-ticket"></i></div><div class="pvn">Ticketing SLA</div><div class="pvc">${br} vencidos</div></div>
          <div class="pva"><i class="ti ti-chevron-right"></i></div>
          <div class="pvs"><div class="pvi wrn"><i class="ti ti-tools"></i></div><div class="pvn">Remediação</div><div class="pvc">Em progresso</div></div>
          <div class="pva"><i class="ti ti-chevron-right"></i></div>
          <div class="pvs"><div class="pvi idle"><i class="ti ti-shield-check"></i></div><div class="pvn">Validação API</div><div class="pvc">${res} fechadas</div></div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-hd"><i class="ti ti-building" style="color:var(--accent)"></i><div><div class="card-t">Risco por Business Unit</div><div class="card-s">Vulnerabilidades ativas</div></div></div>
      <div class="card-bd" style="display:flex;flex-direction:column;gap:8px">
        ${Object.entries(byBU).sort((a,b)=>b[1]-a[1]).map(([bu,n])=>{const p=Math.round(n/a.length*100);return`<div><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px"><span style="color:var(--text2)">${bu}</span><span style="color:var(--text3)">${n} (${p}%)</span></div><div class="pb"><div class="pbf" style="width:${p}%;background:${p>40?'var(--crit)':p>25?'var(--high)':'var(--accent)'}"></div></div></div>`;}).join('')}
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-alert-triangle" style="color:var(--crit)"></i><div><div class="card-t">Críticas — Ação Imediata</div><div class="card-s">Por score, impacto financeiro e SLA</div></div><div class="card-ac"><button class="btn btn-s" onclick="setView('vulns')">Ver todas →</button></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Ticket</th><th>Vulnerabilidade</th><th>Score</th><th>Impacto</th><th>KEV</th><th>MITRE</th><th>SLA</th><th>Status</th><th></th></tr></thead>
      <tbody>${VULNS.filter(v=>v.status!=='Resolved'&&v.sev==='CRITICAL').sort((a,b)=>b.final_score-a.final_score).slice(0,6).map(v=>`
      <tr class="tr" onclick="openDov('${v.id}')">
        <td class="mono">${v.ticket||v.id}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
        <td><span style="color:${RC(v.final_score)};font-weight:700">${v.final_score}</span></td>
        <td style="font-size:11px;font-weight:600;color:${v._fin.category==='Crítico'?'var(--crit)':v._fin.category==='Alto'?'var(--high)':'var(--text2)'}">${v._fin.label}</td>
        <td>${kevBadge(v)}</td>
        <td style="font-size:10px;color:var(--text3)">${v.mitre_technique||'—'}</td>
        <td>${SB(v)}</td>
        <td>${STP(v.status)}</td>
        <td><button class="btn btn-s" onclick="event.stopPropagation();openDov('${v.id}')"><i class="ti ti-arrow-right"></i></button></td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div>
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 2 — THREAT INTELLIGENCE
// ══════════════════════════════════════════════════════════════════════════════
function threatintel() {
  const kevs=VULNS.filter(v=>v.kev&&v.status!=='Resolved');
  const hi=VULNS.filter(v=>v.epss>=0.7&&!v.kev&&v.status!=='Resolved').sort((a,b)=>b.epss-a.epss);
  return `<div class="content">
  <div class="g6">
    <div class="mt"><div class="mt-l">CISA KEV Ativas</div><div class="mt-v vc">${kevs.length}</div><div class="mt-s">Exploração confirmada</div></div>
    <div class="mt"><div class="mt-l">EPSS ≥ 70%</div><div class="mt-v vh">${hi.length}</div><div class="mt-s">Alta prob. exploração</div></div>
    <div class="mt"><div class="mt-l">Com Exploit</div><div class="mt-v vh">${VULNS.filter(v=>v.exploit&&v.status!=='Resolved').length}</div><div class="mt-s">Exploit público</div></div>
    <div class="mt"><div class="mt-l">RCE Ativas</div><div class="mt-v vc">${VULNS.filter(v=>v.rce&&v.status!=='Resolved').length}</div><div class="mt-s">Remote Code Exec.</div></div>
    <div class="mt"><div class="mt-l">Internet-Facing</div><div class="mt-v vh">${VULNS.filter(v=>v.internet_facing&&v.status!=='Resolved').length}</div><div class="mt-s">Expostas externamente</div></div>
    <div class="mt"><div class="mt-l">Exposição KEVs</div><div class="mt-v vc" style="font-size:16px">${FMT(totalFinancialExposure(kevs))}</div><div class="mt-s">Risco estimado</div></div>
  </div>
  <div class="nt ni-"><i class="ti ti-satellite" style="font-size:16px;flex-shrink:0"></i><strong>Fontes ativas:</strong> CISA KEV · EPSS/FIRST · NVD · MITRE ATT&amp;CK · GreyNoise · VulnCheck · Microsoft TI · Vendor Advisories</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-alert-octagon" style="color:var(--crit)"></i><div><div class="card-t">CISA KEV — Known Exploited Vulnerabilities</div><div class="card-s">Exploração ativa confirmada em ambiente real — SLA emergencial: 72h internet-facing</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>CVE</th><th>Vulnerabilidade</th><th>EPSS</th><th>RCE</th><th>Ativo</th><th>Impacto (BRL)</th><th>MITRE</th><th>SLA</th><th>Ações</th></tr></thead>
      <tbody>${kevs.map(v=>`<tr class="tr" onclick="openDov('${v.id}')">
        <td class="mono" style="color:var(--crit)">${v.id}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
        <td>${epss(v)}</td>
        <td>${v.rce?rpill('pc','RCE'):'<span style="color:var(--text3)">—</span>'}</td>
        <td style="font-size:11px;color:var(--text2)">${v.asset}</td>
        <td style="color:var(--crit);font-size:11px;font-weight:600">${v._fin.label}</td>
        <td style="font-size:10px;color:var(--text3)">${v.mitre_technique||'—'}</td>
        <td>${SB(v)}</td>
        <td><div class="btn-g">
          <button class="btn btn-s btn-d" onclick="event.stopPropagation();escalate('${v.id}')"><i class="ti ti-arrow-up"></i>Escalar</button>
          <button class="btn btn-s" onclick="event.stopPropagation();triggerPB('${v.id}')"><i class="ti ti-player-play"></i></button>
        </div></td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div>
  ${hi.length>0?`<div class="card">
    <div class="card-hd"><i class="ti ti-eye" style="color:var(--high)"></i><div><div class="card-t">EPSS Alto — Não estão no KEV (≥ 70%)</div><div class="card-s">Monitorar — risco crescente de exploração</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>CVE</th><th>Vulnerabilidade</th><th>CVSS</th><th>EPSS</th><th>Ativo</th><th>SLA</th></tr></thead>
      <tbody>${hi.slice(0,5).map(v=>`<tr class="tr" onclick="openDov('${v.id}')">
        <td class="mono" style="color:var(--high)">${v.id}</td>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.title}</td>
        <td class="mono">${v.cvss}</td>
        <td><span style="color:var(--high);font-weight:700">${(v.epss*100).toFixed(0)}%</span></td>
        <td style="font-size:11px;color:var(--text2)">${v.asset}</td>
        <td>${SB(v)}</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div>`:''}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 3 — MÉTRICAS & MTTR
// ══════════════════════════════════════════════════════════════════════════════
function metrics() {
  const lm=MONTHLY_TRENDS[MONTHLY_TRENDS.length-1], pm=MONTHLY_TRENDS[MONTHLY_TRENDS.length-2];
  const dt=((lm.mttr_crit-pm.mttr_crit)/pm.mttr_crit*100).toFixed(1);
  return `<div class="content">
  <div class="g6">
    <div class="mt"><div class="mt-l">MTTR — Críticas</div><div class="mt-v vh">${lm.mttr_crit}d</div><div class="mt-t ${lm.mttr_crit<pm.mttr_crit?'td2':'tu'}">${dt<0?'↓':'↑'} ${Math.abs(dt)}% vs mês anterior</div></div>
    <div class="mt"><div class="mt-l">MTTR — Altas</div><div class="mt-v vh">${lm.mttr_high}d</div><div class="mt-s">Meta: ≤20d</div></div>
    <div class="mt"><div class="mt-l">SLA Compliance</div><div class="mt-v vk">${Math.round(lm.sla_compliance*100)}%</div><div class="mt-t td2">↑ ${Math.round((lm.sla_compliance-pm.sla_compliance)*100)}pp mês</div></div>
    <div class="mt"><div class="mt-l">Ativos Cobertos</div><div class="mt-v vk">89%</div><div class="mt-s">187/210</div></div>
    <div class="mt"><div class="mt-l">Pipelines com Gate</div><div class="mt-v vh">74%</div><div class="mt-s">28/38</div></div>
    <div class="mt"><div class="mt-l">Sem Owner</div><div class="mt-v vc">14</div><div class="mt-s">Requer ação</div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-hd"><i class="ti ti-chart-bar" style="color:var(--accent)"></i><div><div class="card-t">Abertas vs Fechadas — 6 meses</div><div class="card-s"><span style="color:var(--crit)">■</span> Abertas &nbsp;<span style="color:var(--success)">■</span> Fechadas</div></div></div>
      <div class="card-bd">${barChart(MONTHLY_TRENDS)}</div>
    </div>
    <div class="card">
      <div class="card-hd"><i class="ti ti-clock-play" style="color:var(--accent)"></i><div><div class="card-t">MTTR por Time</div><div class="card-s">Dias para remediar críticas · meta ≤7d</div></div></div>
      <div class="card-bd" style="display:flex;flex-direction:column;gap:8px">
        ${MTTR_BY_TEAM.sort((a,b)=>b.mttr_crit-a.mttr_crit).map(t=>{const mx=Math.max(...MTTR_BY_TEAM.map(x=>x.mttr_crit)); return`<div><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px"><span style="color:var(--text2)">${t.team}</span><span style="color:${t.mttr_crit>10?'var(--high)':'var(--success)'};font-weight:700">${t.mttr_crit}d · ${Math.round(t.sla_rate*100)}% SLA</span></div><div class="pb"><div class="pbf" style="width:${Math.round(t.mttr_crit/mx*100)}%;background:${t.mttr_crit>12?'var(--crit)':t.mttr_crit>8?'var(--high)':'var(--success)'}"></div></div></div>`;}).join('')}
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-urgent" style="color:var(--crit)"></i><div><div class="card-t">Key Risk Indicators (KRIs)</div><div class="card-s">BREACH = ação imediata da liderança · WARN = monitorar</div></div></div>
    <div class="card-bd" style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      ${KRI_ALERTS.map(k=>`<div class="kri ${k.status}"><div style="flex:1"><div style="font-size:11px;font-weight:600">${k.label}</div><div style="font-size:10px;color:var(--text3)">Threshold: ${k.threshold} · Atual: ${k.value} ${k.unit}</div></div><span class="pill ${k.status==='breach'?'pc':'ph'}" style="font-size:9px">${k.status.toUpperCase()}</span></div>`).join('')}
    </div>
  </div>
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 4 — VULNERABILIDADES
// ══════════════════════════════════════════════════════════════════════════════
function vulns() {
  const f=filt();
  return `<div>
  <div class="frow">
    <span style="font-size:11px;color:var(--text3);font-weight:600">SEV:</span>
    ${['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(s=>`<div class="fc ${FS===s?'act':''}" onclick="sf('${s}')">${s==='ALL'?'Todas':s}</div>`).join('')}
    <span style="font-size:11px;color:var(--text3);font-weight:600;margin-left:8px">STATUS:</span>
    ${['ALL','New','In Progress','Resolved','Awaiting Validation'].map(s=>`<div class="fc ${FST===s?'act':''}" onclick="sft('${s}')">${s==='ALL'?'Todos':s}</div>`).join('')}
    <span style="margin-left:auto;font-size:11px;color:var(--text3)">${f.length} resultado(s)</span>
  </div>
  <div style="padding:12px 16px">
    <div class="tbl"><table>
      <thead><tr><th>Ticket</th><th>Vulnerabilidade</th><th>Sev.</th><th>Score</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Ativo</th><th>Impacto (BRL)</th><th>Fonte</th><th>SLA</th><th>Status</th><th></th></tr></thead>
      <tbody>${f.map(v=>`<tr class="tr" onclick="openDov('${v.id}')">
        <td class="mono" style="color:var(--text3)">${v.ticket||'—'}</td>
        <td style="max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
        <td>${SP(v.sev)}</td>
        <td><span style="color:${RC(v.final_score)};font-weight:700">${v.final_score}</span></td>
        <td class="mono" style="color:var(--text2)">${v.cvss}</td>
        <td>${epss(v)}</td>
        <td>${kevBadge(v)}</td>
        <td style="font-size:11px;color:var(--text2)">${v.asset}</td>
        <td style="font-size:10px;font-weight:600;color:${v._fin.category==='Crítico'?'var(--crit)':v._fin.category==='Alto'?'var(--high)':'var(--text3)'}">${v._fin.label}</td>
        <td style="font-size:10px;color:var(--text3)">${v.source}</td>
        <td>${SB(v)}</td>
        <td>${STP(v.status)}</td>
        <td><button class="btn btn-s" onclick="event.stopPropagation();openDov('${v.id}')"><i class="ti ti-arrow-right"></i></button></td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 5 — ATIVOS
// ══════════════════════════════════════════════════════════════════════════════
function assets() {
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Total Ativos</div><div class="mt-v vi">${ASSETS.length}</div><div class="mt-s">187 com scan recente</div></div>
    <div class="mt"><div class="mt-l">Internet-Facing</div><div class="mt-v vc">${ASSETS.filter(a=>a.internet_facing).length}</div></div>
    <div class="mt"><div class="mt-l">PCI Scope</div><div class="mt-v vh">${ASSETS.filter(a=>a.pci_scope).length}</div></div>
    <div class="mt"><div class="mt-l">EOL / EOS</div><div class="mt-v vc">${ASSETS.filter(a=>a.eol).length}</div><div class="mt-s">Em produção</div></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-server" style="color:var(--accent)"></i><div><div class="card-t">Inventário de Ativos</div><div class="card-s">Owner · criticidade · exposição · cobertura de scan</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>ID</th><th>Ativo</th><th>Tipo</th><th>Ambiente</th><th>Crit.</th><th>Owner</th><th>Internet</th><th>PCI</th><th>LGPD</th><th>Scan</th><th>Vulns</th><th>Score</th></tr></thead>
      <tbody>${ASSETS.map(a=>`<tr class="tr">
        <td class="mono" style="color:var(--text3)">${a.id}</td>
        <td style="font-weight:500">${a.hostname}${a.eol?rpill('pc','EOL')+" ":''}</td>
        <td style="font-size:11px;color:var(--text2)">${a.type}</td>
        <td>${EP(a.env)}</td>
        <td>${SP({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW'}[a.criticality]||'LOW')}</td>
        <td style="font-size:10px;color:var(--text2)">${a.owner}</td>
        <td>${a.internet_facing?rpill('pc','SIM'):'<span style="color:var(--text3)">—</span>'}</td>
        <td>${a.pci_scope?rpill('pnist','PCI'):'—'}</td>
        <td>${a.lgpd_scope?rpill('pai','LGPD'):'—'}</td>
        <td style="font-size:10px;color:var(--text3)">${FD(a.last_scan)}</td>
        <td style="font-weight:700;color:${a.open_vulns>0?'var(--crit)':'var(--success)'}">${a.open_vulns}</td>
        <td><span style="color:${RC(a.risk_score)};font-weight:700">${a.risk_score}</span></td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 6 — FORNECEDORES
// ══════════════════════════════════════════════════════════════════════════════
function suppliers() {
  const rm={critical:'pc',high:'ph',medium:'pm',low:'pl'};
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Tier 1 Críticos</div><div class="mt-v vh">${SUPPLIERS.filter(s=>s.tier===1).length}</div></div>
    <div class="mt"><div class="mt-l">Risco Crítico/Alto</div><div class="mt-v vc">${SUPPLIERS.filter(s=>s.risk==='critical'||s.risk==='high').length}</div></div>
    <div class="mt"><div class="mt-l">Vulns em Fornecedores</div><div class="mt-v vh">${SUPPLIER_VULNS.filter(v=>v.status!=='Resolved').length}</div></div>
    <div class="mt"><div class="mt-l">Assessments Vencidos</div><div class="mt-v vc">${SUPPLIERS.filter(s=>new Date(s.next_assessment)<new Date()).length}</div></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-building-factory-2" style="color:var(--accent)"></i><div><div class="card-t">Supply Chain Risk — Fornecedores Críticos</div><div class="card-s">Tier 1/2 · PCI · LGPD · dados compartilhados</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Fornecedor</th><th>Categoria</th><th>Tier</th><th>Risco</th><th>Score</th><th>Vulns</th><th>PCI</th><th>LGPD</th><th>Próx. Assess.</th><th>SLA</th></tr></thead>
      <tbody>${SUPPLIERS.map(s=>`<tr class="tr">
        <td style="font-weight:500">${s.name}</td>
        <td style="font-size:11px;color:var(--text2)">${s.category}</td>
        <td style="font-size:11px;color:var(--text3)">Tier ${s.tier}</td>
        <td>${rpill(rm[s.risk]||'pi',s.risk.toUpperCase())}</td>
        <td><span style="color:${RC(s.score)};font-weight:700">${s.score}</span></td>
        <td style="color:${s.vulns_critical>0?'var(--crit)':s.vulns_open>0?'var(--high)':'var(--success)'};font-weight:700">${s.vulns_open} (${s.vulns_critical} crit)</td>
        <td>${s.pci_scope?rpill('pnist','PCI'):'—'}</td>
        <td>${s.lgpd_scope?rpill('pai','LGPD'):'—'}</td>
        <td style="font-size:11px;color:${new Date(s.next_assessment)<new Date()?'var(--crit)':'var(--text3)'}">${FD(s.next_assessment)}</td>
        <td style="font-size:11px;color:var(--text3)">${s.sla_days}d</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-bug" style="color:var(--high)"></i><div><div class="card-t">Vulnerabilidades em Fornecedores</div><div class="card-s">Plano formal · SLA · acompanhamento · impacto</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>ID</th><th>Fornecedor</th><th>Vulnerabilidade</th><th>Sev.</th><th>Reportada</th><th>SLA</th><th>Status</th><th>Impacto</th></tr></thead>
      <tbody>${SUPPLIER_VULNS.map(sv=>{const sup=SUPPLIERS.find(s=>s.id===sv.supplier_id)||{};return`<tr class="tr"><td class="mono" style="color:var(--text3)">${sv.vuln_id}</td><td style="font-size:11px">${sup.name||sv.supplier_id}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${sv.title}</td><td>${SP(sv.sev)}</td><td style="font-size:11px;color:var(--text3)">${FD(sv.reported)}</td><td style="font-size:11px;color:${new Date(sv.sla)<new Date()?'var(--crit)':'var(--text3)'}">${FD(sv.sla)}</td><td>${rpill(sv.status==='Overdue'?'pc':sv.status==='In Progress'?'pp':'pn',sv.status)}</td><td style="color:var(--high);font-size:11px;font-weight:600">${sv.financial_impact}</td></tr>`;}).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 7 — PLAYBOOKS
// ══════════════════════════════════════════════════════════════════════════════
function playbooks() {
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Ativos</div><div class="mt-v vi">${PLAYBOOKS.filter(p=>p.status==='active').length}</div></div>
    <div class="mt"><div class="mt-l">Standby</div><div class="mt-v vt">${PLAYBOOKS.filter(p=>p.status==='standby').length}</div></div>
    <div class="mt"><div class="mt-l">Passos Automáticos</div><div class="mt-v vk">${PLAYBOOKS.flatMap(p=>p.steps).filter(s=>s.auto).length}</div></div>
    <div class="mt"><div class="mt-l">Vulns Cobertas</div><div class="mt-v vh">${[...new Set(PLAYBOOKS.flatMap(p=>p.vulns))].length}</div></div>
  </div>
  ${PLAYBOOKS.map(pb=>{
    const dn=pb.steps.filter(s=>s.done).length, tot=pb.steps.length, pct=Math.round(dn/tot*100);
    return `<div class="card">
      <div class="card-hd"><i class="ti ${pb.icon}" style="color:${pb.color}"></i><div><div class="card-t">${pb.name}</div><div class="card-s" style="font-size:10px"><code style="color:var(--accent);font-size:10px">${pb.trigger}</code></div></div>
        <div class="card-ac">${rpill(pb.status==='active'?'ph':'pn',pb.status.toUpperCase())}<span style="font-size:11px;color:var(--text3);margin-left:8px">${dn}/${tot} passos · SLA ${pb.sla}</span></div></div>
      <div class="card-bd">
        ${pb.triggered?`<div style="font-size:11px;color:var(--text2);margin-bottom:8px">Acionado ${FD(pb.triggered)} · Vulns: ${pb.vulns.join(', ')||'—'}</div>`:''}
        <div style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text3);margin-bottom:3px"><span>Progresso</span><span>${pct}%</span></div><div class="pb" style="height:4px"><div class="pbf" style="width:${pct}%;background:${pct===100?'var(--success)':pb.status==='active'?'var(--accent)':'var(--text3)'}"></div></div></div>
        ${pb.steps.map(s=>{const isN=!s.done&&pb.steps.filter(x=>!x.done)[0]===s;return`<div class="pbs"><div class="pbn ${s.done?'pb-d':isN?'pb-a':'pb-i'}">${s.n}</div><div style="flex:1"><div style="font-size:11px;color:${s.done?'var(--text2)':'var(--text)'};${s.done?'text-decoration:line-through':''}">${s.label}</div><div style="font-size:9px;color:var(--text3)">${s.auto?'🤖 Automático':'👤 Manual'}</div></div>${s.done?'<i class="ti ti-check" style="color:var(--success);font-size:14px"></i>':''}</div>`;}).join('')}
      </div>
    </div>`;
  }).join('')}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 8 — RECLASSIFICAÇÃO
// ══════════════════════════════════════════════════════════════════════════════
function reclassify() {
  return `<div class="content">
  <div class="nt ni-"><i class="ti ti-info-circle" style="font-size:16px;flex-shrink:0"></i>Reclassificação ajusta o score contextual sem alterar a severidade original do scanner. Toda alteração exige justificativa técnica auditável.</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-adjustments-horizontal" style="color:var(--accent)"></i><div><div class="card-t">Reclassificação de Risco</div><div class="card-s">Score técnico original → Score ajustado por contexto de negócio</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Ticket</th><th>Vulnerabilidade</th><th>Sev.</th><th>Score Técnico</th><th>Score Final</th><th>Delta</th><th>Fatores</th><th>Justificativa</th><th></th></tr></thead>
      <tbody>${VULNS.filter(v=>v.status!=='Resolved').map(v=>{
        const o=Math.min(100,Math.round((v.cvss||0)/10*25+(v.exploit?10:0)));
        const d=v.final_score-o;
        return`<tr class="tr" onclick="openRC('${v.id}')">
          <td class="mono" style="color:var(--text3)">${v.ticket||v.id}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
          <td>${SP(v.sev)}</td>
          <td class="mono">${o}</td>
          <td><span style="color:${RC(v.final_score)};font-weight:700;font-family:var(--mono)">${v.final_score}</span></td>
          <td style="font-size:11px;font-weight:700;color:${d>0?'var(--crit)':d<0?'var(--success)':'var(--text3)'}">${d>0?'+'+d:d}</td>
          <td style="font-size:9px;color:var(--text2)">${[v.kev?'KEV':'',v.internet_facing?'Internet':'',v.compensating_controls?'Control':'',v.pci_scope?'PCI':'',v.rce?'RCE':''].filter(Boolean).join(' ')||'—'}</td>
          <td style="font-size:10px;color:var(--text2);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.reclassify_reason||'—'}</td>
          <td><button class="btn btn-s" onclick="event.stopPropagation();openRC('${v.id}')"><i class="ti ti-edit"></i></button></td>
        </tr>`;}).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 9 — EXCEÇÕES
// ══════════════════════════════════════════════════════════════════════════════
function exceptions() {
  return `<div class="content">
  <div class="nt nw"><i class="ti ti-shield-x" style="font-size:16px;flex-shrink:0"></i><strong>Atenção:</strong> Exceções não ocultam vulnerabilidades. Requerem justificativa técnica, controle compensatório, aprovação formal, prazo e revalidação periódica.</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-shield-x" style="color:var(--high)"></i><div><div class="card-t">Exceções e Aceite de Risco</div><div class="card-s">Aprovação formal com evidência e prazo de validade</div></div><div class="card-ac"><button class="btn btn-p btn-s" onclick="openModal('addexc')"><i class="ti ti-plus"></i> Nova Exceção</button></div></div>
    <div class="tbl"><table>
      <thead><tr><th>ID</th><th>Vulnerabilidade</th><th>Status</th><th>Owner</th><th>Aprovador</th><th>Controles</th><th>Criada</th><th>Expira</th></tr></thead>
      <tbody>${EXCS.map(e=>{const v=VULNS.find(x=>x.id===e.vid)||{title:e.vid};return`<tr class="tr"><td class="mono" style="color:var(--text3)">${e.id}</td><td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td><td>${rpill(e.st==='approved'?'pd':e.st==='pending'?'ph':'pc',e.st==='approved'?'Aprovada':e.st==='pending'?'Pendente':'Expirada')}</td><td style="font-size:11px;color:var(--text2)">${e.owner}</td><td style="font-size:11px;color:var(--text2)">${e.appr||'—'}</td><td style="font-size:10px;color:var(--text3)">${e.ctrl||'—'}</td><td style="font-size:11px;color:var(--text3)">${FD(e.cr)}</td><td style="font-size:11px;color:${new Date(e.exp)<new Date()?'var(--crit)':'var(--text3)'}">${FD(e.exp)}</td></tr>`;}).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 10 — GESTÃO SLA
// ══════════════════════════════════════════════════════════════════════════════
function sla() {
  const a=VULNS.filter(v=>v.status!=='Resolved');
  const br=a.filter(v=>v.sla_used>=v.sla_max), wa=a.filter(v=>v.sla_used/v.sla_max>=.75&&v.sla_used<v.sla_max);
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">SLA Vencido</div><div class="mt-v vc">${br.length}</div><div class="mt-s">Ação imediata</div></div>
    <div class="mt"><div class="mt-l">Alerta ≥75%</div><div class="mt-v vh">${wa.length}</div><div class="mt-s">Vencendo em breve</div></div>
    <div class="mt"><div class="mt-l">Compliance SLA</div><div class="mt-v vk">${Math.round((1-br.length/Math.max(a.length,1))*100)}%</div></div>
    <div class="mt"><div class="mt-l">MTTR Críticas</div><div class="mt-v vh">${MONTHLY_TRENDS[MONTHLY_TRENDS.length-1].mttr_crit}d</div><div class="mt-s">Meta: ≤7d</div></div>
  </div>
  ${br.length>0?`<div class="card">
    <div class="card-hd"><i class="ti ti-clock-x" style="color:var(--crit)"></i><div><div class="card-t">SLA Vencido — Escalonamento Ativo</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Ticket</th><th>Vulnerabilidade</th><th>Sev.</th><th>Owner</th><th>SLA</th><th>Vencido</th><th>Escalonamento</th><th>Ações</th></tr></thead>
      <tbody>${br.map(v=>{const esc=getEscalationLevel(v);return`<tr class="tr">
        <td class="mono">${v.ticket||v.id}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
        <td>${SP(v.sev)}</td>
        <td style="font-size:11px;color:var(--text2)">${v.owner}</td>
        <td>${SB(v)}</td>
        <td style="color:var(--crit);font-weight:700">+${v.sla_used-v.sla_max}d</td>
        <td style="font-size:10px;color:${esc.color}">${esc.label}</td>
        <td><div class="btn-g">
          <button class="btn btn-s" onclick="notifyOwner('${v.id}')"><i class="ti ti-send"></i>Cobrar</button>
          <button class="btn btn-s btn-d" onclick="escalate('${v.id}')"><i class="ti ti-arrow-up"></i>Escalar</button>
        </div></td>
      </tr>`;}).join('')}</tbody>
    </table></div>
  </div>`:''}
  <div class="card">
    <div class="card-hd"><i class="ti ti-clock" style="color:var(--high)"></i><div><div class="card-t">Próximos do Vencimento ≥75%</div><div class="card-s">Alertas preventivos — cobrar antes de vencer</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Ticket</th><th>Vulnerabilidade</th><th>Sev.</th><th>Owner</th><th>SLA</th><th>Restam</th><th>Impacto</th></tr></thead>
      <tbody>${wa.map(v=>`<tr class="tr" onclick="openDov('${v.id}')">
        <td class="mono">${v.ticket||v.id}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500">${v.title}</td>
        <td>${SP(v.sev)}</td>
        <td style="font-size:11px;color:var(--text2)">${v.owner}</td>
        <td>${SB(v)}</td>
        <td style="color:var(--high);font-weight:700">${getSlaRemaining(v)}d</td>
        <td style="font-size:11px;font-weight:600;color:var(--high)">${v._fin.label}</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 11 — CI/CD SECURITY
// ══════════════════════════════════════════════════════════════════════════════
function cicd() {
  const tp={secret:'pc',sast:'ph',sca:'pm',iac:'pnist',container:'pai'};
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Pipelines Bloqueados</div><div class="mt-v vc">${PIPELINE_GATES.filter(g=>g.status==='blocked').length}</div><div class="mt-s">Deploy impedido</div></div>
    <div class="mt"><div class="mt-l">Em Alerta</div><div class="mt-v vh">${PIPELINE_GATES.filter(g=>g.status==='warning').length}</div><div class="mt-s">Aprovação manual</div></div>
    <div class="mt"><div class="mt-l">Findings Abertos</div><div class="mt-v vh">${CICD_FINDINGS.filter(f=>f.status==='open').length}</div></div>
    <div class="mt"><div class="mt-l">Secrets Expostos</div><div class="mt-v vc">${CICD_FINDINGS.filter(f=>f.type==='secret'&&f.status==='open').length}</div><div class="mt-s">Revogar imediatamente</div></div>
  </div>
  <div class="nt nw"><i class="ti ti-shield-exclamation" style="font-size:16px;flex-shrink:0"></i><strong>Policy as Code ativa:</strong> SAST · SCA · Secret Scanning · IaC Scan · Container Scan. Merges bloqueados automaticamente quando risk ≥ CRITICAL com exploit disponível.</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-git-branch" style="color:var(--accent)"></i><div><div class="card-t">Security Gates por Repositório</div><div class="card-s">Status do último scan — bloqueio de deploy</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Repositório</th><th>Gates Ativos</th><th>Status</th><th>Motivo do Bloqueio</th><th>Último Scan</th><th>Ambiente</th></tr></thead>
      <tbody>${PIPELINE_GATES.map(g=>`<tr class="tr">
        <td class="mono" style="color:var(--text2)">${g.repo}</td>
        <td style="font-size:10px;color:var(--text3)">${g.gates.join(' · ')}</td>
        <td>${rpill(g.status==='blocked'?'pc':g.status==='warning'?'ph':'pd',g.status==='blocked'?'BLOQUEADO':g.status==='warning'?'ALERTA':'OK')}</td>
        <td style="font-size:11px;color:var(--text2);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${g.reason||'—'}</td>
        <td style="font-size:11px;color:var(--text3)">${g.last_run}</td>
        <td>${EP(g.env)}</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-bug" style="color:var(--high)"></i><div><div class="card-t">Findings Abertos em Pipelines</div><div class="card-s">Secrets · SAST · SCA · IaC · Container — por repositório</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>ID</th><th>Tipo</th><th>Ferramenta</th><th>Sev.</th><th>Finding</th><th>Repositório</th><th>Branch / PR</th><th>Bloqueando</th></tr></thead>
      <tbody>${CICD_FINDINGS.filter(f=>f.status==='open').map(f=>`<tr class="tr">
        <td class="mono" style="font-size:10px;color:var(--text3)">${f.id}</td>
        <td>${rpill(tp[f.type]||'pi',f.type.toUpperCase())}</td>
        <td style="font-size:10px;color:var(--text3)">${f.tool}</td>
        <td>${SP(f.sev)}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">${f.title}</td>
        <td class="mono" style="font-size:10px;color:var(--text2)">${f.repo}</td>
        <td style="font-size:10px;color:var(--text3)">${f.pr||f.branch}</td>
        <td>${f.blocking?rpill('pc','SIM'):'<span style="color:var(--text3);font-size:10px">—</span>'}</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO 12 — COMPLIANCE / GRC
// ══════════════════════════════════════════════════════════════════════════════
function compliance() {
  const fws=[...new Set(COMPLIANCE_CONTROLS.map(c=>c.fw))];
  const sc=fw=>{const c=COMPLIANCE_CONTROLS.filter(x=>x.fw===fw);return Math.round(c.filter(x=>x.status==='implemented').length/c.length*100);};
  return `<div class="content">
  <div class="g4">${fws.slice(0,4).map(fw=>{const s=sc(fw);return`<div class="mt"><div class="mt-l">${fw}</div><div class="mt-v ${s>=80?'vk':s>=60?'vh':'vc'}">${s}%</div><div class="mt-s">controles implementados</div></div>`;}).join('')}</div>
  ${fws.length>4?`<div class="g4">${fws.slice(4).map(fw=>{const s=sc(fw);return`<div class="mt"><div class="mt-l">${fw}</div><div class="mt-v ${s>=80?'vk':s>=60?'vh':'vc'}">${s}%</div><div class="mt-s">controles</div></div>`;}).join('')}</div>`:''}
  <div class="nt ni-"><i class="ti ti-certificate" style="font-size:16px;flex-shrink:0"></i><strong>Evidências auditáveis:</strong> scan reports · rescan · tickets · exceções · SLA logs · histórico de cobranças — exportáveis para auditoria interna, externa, BACEN e PCI DSS.</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-list-check" style="color:var(--accent)"></i><div><div class="card-t">Mapeamento de Controles — NIST · PCI DSS · ISO 27001 · LGPD · CMN 4.893</div><div class="card-s">Status · evidências · gaps identificados</div></div>
    <div class="card-ac"><button class="btn btn-s btn-p" onclick="quickMsg('Gere relatório completo de auditoria com mapeamento para NIST CSF 2.0, PCI DSS 4.0, ISO 27001:2022, LGPD e CMN 4.893/2021. Inclua status de cada controle, evidências disponíveis, gaps e recomendações de melhoria.')"><i class="ti ti-robot"></i> Relatório IA</button></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Framework</th><th>Controle</th><th>Descrição</th><th>Status</th><th>Evidência</th><th>Gap</th></tr></thead>
      <tbody>${COMPLIANCE_CONTROLS.map(c=>`<tr>
        <td>${rpill('pnist',c.fw.split(' ')[0])}</td>
        <td class="mono" style="font-size:10px;color:var(--accent)">${c.control}</td>
        <td style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.desc}</td>
        <td>${rpill(c.status==='implemented'?'pd':c.status==='partial'?'ph':'pc',c.status==='implemented'?'OK':c.status==='partial'?'Parcial':'Gap')}</td>
        <td style="font-size:10px;color:var(--text2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.evidence}</td>
        <td style="font-size:10px;color:${c.gap?'var(--high)':'var(--text3)'};max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.gap||'—'}</td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULOS 13-17 — COMMS · RISCO · INTEGRAÇÕES · AGENTE IA · CONFIGURAÇÕES
// ══════════════════════════════════════════════════════════════════════════════
function comms() {
  const ts=[
    {l:'Alerta Amigável (7 dias)',i:'ti-bell',c:'var(--med)',q:'Gere comunicado amigável para times com SLA vencendo em 7 dias com dados reais da plataforma'},
    {l:'Lembrete Urgente (3 dias)',i:'ti-bell-ringing',c:'var(--high)',q:'Gere lembrete urgente para SLAs críticos vencendo em 3 dias'},
    {l:'Escalação — SLA Vencido',i:'ti-alert-triangle',c:'var(--crit)',q:'Gere comunicado formal de escalação para todas as vulnerabilidades com SLA vencido, com impacto financeiro e regulatório'},
    {l:'Sumário Executivo CISO',i:'ti-briefcase',c:'var(--accent)',q:'Gere sumário executivo completo para CISO com principais riscos, KPIs, MTTR, KEVs, impacto financeiro estimado e recomendações estratégicas'},
    {l:'Relatório GRC / Auditoria',i:'ti-certificate',c:'#a084ff',q:'Gere relatório para auditoria com mapeamento NIST CSF, PCI DSS 4.0, ISO 27001:2022, LGPD e CMN 4.893 com status de controles e evidências'},
    {l:'Plano Técnico por Squad',i:'ti-code',c:'var(--success)',q:'Gere plano técnico de correção priorizado por squad com score de risco, impacto financeiro e recomendações de remediação'},
  ];
  return `<div class="content">
  <div class="nt ni-"><i class="ti ti-info-circle" style="font-size:16px;flex-shrink:0"></i>Comunicados gerados pelo Agente IA com dados reais da plataforma. Canais: Slack · Microsoft Teams · E-mail · PagerDuty.</div>
  <div class="g2">${ts.map(t=>`<div class="card" style="cursor:pointer" onclick="quickMsg('${t.q.replace(/'/g,"\\'")}')"><div class="card-hd"><i class="ti ${t.i}" style="color:${t.c}"></i><div><div class="card-t">${t.l}</div></div><div class="card-ac"><button class="btn btn-s"><i class="ti ti-robot"></i> Gerar via IA</button></div></div></div>`).join('')}
  </div></div>`;
}

function risk() {
  const bT={}; VULNS.filter(v=>v.status!=='Resolved').forEach(v=>{if(!bT[v.team])bT[v.team]={total:0,crit:0,high:0,br:0,fin:0};bT[v.team].total++;if(v.sev==='CRITICAL')bT[v.team].crit++;if(v.sev==='HIGH')bT[v.team].high++;if(v.sla_used>=v.sla_max)bT[v.team].br++;bT[v.team].fin+=v._fin.value;});
  const mF=Math.max(...Object.values(bT).map(d=>d.fin));
  return `<div class="content">
  <div class="card">
    <div class="card-hd"><i class="ti ti-chart-area" style="color:var(--accent)"></i><div><div class="card-t">Risco por Time — Vulnerabilidades + Exposição Financeira Estimada</div></div></div>
    <div class="tbl"><table>
      <thead><tr><th>Time</th><th>Total</th><th>Críticas</th><th>Altas</th><th>SLA Vencido</th><th>Exposição (BRL)</th><th>Distribuição</th></tr></thead>
      <tbody>${Object.entries(bT).sort((a,b)=>b[1].fin-a[1].fin).map(([t,d])=>`<tr class="tr">
        <td style="font-weight:500">${t}</td>
        <td style="font-weight:700">${d.total}</td>
        <td style="color:var(--crit);font-weight:700">${d.crit}</td>
        <td style="color:var(--high);font-weight:700">${d.high}</td>
        <td style="color:${d.br>0?'var(--crit)':'var(--text3)'};font-weight:700">${d.br}</td>
        <td style="font-weight:600;color:var(--high);font-size:11px">${FMT(d.fin)}</td>
        <td style="width:140px"><div class="pb"><div class="pbf" style="width:${Math.round(d.fin/mF*100)}%;background:${d.crit>0?'var(--crit)':'var(--high)'}"></div></div></td>
      </tr>`).join('')}</tbody>
    </table></div>
  </div></div>`;
}

function integrations() {
  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Conectadas</div><div class="mt-v vk">${INTEGRATIONS.filter(i=>i.status==='connected').length}</div></div>
    <div class="mt"><div class="mt-l">Parcial</div><div class="mt-v vh">${INTEGRATIONS.filter(i=>i.status==='partial').length}</div></div>
    <div class="mt"><div class="mt-l">Desconectadas</div><div class="mt-v vc">${INTEGRATIONS.filter(i=>i.status==='off').length}</div></div>
    <div class="mt"><div class="mt-l">Findings Ativos</div><div class="mt-v vi">${INTEGRATIONS.reduce((s,i)=>s+(i.findings||0),0)}</div></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-plug" style="color:var(--accent)"></i><div><div class="card-t">Status das Integrações</div><div class="card-s">Tenable · Qualys · Snyk · Wiz · GitHub · BloodHound · Jira · Slack · Teams</div></div></div>
    <div class="card-bd">
      <div class="int-grid">
        ${INTEGRATIONS.map(i=>`<div class="int-c">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="width:36px;height:36px;border-radius:var(--r);background:var(--bg4);display:flex;align-items:center;justify-content:center;font-size:18px;color:${i.color}"><i class="ti ${i.icon}"></i></div>
            <div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:600">${i.name}</div><div style="font-size:10px;color:var(--text3)">${i.type}</div></div>
          </div>
          <div style="display:flex;align-items:center;gap:5px;font-size:11px">
            <div class="idd ${i.status==='connected'?'d-on':i.status==='partial'?'d-pt':'d-off'}"></div>
            <span style="color:${i.status==='connected'?'var(--success)':i.status==='partial'?'var(--high)':'var(--text3)'}">${i.status==='connected'?'Conectada':i.status==='partial'?'Parcial':'Desconectada'}</span>
          </div>
          <div style="font-size:10px;color:var(--text3)">${i.last_sync||'—'}</div>
          ${i.findings!=null?`<div style="font-size:10px;color:var(--text2)">${i.findings} findings</div>`:''}
          ${i.note?`<div style="font-size:10px;color:var(--high)">${i.note}</div>`:''}
          <button class="btn btn-s" onclick="syncNow('${i.name}')"><i class="ti ti-refresh"></i> Sync</button>
        </div>`).join('')}
      </div>
    </div>
  </div></div>`;
}

function agent() {
  const qs=['Explique os 5 maiores riscos ao CISO','Sumário executivo para comitê de risco','Compare MTTR e SLA dos times','KEVs com impacto financeiro estimado','Quais vulns vão para comitê executivo?','Plano priorizado de correção por squad','Compliance PCI DSS 4.0 e LGPD','Fornecedores com maior risco','Escalação para SLAs vencidos','Impacto financeiro total das vulns','Padrão de reincidência nos times','Campanhas de correção por tecnologia'];
  return `<div class="content" style="height:calc(100vh - var(--th) - 40px);display:flex;flex-direction:column">
  <div class="card" style="flex:1;display:flex;flex-direction:column;overflow:hidden">
    <div class="card-hd"><i class="ti ti-robot" style="color:var(--ai)"></i><div><div class="card-t">Agente RBVM — IA Generativa</div><div class="card-s">Claude Sonnet · Dados reais · Rastreável · Governança ativa</div></div><div class="card-ac"><button class="btn btn-s" onclick="clearAgent()"><i class="ti ti-trash"></i> Limpar</button></div></div>
    <div class="nt ni-" style="margin:12px 16px 0;flex-shrink:0"><i class="ti ti-shield-check" style="font-size:14px;flex-shrink:0"></i><strong>Guardrails ativos:</strong> Não inventa dados · Não fecha vulns sem rescan · Não aprova exceções · Não executa mudanças sem aprovação humana.</div>
    <div class="card-bd" style="flex:1;display:flex;flex-direction:column;overflow:hidden;gap:10px">
      <div class="am" id="am" style="flex:1;max-height:none"></div>
      <div style="display:flex;gap:5px;flex-wrap:wrap">${qs.map(q=>`<div class="qb" onclick="quickMsg('${q.replace(/'/g,"\\'")}')"> ${q}</div>`).join('')}</div>
      <div style="display:flex;gap:8px;margin-top:4px">
        <input class="ag-in" id="ai" placeholder="Pergunte sobre vulns, riscos, SLAs, compliance, fornecedores, tendências históricas..." onkeydown="if(event.key==='Enter')sendAgent()"/>
        <button class="btn btn-p" onclick="sendAgent()"><i class="ti ti-send"></i> Enviar</button>
      </div>
    </div>
  </div></div>`;
}

function settings() {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const lang  = getLang();
  return `<div class="content">
  <div class="g2">
    <!-- THEME -->
    <div class="card">
      <div class="card-hd"><i class="ti ti-sun" style="color:var(--accent)"></i><div><div class="card-t">${t('settings.theme')}</div><div class="card-s">Dark · White</div></div></div>
      <div class="card-bd" style="display:flex;flex-direction:column;gap:8px">
        <button class="theme-btn ${theme==='dark'?'active':''}" onclick="setTheme('dark')">
          <i class="ti ti-moon" style="font-size:20px;color:var(--accent)"></i>
          <div style="text-align:left">
            <div style="font-size:13px;font-weight:600">${t('settings.themeDark')}</div>
            <div style="font-size:11px;color:var(--text2)">${t('settings.themeDarkDesc')}</div>
          </div>
          ${theme==='dark'?`<i class="ti ti-check" style="color:var(--success);margin-left:auto"></i>`:''}
        </button>
        <button class="theme-btn ${theme==='white'?'active':''}" onclick="setTheme('white')">
          <i class="ti ti-sun" style="font-size:20px;color:#f0c040"></i>
          <div style="text-align:left">
            <div style="font-size:13px;font-weight:600">${t('settings.themeWhite')}</div>
            <div style="font-size:11px;color:var(--text2)">${t('settings.themeWhiteDesc')}</div>
          </div>
          ${theme==='white'?`<i class="ti ti-check" style="color:var(--success);margin-left:auto"></i>`:''}
        </button>
      </div>
    </div>
    <!-- LANGUAGE -->
    <div class="card">
      <div class="card-hd"><i class="ti ti-world" style="color:var(--accent)"></i><div><div class="card-t">${t('settings.language')}</div><div class="card-s">pt-BR · en-US</div></div></div>
      <div class="card-bd" style="display:flex;flex-direction:column;gap:8px">
        <button class="theme-btn ${lang==='pt-BR'?'active':''}" onclick="setLanguage('pt-BR')">
          <span style="font-size:22px">🇧🇷</span>
          <div style="text-align:left">
            <div style="font-size:13px;font-weight:600">${t('settings.langPt')}</div>
          </div>
          ${lang==='pt-BR'?`<i class="ti ti-check" style="color:var(--success);margin-left:auto"></i>`:''}
        </button>
        <button class="theme-btn ${lang==='en-US'?'active':''}" onclick="setLanguage('en-US')">
          <span style="font-size:22px">🇺🇸</span>
          <div style="text-align:left">
            <div style="font-size:13px;font-weight:600">${t('settings.langEn')}</div>
          </div>
          ${lang==='en-US'?`<i class="ti ti-check" style="color:var(--success);margin-left:auto"></i>`:''}
        </button>
      </div>
    </div>
  </div>
  <!-- PLATFORM INFO -->
  <div class="card">
    <div class="card-hd"><i class="ti ti-info-circle" style="color:var(--accent)"></i><div><div class="card-t">${t('settings.version')}</div></div></div>
    <div class="card-bd">
      <div class="dg3" style="margin-bottom:12px">
        <div class="di"><div class="di-l">${t('settings.version')}</div><div class="di-v">v1.0.0-modular</div></div>
        <div class="di"><div class="di-l">${t('settings.demoStatus')}</div><div class="di-v" style="color:var(--success)">✓ Live</div></div>
        <div class="di"><div class="di-l">${t('settings.architecture')}</div><div class="di-v" style="font-size:11px">${t('settings.archDesc')}</div></div>
      </div>
      <div class="nt ni-"><i class="ti ti-database" style="font-size:14px;flex-shrink:0"></i><div><strong>${t('settings.demoNotice')}</strong> — ${t('settings.demoNoticeText')}</div></div>
      <div class="nt nc-" style="margin-top:8px"><i class="ti ti-copyright" style="font-size:14px;flex-shrink:0"></i><div><strong>${t('settings.ipNotice')}</strong> — ${t('settings.ipNoticeText')}</div></div>
    </div>
  </div>
  <!-- EMPRESA/SLA config preserved -->
  <div class="card">
    <div class="card-hd"><i class="ti ti-building" style="color:var(--accent)"></i><div><div class="card-t">Empresa & SLAs</div><div class="card-s">Configurações operacionais</div></div></div>
    <div class="card-bd" style="display:flex;flex-direction:column;gap:16px">
      <div><div class="ds">Empresa</div>
        <div class="dg">
          <div class="di"><div class="di-l">Nome</div><div class="di-v">Corporação XPTO</div></div>
          <div class="di"><div class="di-l">CNPJ</div><div class="di-v mono">00.000.000/0001-00</div></div>
          <div class="di"><div class="di-l">Segmento</div><div class="di-v">Serviços Financeiros</div></div>
          <div class="di"><div class="di-l">CISO</div><div class="di-v">ciso@corp.example</div></div>
        </div>
      </div>
      <div><div class="ds">SLA Padrão (dias corridos)</div>
        <div class="dg">
          ${[['CRITICAL','7d','var(--crit)'],['HIGH','15d','var(--high)'],['MEDIUM','30d','var(--med)'],['LOW','60d','var(--low)']].map(([s,d,c])=>`
          <div class="di"><div class="di-l">${s}</div><div class="di-v" style="color:${c}">${d}</div></div>`).join('')}
        </div>
      </div>
      <div><div class="ds">Frameworks de Compliance</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${['NIST CSF 2.0','PCI DSS 4.0','ISO 27001:2022','LGPD','CMN 4.893/2021','BACEN Res. 4.658'].map(f=>`<span class="pill pi" style="font-size:10px">${f}</span>`).join('')}
        </div>
      </div>
      <div class="btn-g">
        <button class="btn btn-d btn-s" onclick="resetPreferences()"><i class="ti ti-refresh"></i> ${t('settings.resetPrefs')}</button>
      </div>
    </div>
  </div>
  </div>`;
}


// ══════════════════════════════════════════════════════════════════════════════
//  DETAIL PANEL — COMPLETO COM AUDIT TRAIL + LIFECYCLE ACTIONS
// ══════════════════════════════════════════════════════════════════════════════
window.openDov = function(id) {
  const v=VULNS.find(x=>x.id===id); if(!v) return;
  const exp=explainScore(v), rl=getRiskLabel(v.final_score);
  const st=v.status, tk=TICKETS[id];
  const auditEvs=getAuditForVuln(id);
  const hasTk=!!tk||!!v.ticket;
  const toolMap2={server:'Tenable',application:'Veracode',cloud:'Wiz',container:'Trivy',repository:'GitHub Secret Scanning',ad:'BloodHound',iac:'Checkov',network:'Tenable'};

  const actionBtns=()=>{
    const btns=[];
    if(!hasTk) btns.push(`<button class="btn btn-p" onclick="openTicketModal('${id}')"><i class="ti ti-ticket"></i> Criar Ticket</button>`);
    if(hasTk&&['New','In Progress','Ticket Created'].includes(st)) btns.push(`<button class="btn btn-o" onclick="dovMarkResolved('${id}')"><i class="ti ti-circle-check"></i> Resolvido pelo Time</button>`);
    if(['Resolved by Team','Awaiting Validation','Awaiting Technical Validation'].includes(st)) btns.push(`<button class="btn btn-p" onclick="dovTriggerRescan('${id}')"><i class="ti ti-refresh"></i> Acionar Rescan</button>`);
    if(['Rescan Requested','Validation Running','Fixed Confirmed','Still Vulnerable'].includes(st)){
      btns.push(`<button class="btn btn-o" onclick="dovConfirmFixed('${id}')"><i class="ti ti-shield-check"></i> Confirmar Correção</button>`);
      btns.push(`<button class="btn btn-d" onclick="dovStillPresent('${id}')"><i class="ti ti-refresh-alert"></i> Still Vulnerable</button>`);
    }
    if(st==='Closed with Evidence') btns.push(`<span class="pill pd" style="padding:6px 10px;font-size:11px"><i class="ti ti-lock"></i> Encerrado com evidência</span>`);
    if(!['Closed with Evidence','Fixed Confirmed'].includes(st)) btns.push(`<button class="btn" onclick="openFPContest('${id}')"><i class="ti ti-shield-question"></i> Contestar FP</button>`);
    btns.push(`<button class="btn" onclick="aiComm('${id}')"><i class="ti ti-robot"></i> IA</button>`);
    btns.push(`<button class="btn" onclick="notifyOwner('${id}')"><i class="ti ti-send"></i> Notificar</button>`);
    btns.push(`<button class="btn" onclick="openRC('${id}')"><i class="ti ti-adjustments"></i> Reclassificar</button>`);
    return btns.join('');
  };

  document.getElementById('dov-c').innerHTML = `
  <div class="dov-hd">
    <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
      ${SP(v.sev)} ${v.kev?rpill('pc','CISA KEV'):''} ${v.exploit?rpill('ph','EXPLOIT'):''} ${v.rce?rpill('pc','RCE'):''} ${v.internet_facing?rpill('ph','INTERNET'):''}
    </div>
    <div style="font-size:14px;font-weight:700;line-height:1.3">${v.title}</div>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
      <span class="mono" style="color:var(--text3)">${v.id}</span>
      <span style="font-size:11px;color:var(--text2)">Ticket: <strong class="mono">${tk?.id||v.ticket||'—'}</strong></span>
      <span style="font-size:11px;color:var(--text2)">Fonte: ${v.source}</span>
    </div>
  </div>
  <div class="dov-sc">
    <div class="dg3">
      <div class="di"><div class="di-l">Score</div><div class="di-v" style="color:${RC(v.final_score)};font-size:22px">${v.final_score}</div><div style="font-size:10px;color:var(--text3)">${rl.label}</div></div>
      <div class="di"><div class="di-l">Impacto Financeiro</div><div class="di-v" style="color:${v._fin.category==='Crítico'?'var(--crit)':'var(--high)'};font-size:15px">${v._fin.label}</div><div style="font-size:10px;color:var(--text3)">${v._fin.category}</div></div>
      <div class="di"><div class="di-l">CVSS / EPSS</div><div class="di-v">${v.cvss} / ${v.epss!=null?(v.epss*100).toFixed(0)+'%':'—'}</div></div>
      <div class="di"><div class="di-l">Ambiente</div><div class="di-v">${EP(v.env)}</div></div>
      <div class="di"><div class="di-l">SLA</div><div class="di-v">${SB(v)}</div></div>
      <div class="di"><div class="di-l">Status</div><div class="di-v">${statusEx(st)}</div></div>
    </div>
    <div><div class="ds">Ativo &amp; Responsável</div>
      <div class="dg">
        <div class="di"><div class="di-l">Ativo</div><div class="di-v">${v.asset}</div></div>
        <div class="di"><div class="di-l">Tipo</div><div class="di-v">${v.asset_type}</div></div>
        <div class="di"><div class="di-l">Owner</div><div class="di-v" style="font-size:11px">${v.owner}</div></div>
        <div class="di"><div class="di-l">Squad / BU</div><div class="di-v" style="font-size:11px">${v.squad} · ${v.bu}</div></div>
      </div>
    </div>
    ${v.mitre_technique?`<div><div class="ds">MITRE ATT&amp;CK</div><div class="di"><div class="di-l">Técnica</div><div class="di-v"><span class="pill pai">${v.mitre_technique}</span> ${v.mitre_tactic||''}</div></div></div>`:''}
    ${v.pci_scope||v.lgpd_scope||v.data_sensitive?`<div><div class="ds">Contexto Regulatório</div><div style="display:flex;gap:8px;flex-wrap:wrap">${v.pci_scope?rpill('pnist','PCI DSS 4.0'):''}${v.lgpd_scope?rpill('pai','LGPD'):''}${v.data_sensitive?rpill('ph','Dados sensíveis'):''}${v.compensating_controls?rpill('pd','Controle compensatório'):''}</div></div>`:''}
    <div><div class="ds">Score Multicritério</div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px">
        ${exp.map(e=>`<div class="ser"><span class="sef">${e.factor}</span><span class="sep ${e.value>0?'pos':'neg'}">${e.value>0?'+'+e.value:e.value} pts</span></div>`).join('')}
        <div class="ser" style="border-top:2px solid var(--border);margin-top:4px;padding-top:8px"><span style="font-weight:700">Score Final</span><span style="color:${RC(v.final_score)};font-size:14px;font-weight:700">${v.final_score}</span></div>
      </div>
    </div>
    <div><div class="ds">Impacto de Negócio</div><div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px;font-size:12px;color:var(--text2);line-height:1.6">${v.business_impact}</div></div>
    <div><div class="ds">Recomendação de Correção</div><div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px;font-size:12px;color:var(--text2);line-height:1.6">${v.remediation}</div></div>
    ${v.reclassify_reason?`<div class="nt nw"><i class="ti ti-adjustments" style="font-size:14px;flex-shrink:0"></i><strong>Reclassificação:</strong> ${v.reclassify_reason}</div>`:''}
    <div><div class="ds">Ações do Ciclo de Remediação</div>
      <div class="btn-g" style="padding:4px 0">${actionBtns()}</div>
      <div style="font-size:9px;color:var(--text3);margin-top:6px">Criar ticket ≠ corrigido · Resolvido pelo time ≠ fechado · Validação técnica é obrigatória.</div>
    </div>
    <div><div class="ds">Audit Trail — Histórico Auditável</div>
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px;max-height:220px;overflow-y:auto">
        ${auditEvs.length===0
          ?'<div style="color:var(--text3);font-size:11px">Nenhum evento. Crie um ticket para iniciar o ciclo.</div>'
          :auditEvs.map(e=>`<div class="at-row">
              <div class="at-ic ${e.actor==='system'?'at-ic-sys':e.actor==='ai'?'at-ic-ai':'at-ic-usr'}"><i class="ti ${e.icon||'ti-circle'}" style="font-size:11px"></i></div>
              <div class="at-body">
                <div class="at-action">${e.action}${e.before&&e.after?` <span style="font-size:9px;color:var(--text3)">${e.before} → ${e.after}</span>`:''}</div>
                <div class="at-meta">${e.ts} · ${e.name} · ${e.src||'—'}</div>
                ${e.detail?`<div class="at-detail">${e.detail}</div>`:''}
              </div>
            </div>`).join('')}
        <div class="at-row" style="opacity:.35;pointer-events:none"><div class="at-ic at-ic-sys"><i class="ti ti-dots" style="font-size:11px"></i></div><div class="at-body"><div class="at-action" style="font-style:italic;font-size:10px">Próximos eventos registrados ao executar ações acima</div></div></div>
      </div>
    </div>
    <div style="padding-top:4px">
      <button class="btn btn-s" onclick="LC_VULN_ID='${id}';setView('lifecycle')"><i class="ti ti-route"></i> Ver Jornada Completa</button>
    </div>
  </div>`;
  document.getElementById('dov').classList.add('open');
};
window.closeDov = () => document.getElementById('dov').classList.remove('open');

// ── DOV STATUS ACTIONS ────────────────────────────────────────────────────────
window.dovMarkResolved = id => {
  saveStatus(id,'Resolved by Team');
  addAuditEvent(id,{actor:'user',name:'Owner Técnico',icon:'ti-circle-check',action:'Resolvido pelo Time Técnico',before:'In Progress',after:'Resolved by Team',detail:'Ticket marcado como resolvido. Validação técnica obrigatória antes de fechar.',src:'User'});
  toast('Status → Resolvido pelo Time. Validação técnica obrigatória.','ts'); openDov(id);
};
window.dovTriggerRescan = id => {
  const v2=VULNS.find(x=>x.id===id);
  const tm2={server:'Tenable',application:'Veracode',cloud:'Wiz',container:'Trivy',repository:'GitHub Secret Scanning',ad:'BloodHound',iac:'Checkov',network:'Tenable'};
  const t2=tm2[v2?.asset_type]||'Tenable';
  saveStatus(id,'Rescan Requested');
  addAuditEvent(id,{actor:'system',name:'RBVM Validation Engine',icon:'ti-refresh',action:'Rescan solicitado via API',before:'Resolved by Team',after:'Rescan Requested',detail:`Ferramenta: ${t2} · Validação técnica iniciada`,src:t2});
  toast(`Rescan acionado via ${t2}...`,'ts');
  setTimeout(()=>{ saveStatus(id,'Validation Running'); addAuditEvent(id,{actor:'system',name:t2,icon:'ti-radar',action:'Validação em execução',before:'Rescan Requested',after:'Validation Running',detail:`${t2} escaneando ativo`,src:t2}); openDov(id); render(); },1400);
};
window.dovConfirmFixed = id => {
  const v3=VULNS.find(x=>x.id===id);
  const tm3={server:'Tenable',application:'Veracode',cloud:'Wiz',container:'Trivy',repository:'GitHub Secret Scanning',ad:'BloodHound',iac:'Checkov',network:'Tenable'};
  const t3=tm3[v3?.asset_type]||'Tenable';
  saveStatus(id,'Closed with Evidence');
  addAuditEvent(id,{actor:'system',name:t3,icon:'ti-shield-check',action:'Correção confirmada — vulnerability NOT found',before:'Validation Running',after:'Closed with Evidence',detail:`${t3} não detectou o finding no rescan. Evidência: scan-${id}-${Date.now()}.pdf`,src:t3});
  addAuditEvent(id,{actor:'system',name:'RBVM Engine',icon:'ti-lock',action:'Vulnerabilidade encerrada com evidência técnica',before:'Fixed Confirmed',after:'Closed with Evidence',detail:'Indicadores executivos atualizados. Ciclo encerrado.',src:'Internal'});
  toast('Correção confirmada — vulnerabilidade encerrada com evidência!','ts');
  openDov(id); render();
};
window.dovStillPresent = id => {
  saveStatus(id,'Still Vulnerable');
  addAuditEvent(id,{actor:'system',name:'Scanner',icon:'ti-alert-triangle',action:'Finding AINDA PRESENTE após rescan',before:'Validation Running',after:'Still Vulnerable',detail:'Vulnerabilidade não corrigida. Ticket reaberto. SLA reiniciado.',src:'Scanner'});
  setTimeout(()=>{ saveStatus(id,'Reopened'); addAuditEvent(id,{actor:'system',name:'RBVM Engine',icon:'ti-refresh-alert',action:'Ticket reaberto — reincidência registrada',before:'Still Vulnerable',after:'Reopened',detail:'SLA reiniciado. GRC notificado. Escalonamento automático ativado.',src:'Internal'}); openDov(id); render(); },700);
  toast('Finding persistente — ticket reaberto e SLA reiniciado','te');
};


// ── MODALS ────────────────────────────────────────────────────────────────────
window.openModal = function(type, data) {
  const mc=document.getElementById('mc');
  if(type==='reclassify'&&data) {
    mc.innerHTML=`<div class="modal-t"><i class="ti ti-adjustments-horizontal" style="color:var(--accent)"></i>Reclassificação — ${data.id}</div>
    <div style="font-size:12px;color:var(--text2);margin-bottom:16px">${data.title}</div>
    <div class="ff" style="margin-bottom:12px"><div class="fl">Justificativa técnica auditável</div><textarea class="fi" id="rc-r">${data.reclassify_reason||''}</textarea></div>
    <div class="ff" style="margin-bottom:12px"><div class="fl">Controle Compensatório</div><select class="fi" id="rc-c"><option value="0">Nenhum</option><option value="1" ${data.compensating_controls?'selected':''}>Ativo</option></select></div>
    <div class="modal-ft"><button class="btn" onclick="closeMod()">Cancelar</button><button class="btn btn-p" onclick="saveRC('${data.id}')"><i class="ti ti-check"></i> Salvar</button></div>`;
  } else if(type==='report') {
    mc.innerHTML=`<div class="modal-t"><i class="ti ti-file-analytics" style="color:var(--accent)"></i>Gerar Relatório</div>
    <div class="fr"><div class="ff"><div class="fl">Público-alvo</div><select class="fi"><option>CISO / Executivo</option><option>Gestores de Tecnologia</option><option>Squads Técnicos</option><option>GRC / Auditoria</option><option>Comitê de Risco</option></select></div><div class="ff"><div class="fl">Formato</div><select class="fi"><option>PDF Executivo</option><option>PowerPoint</option><option>Excel/CSV</option><option>Dashboard Web</option></select></div></div>
    <div class="modal-ft"><button class="btn" onclick="closeMod()">Cancelar</button><button class="btn btn-p" onclick="toast('Relatório gerado via IA — pronto','ts');closeMod()"><i class="ti ti-send"></i> Gerar via IA</button></div>`;
  } else if(type==='addexc') {
    mc.innerHTML=`<div class="modal-t"><i class="ti ti-shield-x" style="color:var(--high)"></i>Solicitar Exceção de Risco</div>
    <div class="fr"><div class="ff"><div class="fl">Vulnerabilidade</div><select class="fi">${VULNS.map(v=>`<option>${v.id} — ${v.title.substring(0,45)}</option>`).join('')}</select></div><div class="ff"><div class="fl">Tipo</div><select class="fi"><option>Aceite temporário</option><option>Aceite formal</option><option>Mitigação compensatória</option></select></div></div>
    <div class="ff" style="margin-bottom:12px"><div class="fl">Justificativa técnica e de negócio</div><textarea class="fi" placeholder="Razão técnica, impacto de negócio e plano de correção futuro..."></textarea></div>
    <div class="ff" style="margin-bottom:12px"><div class="fl">Controles Compensatórios</div><input class="fi" placeholder="Ex: WAF ativo, MFA obrigatório, isolamento de rede..."/></div>
    <div class="modal-ft"><button class="btn" onclick="closeMod()">Cancelar</button><button class="btn btn-p" onclick="toast('Exceção submetida — aguardando aprovação CISO','ts');closeMod()"><i class="ti ti-send"></i> Submeter</button></div>`;
  }
  document.getElementById('mbg').classList.add('open');
};
window.saveRC = id => {
  const v=VULNS.find(x=>x.id===id); if(!v) return;
  v.reclassify_reason=document.getElementById('rc-r').value;
  v.compensating_controls=document.getElementById('rc-c').value==='1';
  v.final_score=computeRiskScore(v); v._fin=estimateFinancialImpact(v);
  toast(`Score atualizado: ${v.final_score}`,'ts'); closeMod(); render();
};
window.openRC    = id => openModal('reclassify', VULNS.find(x=>x.id===id));
window.closeMod  = () => document.getElementById('mbg').classList.remove('open');
document.getElementById('mbg').addEventListener('click',e=>{if(e.target===e.currentTarget)closeMod();});

// ── ACTIONS ───────────────────────────────────────────────────────────────────
function toast(msg,cls='') {
  const el=document.getElementById('toast'), tm=document.getElementById('tm');
  if(!el||!tm) return; tm.textContent=msg; el.className='show '+cls;
  clearTimeout(window._tt); window._tt=setTimeout(()=>el.classList.remove('show'),3500);
}
window.toast        = toast;
window.notifyOwner  = id => { addAuditEvent(id,{actor:'system',name:'Notification Engine',icon:'ti-send',action:'Notificação enviada ao owner',before:null,after:null,detail:`Canal: Slack/Teams · Destinatário: ${VULNS.find(x=>x.id===id)?.owner||id}`,src:'Slack/Teams'}); toast(`Notificação enviada para ${VULNS.find(x=>x.id===id)?.owner||id}`,'ts'); };
window.escalate     = id => { addAuditEvent(id,{actor:'system',name:'Escalation Engine',icon:'ti-arrow-up',action:'Escalonamento executado',before:null,after:null,detail:'CISO + GRC + Liderança notificados via PagerDuty',src:'PagerDuty'}); toast(`${id}: Escalado para CISO + GRC + Liderança`,'ts'); };
window.syncNow      = n  => { toast(`Sincronizando ${n}...`); setTimeout(()=>toast(`${n}: Concluído`,'ts'),1500); };
window.clearAgent   = () => { AH=[AH[0]]; render(); };
window.triggerPB    = id => toast(`Playbook acionado para ${id}`,'ts');
window.triggerRescan= id => dovTriggerRescan(id);
window.markResolved = id => { dovMarkResolved(id); closeDov(); };

// ── TICKET MODAL ──────────────────────────────────────────────────────────────
window.openTicketModal = function(id) {
  const v=VULNS.find(x=>x.id===id); if(!v) return;
  const prio=v.sev==='CRITICAL'?'P1 — Critical':v.sev==='HIGH'?'P2 — High':'P3 — Medium';
  const due=v.due||new Date(Date.now()+v.sla_max*86400000).toISOString().slice(0,10);
  const mc=document.getElementById('mc');
  mc.innerHTML=`<div class="modal-t"><i class="ti ti-ticket" style="color:var(--accent)"></i>Criar Ticket — ${id}</div>
  <div class="fr" style="margin-bottom:10px">
    <div class="ff"><div class="fl">Ferramenta</div><select class="fi" id="tk-tool"><option>Jira</option><option>ServiceNow</option></select></div>
    <div class="ff"><div class="fl">Tipo</div><select class="fi" id="tk-type"><option>Security Finding</option><option>Incident</option><option>Task</option><option>Change Request</option></select></div>
  </div>
  <div class="tick-sep"></div>
  <div class="g2" style="gap:8px;margin-bottom:10px">
    <div class="tick-field"><div class="tick-label">Vulnerabilidade</div><div class="tick-val mono">${id}</div></div>
    <div class="tick-field"><div class="tick-label">Ativo</div><div class="tick-val">${v.asset}</div></div>
    <div class="tick-field"><div class="tick-label">Owner</div><div class="tick-val">${v.owner}</div></div>
    <div class="tick-field"><div class="tick-label">Squad / BU</div><div class="tick-val">${v.squad} · ${v.bu}</div></div>
    <div class="tick-field"><div class="tick-label">Severidade / Score</div><div class="tick-val">${v.sev} · Score: ${v.final_score}</div></div>
    <div class="tick-field"><div class="tick-label">Prioridade / Due Date</div><div class="tick-val">${prio} · ${due}</div></div>
    <div class="tick-field"><div class="tick-label">Impacto Financeiro</div><div class="tick-val" style="color:var(--crit)">${v._fin.label}</div></div>
    <div class="tick-field"><div class="tick-label">SLA</div><div class="tick-val">${v.sla_max} dias · Due: ${due}</div></div>
  </div>
  <div class="tick-field" style="margin-bottom:8px"><div class="tick-label">Descrição Técnica</div><div class="tick-val" style="font-size:11px;line-height:1.5">${v.business_impact}</div></div>
  <div class="tick-field" style="margin-bottom:8px"><div class="tick-label">Recomendação de Correção</div><div class="tick-val" style="font-size:11px;line-height:1.5">${v.remediation}</div></div>
  <div class="tick-field" style="margin-bottom:8px"><div class="tick-label">Tags</div><div class="tick-val" style="font-size:11px">${[v.sev,v.kev?'KEV':'',v.exploit?'exploit':'',v.rce?'rce':'',v.source,v.nist||''].filter(Boolean).join(', ')}</div></div>
  <div class="nt ni-" style="margin-bottom:10px"><i class="ti ti-info-circle" style="font-size:14px;flex-shrink:0"></i>Criar ticket ≠ vulnerabilidade corrigida. Após correção, validação técnica via rescan é obrigatória.</div>
  <div class="modal-ft">
    <button class="btn" onclick="closeMod()">Cancelar</button>
    <button class="btn btn-p" onclick="execCreateTicket('${id}')"><i class="ti ti-ticket"></i> Criar Ticket Agora</button>
  </div>`;
  document.getElementById('mbg').classList.add('open');
};
window.execCreateTicket = function(id) {
  const tool=document.getElementById('tk-tool')?.value||'Jira';
  const type=document.getElementById('tk-type')?.value||'Security Finding';
  const v=VULNS.find(x=>x.id===id); if(!v) return;
  const num=Math.floor(1000+Math.random()*9000);
  const tkId=`${tool==='Jira'?'SEC':'INC'}-${num}`;
  TICKETS[id]={id:tkId,tool,type,vuln_id:id,created:new Date().toISOString().slice(0,16).replace('T',' '),status:'Open'};
  LS.set('tickets',TICKETS);
  saveStatus(id,'Ticket Created');
  addAuditEvent(id,{actor:'system',name:`${tool} Integration`,icon:'ti-ticket',action:`Ticket criado: ${tkId}`,before:'New',after:'Ticket Created',detail:`${tool} · Tipo: ${type} · Prioridade: ${v.sev==='CRITICAL'?'P1':'P2'} · SLA: ${v.sla_max}d · Due: ${v.due||'—'}`,src:tool});
  document.getElementById('mc').innerHTML=`
  <div class="tick-success">
    <i class="ti ti-circle-check" style="font-size:32px;color:var(--success);display:block;margin:0 auto 10px"></i>
    <div style="font-size:16px;font-weight:700;color:var(--success);margin-bottom:6px">Ticket Criado com Sucesso!</div>
    <div class="mono" style="font-size:22px;color:var(--accent);margin:6px 0">${tkId}</div>
    <div style="font-size:11px;color:var(--text2);margin-bottom:4px">Ferramenta: ${tool} · Tipo: ${type} · Status: Open</div>
    <div style="font-size:11px;color:var(--text2);margin-bottom:12px">Owner: ${v.owner} · Due: ${v.due||'—'}</div>
    <div class="btn-g" style="justify-content:center">
      <button class="btn btn-s btn-p" onclick="closeMod();openDov('${id}')"><i class="ti ti-arrow-right"></i> Ver Vulnerabilidade</button>
      <button class="btn btn-s" onclick="closeMod();LC_VULN_ID='${id}';setView('lifecycle')"><i class="ti ti-route"></i> Ver Lifecycle</button>
      <button class="btn btn-s" onclick="closeMod()">Fechar</button>
    </div>
  </div>`;
  toast(`Ticket ${tkId} criado no ${tool}!`,'ts'); render();
};

// ── AGENTE IA ─────────────────────────────────────────────────────────────────
window.quickMsg = function(msg) {
  if(VIEW!=='agent') setView('agent');
  setTimeout(()=>{ const el=document.getElementById('ai'); if(el){el.value=msg;sendAgent();} },200);
};
window.aiComm = function(id) {
  const v=VULNS.find(x=>x.id===id); closeDov();
  quickMsg(`Gere comunicado profissional para o time ${v.team} sobre ${v.id}: "${v.title}". Inclua: score ${v.final_score}, CVSS ${v.cvss}, EPSS ${v.epss||'N/A'}, KEV=${v.kev}, impacto ${v._fin.label}, SLA restante ${getSlaRemaining(v)}d, ambiente ${v.env}, recomendação: ${v.remediation}.`);
};

window.sendAgent = async function() {
  const inp=document.getElementById('ai'), cont=document.getElementById('am');
  const txt=inp?.value.trim(); if(!txt||!cont) return;
  inp.value=''; AH.push({role:'user',text:txt}); rMsgs(true);

  const a=VULNS.filter(v=>v.status!=='Resolved');
  const lm=MONTHLY_TRENDS[MONTHLY_TRENDS.length-1];
  const vSum=VULNS.map(v=>({id:v.id,ticket:v.ticket,title:v.title,sev:v.sev,cvss:v.cvss,epss:v.epss,kev:v.kev,exploit:v.exploit,rce:v.rce,score:v.final_score,fin:v._fin.label,team:v.team,squad:v.squad,bu:v.bu,owner:v.owner,status:v.status,sla:`${v.sla_used}/${v.sla_max}d`,breach:v.sla_used>=v.sla_max,env:v.env,asset:v.asset,source:v.source,pci:v.pci_scope,lgpd:v.lgpd_scope,mitre:v.mitre_technique||null}));
  const kriB=KRI_ALERTS.filter(k=>k.status==='breach').map(k=>k.label).join(', ');
  const blk=PIPELINE_GATES.filter(g=>g.status==='blocked').map(g=>g.repo).join(', ');
  const cGaps=COMPLIANCE_CONTROLS.filter(c=>c.gap).map(c=>`${c.fw} ${c.control}: ${c.gap}`).slice(0,6).join('\n');
  const sAlerts=SUPPLIER_VULNS.filter(v=>v.status==='Overdue').map(v=>v.vuln_id).join(', ');

  const sys=`Você é o Agente RBVM de uma plataforma enterprise de segurança em ambiente financeiro regulado.

VULNERABILIDADES (${VULNS.length} total, ${a.length} abertas):
${JSON.stringify(vSum,null,1)}

MÉTRICAS:
- Exposição financeira total: ${FMT(totalFinancialExposure(VULNS))}
- MTTR críticas: ${lm.mttr_crit}d | Altas: ${lm.mttr_high}d | SLA compliance: ${Math.round(lm.sla_compliance*100)}%
- Mês atual: ${lm.opened} abertas · ${lm.closed} fechadas · ${lm.kev} KEVs
- MTTR por time: ${JSON.stringify(MTTR_BY_TEAM.map(t=>({time:t.team,mttr_crit:t.mttr_crit+'d',sla:Math.round(t.sla_rate*100)+'%'})))}

KRIs BREACH: ${kriB||'Nenhum'}
PIPELINES BLOQUEADOS: ${blk||'Nenhum'}
COMPLIANCE GAPS:\n${cGaps||'Nenhum'}
FORNECEDORES OVERDUE: ${sAlerts||'Nenhum'}
EXCEÇÕES PENDENTES: ${EXCS.filter(e=>e.st==='pending').length}
PLAYBOOKS ATIVOS: ${PLAYBOOKS.filter(p=>p.status==='active').map(p=>p.name).join(', ')}

CONTEXTO: Setor financeiro regulado · LGPD · PCI DSS 4.0 · CMN 4.893/2021 · ISO 27001:2022 · NIST CSF 2.0
TIMES: AppSec · CloudOps · Infrastructure · Network · DevOps
FERRAMENTAS: Tenable · Qualys · Snyk · Wiz · GHAS · BloodHound · Defender · Jira

GUARDRAILS DE GOVERNANÇA:
- Responda APENAS com dados acima. Nunca invente CVEs, dados ou métricas.
- Cite sempre IDs específicos (SEC-XXXX, CVE-XXXX) em análises.
- Nunca sugira fechar vulnerabilidades sem evidência de rescan técnico.
- Nunca aprove exceções — apenas sugira para revisão humana com justificativa.
- Nunca diga que a plataforma fez ações que não estão nos dados.
- Máximo 500 palavras. Use markdown (negrito, listas, tabelas quando útil).`;

  // Build source metadata for transparency
  const activeVulns=VULNS.filter(v=>v.status!=='Resolved');
  const sourceMeta={
    vulns_total:VULNS.length, vulns_active:activeVulns.length,
    period:'últimos 6 meses', data_date:'2024-05-22',
    sources_used:['RBVM Platform Dataset','CISA KEV','EPSS/FIRST','MONTHLY_TRENDS','KRI_ALERTS','COMPLIANCE_CONTROLS','SUPPLIER_VULNS','CICD_FINDINGS'],
    limitations:['Dados mockados para demonstração','Integrações reais não conectadas','Valores financeiros são estimativas','Sem dados em tempo real'],
    vulns_referenced:activeVulns.filter(v=>v.kev||v.sla_used>=v.sla_max).map(v=>v.id).slice(0,6),
  };

  try {
    const r=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:'claude-sonnet-4-20250514',max_tokens:1000,system:sys,messages:AH.map(m=>({role:m.role==='ai'?'assistant':'user',content:m.text}))})});
    const d=await r.json();
    const reply=d.content?.map(b=>b.text||'').join('')||'Erro ao obter resposta.';
    AH.push({role:'ai',text:reply,sources:sourceMeta});
    addAuditEvent('AI_AGENT',{actor:'ai',name:'RBVM AI Agent',icon:'ti-robot',action:'Resposta gerada pelo Agente IA',before:null,after:null,detail:`Query: "${txt.substring(0,80)}..." · Vulns analisadas: ${sourceMeta.vulns_active}`,src:'Claude Sonnet'});
  } catch(e) {
    AH.push({role:'ai',text:'Erro ao conectar ao agente. Verifique a API Anthropic.'});
  }
  rMsgs(false);
};

function rMsgs(typing) {
  const el=document.getElementById('am'); if(!el) return;
  el.innerHTML=AH.map(m=>`<div class="ag-msg ${m.role==='ai'?'msg-ai':'msg-u'}">
    <div class="ag-meta">${m.role==='ai'?'🤖 RBVM Agent — Claude Sonnet':'Você'}</div>
    ${m.text.replace(/\n/g,'<br>').replace(/\*\*(.*?)\*\*/g,'<strong>$1</strong>').replace(/`(.*?)`/g,'<code style="background:var(--bg4);padding:1px 4px;border-radius:3px;font-family:var(--mono);font-size:10px">$1</code>')}
    ${m.sources?`<div class="ai-sources">
      <div class="ai-sources-title">📊 Fontes usadas pela IA</div>
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:4px">
        <span>Vulns analisadas: <strong>${m.sources.vulns_active}</strong>/${m.sources.vulns_total}</span>
        <span>Período: <strong>${m.sources.period}</strong></span>
        <span>Data ref.: <strong>${m.sources.data_date}</strong></span>
      </div>
      <div style="margin-top:4px">Fontes: ${m.sources.sources_used.map(s=>`<span style="margin-right:6px;color:var(--accent)">${s}</span>`).join('')}</div>
      <div style="margin-top:4px;color:var(--high)">⚠ ${m.sources.limitations.join(' · ')}</div>
      ${m.sources.vulns_referenced.length?`<div style="margin-top:4px">CVEs/IDs referenciados: ${m.sources.vulns_referenced.map(id=>`<span class="pill pn" style="font-size:8px;margin:1px">${id}</span>`).join('')}</div>`:''}
    </div>`:''}
  </div>`).join('');
  if(typing) el.innerHTML+=`<div class="ag-msg msg-ai"><div class="tdots"><div class="td"></div><div class="td"></div><div class="td"></div></div></div>`;
  el.scrollTop=el.scrollHeight;
}

// ══════════════════════════════════════════════════════════════════════════════
//  PERSISTÊNCIA — localStorage
// ══════════════════════════════════════════════════════════════════════════════
const LS = {
  get: k => { try { return JSON.parse(localStorage.getItem('rbvm_'+k)); } catch { return null; } },
  set: (k,v) => { try { localStorage.setItem('rbvm_'+k, JSON.stringify(v)); } catch {} },
};
// Persisted state
let TICKETS     = LS.get('tickets')     || {};  // {vulnId: {id,tool,type,created,...}}
let VULN_STATUS = LS.get('vstatus')     || {};  // {vulnId: status}
let AUDIT_ADDED = LS.get('audit')       || {};  // {vulnId: [events]}
let LC_VULN_ID  = 'CVE-2024-23897';            // selected lifecycle vuln
let WR_SEL     = 'WR-001';                      // selected war room incident
let CJ_SEL     = 'CJ-001';                      // selected crown jewel
let SBOM_TAB   = 'overview';                    // sbom active tab: overview|components|licenses|eol
let FP_TAB     = 'queue';                       // fp active tab: queue|stats|history
let SBOM_FILTER_APP = 'ALL';
let SBOM_FILTER_ECO = 'ALL';
let SBOM_FILTER_CVE = false;
let FP_LOCAL = loadFPRecords(); // user-added FPs
let ASM_TAB    = 'overview';                    // asm active tab
let ASM_CAT    = 'ALL';                         // asm category filter
let ASM_EXPAND     = null;                       // expanded asset id
let PATCH_TAB      = 'campaigns';               // patch active tab
let PATCH_CAMP_SEL  = null;                     // selected campaign id
let RPT_TAB        = 'generate';               // reports active tab
let RPT_TYPE       = 'executive';              // selected report type
let RPT_EV_SEL     = [];                       // selected vulns for evidence
let RPT_HISTORY    = loadReportHistory();
let OFT_TAB        = 'overview';               // offensive findings active tab
let OFT_RT_EXP     = null;                      // expanded RT finding id
let OFT_BB_EXP     = null;                      // expanded BB finding id

// Apply persisted statuses
VULNS.forEach(v => {
  if (VULN_STATUS[v.id]) v.status = VULN_STATUS[v.id];
  v._fin = estimateFinancialImpact(v);
});

function saveStatus(id, status) {
  const v=VULNS.find(x=>x.id===id); if(!v) return;
  v.status = status; VULN_STATUS[id]=status;
  LS.set('vstatus', VULN_STATUS);
}
function addAuditEvent(vulnId, ev) {
  if (!AUDIT_ADDED[vulnId]) AUDIT_ADDED[vulnId]=[];
  AUDIT_ADDED[vulnId].push({...ev, ts: new Date().toISOString().slice(0,16).replace('T',' ')});
  LS.set('audit', AUDIT_ADDED);
}
function getAuditForVuln(id) {
  return getAuditTrail(id, AUDIT_ADDED);
}

// Extended status pill
function statusEx(s) {
  const m={'New':['pn','Novo'],'In Progress':['pp','Em andamento'],'Ticket Created':['ps-tc','Ticket Criado'],'Resolved by Team':['ps-rt','Resolvido pelo Time'],'Awaiting Validation':['ps-av','Aguard. Validação'],'Awaiting Technical Validation':['ps-av','Aguard. Validação'],'Rescan Requested':['ps-rr','Rescan Solicitado'],'Validation Running':['pp','Validando...'],'Fixed Confirmed':['ps-fc','Confirmado ✓'],'Still Vulnerable':['ps-sv','Ainda Vulnerável'],'Reopened':['ps-sv','Reaberto'],'Closed with Evidence':['ps-ce','Fechado ✓'],'Recurrence Detected':['ps-rd','Reincidência'],'Resolved':['pd','Resolvido']};
  const [cls,lbl]=m[s]||['pn',s];
  return `<span class="pill ${cls}" style="font-size:10px">${lbl}</span>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO A — REMEDIATION LIFECYCLE
// ══════════════════════════════════════════════════════════════════════════════
const LC_FEATURED = ['CVE-2024-23897','CVE-2024-21762','CVE-2024-6387','SCA-2024-LOG4J','CLOUD-2024-S3','CICD-2024-001','AD-2024-001'];

function lifecycle() {
  const v=VULNS.find(x=>x.id===LC_VULN_ID)||VULNS[0];
  const events=getAuditForVuln(v.id);
  const tk=TICKETS[v.id];

  const steps=[
    {id:'detect',   icon:'ti-radar',            label:'Finding Detectado',               desc:'Scanner identifica e envia para a plataforma'},
    {id:'normalize',icon:'ti-transform',         label:'Normalização & Deduplicação',     desc:'RBVM normaliza, padroniza e remove duplicatas'},
    {id:'enrich',   icon:'ti-database',          label:'Enriquecimento com TI',           desc:'CVSS, EPSS, KEV, exploit, MITRE ATT&CK, exposição'},
    {id:'score',    icon:'ti-chart-bar',          label:'Risk Score Calculado',            desc:'Score multicritério baseado em 10+ fatores de risco'},
    {id:'owner',    icon:'ti-user',              label:'Owner & Squad Identificados',     desc:'CMDB vincula ativo ao owner e squad responsável'},
    {id:'ticket',   icon:'ti-ticket',            label:'Ticket Criado',                   desc:'Jira/ServiceNow com campos completos e prioridade'},
    {id:'sla',      icon:'ti-clock',             label:'SLA Iniciado',                    desc:'Timer de cobrança conforme política corporativa'},
    {id:'notify',   icon:'ti-send',              label:'Alerta Enviado',                  desc:'Owner notificado via Slack/Teams/PagerDuty'},
    {id:'track',    icon:'ti-activity',          label:'Acompanhamento de SLA',           desc:'Cobranças preventivas e escalonamento automático'},
    {id:'resolved', icon:'ti-circle-check',      label:'Resolvido pelo Time Técnico',     desc:'Owner marca ticket como resolvido — sem encerrar'},
    {id:'await',    icon:'ti-hourglass',         label:'Aguardando Validação Técnica',    desc:'RBVM move para validação obrigatória — não fecha direto'},
    {id:'rescan',   icon:'ti-refresh',           label:'Rescan / Validação via API',      desc:'Scanner de origem confirma ou nega a correção'},
    {id:'result',   icon:'ti-shield-check',      label:'Resultado da Validação',          desc:'Fixed Confirmed → fecha · Still Vulnerable → reabre'},
    {id:'close',    icon:'ti-lock',              label:'Fechado com Evidência',           desc:'Vulnerabilidade encerrada com evidência técnica'},
  ];

  // Determine step states from events and current vuln status
  const st=v.status;
  const hasTk = !!tk||!!v.ticket;
  const stepState = (id) => {
    const done={'detect':true,'normalize':true,'enrich':true,'score':true,'owner':true};
    if(done[id]) return 'done';
    if(id==='ticket') return hasTk?'done':'cur';
    if(id==='sla') return hasTk?'done':'pend';
    if(id==='notify') return hasTk?'done':'pend';
    if(id==='track') return hasTk&&st!=='New'?'done':'pend';
    if(id==='resolved') return ['Resolved by Team','Awaiting Validation','Awaiting Technical Validation','Rescan Requested','Validation Running','Fixed Confirmed','Still Vulnerable','Reopened','Closed with Evidence','Recurrence Detected'].includes(st)?'done':hasTk?'cur':'pend';
    if(id==='await') return ['Awaiting Validation','Awaiting Technical Validation','Rescan Requested','Validation Running','Fixed Confirmed','Still Vulnerable','Closed with Evidence'].includes(st)?'done':'pend';
    if(id==='rescan') return ['Rescan Requested','Validation Running','Fixed Confirmed','Still Vulnerable','Closed with Evidence'].includes(st)?'done':['Awaiting Validation','Awaiting Technical Validation'].includes(st)?'cur':'pend';
    if(id==='result') return ['Fixed Confirmed','Still Vulnerable','Closed with Evidence'].includes(st)?'done':['Rescan Requested','Validation Running'].includes(st)?'cur':'pend';
    if(id==='close') return st==='Closed with Evidence'||st==='Fixed Confirmed'?'done':'pend';
    return 'pend';
  };

  const stepEvent = (id) => {
    const m={detect:events[0],normalize:events[1],enrich:events[2],score:events[3],owner:events[4],ticket:events[5]||tk,sla:events[6],notify:events[7]};
    return m[id];
  };

  const nextAction = () => {
    if(!hasTk) return {label:'Criar Ticket no Jira/ServiceNow',action:`openTicketModal('${v.id}')`,cls:'btn-p',icon:'ti-ticket'};
    if(['In Progress','Ticket Created'].includes(st)) return {label:'Marcar como Resolvido pelo Time',action:`lcMarkResolved('${v.id}')`,cls:'btn-o',icon:'ti-check'};
    if(['Resolved by Team','Awaiting Validation','Awaiting Technical Validation'].includes(st)) return {label:'Solicitar Rescan / Validação Técnica',action:`lcTriggerRescan('${v.id}')`,cls:'btn-p',icon:'ti-refresh'};
    if(['Rescan Requested','Validation Running'].includes(st)) return {label:'Validação em andamento...',action:'',cls:'btn disabled',icon:'ti-loader'};
    if(st==='Fixed Confirmed'||st==='Closed with Evidence') return null;
    return {label:'Criar Ticket',action:`openTicketModal('${v.id}')`,cls:'btn-p',icon:'ti-ticket'};
  };
  const na=nextAction();

  return `<div class="content">
  <div class="nt ni-" style="align-items:center"><i class="ti ti-route" style="font-size:16px;flex-shrink:0"></i><strong>Remediation Lifecycle</strong> — Jornada completa de uma vulnerabilidade: do finding à evidência de correção. Este é o diferencial central da plataforma.</div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-selector" style="color:var(--accent)"></i><div><div class="card-t">Selecionar Vulnerabilidade</div><div class="card-s">Escolha um finding crítico para acompanhar a jornada</div></div></div>
    <div class="card-bd">
      <select class="fi" onchange="lcSelectVuln(this.value)" style="width:100%;margin-bottom:0">
        ${LC_FEATURED.map(id=>{const vx=VULNS.find(x=>x.id===id); return`<option value="${id}" ${id===LC_VULN_ID?'selected':''}>${id} — ${vx?.title?.substring(0,65)||id}</option>`;}).join('')}
      </select>
    </div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-bug" style="color:${RC(v.final_score)}"></i>
      <div><div class="card-t">${v.title}</div><div class="card-s">${v.asset} · ${v.source} · Owner: ${v.owner}</div></div>
      <div class="card-ac">${statusEx(v.status)}<span style="margin-left:8px;font-size:11px;color:${RC(v.final_score)};font-weight:700">Score: ${v.final_score}</span>${v.kev?rpill('pc','KEV'):''}</div>
    </div>
    <div class="dg3" style="padding:12px 16px 0">
      <div class="di"><div class="di-l">Severidade</div><div class="di-v">${SP(v.sev)}</div></div>
      <div class="di"><div class="di-l">Ticket</div><div class="di-v mono">${tk?.id||v.ticket||'—'}</div></div>
      <div class="di"><div class="di-l">Impacto Financeiro</div><div class="di-v" style="color:var(--crit);font-size:12px">${v._fin.label}</div></div>
    </div>
    <div class="card-bd" style="padding-top:8px">
      <div style="position:relative;padding:8px 0">
        ${steps.map((s,i)=>{
          const state=stepState(s.id), ev=stepEvent(s.id);
          const dotCls={done:'lc-done',cur:'lc-cur',pend:'lc-pend',warn:'lc-warn'}[state]||'lc-pend';
          return `<div class="lc-step">
            <div class="lc-dot ${dotCls}"><i class="ti ${s.icon}"></i></div>
            <div class="lc-body">
              <div class="lc-head">
                <span class="lc-name" style="color:${state==='done'?'var(--text)':state==='cur'?'var(--accent)':'var(--text3)'}">${s.label}</span>
                ${state==='done'?'<i class="ti ti-check" style="color:var(--success);font-size:12px"></i>':''}
                ${state==='cur'?rpill('pi','ATUAL'):''}
                ${ev?`<span class="lc-ts">${ev.ts}</span><span class="lc-actor">· ${ev.name||ev.actor||''}</span>`:''}
              </div>
              <div class="lc-detail" style="color:${state==='pend'?'var(--text3)':'var(--text2)'}">${ev?.detail||s.desc}</div>
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>
  </div>
  ${na?`<div class="card">
    <div class="card-hd"><i class="ti ti-arrow-right" style="color:var(--accent)"></i><div><div class="card-t">Próxima Ação Recomendada</div><div class="card-s">O que a plataforma espera agora para avançar o ciclo</div></div></div>
    <div class="card-bd" style="display:flex;gap:10px;align-items:center">
      <button class="btn ${na.cls}" ${na.action?`onclick="${na.action}"`:'disabled'}><i class="ti ${na.icon}"></i>${na.label}</button>
      ${hasTk&&['In Progress','Ticket Created'].includes(st)?`<button class="btn btn-d" onclick="lcMarkStillPresent('${v.id}')"><i class="ti ti-refresh-alert"></i> Finding Ainda Presente</button>`:''}
      <button class="btn" onclick="openDov('${v.id}')"><i class="ti ti-info-circle"></i> Ver Detalhe Completo</button>
    </div>
  </div>`:'<div class="nt nok"><i class="ti ti-lock" style="font-size:16px;flex-shrink:0"></i><strong>Ciclo encerrado</strong> — Vulnerabilidade fechada com evidência técnica. Monitore por reincidência no próximo scan.</div>'}
  <div class="card">
    <div class="card-hd"><i class="ti ti-list-details" style="color:var(--accent)"></i><div><div class="card-t">Audit Trail</div><div class="card-s">Histórico completo e auditável de eventos desta vulnerabilidade</div></div></div>
    <div class="card-bd">
      ${getAuditForVuln(v.id).length===0?'<div style="color:var(--text3);font-size:11px">Sem eventos registrados ainda.</div>':
        getAuditForVuln(v.id).map(e=>`<div class="at-row">
          <div class="at-ic ${e.actor==='system'?'at-ic-sys':e.actor==='ai'?'at-ic-ai':'at-ic-usr'}"><i class="ti ${e.icon||'ti-circle'}"></i></div>
          <div class="at-body">
            <div class="at-action">${e.action}</div>
            <div class="at-meta">${e.ts} · ${e.name} · Fonte: ${e.src||'—'} ${e.before&&e.after?`· Status: ${e.before} → ${e.after}`:''}</div>
            <div class="at-detail">${e.detail||''}</div>
          </div>
        </div>`).join('')}
    </div>
  </div>
  </div>`;
}
window.lcSelectVuln = id => { LC_VULN_ID=id; render(); };
window.lcMarkResolved = id => {
  saveStatus(id,'Awaiting Validation');
  addAuditEvent(id,{actor:'user',name:'Owner Técnico',icon:'ti-circle-check',action:'Resolvido pelo Time Técnico',before:'In Progress',after:'Awaiting Validation',detail:'Ticket marcado como resolvido. Aguardando validação técnica obrigatória.',src:'User'});
  toast('Marcado como resolvido — aguardando validação técnica','ts'); render();
};
window.lcTriggerRescan = id => {
  const v=VULNS.find(x=>x.id===id);
  const toolMap={server:'Tenable',application:'Veracode',cloud:'Wiz',container:'Trivy',repository:'GitHub Secret Scanning',ad:'BloodHound',iac:'Checkov',network:'Tenable',sca:'Snyk'};
  const tool=toolMap[v?.asset_type]||'Tenable';
  saveStatus(id,'Rescan Requested');
  addAuditEvent(id,{actor:'system',name:'RBVM Validation Engine',icon:'ti-refresh',action:'Rescan solicitado — validação técnica',before:'Awaiting Validation',after:'Rescan Requested',detail:`Tool: ${tool} · Aguardando resultado do scanner de origem`,src:tool});
  toast(`Rescan solicitado via ${tool}. Aguardando resultado...`,'ts');
  setTimeout(()=>{
    saveStatus(id,'Validation Running');
    addAuditEvent(id,{actor:'system',name:tool,icon:'ti-radar',action:'Validação em execução...',before:'Rescan Requested',after:'Validation Running',detail:`${tool} executando nova varredura no ativo`,src:tool});
    render();
  },1500);
};
window.lcMarkStillPresent = id => {
  saveStatus(id,'Still Vulnerable');
  addAuditEvent(id,{actor:'user',name:'Security Analyst',icon:'ti-alert-triangle',action:'Finding ainda presente após análise',before:'In Progress',after:'Still Vulnerable',detail:'Vulnerabilidade não corrigida confirmada manualmente. Ticket reaberto.',src:'Manual'});
  setTimeout(()=>{
    saveStatus(id,'Reopened');
    addAuditEvent(id,{actor:'system',name:'RBVM Engine',icon:'ti-refresh-alert',action:'Ticket reaberto automaticamente — finding persistente',before:'Still Vulnerable',after:'Reopened',detail:'SEC reaberto + SLA reiniciado + Owner notificado novamente + escalonamento registrado.',src:'Internal'});
    toast('Finding persistente — ticket reaberto e SLA reiniciado','te'); render();
  },800);
};

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO B — DATA QUALITY & COVERAGE
// ══════════════════════════════════════════════════════════════════════════════
function dataquality() {
  const dqItems=[
    {cat:'Ativos',     sev:'crit', icon:'ti-user-x',       label:'Sem owner definido',               val:14, fix:'Cadastrar owner no CMDB para cada ativo', detail:'Sem owner, a plataforma não direciona cobranças, tickets ou escalações.'},
    {cat:'Ativos',     sev:'crit', icon:'ti-tag-off',       label:'Sem criticidade cadastrada',        val:8,  fix:'Classificar criticidade (critical/high/medium/low) no CMDB', detail:'Sem criticidade, o risk score não é calculado corretamente.'},
    {cat:'Ativos',     sev:'high', icon:'ti-radar-2',       label:'Sem scan recente (>30 dias)',        val:23, fix:'Agendar scans regulares via Tenable/Qualys', detail:'Ativos sem scan recente podem ter vulnerabilidades não detectadas.'},
    {cat:'Ativos',     sev:'crit', icon:'ti-device-laptop-off',label:'EOL/EOS em produção',            val:3,  fix:'Plano de migração ou compensação formal obrigatório', detail:'Sistemas EOL não recebem patches — risco crescente sem solução.'},
    {cat:'Ativos',     sev:'high', icon:'ti-building-off',  label:'Sem business unit associada',       val:6,  fix:'Completar cadastro no CMDB com BU responsável', detail:'Sem BU, não é possível gerar relatórios por área de negócio.'},
    {cat:'Vulns',      sev:'crit', icon:'ti-ticket-off',    label:'Sem ticket associado',              val:VULNS.filter(v=>!v.ticket&&v.status!=='Resolved').length, fix:'Criar ticket para cada finding crítico/alto', detail:'Sem ticket, não há SLA, cobrança, evidência nem rastreabilidade.'},
    {cat:'Vulns',      sev:'high', icon:'ti-calendar-x',   label:'Sem SLA definido',                  val:VULNS.filter(v=>!v.sla_max).length, fix:'Aplicar política de SLA a todos os findings', detail:'Sem SLA, a plataforma não cobra nem escalona automaticamente.'},
    {cat:'CI/CD',      sev:'high', icon:'ti-git-branch-deleted',label:'Pipelines sem security gate',   val:10, fix:'Configurar SAST/SCA/Secret Scanning nos repos restantes', detail:'10 de 38 pipelines sem gate — vulns chegam a produção sem controle.'},
    {cat:'CI/CD',      sev:'crit', icon:'ti-key-off',       label:'Repos sem secret scanning',         val:7,  fix:'Habilitar GitHub Secret Scanning ou Gitleaks em todos os repos', detail:'Secrets expostos são o vetor de exploração mais rápido.'},
    {cat:'CI/CD',      sev:'high', icon:'ti-box-off',       label:'Containers sem scan de imagem',     val:4,  fix:'Configurar Trivy/Grype em todos os builds de container', detail:'Imagens desatualizadas sem scan acumulam CVEs desconhecidas.'},
    {cat:'Fornecedores',sev:'high',icon:'ti-building-factory-off',label:'Assessments de fornecedores vencidos', val:SUPPLIERS?.filter(s=>new Date(s.next_assessment)<new Date()).length||2, fix:'Revalidar fornecedores com assessment vencido urgentemente', detail:'Fornecedores sem assessment são risco de supply chain não mensurado.'},
    {cat:'Integrações',sev:'med', icon:'ti-plug-x',         label:'Integrações com falha ou parcial',  val:INTEGRATIONS?.filter(i=>i.status!=='connected').length||3, fix:'Renovar credenciais e verificar conectividade das integrações', detail:'Dados incompletos ou desatualizados comprometem a priorização.'},
    {cat:'Cloud',      sev:'ok',  icon:'ti-cloud-check',    label:'Cloud accounts com CSPM ativo',     val:6,  fix:'Manter cobertura total — OK', detail:'Todas as cloud accounts estão monitoradas pelo Wiz.'},
  ];
  const sevMap={crit:{cls:'dq-crit',icon:'ti-alert-octagon'},high:{cls:'dq-high',icon:'ti-alert-triangle'},med:{cls:'dq-med',icon:'ti-info-circle'},ok:{cls:'dq-ok',icon:'ti-check'}};
  const cats=[...new Set(dqItems.map(i=>i.cat))];
  const total=dqItems.filter(i=>i.sev!=='ok').reduce((s,i)=>s+i.val,0);
  const crits=dqItems.filter(i=>i.sev==='crit').reduce((s,i)=>s+i.val,0);
  return `<div class="content">
  <div class="nt nw"><i class="ti ti-alert-triangle" style="font-size:16px;flex-shrink:0"></i><strong>Data Quality é pré-requisito do RBVM.</strong> Sem owner, criticidade e dados confiáveis, a plataforma não consegue priorizar, direcionar, cobrar, escalar ou evidenciar corretamente.</div>
  <div class="g4">
    <div class="mt"><div class="mt-l">Problemas Totais</div><div class="mt-v vc">${total}</div><div class="mt-s">dados faltando</div></div>
    <div class="mt"><div class="mt-l">Críticos</div><div class="mt-v vc">${crits}</div><div class="mt-s">bloqueiam RBVM</div></div>
    <div class="mt"><div class="mt-l">Score de Cobertura</div><div class="mt-v ${total<20?'vk':'vh'}">${Math.max(0,100-total)}%</div><div class="mt-s">maturidade estimada</div></div>
    <div class="mt"><div class="mt-l">Ativos sem Criticidade</div><div class="mt-v vc">8</div><div class="mt-s">score inválido</div></div>
  </div>
  ${cats.map(cat=>`
  <div class="card">
    <div class="card-hd"><i class="ti ti-category" style="color:var(--accent)"></i><div><div class="card-t">${cat}</div></div></div>
    <div class="card-bd" style="padding-top:8px">
      ${dqItems.filter(i=>i.cat===cat).map(i=>{const sm=sevMap[i.sev];return`<div class="dq-item">
        <div class="dq-icon ${sm.cls}"><i class="ti ${i.icon}"></i></div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px"><span style="font-size:12px;font-weight:600">${i.label}</span><span class="pill ${i.sev==='crit'?'pc':i.sev==='high'?'ph':i.sev==='med'?'pm':'pd'}" style="font-size:9px">${i.sev==='ok'?'OK':i.val>0?i.val:''}</span></div>
          <div style="font-size:11px;color:var(--text2);margin-top:2px">${i.detail}</div>
          <div style="font-size:10px;color:var(--accent);margin-top:3px">→ ${i.fix}</div>
        </div>
      </div>`;}).join('')}
    </div>
  </div>`).join('')}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO C — EXECUTIVE INTELLIGENCE
// ══════════════════════════════════════════════════════════════════════════════
function execintel() {
  const active=VULNS.filter(v=>v.status!=='Resolved');
  const lm=MONTHLY_TRENDS[MONTHLY_TRENDS.length-1];
  const pm=MONTHLY_TRENDS[MONTHLY_TRENDS.length-2];
  const finTotal=FMT(totalFinancialExposure(VULNS));
  const slaRate=Math.round(lm.sla_compliance*100);
  const mttrDelta=((lm.mttr_crit-pm.mttr_crit)/pm.mttr_crit*100).toFixed(1);
  const excsExpiring=EXCS.filter(e=>{const d=new Date(e.exp); return d>new Date()&&(d-new Date())/(1000*60*60*24)<30;}).length;
  const decisions=[
    {icon:'ti-alert-octagon', sev:'crit',  q:'Quais KEVs seguem abertas e qual o risco para a organização?',         label:`${active.filter(v=>v.kev).length} KEVs ativas — exploração confirmada em ambiente real`},
    {icon:'ti-clock-x',       sev:'crit',  q:'Quais SLAs críticos estão vencidos e quem é responsável?',             label:`${active.filter(v=>v.sla_used>=v.sla_max).length} SLAs vencidos — escalonamento ativo`},
    {icon:'ti-currency-dollar',sev:'high', q:'Qual a exposição financeira estimada das vulnerabilidades críticas?',  label:`Exposição estimada: ${finTotal} em risco ativo`},
    {icon:'ti-git-branch',    sev:'high',  q:'Quais pipelines estão bloqueados e qual o impacto em entrega?',        label:`${PIPELINE_GATES?.filter(g=>g.status==='blocked').length||4} pipelines bloqueados — deploy impedido`},
    {icon:'ti-shield-x',      sev:'med',   q:'Quais exceções críticas vencem em breve e precisam de revisão?',       label:`${excsExpiring} exceções vencem em menos de 30 dias`},
    {icon:'ti-chart-line',    sev:'ok',    q:'Qual a tendência de MTTR e SLA compliance nos últimos 6 meses?',      label:`MTTR ${mttrDelta<0?'↓ melhorando':'↑ piorando'} ${Math.abs(mttrDelta)}% · SLA Compliance ${slaRate}%`},
  ];
  const slides=['Visão Executiva de Risco','Tendência de Risco — 6 meses','Top KEVs e Exposição Externa','MTTR e SLA Compliance','Exceções Ativas e Risco Aceito','Decisões Pendentes para Liderança','Plano de Ação — Próximos 30 dias'];
  return `<div class="content">
  <div class="nt ni-"><i class="ti ti-brain" style="font-size:16px;flex-shrink:0"></i><strong>Executive Intelligence</strong> — Respostas para as perguntas que liderança faz. Gerado a partir dos dados reais da plataforma.</div>
  <div class="g4">
    <div class="mt"><div class="mt-l">Exposição Total</div><div class="mt-v vc" style="font-size:17px">${finTotal}</div><div class="mt-s">risco financeiro estimado</div></div>
    <div class="mt"><div class="mt-l">Risco Caiu?</div><div class="mt-v ${mttrDelta<0?'vk':'vc'}">${mttrDelta<0?'SIM':'NÃO'}</div><div class="mt-s">MTTR ${Math.abs(mttrDelta)}% ${mttrDelta<0?'melhor':'pior'}</div></div>
    <div class="mt"><div class="mt-l">SLA Compliance</div><div class="mt-v ${slaRate>=80?'vk':'vh'}">${slaRate}%</div><div class="mt-s">meta: ≥90%</div></div>
    <div class="mt"><div class="mt-l">Backlog Crítico</div><div class="mt-v vc">${active.filter(v=>v.sev==='CRITICAL').length}</div><div class="mt-s">requer decisão</div></div>
  </div>
  <div class="card">
    <div class="card-hd"><i class="ti ti-checklist" style="color:var(--crit)"></i><div><div class="card-t">Decisões Pendentes para Liderança</div><div class="card-s">Perguntas que a diretoria precisa responder esta semana</div></div></div>
    <div class="card-bd">
      ${decisions.map(d=>`<div style="display:flex;align-items:center;gap:10px;padding:10px;border-radius:var(--r);border:1px solid var(--border);background:var(--bg3);margin-bottom:6px;cursor:pointer" onclick="quickMsg('${d.q.replace(/'/g,"\\'")}')">
        <i class="ti ${d.icon}" style="color:${d.sev==='crit'?'var(--crit)':d.sev==='high'?'var(--high)':d.sev==='ok'?'var(--success)':'var(--med)'};font-size:18px;flex-shrink:0"></i>
        <div style="flex:1"><div style="font-size:12px;font-weight:500">${d.label}</div><div style="font-size:10px;color:var(--text3)">${d.q}</div></div>
        <span class="pill ${d.sev==='crit'?'pc':d.sev==='high'?'ph':d.sev==='ok'?'pd':'pm'}" style="font-size:9px;flex-shrink:0">${d.sev==='crit'?'CRÍTICO':d.sev==='high'?'ALTO':d.sev==='ok'?'OK':'MÉDIO'}</span>
      </div>`).join('')}
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-hd"><i class="ti ti-presentation" style="color:var(--accent)"></i><div><div class="card-t">Gerar Apresentação Executiva</div><div class="card-s">PowerPoint para CISO e comitê de risco</div></div></div>
      <div class="card-bd">
        <div style="font-size:11px;color:var(--text2);margin-bottom:10px">Slides que seriam gerados:</div>
        ${slides.map((s,i)=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:4px;background:var(--bg4);margin-bottom:4px;font-size:11px"><span style="color:var(--text3);font-weight:700;min-width:20px">${i+1}.</span><span>${s}</span></div>`).join('')}
        <div class="btn-g" style="margin-top:12px">
          <button class="btn btn-p" onclick="quickMsg('Gere resumo executivo completo para o CISO com risco atual, KEVs abertas, MTTR, SLA compliance, exposição financeira, exceções e decisões pendentes para liderança.')"><i class="ti ti-robot"></i> Gerar via Agente IA</button>
          <button class="btn" onclick="toast('Exportação PDF/PPTX: integração com backend necessária para versão enterprise','ts')"><i class="ti ti-file-analytics"></i> Exportar PDF/PPTX</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-hd"><i class="ti ti-target" style="color:var(--high)"></i><div><div class="card-t">Plano de Ação — Próximos 30 dias</div><div class="card-s">Prioridades executivas para redução de risco</div></div></div>
      <div class="card-bd">
        ${[
          {p:1,action:'Corrigir todas as CISA KEV abertas',prazo:'72h — 7 dias',who:'CloudOps + Network',status:'URGENTE'},
          {p:2,action:'Resolver SLAs vencidos com escalação ativa',prazo:'Esta semana',who:'Todos os times',status:'URGENTE'},
          {p:3,action:'Desbloquear pipelines críticos (CI/CD)',prazo:'48h',who:'DevSecOps',status:'BLOQUEANTE'},
          {p:4,action:'Renovar assessments de fornecedores vencidos',prazo:'30 dias',who:'GRC + Procurement',status:'REGULATÓRIO'},
          {p:5,action:'Cadastrar owners para 14 ativos sem responsável',prazo:'15 dias',who:'CMDB Team',status:'QUALIDADE'},
        ].map(a=>`<div style="display:flex;gap:8px;padding:8px;border-radius:var(--r);background:var(--bg3);border:1px solid var(--border);margin-bottom:6px">
          <span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">${a.p}.</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:11px;font-weight:600">${a.action}</div>
            <div style="font-size:10px;color:var(--text3)">Prazo: ${a.prazo} · Resp: ${a.who}</div>
          </div>
          <span class="pill ${a.status==='URGENTE'?'pc':a.status==='BLOQUEANTE'?'ph':'pn'}" style="font-size:8px;flex-shrink:0">${a.status}</span>
        </div>`).join('')}
      </div>
    </div>
  </div>
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  MÓDULO D — SMART TICKET GROUPING
// ══════════════════════════════════════════════════════════════════════════════
function smartgroup() {
  const active=VULNS.filter(v=>v.status!=='Resolved'&&v.status!=='Closed with Evidence');
  // Group by CVE (same CVE, multiple assets)
  const byCVE={};active.forEach(v=>{if(!byCVE[v.id])byCVE[v.id]=[];byCVE[v.id].push(v);});
  // Group by squad
  const bySquad={};active.forEach(v=>{if(!bySquad[v.squad])bySquad[v.squad]=[];bySquad[v.squad].push(v);});
  // Group by source
  const bySrc={};active.forEach(v=>{if(!bySrc[v.source])bySrc[v.source]=[];bySrc[v.source].push(v);});

  const suggestions=[
    {type:'EMERGENCIAL INDIVIDUAL',color:'var(--crit)',icon:'ti-alert-octagon',title:'CVEs com CISA KEV — Tickets Individuais P0/P1',reason:'KEVs com exploração ativa requerem ticket individual para rastreabilidade máxima e SLA emergencial.', items:active.filter(v=>v.kev).map(v=>v.id),reduction:null,epic:false},
    {type:'CAMPANHA DE PATCH',color:'var(--high)',icon:'ti-package',title:'Windows/Infrastructure — Patch Campaign',reason:'Multiple vulns na mesma tecnologia podem ser agrupadas em um Epic com Tasks por squad.',items:active.filter(v=>v.asset_type==='server'&&!v.kev).map(v=>v.id),reduction:'Reduz de '+active.filter(v=>v.asset_type==='server'&&!v.kev).length+' tickets para 1 Epic',epic:true},
    {type:'ÉPICO POR SQUAD',color:'var(--accent)',icon:'ti-users',title:'AppSec Squad — Security Backlog Epic',reason:'Findings do mesmo squad podem virar 1 épico com subtasks priorizadas por risk score.',items:Object.entries(bySquad).find(([k])=>k.includes('AppSec'))?.[1]?.map(v=>v.id)||[],reduction:'1 Epic por squad com subtasks priorizadas',epic:true},
    {type:'SCA / DEPENDÊNCIAS',color:'#a084ff',icon:'ti-code',title:'Dependências Vulneráveis — Package Update Campaign',reason:'Vulns de dependências afetando múltiplos repos viram um épico por squad com PRs automáticos.',items:active.filter(v=>v.source==='Snyk'||v.source?.includes('Dependabot')).map(v=>v.id),reduction:'1 Epic + PRs automáticos via Snyk',epic:true},
    {type:'CI/CD — INDIVIDUAL',color:'var(--high)',icon:'ti-git-branch',title:'Secrets e CI/CD Blockers — Incidentes Individuais',reason:'Secrets expostos e blockers de pipeline são sempre individuais — risco específico e ação imediata.',items:active.filter(v=>v.asset_type==='repository').map(v=>v.id),reduction:null,epic:false},
  ];

  const totalOriginal=active.length;
  const totalGrouped=suggestions.reduce((s,sg)=>s+(sg.epic?1:sg.items.length),0);
  return `<div class="content">
  <div class="nt ni-"><i class="ti ti-stack-2" style="font-size:16px;flex-shrink:0"></i><strong>Smart Ticket Grouping</strong> — Evitar abrir milhares de tickets inúteis. Estratégia inteligente reduz ruído operacional e mantém rastreabilidade.</div>
  <div class="g4">
    <div class="mt"><div class="mt-l">Findings Abertos</div><div class="mt-v vi">${totalOriginal}</div><div class="mt-s">sem agrupamento</div></div>
    <div class="mt"><div class="mt-l">Após Agrupamento</div><div class="mt-v vk">~${totalGrouped}</div><div class="mt-s">tickets/epics sugeridos</div></div>
    <div class="mt"><div class="mt-l">Redução de Ruído</div><div class="mt-v vk">${Math.round((1-totalGrouped/Math.max(totalOriginal,1))*100)}%</div><div class="mt-s">menos tickets</div></div>
    <div class="mt"><div class="mt-l">Critério Principal</div><div class="mt-v vt" style="font-size:14px">Risco + Squad</div><div class="mt-s">agrupamento inteligente</div></div>
  </div>
  <div class="notice nw" style="display:flex;gap:8px;align-items:flex-start;padding:10px 12px;border-radius:var(--r)"><i class="ti ti-alert-triangle" style="font-size:16px;flex-shrink:0;color:var(--high)"></i><span style="font-size:11px;color:var(--high)"><strong>Regra crítica:</strong> KEVs, secrets expostos e RCEs internet-facing devem SEMPRE ter tickets individuais — nunca agrupados. O agrupamento é para reduzir ruído em vulns de menor urgência.</span></div>
  ${suggestions.map(sg=>`<div class="sg-card">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <i class="ti ${sg.icon}" style="color:${sg.color};font-size:18px"></i>
      <div><div class="sg-type" style="color:${sg.color}">${sg.type}</div><div class="sg-title">${sg.title}</div></div>
      <div style="margin-left:auto;text-align:right">${sg.epic?rpill('pi','EPIC'):'<span class="pill pn" style="font-size:9px">INDIVIDUAL</span>'}</div>
    </div>
    <div style="font-size:11px;color:var(--text2);margin-bottom:8px">${sg.reason}</div>
    <div class="sg-stat">
      <span>${sg.items.length} findings</span>
      ${sg.reduction?`<span style="color:var(--success)">→ ${sg.reduction}</span>`:''}
    </div>
    ${sg.items.length>0?`<div style="margin-top:8px;display:flex;gap:4px;flex-wrap:wrap">${sg.items.slice(0,6).map(id=>`<span class="pill pn" style="font-size:9px">${id}</span>`).join('')}${sg.items.length>6?`<span style="font-size:10px;color:var(--text3)">+${sg.items.length-6} mais</span>`:''}</div>`:''}
    <div class="btn-g" style="margin-top:10px">
      <button class="btn btn-s btn-p" onclick="toast('Grouping aplicado — ${sg.items.length} findings → ${sg.epic?'1 Epic':'tickets individuais'}','ts')"><i class="ti ti-plus"></i> Aplicar Agrupamento</button>
      <button class="btn btn-s" onclick="quickMsg('Gere um plano de agrupamento de tickets para: ${sg.title}. Inclua critério de agrupamento, risco de agrupamento indevido e estrutura de Epic/Tasks sugerida.')"><i class="ti ti-robot"></i> Detalhar via IA</button>
    </div>
  </div>`).join('')}
  </div>`;
}

// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 1 — ZERO-DAY WAR ROOM
// ══════════════════════════════════════════════════════════════════════════════
function warroom() {
  const active = WAR_ROOM_INCIDENTS.filter(i => i.status === 'active');
  const inc = WAR_ROOM_INCIDENTS.find(i => i.id === WR_SEL) || WAR_ROOM_INCIDENTS[0];
  const done = inc.containment.filter(c => c.done).length;
  const pct  = Math.round(done / inc.containment.length * 100);
  const exposed = inc.affected_assets.filter(a => a.status === 'exposed').length;

  // Elapsed timer
  const elapsed = (() => {
    const d = new Date(inc.detected);
    const now = new Date('2024-05-21 09:30');
    const diff = Math.floor((now - d) / 60000);
    const h = Math.floor(diff / 60), m = diff % 60;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
  })();

  const assetStatus = s => ({
    exposed:    { dot:'wr-exposed',    label:'EXPOSTO',     pill:'pc' },
    workaround: { dot:'wr-workaround', label:'Workaround',  pill:'pm' },
    patched:    { dot:'wr-patched',    label:'Corrigido',   pill:'pd' },
    patching:   { dot:'wr-workaround', label:'Patchando...', pill:'pp' },
  })[s] || { dot:'wr-exposed', label:s, pill:'pn' };

  return `<div class="content">
  <div class="wr-banner">
    <i class="ti ti-alert-hexagon" style="font-size:28px;color:var(--crit);flex-shrink:0"></i>
    <div style="flex:1">
      <div style="font-size:11px;font-weight:700;color:var(--crit);text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px">ZERO-DAY WAR ROOM ATIVO — ${inc.severity}</div>
      <div style="font-size:14px;font-weight:700;color:var(--text)">${inc.cve} — ${inc.title}</div>
      <div style="font-size:11px;color:var(--text2);margin-top:2px">Detectado: ${inc.detected} · ${inc.affected_count} ativos · Containment: ${done}/${inc.containment.length} etapas</div>
    </div>
    <div style="text-align:right;flex-shrink:0">
      <div style="font-size:10px;color:var(--text3);margin-bottom:2px">TEMPO DECORRIDO</div>
      <div class="wr-timer">${elapsed}</div>
      <div style="font-size:10px;color:${exposed>0?'var(--crit)':'var(--success)'};font-weight:600;margin-top:3px">${exposed>0?exposed+' ativo(s) ainda exposto(s)':'Todos os ativos contidos'}</div>
    </div>
  </div>

  <div style="display:flex;gap:8px;flex-wrap:wrap">
    ${WAR_ROOM_INCIDENTS.filter(i=>i.status==='active').map(i => `<div class="wr-tab ${i.id===WR_SEL?'active':''}" onclick="wrSelect('${i.id}')"><strong>${i.id}</strong> — ${i.cve}</div>`).join('')}
  </div>

  <div class="g2">
    <!-- LEFT: Assets + Containment -->
    <div style="display:flex;flex-direction:column;gap:10px">
      <div class="card">
        <div class="card-hd"><i class="ti ti-server" style="color:var(--crit)"></i><div><div class="card-t">Ativos Afetados (${inc.affected_count})</div><div class="card-s">${exposed} expostos · Patch ETA: ${inc.patch_eta||'a definir'}</div></div></div>
        <div class="card-bd" style="padding-top:6px">
          ${inc.affected_assets.map(a => {
            const st = assetStatus(a.status);
            return `<div class="wr-asset">
              <div class="wr-dot ${st.dot}"></div>
              <div style="flex:1">
                <div style="font-size:12px;font-weight:500">${a.name}</div>
                <div style="font-size:10px;color:var(--text3)">${a.internet?'🌐 internet-facing':' rede interna'} · ${a.critical?'Crítico':'Standard'}</div>
              </div>
              <span class="pill ${st.pill}" style="font-size:9px">${st.label}</span>
              ${a.status==='exposed'?`<button class="btn btn-s btn-d" onclick="wrContainAsset('${inc.id}','${a.name}')"><i class="ti ti-shield"></i></button>`:''}
            </div>`;
          }).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><i class="ti ti-list-check" style="color:var(--accent)"></i><div><div class="card-t">Checklist de Contenção</div><div class="card-s">${pct}% concluído — ${inc.containment.length-done} etapas pendentes</div></div></div>
        <div class="card-bd" style="padding-top:6px">
          <div class="pbar" style="height:5px;margin-bottom:12px"><div class="pbf" style="width:${pct}%;background:${pct===100?'var(--success)':pct>60?'var(--med)':'var(--high)'}"></div></div>
          ${inc.containment.map(s => `<div class="pbs">
            <div class="pb-num ${s.done?'pbs-done':s.n===inc.containment.find(x=>!x.done)?.n?'pbs-act':'pbs-idle'}">${s.n}</div>
            <div style="flex:1"><div style="font-size:11px;color:${s.done?'var(--text2)':'var(--text)'};${s.done?'text-decoration:line-through':''}">${s.label}</div><div style="font-size:9px;color:var(--text3)">${s.auto?'🤖 Automático':'👤 Manual'}</div></div>
            ${s.done?'<i class="ti ti-check" style="color:var(--success);font-size:14px"></i>':s.n===inc.containment.find(x=>!x.done)?.n?`<button class="btn btn-s btn-o" onclick="wrCompleteStep('${inc.id}',${s.n-1})"><i class="ti ti-check"></i></button>`:''}
          </div>`).join('')}
        </div>
      </div>
    </div>

    <!-- RIGHT: Timeline + Actions + IoCs -->
    <div style="display:flex;flex-direction:column;gap:10px">
      <div class="card">
        <div class="card-hd"><i class="ti ti-activity" style="color:var(--accent)"></i><div><div class="card-t">Timeline do Incidente</div><div class="card-s">Cronologia de eventos — T+0 até agora</div></div></div>
        <div class="card-bd" style="padding-top:8px">
          ${inc.timeline.map(e => `<div class="wr-tl-row">
            <div class="wr-tl-t">${e.t}</div>
            <div style="flex-shrink:0;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--bg4);margin-top:0"><i class="ti ${e.icon}" style="color:${e.color};font-size:12px"></i></div>
            <div style="flex:1;min-width:0">
              <div style="font-size:11px;font-weight:500;line-height:1.4">${e.action}</div>
              <div style="font-size:10px;color:var(--text3);margin-top:1px">${e.ts} · ${e.actor}</div>
            </div>
          </div>`).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><i class="ti ti-send" style="color:var(--accent)"></i><div><div class="card-t">Comunicação de Crise</div><div class="card-s">Templates pré-aprovados para cada canal</div></div></div>
        <div class="card-bd">
          <div class="btn-g">
            <button class="btn btn-d" onclick="wrComm('${inc.id}','alert')"><i class="ti ti-alert-octagon"></i> Alerta Inicial P0</button>
            <button class="btn btn-s" onclick="wrComm('${inc.id}','board')"><i class="ti ti-briefcase"></i> Board Update</button>
            <button class="btn btn-s" onclick="wrComm('${inc.id}','technical')"><i class="ti ti-terminal"></i> Brief Técnico</button>
            <button class="btn btn-s" onclick="quickMsg('Gere um comunicado de crise para o incidente ${inc.id} — ${inc.cve}: ${inc.title}. Inclua: status de contenção ${done}/${inc.containment.length} etapas, ${exposed} ativos ainda expostos, workaround: ${inc.workaround}, patch ETA: ${inc.patch_eta||'a definir'}. Tom: urgente mas controlado.')"><i class="ti ti-robot"></i> IA</button>
          </div>
          ${inc.patch_available?`<div class="nt nok" style="margin-top:10px"><i class="ti ti-package" style="font-size:14px;flex-shrink:0"></i>Patch disponível: ${inc.patch_note}</div>`:`<div class="nt nc-" style="margin-top:10px"><i class="ti ti-exclamation-mark" style="font-size:14px;flex-shrink:0"></i>Sem patch disponível ainda. Workaround obrigatório enquanto aguarda.</div>`}
          <div style="margin-top:10px"><div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Workaround Aplicar</div><div style="background:var(--bg4);border-radius:var(--r);padding:8px 12px;font-size:11px;color:var(--text2);font-family:var(--mono);line-height:1.5">${inc.workaround}</div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><i class="ti ti-eye-off" style="color:var(--high)"></i><div><div class="card-t">Indicators of Compromise (IoCs)</div></div></div>
        <div class="card-bd" style="padding-top:6px">
          ${inc.iocs.map(ioc=>`<div style="display:flex;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid var(--border)"><i class="ti ti-point-filled" style="color:var(--crit);font-size:10px;margin-top:3px;flex-shrink:0"></i><span style="font-size:11px;color:var(--text2)">${ioc}</span></div>`).join('')}
        </div>
      </div>
    </div>
  </div>
  </div>`;
}
window.wrSelect       = id => { WR_SEL = id; render(); };
window.wrContainAsset = (incId, assetName) => {
  const inc = WAR_ROOM_INCIDENTS.find(i=>i.id===incId);
  const a = inc?.affected_assets.find(x=>x.name===assetName);
  if(a){ a.status='workaround'; toast(`${assetName}: workaround aplicado — status atualizado`,'ts'); render(); }
};
window.wrCompleteStep = (incId, idx) => {
  const inc = WAR_ROOM_INCIDENTS.find(i=>i.id===incId);
  if(inc?.containment[idx]) { inc.containment[idx].done=true; toast(`Etapa ${idx+1} concluída ✓`,'ts'); render(); }
};
window.wrComm = (incId, type) => {
  const inc = WAR_ROOM_INCIDENTS.find(i=>i.id===incId);
  const msgs = {
    alert: `🚨 *WAR ROOM P0 — ${inc?.cve}*

*${inc?.title}*

Detectado: ${inc?.detected}
Ativos afetados: ${inc?.affected_count}
Workaround: ${inc?.workaround}

Ação imediata requerida de todos os times responsáveis.`,
    board: `📊 *ATUALIZAÇÃO EXECUTIVA — ${inc?.id}*

${inc?.title}

Contenção: ${inc?.containment.filter(c=>c.done).length}/${inc?.containment.length} etapas
Patch ETA: ${inc?.patch_eta||'a definir'}
Risco residual: ${inc?.affected_assets.filter(a=>a.status==='exposed').length>0?'ALTO':'MÉDIO — workaround ativo'}`,
    technical: `🔧 *BRIEF TÉCNICO — ${inc?.cve}*

${inc?.summary}

Workaround: ${inc?.workaround}
Patch: ${inc?.patch_note}
IoCs: ${inc?.iocs?.join(' | ')}`,
  };
  navigator.clipboard?.writeText(msgs[type]||'').catch(()=>{});
  toast(`Comunicado copiado para clipboard — colar no Slack/Teams`,'ts');
};

// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 1 — CROWN JEWELS & ATTACK PATH ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════
function attackPathSVG(path) {
  const steps = path.steps;
  const nW=110, nH=40, gap=48, pad=10;
  const totalW = steps.length*(nW+gap)-gap+pad*2;
  const totalH = nH+40+pad*2;
  const colorOf = t => ({
    entry:     {fill:'rgba(255,140,56,.12)',stroke:'var(--high)',text:'var(--high)'},
    node:      {fill:'var(--bg4)',stroke:'var(--border2)',text:'var(--text)'},
    technique: {fill:'rgba(255,76,76,.1)',stroke:'var(--crit)',text:'var(--crit)'},
    target:    {fill:'rgba(255,76,76,.2)',stroke:'var(--crit)',text:'var(--crit)'},
  }[t]||{fill:'var(--bg4)',stroke:'var(--border2)',text:'var(--text)'});

  let s = `<svg viewBox="0 0 ${totalW} ${totalH}" style="width:100%;min-width:420px" xmlns="http://www.w3.org/2000/svg">`;
  steps.forEach((step,i) => {
    const x=pad+i*(nW+gap), y=pad+20;
    const c=colorOf(step.type);
    // Arrow from prev
    if(i>0){
      const ax=x-gap+2, ay=y+nH/2;
      const dash = step.type==='technique'?'4,3':'none';
      s+=`<line x1="${ax}" y1="${ay}" x2="${x-6}" y2="${ay}" stroke="var(--crit)" stroke-width="1.5" stroke-dasharray="${dash}" opacity=".7"/>`;
      s+=`<polygon points="${x-6},${ay-4} ${x},${ay} ${x-6},${ay+4}" fill="var(--crit)" opacity=".7"/>`;
    }
    // Node rect
    s+=`<rect x="${x}" y="${y}" width="${nW}" height="${nH}" rx="5" fill="${c.fill}" stroke="${c.stroke}" stroke-width="1.5"/>`;
    // Step label (wrap at 14 chars)
    const lbl = step.label; const mid = lbl.length>14?lbl.substring(0,14):null;
    if(mid){
      s+=`<text x="${x+nW/2}" y="${y+15}" text-anchor="middle" font-size="9.5" fill="${c.text}" font-family="system-ui" font-weight="600">${lbl.substring(0,14)}</text>`;
      s+=`<text x="${x+nW/2}" y="${y+27}" text-anchor="middle" font-size="9.5" fill="${c.text}" font-family="system-ui" font-weight="600">${lbl.substring(14)}</text>`;
    } else {
      s+=`<text x="${x+nW/2}" y="${y+22}" text-anchor="middle" font-size="9.5" fill="${c.text}" font-family="system-ui" font-weight="600">${lbl}</text>`;
    }
    // Detail below
    const det = step.detail.length>16?step.detail.substring(0,16)+'…':step.detail;
    s+=`<text x="${x+nW/2}" y="${y+nH+12}" text-anchor="middle" font-size="8" fill="var(--text3)" font-family="system-ui">${det}</text>`;
  });
  s+='</svg>';
  return s;
}

function protectionRing(score, color) {
  const r=22, circ=2*Math.PI*r, fill=circ*(score/100);
  return `<div class="cj-ring"><svg viewBox="0 0 56 56"><circle cx="28" cy="28" r="${r}" fill="none" stroke="var(--bg4)" stroke-width="5"/><circle cx="28" cy="28" r="${r}" fill="none" stroke="${color}" stroke-width="5" stroke-dasharray="${fill} ${circ}" stroke-linecap="round"/></svg><div class="cj-ring-score" style="color:${color}">${score}</div></div>`;
}

function crownj() {
  const sel = CROWN_JEWELS.find(c=>c.id===CJ_SEL)||CROWN_JEWELS[0];
  const avgProt = Math.round(CROWN_JEWELS.reduce((s,c)=>s+c.protection_score,0)/CROWN_JEWELS.length);
  const exposed = CROWN_JEWELS.filter(c=>c.open_vulns>0).length;
  const ap = sel.attack_paths[0];

  return `<div class="content">
  <div class="g4">
    <div class="mt"><div class="mt-l">Crown Jewels</div><div class="mt-v vi">${CROWN_JEWELS.length}</div><div class="mt-s">ativos críticos mapeados</div></div>
    <div class="mt"><div class="mt-l">Com Vulnerabilidade</div><div class="mt-v vc">${exposed}</div><div class="mt-s">expõem crown jewels</div></div>
    <div class="mt"><div class="mt-l">Proteção Média</div><div class="mt-v ${avgProt>=75?'vk':avgProt>=60?'vh':'vc'}">${avgProt}%</div><div class="mt-s">score de proteção</div></div>
    <div class="mt"><div class="mt-l">Caminhos de Ataque</div><div class="mt-v vc">${CROWN_JEWELS.reduce((s,c)=>s+c.attack_paths.length,0)}</div><div class="mt-s">mapeados com MITRE</div></div>
  </div>
  <div class="nt nw"><i class="ti ti-crown" style="font-size:16px;flex-shrink:0"></i><strong>Crown Jewels</strong> são os ativos cuja comprometimento causaria dano catastrófico ao negócio, independente de qualquer SLA. Recebem tratamento de risco prioritário e revisão de ataque contínua.</div>

  <div class="g2">
    <!-- LEFT: Crown Jewels list -->
    <div>
      ${CROWN_JEWELS.map(cj => {
        const c = getProtectionColor(cj.protection_score);
        return `<div class="cj-card ${cj.id===CJ_SEL?'active':''}" onclick="cjSelect('${cj.id}')" style="margin-bottom:8px;${cj.id===CJ_SEL?'border-color:'+cj.color:''}">
          <div style="display:flex;align-items:center;gap:12px">
            ${protectionRing(cj.protection_score, c)}
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">
                <i class="ti ${cj.icon}" style="color:${cj.color};font-size:16px"></i>
                <span style="font-size:13px;font-weight:600">${cj.name}</span>
              </div>
              <div style="font-size:10px;color:var(--text3)">${cj.category} · ${cj.attack_paths.length} caminho(s) de ataque</div>
              <div style="display:flex;gap:6px;margin-top:5px;flex-wrap:wrap">
                ${cj.open_vulns>0?`<span class="pill pc" style="font-size:9px">${cj.open_vulns} vuln expondo</span>`:'<span class="pill pd" style="font-size:9px">Sem vuln direta</span>'}
                <span class="pill pn" style="font-size:9px">Proteção: ${cj.protection_score}%</span>
              </div>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>

    <!-- RIGHT: Crown Jewel detail -->
    <div class="cj-detail">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <i class="ti ${sel.icon}" style="color:${sel.color};font-size:24px"></i>
        <div><div style="font-size:15px;font-weight:700">${sel.name}</div><div style="font-size:11px;color:var(--text2)">${sel.category}</div></div>
      </div>
      <div style="font-size:12px;color:var(--text2);line-height:1.6;margin-bottom:14px">${sel.description}</div>

      ${sel.open_vulns>0?`<div class="nt nc-" style="margin-bottom:12px"><i class="ti ti-alert-triangle" style="font-size:14px;flex-shrink:0"></i><strong>${sel.open_vulns} vulnerabilidade(s) expondo diretamente este crown jewel:</strong> ${sel.vuln_ids.map(id=>`<span class="pill pc" style="font-size:9px;margin-left:4px">${id}</span>`).join('')}<button class="btn btn-s btn-d" style="margin-left:auto" onclick="fBySev('ALL');setView('vulns')">Ver Vuln →</button></div>`:''}

      <div class="ds">Caminho de Ataque — ${ap.name}</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span class="pill ${ap.difficulty==='low'?'pc':ap.difficulty==='medium'?'ph':'pd'}" style="font-size:9px">${getDifficultyLabel(ap.difficulty)}</span>
        ${ap.mitre.map(m=>`<span class="pill pai" style="font-size:9px">${m}</span>`).join('')}
      </div>
      <div class="ap-wrap">${attackPathSVG(ap)}</div>
      <div class="ap-legend">
        <span style="color:var(--high)">■ Entrada</span>
        <span style="color:var(--text3)">■ Nó</span>
        <span style="color:var(--crit)">■ Técnica MITRE</span>
        <span style="color:var(--crit)">■ Crown Jewel</span>
        <span style="color:var(--text3)">╌ Move lateral</span>
      </div>

      <div class="ds" style="margin-top:14px">Controles Ausentes que Habilitam este Caminho</div>
      ${ap.gaps.map(g=>`<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px"><i class="ti ti-x" style="color:var(--crit);font-size:12px;flex-shrink:0"></i><span style="color:var(--text2)">${g}</span></div>`).join('')}

      <div class="ds" style="margin-top:14px">Blast Radius — Impacto se Comprometido</div>
      ${sel.blast_radius.map((b,i)=>`<div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11px"><span style="color:var(--crit);font-weight:700;min-width:16px">${i+1}.</span><span style="color:var(--text2)">${b}</span></div>`).join('')}

      <div class="ds" style="margin-top:14px">Recomendações de Proteção</div>
      ${sel.recommendations.map(r=>`<div style="display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:11px"><i class="ti ti-arrow-right" style="color:var(--accent);font-size:12px;flex-shrink:0;margin-top:1px"></i><span style="color:var(--text2)">${r}</span></div>`).join('')}

      <div class="btn-g" style="margin-top:14px">
        <button class="btn btn-p btn-s" onclick="quickMsg('Analise o crown jewel ${sel.name} (ID: ${sel.id}). Caminho de ataque ativo: ${ap.name}. Gaps identificados: ${ap.gaps.join(', ')}. Gere um plano de proteção priorizado com controles técnicos específicos, quick wins e roadmap de 90 dias.')"><i class="ti ti-robot"></i> Plano de Proteção via IA</button>
        <button class="btn btn-s" onclick="quickMsg('Calcule o blast radius real do crown jewel ${sel.name} em nosso ambiente. Ativos conectados, dados em escopo, obrigações regulatórias impactadas e estimativa de dano financeiro caso comprometido.')"><i class="ti ti-ripple"></i> Blast Radius via IA</button>
      </div>
    </div>
  </div>
  </div>`;
}
window.cjSelect = id => { CJ_SEL = id; render(); };


// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 2A — SBOM (Software Bill of Materials)
// ══════════════════════════════════════════════════════════════════════════════
function sbom() {
  const st = getSbomStats();
  const filtered = SBOM_COMPONENTS.filter(c => {
    if (SBOM_FILTER_APP !== 'ALL' && !c.apps.includes(SBOM_FILTER_APP)) return false;
    if (SBOM_FILTER_ECO !== 'ALL' && c.ecosystem !== SBOM_FILTER_ECO) return false;
    if (SBOM_FILTER_CVE && c.cves.length === 0) return false;
    return true;
  });

  const ecoBadge = eco => {
    const m = {maven:'eco-maven',npm:'eco-npm',pypi:'eco-pypi',docker:'eco-docker',system:'eco-system'};
    return `<span class="eco-badge ${m[eco]||'eco-system'}">${eco}</span>`;
  };
  const licClass = r => ({critical:'lic-critical',high:'lic-high',medium:'lic-medium',none:'lic-none'}[r]||'lic-none');

  const overviewHTML = () => `
    <div class="content">
    <div class="g6" style="margin-bottom:0">
      <div class="mt"><div class="mt-l">Componentes Total</div><div class="mt-v vi">${SBOM_APPS.reduce((s,a)=>s+a.components_total,0).toLocaleString()}</div><div class="mt-s">${SBOM_APPS.length} aplicações</div></div>
      <div class="mt"><div class="mt-l">Com CVE Conhecida</div><div class="mt-v vc">${st.withCves}</div><div class="mt-s">${st.totalCves} CVEs total</div></div>
      <div class="mt"><div class="mt-l">Diretos Vuln.</div><div class="mt-v vc">${st.directVuln}</div><div class="mt-s">dependência direta</div></div>
      <div class="mt"><div class="mt-l">EOL / EOS</div><div class="mt-v vc">${st.eolComps}</div><div class="mt-s">sem suporte ativo</div></div>
      <div class="mt"><div class="mt-l">Risco de Licença</div><div class="mt-v vh">${st.licRisk}</div><div class="mt-s">análise jurídica</div></div>
      <div class="mt"><div class="mt-l">Cobertura SBOM</div><div class="mt-v vk">${SBOM_APPS.length}/5</div><div class="mt-s">aplicações com SBOM</div></div>
    </div>
    <div class="nt nw" style="margin:14px 0 0"><i class="ti ti-alert-triangle" style="font-size:16px;flex-shrink:0"></i><strong>PCI DSS 4.0 Req 6.3.2</strong> e <strong>Executive Order 14028</strong> exigem SBOM para todos os sistemas críticos. ${st.eolComps} componente(s) EOL em produção requerem plano de substituição documentado.</div>
    <div class="card" style="margin-top:14px">
      <div class="card-hd"><i class="ti ti-apps" style="color:var(--accent)"></i><div><div class="card-t">Aplicações com SBOM ativo</div><div class="card-s">Cobertura por scanner · último scan · componentes</div></div>
        <div class="card-ac">
          <span class="sbom-export" onclick="toast('Export CycloneDX JSON gerado — download disponível em ambiente com backend','ts')"><i class="ti ti-file-code"></i> CycloneDX</span>
          <span class="sbom-export" onclick="toast('Export SPDX 2.3 gerado','ts')"><i class="ti ti-file-text"></i> SPDX 2.3</span>
        </div>
      </div>
      <div class="tbl"><table>
        <thead><tr><th>Aplicação</th><th>Tipo</th><th>Squad</th><th>Scanner</th><th>Último Scan</th><th>Total Comp.</th><th>Com CVE</th><th>Risco Lic.</th></tr></thead>
        <tbody>${SBOM_APPS.map(a=>`<tr class="tr" onclick="SBOM_FILTER_APP='${a.id}';SBOM_TAB='components';render()">
          <td style="font-weight:500">${a.name}</td>
          <td>${ecoBadge(a.type)}</td>
          <td style="font-size:11px;color:var(--text2)">${a.squad}</td>
          <td style="font-size:11px;color:var(--text3)">${a.scanner}</td>
          <td style="font-size:11px;color:var(--text3)">${a.last_scan}</td>
          <td style="font-weight:700">${a.components_total.toLocaleString()}</td>
          <td style="color:${a.components_vuln>0?'var(--crit)':'var(--success)'};font-weight:700">${a.components_vuln}</td>
          <td style="color:${a.license_risk>0?'var(--high)':'var(--text3)'}">
            ${a.license_risk>0?`<span class="pill ph" style="font-size:9px">${a.license_risk} comp.</span>`:'<span style="font-size:10px">—</span>'}
          </td>
        </tr>`).join('')}</tbody>
      </table></div>
    </div>
    </div>`;

  const componentsHTML = () => `
    <div>
    <div class="frow">
      <span style="font-size:11px;color:var(--text3);font-weight:600">APP:</span>
      <div class="fc ${SBOM_FILTER_APP==='ALL'?'act':''}" onclick="SBOM_FILTER_APP='ALL';render()">Todas</div>
      ${SBOM_APPS.map(a=>`<div class="fc ${SBOM_FILTER_APP===a.id?'act':''}" onclick="SBOM_FILTER_APP='${a.id}';render()">${a.name}</div>`).join('')}
      <span style="font-size:11px;color:var(--text3);font-weight:600;margin-left:10px">ECOSSISTEMA:</span>
      ${['ALL','maven','npm','pypi','docker','system'].map(e=>`<div class="fc ${SBOM_FILTER_ECO===e?'act':''}" onclick="SBOM_FILTER_ECO='${e}';render()">${e==='ALL'?'Todos':e}</div>`).join('')}
      <div class="fc ${SBOM_FILTER_CVE?'act':''}" onclick="SBOM_FILTER_CVE=!SBOM_FILTER_CVE;render()">⚠ Só com CVE</div>
      <span style="margin-left:auto;font-size:11px;color:var(--text3)">${filtered.length} componente(s)</span>
    </div>
    <div style="padding:12px 16px">
    <div class="tbl"><table>
      <thead><tr><th>Componente</th><th>Versão atual</th><th>Última</th><th>Ecossistema</th><th>Tipo</th><th>Licença</th><th>EOL</th><th>CVEs</th><th>Aplicações</th><th>Ação</th></tr></thead>
      <tbody>${filtered.map(c=>{
        const licRisk=LICENSE_RISKS[c.license];
        const hasVuln=c.cves.length>0;
        return `<tr class="tr" style="${hasVuln?'background:rgba(255,76,76,.03)':''}">
          <td style="font-weight:${hasVuln?'600':'400'}">${c.name}</td>
          <td class="mono" style="color:${c.eol?'var(--crit)':hasVuln?'var(--high)':'var(--text2)'}">${c.version}</td>
          <td class="mono" style="color:${c.version===c.latest?'var(--success)':'var(--text3)'}">${c.latest}</td>
          <td>${ecoBadge(c.ecosystem)}</td>
          <td><span class="${c.dep_type==='direct'?'dep-direct':'dep-trans'}">${c.dep_type==='direct'?'Direta':'Transitiva'}</span></td>
          <td class="${licRisk?licClass(licRisk.level):'lic-none'}">${c.license}</td>
          <td>${c.eol?`<span class="pill pc" style="font-size:9px" title="${c.eol_date}">EOL</span>`:'<span style="color:var(--success);font-size:10px">✓</span>'}</td>
          <td>${c.cves.length>0?`<span class="pill pc" style="font-size:9px" title="${c.cves.join(', ')}">${c.cves.length} CVE</span>`:'<span style="color:var(--success);font-size:10px">—</span>'}</td>
          <td style="font-size:10px;color:var(--text3)">${c.apps.map(id=>SBOM_APPS.find(a=>a.id===id)?.name||id).join(', ')}</td>
          <td>${c.can_upgrade?`<button class="btn btn-s btn-o" onclick="sbomUpgrade('${c.id}')"><i class="ti ti-arrow-up"></i> Upgrade</button>`:`<span class="pill pn" style="font-size:9px">Manual</span>`}</td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>
    </div></div>`;

  const licensesHTML = () => `
    <div class="content">
    <div class="nt nc-"><i class="ti ti-gavel" style="font-size:16px;flex-shrink:0"></i><strong>Risco Jurídico:</strong> Componentes GPL/AGPL em produto proprietário sem autorização podem exigir liberação do código fonte ou gerar litígio. Revisão legal obrigatória.</div>
    ${SBOM_COMPONENTS.filter(c=>c.license_risk!=='none').map(c=>{const lr=LICENSE_RISKS[c.license];return`<div class="card" style="margin-top:10px;border-left:3px solid ${lr?.level==='critical'?'var(--crit)':'var(--high)'}">
      <div class="card-hd"><i class="ti ti-gavel" style="color:${lr?.level==='critical'?'var(--crit)':'var(--high)'}"></i><div><div class="card-t">${c.name} v${c.version} — ${lr?.label||c.license}</div><div class="card-s">Usado em: ${c.apps.map(id=>SBOM_APPS.find(a=>a.id===id)?.name||id).join(', ')}</div></div><div class="card-ac"><span class="pill ${lr?.level==='critical'?'pc':'ph'}">${lr?.level?.toUpperCase()||'RISCO'}</span></div></div>
      <div class="card-bd"><div style="font-size:12px;color:var(--text2);margin-bottom:8px">${lr?.desc||''}</div><div class="nt nw"><i class="ti ti-arrow-right" style="font-size:14px;flex-shrink:0"></i>${c.upgrade_note}</div>
      <button class="btn btn-s" style="margin-top:8px" onclick="quickMsg('Analise o risco jurídico do componente ${c.name} (licença ${c.license}) usado em produto proprietário. Qual o risco real? Quais alternativas com licença permissiva oferecem funcionalidade similar? Qual o plano de substituição recomendado?')"><i class="ti ti-robot"></i> Análise Jurídica via IA</button></div>
    </div>`;}).join('')}
    <div class="card" style="margin-top:10px">
      <div class="card-hd"><i class="ti ti-check" style="color:var(--success)"></i><div><div class="card-t">Licenças Permissivas (${SBOM_COMPONENTS.filter(c=>c.license_risk==='none').length} componentes)</div></div></div>
      <div class="card-bd" style="display:flex;gap:6px;flex-wrap:wrap">
        ${[...new Set(SBOM_COMPONENTS.filter(c=>c.license_risk==='none').map(c=>c.license))].map(l=>`<span class="pill pd" style="font-size:10px">${l}</span>`).join('')}
      </div>
    </div>
    </div>`;

  const eolHTML = () => `
    <div class="content">
    <div class="nt nc-"><i class="ti ti-calendar-x" style="font-size:16px;flex-shrink:0"></i><strong>Componentes EOL/EOS</strong> não recebem patches de segurança. Cada novo CVE descoberto é permanentemente não corrigível na versão em uso. Risco cresce mensalmente.</div>
    ${SBOM_COMPONENTS.filter(c=>c.eol).map(c=>`<div class="card" style="margin-top:10px;border-left:3px solid var(--crit)">
      <div class="card-hd"><i class="ti ti-calendar-x" style="color:var(--crit)"></i><div><div class="card-t">${c.name} v${c.version}</div><div class="card-s">EOL desde ${c.eol_date||'data não publicada'} · Ecossistema: ${c.ecosystem} · Usado em: ${c.apps.map(id=>SBOM_APPS.find(a=>a.id===id)?.name||id).join(', ')}</div></div><div class="card-ac"><span class="pill pc">EOL</span>${c.cves.length?`<span class="pill pc" style="font-size:9px">${c.cves.length} CVEs sem patch</span>`:''}</div></div>
      <div class="card-bd"><div class="nt nw" style="margin-bottom:8px"><i class="ti ti-arrow-up" style="font-size:14px;flex-shrink:0"></i><strong>Plano de Upgrade:</strong> ${c.upgrade_note}</div>
      <div class="btn-g"><button class="btn btn-s btn-p" onclick="sbomUpgrade('${c.id}')"><i class="ti ti-ticket"></i> Criar Ticket de Upgrade</button><button class="btn btn-s" onclick="quickMsg('Crie um plano de migração para ${c.name} v${c.version} (EOL desde ${c.eol_date}). Alternativas compatíveis, breaking changes, esforço estimado em story points e riscos do processo de migração.')"><i class="ti ti-robot"></i> Plano de Migração via IA</button></div></div>
    </div>`).join('')}
    </div>`;

  const tabs = { overview:'Visão Geral', components:'Componentes', licenses:'Licenças', eol:'EOL Tracker' };
  const tabContent = { overview: overviewHTML, components: componentsHTML, licenses: licensesHTML, eol: eolHTML };
  const body = (tabContent[SBOM_TAB]||overviewHTML)();

  return `<div>
  <div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${SBOM_TAB===k?'active':''}" onclick="sbomTab('${k}')">${v}</div>`).join('')}
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;padding:6px 0">
      <span class="sbom-export" onclick="toast('Scan SBOM agendado para todos os repos','ts')"><i class="ti ti-refresh"></i> Re-scan All</span>
    </div>
  </div>
  ${body}
  </div>`;
}
window.sbomTab = t => { SBOM_TAB=t; SBOM_FILTER_APP='ALL'; SBOM_FILTER_ECO='ALL'; SBOM_FILTER_CVE=false; render(); };
window.sbomUpgrade = id => {
  const c = SBOM_COMPONENTS.find(x=>x.id===id);
  if(!c) return;
  toast(`Ticket de upgrade criado: ${c.name} ${c.version} → ${c.latest}`,'ts');
  addAuditEvent(c.vuln_ids?.[0]||c.id, {actor:'user',name:'SBOM Module',icon:'ti-box-multiple',action:`Upgrade de componente solicitado: ${c.name} ${c.version} → ${c.latest}`,before:null,after:null,detail:c.upgrade_note,src:'SBOM'});
};

// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 2B — FALSE POSITIVE WORKFLOW
// ══════════════════════════════════════════════════════════════════════════════
function fpw() {
  const allFP = [...FP_RECORDS, ...FP_LOCAL];
  const pending  = allFP.filter(r=>r.status==='under_review');
  const accepted = allFP.filter(r=>r.status==='accepted');
  const rejected = allFP.filter(r=>r.status==='rejected');
  const fpSt = getFPStats();

  const statusBadge = s => ({
    accepted:    '<span class="pill pd" style="font-size:10px">FP Aceito</span>',
    rejected:    '<span class="pill pc" style="font-size:10px">TP Confirmado</span>',
    under_review:'<span class="pill ph" style="font-size:10px">Em Revisão</span>',
  }[s]||`<span class="pill pn" style="font-size:10px">${s}</span>`);

  const renderFPCard = (r, showActions=false) => {
    const v = VULNS.find(x=>x.id===r.vuln_id)||{title:r.vuln_id,source:r.scanner};
    return `<div class="fp-card fp-status-${r.status}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="mono" style="color:var(--accent);font-size:11px">${r.id}</span>
        ${statusBadge(r.status)}
        <span class="pill pn" style="font-size:9px">${r.scanner}</span>
        <span style="font-size:11px;color:var(--text2)">• ${v.title?.substring(0,50)||r.vuln_id}</span>
        <span style="margin-left:auto;font-size:10px;color:var(--text3)">${r.created}</span>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-bottom:6px">Contestado por: <strong style="color:var(--text2)">${r.contestant}</strong>${r.reviewer?` · Revisor: <strong style="color:var(--text2)">${r.reviewer}</strong>`:' · <em>Aguardando revisor</em>'}</div>
      <div class="fp-quote">${r.justification}</div>
      ${r.evidence?`<div style="font-size:10px;color:var(--text3);margin-top:4px"><i class="ti ti-paperclip" style="font-size:11px"></i> Evidência: ${r.evidence}</div>`:''}
      ${r.reviewer_note?`<div style="margin-top:8px;padding:8px;background:var(--bg4);border-radius:var(--r);font-size:11px;color:${r.status==='accepted'?'var(--success)':'var(--crit)'}"><strong>Decisão do revisor:</strong> ${r.reviewer_note}</div>`:''}
      ${showActions&&r.status==='under_review'?`<div class="btn-g" style="margin-top:10px">
        <button class="btn btn-o btn-s" onclick="fpAccept('${r.id}')"><i class="ti ti-check"></i> Aceitar como FP</button>
        <button class="btn btn-d btn-s" onclick="fpReject('${r.id}')"><i class="ti ti-x"></i> Rejeitar (TP confirmado)</button>
        <button class="btn btn-s" onclick="fpRequestInfo('${r.id}')"><i class="ti ti-info-circle"></i> Pedir mais evidência</button>
        <button class="btn btn-s" onclick="quickMsg('Analise a contestação de falso positivo ${r.id} para a vulnerabilidade ${r.vuln_id} detectada pelo scanner ${r.scanner}. Justificativa do contestante: ${r.justification.substring(0,120)}. Com base na técnica do scanner e no contexto fornecido, qual a probabilidade real de ser um FP? Quais evidências adicionais ajudariam a decidir?')"><i class="ti ti-robot"></i> Análise via IA</button>
      </div>`:''}
    </div>`;
  };

  const queueHTML = () => `
    <div class="content">
    ${pending.length===0?'<div class="nt nok"><i class="ti ti-check" style="font-size:16px;flex-shrink:0"></i>Fila vazia — nenhuma contestação pendente de revisão.</div>':
      `<div class="nt nw"><i class="ti ti-clock" style="font-size:16px;flex-shrink:0"></i><strong>${pending.length} contestação(ões) aguardando revisão.</strong> Meta: revisar em até 48h para não impactar o backlog de remediação.</div>
      ${pending.map(r=>renderFPCard(r,true)).join('')}`}
    <div style="margin-top:14px">
      <button class="btn btn-p btn-s" onclick="openFPContest(null)"><i class="ti ti-plus"></i> Contestar Finding</button>
    </div>
    </div>`;

  const statsHTML = () => `
    <div class="content">
    <div class="g4" style="margin-bottom:0">
      <div class="mt"><div class="mt-l">Total Contestações</div><div class="mt-v vi">${allFP.length}</div></div>
      <div class="mt"><div class="mt-l">FP Aceitos</div><div class="mt-v vk">${accepted.length}</div></div>
      <div class="mt"><div class="mt-l">TP Confirmados</div><div class="mt-v vc">${rejected.length}</div></div>
      <div class="mt"><div class="mt-l">FP Rate Médio</div><div class="mt-v vh">${fpSt.avgRate}%</div><div class="mt-s">por scanner</div></div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-hd"><i class="ti ti-chart-bar" style="color:var(--accent)"></i><div><div class="card-t">Taxa de Falso Positivo por Scanner</div><div class="card-s">FP Rate = contestações aceitas / total findings × 100</div></div></div>
      <div class="card-bd">
        ${FP_SCANNER_STATS.sort((a,b)=>b.fp_rate-a.fp_rate).map(s=>{
          const pct=Math.min(100,s.fp_rate*8); // scale for visual
          const color=s.fp_rate>5?'var(--crit)':s.fp_rate>2?'var(--high)':'var(--success)';
          return `<div style="margin-bottom:10px">
            <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px">
              <span style="color:var(--text2)">${s.scanner}</span>
              <span style="font-weight:700;color:${color}">${s.fp_rate}% FP · ${s.fp_accepted} aceitos / ${s.fp_contested} contestados / ${s.total_findings} findings</span>
            </div>
            <div class="scanner-bar"><div class="scanner-bar-fill" style="width:${pct}%;background:${color}"></div></div>
          </div>`;
        }).join('')}
        <div class="nt ni-" style="margin-top:12px"><i class="ti ti-info-circle" style="font-size:14px;flex-shrink:0"></i>FP Rate > 5% indica necessidade de ajuste de configuração do scanner ou revisão de escopo de cobertura.</div>
      </div>
    </div>
    </div>`;

  const historyHTML = () => `
    <div class="content">
    ${[...accepted,...rejected].sort((a,b)=>b.created.localeCompare(a.created)).map(r=>renderFPCard(r,false)).join('')}
    </div>`;

  const tabs = { queue:`Fila de Revisão (${pending.length})`, stats:'Taxas por Scanner', history:'Histórico' };
  const tabContent = { queue:queueHTML, stats:statsHTML, history:historyHTML };
  const body = (tabContent[FP_TAB]||queueHTML)();

  return `<div>
  <div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${FP_TAB===k?'active':''}" onclick="fpTab('${k}')">${v}</div>`).join('')}
  </div>
  ${body}
  </div>`;
}
window.fpTab = t => { FP_TAB=t; render(); };

window.fpAccept = id => {
  const r=FP_RECORDS.find(x=>x.id===id)||FP_LOCAL.find(x=>x.id===id);
  if(!r) return;
  r.status='accepted'; r.reviewer='security-lead@corp.example'; r.resolved=new Date().toISOString().slice(0,10);
  r.reviewer_note='FP aceito após análise. Evidências validadas. Finding marcado como FP — não reabrir sem nova evidência.';
  // Mark vuln as false positive in status
  const v=VULNS.find(x=>x.id===r.vuln_id);
  if(v){ saveStatus(r.vuln_id,'Closed with Evidence'); addAuditEvent(r.vuln_id,{actor:'user',name:'Security Lead',icon:'ti-shield-check',action:`Falso Positivo aceito (${id}) — finding encerrado`,before:'In Progress',after:'Closed with Evidence',detail:`Scanner: ${r.scanner}. Contestação: ${r.id}. Evidência validada.`,src:'FP Workflow'}); }
  LS.set('fp_records',FP_LOCAL);
  toast(`${id}: FP aceito — finding encerrado`,'ts'); render();
};

window.fpReject = id => {
  const r=FP_RECORDS.find(x=>x.id===id)||FP_LOCAL.find(x=>x.id===id);
  if(!r) return;
  r.status='rejected'; r.reviewer='security-lead@corp.example'; r.resolved=new Date().toISOString().slice(0,10);
  r.reviewer_note='Contestação rejeitada. Finding confirmado como True Positive. Manter no backlog e cobrar remediação.';
  addAuditEvent(r.vuln_id,{actor:'user',name:'Security Lead',icon:'ti-x',action:`FP rejeitado (${id}) — True Positive confirmado`,before:null,after:null,detail:`Scanner ${r.scanner} correto. Contestação improcedente.`,src:'FP Workflow'});
  LS.set('fp_records',FP_LOCAL);
  toast(`${id}: Contestação rejeitada — TP confirmado`,'te'); render();
};

window.fpRequestInfo = id => {
  toast(`Solicitação de evidência adicional enviada para o contestante via email/Slack`,'ts');
};

window.openFPContest = vulnId => {
  const vulnOpts = VULNS.map(v=>`<option value="${v.id}" ${v.id===vulnId?'selected':''}>${v.id} — ${v.title.substring(0,50)}</option>`).join('');
  document.getElementById('mc').innerHTML=`
  <div class="modal-t"><i class="ti ti-shield-question" style="color:var(--high)"></i>Contestar Finding como Falso Positivo</div>
  <div class="nt nw" style="margin-bottom:12px"><i class="ti ti-alert-triangle" style="font-size:14px;flex-shrink:0"></i>FP incorreto pode mascarar risco real. Inclua evidências técnicas concretas que o revisor possa validar de forma independente.</div>
  <div class="fr">
    <div class="ff"><div class="fl">Vulnerabilidade</div><select class="fi" id="fp-vuln">${vulnOpts}</select></div>
    <div class="ff"><div class="fl">Scanner / Ferramenta</div><select class="fi" id="fp-scanner"><option>Tenable VM</option><option>Qualys VMDR</option><option>Snyk</option><option>SonarQube</option><option>Checkov</option><option>Trivy</option><option>Rapid7</option><option>Microsoft Defender</option></select></div>
  </div>
  <div class="ff" style="margin-bottom:12px"><div class="fl">Justificativa Técnica Detalhada</div><textarea class="fi" id="fp-just" placeholder="Por que este finding é um falso positivo neste ambiente específico? Inclua: versão afetada vs versão em uso, configuração específica que mitiga, isolamento de rede, etc."></textarea></div>
  <div class="ff" style="margin-bottom:12px"><div class="fl">Evidências Disponíveis</div><input class="fi" id="fp-ev" placeholder="Ex: diagrama de rede, config dump, scan de confirmação, log de sistema..."/></div>
  <div class="modal-ft">
    <button class="btn" onclick="closeMod()">Cancelar</button>
    <button class="btn btn-p" onclick="submitFPContest()"><i class="ti ti-send"></i> Submeter para Revisão</button>
  </div>`;
  document.getElementById('mbg').classList.add('open');
};

window.submitFPContest = () => {
  const vulnId  = document.getElementById('fp-vuln')?.value;
  const scanner = document.getElementById('fp-scanner')?.value;
  const just    = document.getElementById('fp-just')?.value;
  const ev      = document.getElementById('fp-ev')?.value;
  if(!just||just.length<20){ toast('Justificativa muito curta. Adicione detalhes técnicos.','te'); return; }
  const newFP = {
    id:`FP-${String(FP_RECORDS.length+FP_LOCAL.length+1).padStart(3,'0')}`,
    vuln_id:vulnId, scanner, status:'under_review',
    contestant:'current.user@corp.example', reviewer:null,
    justification:just, evidence:ev||'Sem evidência adicional',
    reviewer_note:null, created:new Date().toISOString().slice(0,10), resolved:null,
  };
  FP_LOCAL.push(newFP);
  LS.set('fp_records',FP_LOCAL);
  addAuditEvent(vulnId,{actor:'user',name:'Security Analyst',icon:'ti-shield-question',action:`Falso Positivo contestado — ${newFP.id}`,before:'In Progress',after:'In Progress',detail:`Scanner: ${scanner}. Motivo: ${just.substring(0,80)}...`,src:'FP Workflow'});
  toast(`${newFP.id} submetido para revisão`,'ts');
  closeMod(); FP_TAB='queue'; render();
};


// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 3 — ATTACK SURFACE MANAGEMENT (ASM)
// ══════════════════════════════════════════════════════════════════════════════
function asm() {
  const all      = EXTERNAL_ASSETS;
  const monitored= all.filter(a => !a.shadow);
  const shadow   = all.filter(a => a.shadow);
  const risky    = monitored.filter(a => a.risk_score >= 60).length;
  const certAlerts = monitored.filter(a => a.ssl.days !== null && a.ssl.days < 30).length;
  const noHeaders  = monitored.filter(a => a.headers.score < 30).length;
  const surfScore  = getAsmScore(all);
  const scoreColor = surfScore >= 60 ? 'var(--crit)' : surfScore >= 35 ? 'var(--high)' : 'var(--success)';

  // Exposure score SVG gauge
  const gaugeR = 50, gaugeC = 2 * Math.PI * gaugeR;
  const gaugeFill = gaugeC * (surfScore / 100);
  const gaugeSvg = `<svg viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg" style="transform:rotate(-90deg)">
    <circle cx="60" cy="60" r="${gaugeR}" fill="none" stroke="var(--bg4)" stroke-width="10"/>
    <circle cx="60" cy="60" r="${gaugeR}" fill="none" stroke="${scoreColor}" stroke-width="10"
      stroke-dasharray="${gaugeFill} ${gaugeC}" stroke-linecap="round"/>
  </svg>`;

  // ── HELPERS ──────────────────────────────────────────────────────────────────
  const riskPill  = s => s >= 75 ? rpill('pc','CRÍTICO') : s >= 55 ? rpill('ph','ALTO') : s >= 35 ? rpill('pm','MÉDIO') : rpill('pl','BAIXO');
  const sslGrade  = g => { const c=g==='A+'||g==='A'?'var(--success)':g==='B'?'var(--med)':g==='C'?'var(--high)':'var(--crit)'; return `<span class="ssl-grade" style="color:${c}">${g}</span>`; };
  const headerDot = ok => `<span class="hdr-check ${ok?'hdr-ok':'hdr-no'}">${ok?'✓':'✗'}</span>`;
  const dnsDot    = (ok,lbl) => `<span class="dns-tag" style="background:${ok?'var(--successbg)':'var(--critbg)'};color:${ok?'var(--success)':'var(--crit)'}">${lbl}</span>`;
  const portRisky = p => [22,23,3306,5432,6379,27017,2375,9200,8080,9000,3000].includes(p);
  const portBadge = p => `<span class="port-badge ${portRisky(p)?'port-risky':''}">${p}</span>`;
  const assetIcon = t => ({web_app:'ti-world',api:'ti-api',vpn:'ti-shield-lock',bastion:'ti-server',mail:'ti-mail',cdn:'ti-cloud',cloud_storage:'ti-brand-aws',shadow_it:'ti-ghost'}[t]||'ti-device-unknown');

  // ── OVERVIEW ─────────────────────────────────────────────────────────────────
  const overviewHTML = () => `<div class="content">
    <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap;margin-bottom:0">
      <div style="display:flex;flex-direction:column;align-items:center;gap:4px">
        <div class="asm-score-wrap">
          ${gaugeSvg}
          <div class="asm-score-val"><div class="asm-score-num" style="color:${scoreColor}">${surfScore}</div><div class="asm-score-lbl">EXPOSURE<br>SCORE</div></div>
        </div>
        <div style="font-size:10px;color:var(--text3)">0=mínimo · 100=máximo</div>
      </div>
      <div style="flex:1;display:grid;grid-template-columns:repeat(3,1fr);gap:10px;min-width:280px">
        <div class="mt"><div class="mt-l">Ativos Externos</div><div class="mt-v vi">${monitored.length}</div><div class="mt-s">monitorados</div></div>
        <div class="mt"><div class="mt-l">Shadow IT</div><div class="mt-v vc">${shadow.length}</div><div class="mt-s">fora do CMDB</div></div>
        <div class="mt"><div class="mt-l">Risco Alto+</div><div class="mt-v vc">${risky}</div><div class="mt-s">score ≥ 60</div></div>
        <div class="mt"><div class="mt-l">Certs < 30 dias</div><div class="mt-v ${certAlerts>0?'vc':'vk'}">${certAlerts}</div><div class="mt-s">vencendo</div></div>
        <div class="mt"><div class="mt-l">Headers Inseguros</div><div class="mt-v vh">${noHeaders}</div><div class="mt-s">score < 30</div></div>
        <div class="mt"><div class="mt-l">Sem TLS válido</div><div class="mt-v ${shadow.length>0?'vc':'vk'}">${all.filter(a=>!a.ssl.valid).length}</div><div class="mt-s">ativos</div></div>
      </div>
    </div>
    ${shadow.length>0?`<div class="nt nc-"><i class="ti ti-ghost" style="font-size:16px;flex-shrink:0"></i><strong>${shadow.length} ativos Shadow IT detectados</strong> — não estão no CMDB. Sem owner, sem monitoramento, sem patch management. Risco desconhecido e potencialmente crítico.<button class="btn btn-s btn-d" style="margin-left:auto" onclick="ASM_TAB='shadow';render()">Ver Shadow IT →</button></div>`:''}
    <div class="g2">
      <div class="card">
        <div class="card-hd"><i class="ti ti-layout-grid" style="color:var(--accent)"></i><div><div class="card-t">Superfície por Categoria</div><div class="card-s">Clique para filtrar</div></div></div>
        <div class="card-bd" style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          ${ASM_CATEGORIES.map(cat=>{
            const assets=all.filter(a=>(cat.id==='shadow_it'?a.shadow:(a.type===cat.id&&!a.shadow)));
            const maxRisk=assets.length?Math.max(...assets.map(a=>a.risk_score)):0;
            return `<div class="asm-cat ${ASM_CAT===cat.id?'active':''}" onclick="ASM_CAT='${cat.id}';ASM_TAB='assets';render()">
              <div class="asm-cat-icon" style="background:rgba(79,122,255,.1);color:${cat.color}"><i class="ti ${cat.icon}"></i></div>
              <div style="flex:1"><div style="font-size:12px;font-weight:500">${cat.label}</div><div style="font-size:10px;color:var(--text3)">${assets.length} ativo(s) ${maxRisk>60?'· '+rpill('pc','risco'):(maxRisk>35?'· '+rpill('ph','alerta'):'')}</div></div>
            </div>`;
          }).join('')}
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><i class="ti ti-arrow-up-right" style="color:var(--crit)"></i><div><div class="card-t">Top 5 Ativos Mais Expostos</div><div class="card-s">Por exposure score</div></div></div>
        <div class="card-bd" style="padding-top:6px">
          ${[...all].sort((a,b)=>b.risk_score-a.risk_score).slice(0,5).map((a,i)=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)${i===4?';border-bottom:none':''}">
            <span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">${i+1}.</span>
            <i class="ti ${assetIcon(a.type)}" style="color:${a.shadow?'var(--crit)':'var(--accent)'};font-size:14px;flex-shrink:0"></i>
            <div style="flex:1;min-width:0"><div class="mono" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${a.hostname}</div><div style="font-size:10px;color:var(--text3)">${a.notes?.substring(0,55)||''}…</div></div>
            <span style="color:${RC(a.risk_score)};font-weight:700;font-size:14px">${a.risk_score}</span>
          </div>`).join('')}
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-hd"><i class="ti ti-clock" style="color:var(--accent)"></i><div><div class="card-t">Histórico de Descobertas</div><div class="card-s">Mudanças na superfície de ataque ao longo do tempo</div></div></div>
      <div class="card-bd" style="padding-top:6px">
        ${ASM_TIMELINE.map(ev=>`<div style="display:flex;gap:10px;padding:7px 0;border-bottom:1px solid var(--border)">
          <span class="mono" style="font-size:10px;color:var(--text3);min-width:80px;flex-shrink:0">${ev.date}</span>
          <div style="flex:1"><div style="font-size:11px;font-weight:500">${ev.event} — ${ev.assets_found} ativos encontrados ${ev.new_assets?`<span class="pill pc" style="font-size:9px">+${ev.new_assets} novos</span>`:''}</div><div style="font-size:10px;color:var(--text3)">${ev.changes.join(' · ')}</div></div>
        </div>`).join('')}
      </div>
    </div>
  </div>`;

  // ── EXTERNAL ASSETS ───────────────────────────────────────────────────────────
  const assetsHTML = () => {
    const filtered = ASM_CAT==='ALL' ? all : ASM_CAT==='shadow_it' ? all.filter(a=>a.shadow) : all.filter(a=>a.type===ASM_CAT&&!a.shadow);
    return `<div>
    <div class="frow">
      <span style="font-size:11px;color:var(--text3);font-weight:600">CATEGORIA:</span>
      <div class="fc ${ASM_CAT==='ALL'?'act':''}" onclick="ASM_CAT='ALL';render()">Todos (${all.length})</div>
      ${ASM_CATEGORIES.map(c=>{const n=c.id==='shadow_it'?all.filter(a=>a.shadow).length:all.filter(a=>a.type===c.id&&!a.shadow).length;return n>0?`<div class="fc ${ASM_CAT===c.id?'act':''}" onclick="ASM_CAT='${c.id}';render()">${c.label} (${n})</div>`:''}).join('')}
      <span style="margin-left:auto;font-size:11px;color:var(--text3)">${filtered.length} ativo(s)</span>
    </div>
    <div style="padding:12px 16px;display:flex;flex-direction:column;gap:8px">
      ${filtered.map(a=>{
        const cert=getCertStatus(a.ssl.days);
        const hdrs=getHeadersGrade(a.headers.score);
        const isExp=ASM_EXPAND===a.id;
        return `<div style="background:var(--bg2);border:1px solid ${a.shadow?'rgba(255,76,76,.3)':isExp?'var(--border2)':'var(--border)'};border-radius:var(--r2);overflow:hidden">
          <div style="display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer" onclick="ASM_EXPAND=ASM_EXPAND==='${a.id}'?null:'${a.id}';render()">
            ${a.shadow?`<div style="background:var(--critbg);border-radius:var(--r);padding:6px;flex-shrink:0"><i class="ti ti-ghost" style="color:var(--crit);font-size:16px"></i></div>`:`<div style="background:var(--bg3);border-radius:var(--r);padding:6px;flex-shrink:0"><i class="ti ${assetIcon(a.type)}" style="color:var(--accent);font-size:16px"></i></div>`}
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                <span class="mono" style="font-size:12px;font-weight:600">${a.hostname}</span>
                ${a.shadow?'<span class="pill pc" style="font-size:9px">SHADOW IT</span>':''}
                ${a.vuln_ids.length?`<span class="pill pc" style="font-size:9px">${a.vuln_ids.length} CVE</span>`:''}
              </div>
              <div style="font-size:10px;color:var(--text3);margin-top:2px">${a.ip} · ${a.ports.map(portBadge).join('')}</div>
            </div>
            <div style="display:flex;align-items:center;gap:12px;flex-shrink:0">
              <div style="text-align:center"><div style="font-size:9px;color:var(--text3)">SSL</div>${sslGrade(a.ssl.grade)}</div>
              <div style="text-align:center"><div style="font-size:9px;color:var(--text3)">CERT</div><span style="font-size:11px;font-weight:700;color:${cert.color}">${cert.label}</span></div>
              <div style="text-align:center"><div style="font-size:9px;color:var(--text3)">HDR</div><span style="font-size:13px;font-weight:800;color:${hdrs.color}">${hdrs.grade}</span></div>
              <span style="color:${RC(a.risk_score)};font-weight:800;font-size:18px">${a.risk_score}</span>
              <i class="ti ti-chevron-${isExp?'up':'down'}" style="color:var(--text3);font-size:14px"></i>
            </div>
          </div>
          ${isExp?`<div class="asm-expand">
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px">
              <div><div class="ds" style="margin-bottom:4px">Serviços Detectados</div>${a.services.map(s=>`<div style="font-size:11px;margin-bottom:4px"><span class="port-badge ${portRisky(s.port)?'port-risky':''}">${s.port}</span> <strong>${s.service}</strong> <span style="color:var(--text3)">${s.banner}</span> ${s.tech.map(t=>`<span class="tech-tag">${t}</span>`).join('')}</div>`).join('')}</div>
              <div><div class="ds" style="margin-bottom:4px">Security Headers</div>
                <div style="display:flex;gap:4px;flex-wrap:wrap">
                  ${[['HSTS',a.headers.hsts],['CSP',a.headers.csp],['X-Frame',a.headers.xfo],['XCTO',a.headers.xcto],['Referrer',a.headers.referrer]].map(([l,v])=>`${headerDot(v)}<span style="font-size:9px;color:var(--text3)">${l}</span>`).join(' ')}
                </div>
                <div style="font-size:10px;color:var(--text3);margin-top:4px">Score: ${a.headers.score}/100 · Grade: ${hdrs.grade}</div>
              </div>
              <div><div class="ds" style="margin-bottom:4px">DNS Health</div>${[['SPF',a.dns.spf],['DKIM',a.dns.dkim],['DMARC',a.dns.dmarc],['DNSSEC',a.dns.dnssec]].map(([l,v])=>dnsDot(v,l)).join(' ')}</div>
            </div>
            ${a.notes?`<div class="nt ${a.risk_score>=70?'nc-':'nw'}" style="margin-bottom:8px"><i class="ti ti-info-circle" style="font-size:14px;flex-shrink:0"></i>${a.notes}</div>`:''}
            ${a.shadow?`<div class="shadow-badge">👻 Discovery: ${a.discovery}</div>`:''}
            ${a.vuln_ids.length?`<div style="margin-bottom:8px"><div class="ds" style="margin-bottom:4px">Vulnerabilidades Associadas</div>${a.vuln_ids.map(id=>`<span class="pill pc" style="font-size:9px;margin:2px;cursor:pointer" onclick="openDov('${id}')">${id}</span>`).join('')}</div>`:''}
            <div class="btn-g">
              ${a.shadow?`<button class="btn btn-s btn-p" onclick="asmAddCMDB('${a.id}')"><i class="ti ti-plus"></i> Adicionar ao CMDB</button><button class="btn btn-s btn-d" onclick="asmDecommission('${a.id}')"><i class="ti ti-trash"></i> Marcar Descontinuado</button>`:''}
              <button class="btn btn-s" onclick="quickMsg('Analise o ativo externo ${a.hostname} (IP: ${a.ip}). Risk score: ${a.risk_score}. SSL grade: ${a.ssl.grade}. Security headers score: ${a.headers.score}/100. Vulnerabilidades: ${a.vuln_ids.join(',')||'nenhuma'}. O que o atacante vê neste ativo? Quais são os vetores de exploração mais prováveis e quais controles reduziriam o exposure score de ${a.risk_score}?')"><i class="ti ti-robot"></i> Análise de Exposição via IA</button>
              <button class="btn btn-s" onclick="triggerRescan('${a.id}')"><i class="ti ti-refresh"></i> Re-scan</button>
            </div>
          </div>`:''}
        </div>`;
      }).join('')}
    </div>
    </div>`;
  };

  // ── CERTIFICATES ─────────────────────────────────────────────────────────────
  const certsHTML = () => {
    const certs = all.filter(a=>a.ssl.valid||a.ssl.expires).sort((a,b)=>(a.ssl.days??-999)-(b.ssl.days??-999));
    const noCert= all.filter(a=>!a.ssl.valid&&!a.ssl.expires);
    return `<div class="content">
    <div class="g4">
      <div class="mt"><div class="mt-l">Certificados Monitorados</div><div class="mt-v vi">${certs.length}</div></div>
      <div class="mt"><div class="mt-l">Expirados</div><div class="mt-v vc">${certs.filter(a=>a.ssl.days<0).length}</div></div>
      <div class="mt"><div class="mt-l">Vencendo < 30d</div><div class="mt-v ${certs.filter(a=>a.ssl.days>=0&&a.ssl.days<30).length>0?'vc':'vk'}">${certs.filter(a=>a.ssl.days>=0&&a.ssl.days<30).length}</div></div>
      <div class="mt"><div class="mt-l">Sem SSL</div><div class="mt-v vc">${noCert.length}</div><div class="mt-s">ativos sem HTTPS</div></div>
    </div>
    ${noCert.length?`<div class="nt nc-"><i class="ti ti-lock-open" style="font-size:16px;flex-shrink:0"></i><strong>${noCert.length} ativo(s) sem SSL/TLS válido</strong> — tráfego não criptografado. Crítico para ativos expostos à internet.</div>`:''}
    <div class="card">
      <div class="card-hd"><i class="ti ti-certificate" style="color:var(--accent)"></i><div><div class="card-t">Inventário de Certificados SSL/TLS</div><div class="card-s">Ordenado por urgência de renovação</div></div></div>
      <div class="tbl"><table>
        <thead><tr><th>Hostname</th><th>Grade</th><th>Emissor</th><th>Expira</th><th>Dias</th><th>Protocolos</th><th>Status</th><th>Ação</th></tr></thead>
        <tbody>
          ${certs.map(a=>{const c=getCertStatus(a.ssl.days);return`<tr class="tr">
            <td class="mono" style="font-size:11px">${a.hostname}</td>
            <td>${sslGrade(a.ssl.grade)}</td>
            <td style="font-size:11px;color:var(--text3)">${a.ssl.issuer||'—'}</td>
            <td style="font-size:11px;color:var(--text3)">${a.ssl.expires||'—'}</td>
            <td><span style="color:${c.color};font-weight:700">${c.label}</span></td>
            <td style="font-size:10px">${(a.ssl.protocols||[]).map(p=>`<span style="color:${p.includes('1.0')||p.includes('1.1')?'var(--crit)':'var(--text3)'};font-size:9px;margin-right:4px">${p}</span>`).join('')}</td>
            <td>${rpill(c.cls,c.label)}</td>
            <td><button class="btn btn-s" onclick="asmRenewCert('${a.id}')"><i class="ti ti-refresh"></i> Renovar</button></td>
          </tr>`}).join('')}
          ${noCert.map(a=>`<tr class="tr"><td class="mono" style="font-size:11px">${a.hostname}</td><td><span class="ssl-grade" style="color:var(--crit)">—</span></td><td colspan="5" style="font-size:11px;color:var(--crit)">Sem certificado SSL — tráfego não criptografado</td><td><button class="btn btn-s btn-d" onclick="asmRenewCert('${a.id}')"><i class="ti ti-plus"></i> Emitir Cert</button></td></tr>`).join('')}
        </tbody>
      </table></div>
    </div>
    </div>`;
  };

  // ── SHADOW IT ─────────────────────────────────────────────────────────────────
  const shadowHTML = () => {
    const sh = all.filter(a => a.shadow);
    return `<div class="content">
    <div class="nt nc-"><i class="ti ti-ghost" style="font-size:16px;flex-shrink:0"></i><strong>Shadow IT</strong> — ativos descobertos por varredura ativa que NÃO constam no CMDB oficial. Sem owner, sem patch management, sem monitoramento. Cada um é um ponto cego do RBVM.</div>
    <div class="g3">
      <div class="mt"><div class="mt-l">Shadow IT Descoberto</div><div class="mt-v vc">${sh.length}</div><div class="mt-s">fora do CMDB</div></div>
      <div class="mt"><div class="mt-l">Risco Médio</div><div class="mt-v vc">${Math.round(sh.reduce((s,a)=>s+a.risk_score,0)/Math.max(sh.length,1))}</div><div class="mt-s">exposure score</div></div>
      <div class="mt"><div class="mt-l">Portas Críticas</div><div class="mt-v vc">${sh.flatMap(a=>a.ports).filter(portRisky).length}</div><div class="mt-s">expostas no shadow IT</div></div>
    </div>
    ${sh.map(a=>`<div class="card" style="border-left:3px solid var(--crit);margin-top:10px">
      <div class="card-hd">
        <div style="background:var(--critbg);border-radius:var(--r);padding:8px"><i class="ti ti-ghost" style="color:var(--crit);font-size:20px"></i></div>
        <div><div class="card-t mono">${a.hostname}</div><div class="card-s">${a.ip} · Descoberto: ${a.last_scan}</div></div>
        <div class="card-ac"><span style="color:${RC(a.risk_score)};font-weight:800;font-size:22px">${a.risk_score}</span></div>
      </div>
      <div class="card-bd">
        <div class="shadow-badge">🔍 ${a.discovery}</div>
        <div style="margin-bottom:10px"><div class="ds" style="margin-bottom:4px">Portas e Serviços Expostos</div>
          ${a.services.map(s=>`<div style="font-size:11px;margin-bottom:4px;display:flex;align-items:center;gap:6px"><span class="port-badge port-risky">${s.port}</span><strong>${s.service}</strong><span style="color:var(--text3)">${s.banner}</span>${s.tech.map(t=>`<span class="tech-tag">${t}</span>`).join('')}</div>`).join('')}
          <div style="margin-top:4px">${a.ports.map(portBadge).join('')}</div>
        </div>
        <div class="nt nc-" style="margin-bottom:10px"><i class="ti ti-alert-triangle" style="font-size:14px;flex-shrink:0"></i>${a.notes}</div>
        <div class="btn-g">
          <button class="btn btn-p btn-s" onclick="asmAddCMDB('${a.id}')"><i class="ti ti-database-plus"></i> Registrar no CMDB</button>
          <button class="btn btn-d btn-s" onclick="asmDecommission('${a.id}')"><i class="ti ti-trash"></i> Marcar Descontinuado</button>
          <button class="btn btn-s" onclick="escalate('${a.id}')"><i class="ti ti-arrow-up"></i> Escalar ao CISO</button>
          <button class="btn btn-s" onclick="quickMsg('Um ativo Shadow IT foi descoberto: ${a.hostname} (${a.ip}). Portas abertas: ${a.ports.join(',')}. Serviços: ${a.services.map(s=>s.service+' '+s.banner).join(', ')}. Risk score: ${a.risk_score}. Gere: (1) análise do risco imediato, (2) hipóteses sobre quem criou este ativo e por quê, (3) passos de contenção imediata, (4) como evitar novos shadow IT.')"><i class="ti ti-robot"></i> Análise via IA</button>
        </div>
      </div>
    </div>`).join('')}
    </div>`;
  };

  const tabs = { overview:'Visão Geral', assets:`Ativos (${all.length})`, certs:'Certificados', shadow:`Shadow IT (${shadow.length})` };
  const tabContent = { overview:overviewHTML, assets:assetsHTML, certs:certsHTML, shadow:shadowHTML };
  const body = (tabContent[ASM_TAB]||overviewHTML)();

  return `<div>
  <div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${ASM_TAB===k?'active':''}" onclick="asmTab('${k}')">${v}</div>`).join('')}
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;padding:6px 0">
      <span class="sbom-export" onclick="toast('ASM scan agendado — próximo ciclo: 24h','ts')"><i class="ti ti-radar-2"></i> Scan Agora</span>
      <span class="sbom-export" onclick="quickMsg('Gere um relatório executivo de Attack Surface Management. Inclua: exposure score ${surfScore}/100, ${monitored.length} ativos externos monitorados, ${shadow.length} shadow IT detectados, principais riscos por categoria, top 3 ativos mais expostos e recomendações prioritárias de redução de superfície.')"><i class="ti ti-robot"></i> Relatório IA</span>
    </div>
  </div>
  ${body}
  </div>`;
}

window.asmTab         = t => { ASM_TAB=t; ASM_CAT='ALL'; ASM_EXPAND=null; render(); };
window.asmAddCMDB     = id => { const a=EXTERNAL_ASSETS.find(x=>x.id===id); if(a){a.in_cmdb=true; toast(`${a.hostname} adicionado ao CMDB — atribuir owner e iniciar scans`,'ts'); render();} };
window.asmDecommission= id => { const a=EXTERNAL_ASSETS.find(x=>x.id===id); if(a){ toast(`${a.hostname} marcado para descomissionamento — equipe de rede notificada`,'ts');} };
window.asmRenewCert   = id => { const a=EXTERNAL_ASSETS.find(x=>x.id===id); if(a){ toast(`Renovação de certificado iniciada para ${a.hostname} via Let's Encrypt/Sectigo`,'ts');} };


// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 4 — PATCH MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════
function patch() {
  const activeCamps  = PATCH_CAMPAIGNS.filter(c => c.status !== 'completed');
  const p0Running    = activeCamps.filter(c => c.priority === 'P0').length;
  const totalAssets  = PATCH_CAMPAIGNS.reduce((s,c) => s + c.asset_count, 0);
  const totalPatched = PATCH_CAMPAIGNS.reduce((s,c) => s + c.patched, 0);
  const debtVal      = getPatchDebt(PATCH_RECORDS, VULNS);
  const validatedRec = PATCH_RECORDS.filter(r => r.status === 'validated');
  const avgMTTR      = validatedRec.length
    ? (validatedRec.reduce((s,r) => s + (r.mttr_days||0), 0) / validatedRec.length).toFixed(1)
    : '—';

  // ── VELOCITY CHART ─────────────────────────────────────────────────────────
  const maxV = Math.max(...PATCH_VELOCITY.map(w => w.deployed));
  const velocityChart = `
    <div class="velocity-bar">
      ${PATCH_VELOCITY.map(w => {
        const hD = Math.round((w.deployed / maxV) * 60);
        const hV = Math.round((w.validated / maxV) * 60);
        return `<div class="vb-group">
          <div class="vb-bars">
            <div class="vb-bar" style="height:${hD}px;background:var(--accent);opacity:.8" title="${w.deployed} deployados"></div>
            <div class="vb-bar" style="height:${hV}px;background:var(--success)" title="${w.validated} validados"></div>
          </div>
          <div class="vb-lbl">${w.week}</div>
        </div>`;
      }).join('')}
    </div>
    <div style="display:flex;gap:12px;margin-top:4px;font-size:10px">
      <span><span style="color:var(--accent)">■</span> Deployado</span>
      <span><span style="color:var(--success)">■</span> Validado</span>
      <span style="margin-left:auto;color:var(--text3)">Total semana atual: ${PATCH_VELOCITY[PATCH_VELOCITY.length-1].deployed} deployados</span>
    </div>`;

  // ── CAMPAIGNS TAB ──────────────────────────────────────────────────────────
  const campaignsHTML = () => `<div class="content">
    <div class="g4">
      <div class="mt"><div class="mt-l">Campanhas Ativas</div><div class="mt-v ${p0Running?'vc':'vi'}">${activeCamps.length}</div><div class="mt-s">${p0Running} emergenciais P0</div></div>
      <div class="mt"><div class="mt-l">Ativos em Campanha</div><div class="mt-v vi">${totalAssets}</div><div class="mt-s">${totalPatched} patched (${Math.round(totalPatched/Math.max(totalAssets,1)*100)}%)</div></div>
      <div class="mt"><div class="mt-l">MTTR Real (patch)</div><div class="mt-v ${avgMTTR>7?'vh':'vk'}">${avgMTTR}d</div><div class="mt-s">Meta: ≤ 7 dias</div></div>
      <div class="mt"><div class="mt-l">Patch Debt</div><div class="mt-v vc">${debtVal}</div><div class="mt-s">ativo-dias acumulados</div></div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:2px;flex-wrap:wrap">
      ${['ALL','emergency','patch_tuesday','sca_update','eol_migration'].map(t => {
        const label = t==='ALL'?'Todas':getCampaignTypeLabel(t).label;
        const n = t==='ALL'?activeCamps.length:activeCamps.filter(c=>c.type===t).length;
        return n>0?`<div class="fc ${!PATCH_CAMP_SEL&&t==='ALL'||false?'act':''}" onclick="patchFilter('${t}')">${label} (${n})</div>`:''
      }).join('')}
      <button class="btn btn-p btn-s" style="margin-left:auto" onclick="openModal('newcampaign')"><i class="ti ti-plus"></i> Nova Campanha</button>
    </div>
    ${activeCamps.map(c => {
      const tp = getCampaignTypeLabel(c.type);
      const pct = Math.round(c.patched / Math.max(c.asset_count,1) * 100);
      const done = c.steps.filter(s => s.done).length;
      const nextStep = c.steps.find(s => !s.done);
      const expanded = PATCH_CAMP_SEL === c.id;
      return `<div class="pc-card ${c.type}">
        <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;cursor:pointer" onclick="PATCH_CAMP_SEL=PATCH_CAMP_SEL==='${c.id}'?null:'${c.id}';render()">
          <div style="flex:1;min-width:240px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
              <span class="pill ${tp.cls}" style="font-size:9px">${tp.label}</span>
              <span class="pill ${c.priority==='P0'?'pc':'ph'}" style="font-size:9px">${c.priority}</span>
              ${c.status==='in_progress'?'<span class="pill pp" style="font-size:9px">EM ANDAMENTO</span>':c.status==='planned'?'<span class="pill pn" style="font-size:9px">PLANEJADO</span>':''}
              <span class="mono" style="font-size:10px;color:var(--text3)">${c.change_id||'sem CHG'}</span>
            </div>
            <div style="font-size:13px;font-weight:600;margin-bottom:3px">${c.name}</div>
            <div style="font-size:10px;color:var(--text3);margin-bottom:6px">Trigger: ${c.trigger}</div>
            <div style="font-size:11px;color:var(--text2)">Lead: <strong>${c.lead}</strong> · Due: <strong>${c.due}</strong></div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;min-width:160px">
            <div style="font-size:11px;color:var(--text2)">${c.patched}/${c.asset_count} ativos · ${done}/${c.steps.length} etapas</div>
            <div style="width:160px"><div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text3);margin-bottom:2px"><span>Progresso</span><span>${pct}%</span></div>
              <div class="pb" style="height:6px"><div class="pbf" style="width:${pct}%;background:${pct===100?'var(--success)':c.priority==='P0'?'var(--crit)':'var(--accent)'}"></div></div>
            </div>
            <i class="ti ti-chevron-${expanded?'up':'down'}" style="color:var(--text3);font-size:14px"></i>
          </div>
        </div>
        ${expanded?`<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">
          <div class="g2" style="margin-bottom:12px">
            <div>
              <div class="ds">Etapas da Campanha</div>
              ${c.steps.map(s => {
                const isNext = s === c.steps.find(x=>!x.done);
                return `<div class="patch-step">
                  <div class="ps-n ${s.done?'pbs-done':isNext?'pbs-act':'pbs-idle'}">${s.n}</div>
                  <div style="flex:1">
                    <div style="font-size:11px;color:${s.done?'var(--text2)':'var(--text)'};${s.done?'text-decoration:line-through':''};">${s.label}</div>
                    <div style="font-size:9px;color:var(--text3)">${s.auto?'🤖 Automático':'👤 Manual'}</div>
                  </div>
                  ${s.done?'<i class="ti ti-check" style="color:var(--success);font-size:13px"></i>':isNext?`<button class="btn btn-s btn-o" onclick="event.stopPropagation();patchExecStep('${c.id}',${s.n-1})"><i class="ti ti-play"></i> Executar</button>`:''}
                </div>`;
              }).join('')}
            </div>
            <div>
              <div class="ds">Rollback Plan</div>
              <div style="background:var(--bg4);border-radius:var(--r);padding:8px 12px;font-size:11px;color:var(--text2);font-family:var(--mono);line-height:1.5;margin-bottom:10px">${c.rollback}</div>
              ${c.notes?`<div class="nt ni-"><i class="ti ti-info-circle" style="font-size:14px;flex-shrink:0"></i>${c.notes}</div>`:''}
              ${c.window_id?`<div style="margin-top:10px"><div class="ds">Janela de Manutenção</div>${(() => { const mw=MAINTENANCE_WINDOWS.find(m=>m.id===c.window_id); return mw?`<div style="font-size:11px;color:var(--text2)"><strong>${mw.date} ${mw.start}–${mw.end}</strong> · ${mw.squad} · ${mw.duration_h}h · Aprovado: ${mw.approved_by||'—'}</div>`:'—'; })()}</div>`:''}
            </div>
          </div>
          <div class="btn-g">
            ${nextStep&&c.status==='in_progress'?`<button class="btn btn-p btn-s" onclick="event.stopPropagation();patchExecStep('${c.id}',${c.steps.indexOf(nextStep)})"><i class="ti ti-play"></i> Executar Próxima Etapa</button>`:''}
            <button class="btn btn-s" onclick="event.stopPropagation();patchTab('status')"><i class="ti ti-list"></i> Status por Ativo</button>
            <button class="btn btn-s" onclick="event.stopPropagation();quickMsg('Gere um relatório de progresso para a campanha de patch ${c.id}: ${c.name}. Progresso: ${c.patched}/${c.asset_count} ativos, ${c.steps.filter(s=>s.done).length}/${c.steps.length} etapas. Trigger: ${c.trigger}. Identifique riscos de não conclusão dentro do prazo ${c.due} e recomende ações para acelerar.')"><i class="ti ti-robot"></i> Relatório IA</button>
          </div>
        </div>`:''}
      </div>`;
    }).join('')}
  </div>`;

  // ── MAINTENANCE WINDOWS TAB ────────────────────────────────────────────────
  const windowsHTML = () => `<div class="content">
    <div class="g4">
      <div class="mt"><div class="mt-l">Janelas Agendadas</div><div class="mt-v vi">${MAINTENANCE_WINDOWS.length}</div><div class="mt-s">próximas 4</div></div>
      <div class="mt"><div class="mt-l">Emergenciais</div><div class="mt-v vc">${MAINTENANCE_WINDOWS.filter(m=>m.type==='emergency').length}</div></div>
      <div class="mt"><div class="mt-l">Padrão</div><div class="mt-v vi">${MAINTENANCE_WINDOWS.filter(m=>m.type==='standard').length}</div></div>
      <div class="mt"><div class="mt-l">Self-Service</div><div class="mt-v vk">${MAINTENANCE_WINDOWS.filter(m=>m.type==='self_service').length}</div></div>
    </div>
    <div class="nt ni-"><i class="ti ti-info-circle" style="font-size:16px;flex-shrink:0"></i>Janelas emergenciais requerem aprovação do CISO. Janelas padrão passam pelo CAB quinzenal. Self-service são pré-aprovadas para squads de desenvolvimento sem downtime.</div>
    ${MAINTENANCE_WINDOWS.sort((a,b)=>a.date.localeCompare(b.date)).map(mw => {
      const camp = PATCH_CAMPAIGNS.find(c => c.id === mw.campaign_id);
      const typeClass = `mw-type-${mw.type}`;
      const daysUntil = Math.ceil((new Date(mw.date) - new Date('2024-05-21')) / 86400000);
      return `<div class="mw-card">
        <div style="display:flex;flex-direction:column;align-items:center;gap:4px;min-width:90px">
          <div class="mw-time">${mw.start}</div>
          <div style="font-size:10px;color:var(--text3)">${mw.date}</div>
          <div style="font-size:9px;color:${daysUntil<=1?'var(--crit)':daysUntil<=3?'var(--high)':'var(--text3)'}">Em ${daysUntil}d</div>
        </div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-wrap:wrap">
            <span class="${typeClass}">${mw.type==='emergency'?'EMERGENCIAL':mw.type==='standard'?'PADRÃO':'SELF-SERVICE'}</span>
            <strong style="font-size:12px">${mw.name}</strong>
          </div>
          <div style="font-size:11px;color:var(--text2);margin-bottom:4px">Squad: ${mw.squad} · Duração: ${mw.duration_h}h (${mw.start}–${mw.end}) · Recorrência: ${mw.recurrence==='one-time'?'Única':mw.recurrence==='monthly'?'Mensal':'Quinzenal'}</div>
          <div style="font-size:10px;color:var(--text3);margin-bottom:4px">Sistemas: ${Array.isArray(mw.systems)?mw.systems.join(' · '):mw.systems}</div>
          <div style="display:flex;gap:10px;font-size:10px;flex-wrap:wrap">
            <span>Aprovado: <strong>${mw.approved_by||'Pendente'}</strong></span>
            <span>Rollback: <strong>${mw.rollback_time_min}min</strong></span>
            <span>Impacto: <strong>${mw.impact}</strong></span>
          </div>
          ${camp?`<div style="margin-top:6px"><span class="pill pi" style="font-size:9px">${camp.id}</span> <span style="font-size:11px;color:var(--text2)">${camp.name}</span></div>`:''}
        </div>
        <div style="display:flex;flex-direction:column;gap:5px;flex-shrink:0">
          <button class="btn btn-s btn-p" onclick="patchSchedule('${mw.id}')"><i class="ti ti-calendar-plus"></i> Agendar</button>
          <button class="btn btn-s" onclick="toast('CAB notificado sobre ${mw.name}','ts')"><i class="ti ti-send"></i> Notificar CAB</button>
        </div>
      </div>`;
    }).join('')}
  </div>`;

  // ── PATCH STATUS TAB ───────────────────────────────────────────────────────
  const statusHTML = () => {
    const byStatus = s => PATCH_RECORDS.filter(r => r.status === s).length;
    return `<div>
    <div class="frow">
      ${['planned','scheduled','in_progress','deployed','validated','failed'].map(s => {
        const m = getPatchStatusMeta(s);
        const n = byStatus(s);
        return n>0?`<span class="pill ${m.cls}" style="font-size:10px">${m.label} (${n})</span>`:'';
      }).join('')}
      <span style="margin-left:auto;font-size:11px;color:var(--text3)">${PATCH_RECORDS.length} registros</span>
    </div>
    <div style="padding:12px 16px">
    <div class="tbl"><table>
      <thead><tr><th>Registro</th><th>Vulnerabilidade</th><th>Ativo</th><th>Patch</th><th>Status</th><th>Agendado</th><th>Deployado</th><th>Validado</th><th>MTTR</th><th>Validador</th></tr></thead>
      <tbody>${PATCH_RECORDS.map(r => {
        const m = getPatchStatusMeta(r.status);
        const v = VULNS.find(x=>x.id===r.vuln_id);
        return `<tr class="tr" onclick="r.vuln_id&&openDov('${r.vuln_id}')">
          <td class="mono" style="font-size:10px;color:var(--text3)">${r.id}</td>
          <td>${v?SP(v.sev):'—'} <span class="mono" style="font-size:10px">${r.vuln_id}</span></td>
          <td style="font-size:11px;font-weight:500;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.asset}</td>
          <td style="font-size:10px;color:var(--text3);font-family:var(--mono);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.patch}</td>
          <td><span class="pill ${m.cls}" style="font-size:9px">${m.label}</span></td>
          <td style="font-size:10px;color:var(--text3)">${r.scheduled?.substring(0,10)||'—'}</td>
          <td style="font-size:10px;color:${r.deployed?'var(--success)':'var(--text3)'}">${r.deployed?.substring(0,10)||'—'}</td>
          <td style="font-size:10px;color:${r.validated_at?'var(--success)':'var(--text3)'}">${r.validated_at?.substring(0,10)||'—'}</td>
          <td style="font-weight:700;color:${r.mttr_days!=null?r.mttr_days>7?'var(--crit)':'var(--success)':'var(--text3)'}">${r.mttr_days!=null?r.mttr_days+'d':'—'}</td>
          <td style="font-size:10px;color:var(--text3);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.validated_by||'—'}</td>
        </tr>`;
      }).join('')}</tbody>
    </table></div>
    </div></div>`;
  };

  // ── ANALYTICS TAB ─────────────────────────────────────────────────────────
  const analyticsHTML = () => {
    const squads = ['Linux SRE','Network Security','Windows SRE','DevSecOps','Backend Platform'];
    const compliance = squads.map(sq => {
      const camps = PATCH_CAMPAIGNS.filter(c => c.squad === sq);
      if (!camps.length) return { squad:sq, pct:100, ok:true };
      const total = camps.reduce((s,c)=>s+c.asset_count,0);
      const patched = camps.reduce((s,c)=>s+c.patched,0);
      return { squad:sq, pct:Math.round(patched/Math.max(total,1)*100), ok:patched/Math.max(total,1)>=0.9 };
    });
    const failedRecords = PATCH_RECORDS.filter(r=>r.rollback);
    const failRate = (failedRecords.length/Math.max(PATCH_RECORDS.length,1)*100).toFixed(1);

    return `<div class="content">
    <div class="patch-debt-badge">
      <div><div style="font-size:11px;font-weight:700;color:var(--crit);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">⚖ PATCH DEBT ACUMULADO</div>
        <div class="debt-num">${debtVal}</div>
        <div style="font-size:11px;color:var(--text2);margin-top:4px">ativo-dias sem patch · ponderado por criticidade</div>
        <div style="font-size:10px;color:var(--text3);margin-top:2px">Cada dia sem patch em ativo crítico adiciona 4 pts · Alto = 2 pts · Médio = 1 pt</div>
      </div>
      <div style="margin-left:auto">
        <button class="btn btn-s btn-d" onclick="quickMsg('O patch debt acumulado é ${debtVal} ativo-dias. Analise quais campanhas de patch reduziriam mais rapidamente este número e priorize. Inclua: top 3 ações com maior redução de debt, estimativa de ativo-dias liberados por ação e prazo recomendado.')"><i class="ti ti-robot"></i> Reduzir Debt via IA</button>
      </div>
    </div>
    <div class="g2">
      <div class="card">
        <div class="card-hd"><i class="ti ti-chart-bar" style="color:var(--accent)"></i><div><div class="card-t">Patch Velocity — Últimas 5 Semanas</div><div class="card-s"><span style="color:var(--accent)">■</span> Deployado &nbsp;<span style="color:var(--success)">■</span> Validado</div></div></div>
        <div class="card-bd">${velocityChart}</div>
      </div>
      <div class="card">
        <div class="card-hd"><i class="ti ti-target" style="color:var(--accent)"></i><div><div class="card-t">Compliance de Patch por Squad</div><div class="card-s">Meta: ≥ 90% patched dentro do SLA</div></div></div>
        <div class="card-bd" style="padding-top:6px">
          ${compliance.map(sq => `<div class="compliance-row">
            <div style="font-size:12px;min-width:140px;font-weight:500">${sq.squad}</div>
            <div style="flex:1"><div class="pb" style="height:6px"><div class="pbf" style="width:${sq.pct}%;background:${sq.pct>=90?'var(--success)':sq.pct>=70?'var(--high)':'var(--crit)'}"></div></div></div>
            <div style="font-size:12px;font-weight:700;color:${sq.ok?'var(--success)':'var(--crit)'};min-width:40px;text-align:right">${sq.pct}%</div>
            ${sq.ok?'<i class="ti ti-check" style="color:var(--success);font-size:13px;margin-left:6px"></i>':'<i class="ti ti-alert-triangle" style="color:var(--crit);font-size:13px;margin-left:6px"></i>'}
          </div>`).join('')}
        </div>
      </div>
    </div>
    <div class="g3">
      <div class="mt"><div class="mt-l">MTTR Real (patch)</div><div class="mt-v ${avgMTTR>7?'vh':'vk'}">${avgMTTR}d</div><div class="mt-s">Meta: ≤ 7d críticas</div></div>
      <div class="mt"><div class="mt-l">Taxa de Falha (rollback)</div><div class="mt-v ${failRate>5?'vc':'vk'}">${failRate}%</div><div class="mt-s">${failedRecords.length} rollbacks</div></div>
      <div class="mt"><div class="mt-l">Patches Validados</div><div class="mt-v vk">${validatedRec.length}</div><div class="mt-s">com evidência de scan</div></div>
    </div>
    </div>`;
  };

  const tabs = { campaigns:`Campanhas (${activeCamps.length})`, windows:'Janelas de Manutenção', status:'Status por Ativo', analytics:'Analytics' };
  const tabFns = { campaigns:campaignsHTML, windows:windowsHTML, status:statusHTML, analytics:analyticsHTML };
  const body = (tabFns[PATCH_TAB]||campaignsHTML)();

  return `<div>
  <div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${PATCH_TAB===k?'active':''}" onclick="patchTab('${k}')">${v}</div>`).join('')}
    <div style="margin-left:auto;display:flex;align-items:center;gap:8px;padding:6px 0">
      <span class="sbom-export" onclick="quickMsg('Gere um relatório executivo de Patch Management. Inclua: ${activeCamps.length} campanhas ativas, ${p0Running} P0 emergenciais, MTTR real ${avgMTTR} dias, patch debt ${debtVal} ativo-dias, compliance por squad e recomendações para atingir 90% de compliance em 30 dias.')"><i class="ti ti-robot"></i> Relatório Executivo</span>
    </div>
  </div>
  ${body}
  </div>`;
}

window.patchTab      = t => { PATCH_TAB=t; PATCH_CAMP_SEL=null; render(); };
window.patchFilter   = t => { PATCH_CAMP_SEL=null; render(); };
window.patchExecStep = (campId, stepIdx) => {
  const c = PATCH_CAMPAIGNS.find(x=>x.id===campId);
  if (!c || !c.steps[stepIdx]) return;
  c.steps[stepIdx].done = true;
  // Check if this step patches an asset
  if (c.steps[stepIdx].label.toLowerCase().includes('patch')) {
    c.patched = Math.min(c.patched + 1, c.asset_count);
    // Find and update a matching PATCH_RECORD
    const pr = PATCH_RECORDS.find(r=>r.vuln_id===c.vuln_ids?.[0]&&r.status==='scheduled');
    if (pr) { pr.status='deployed'; pr.deployed=new Date().toISOString().replace('T',' ').substring(0,16); }
    addAuditEvent(c.vuln_ids?.[0]||campId, {actor:'user',name:'Patch Manager',icon:'ti-package',action:`Patch deployado — campanha ${campId} etapa ${stepIdx+1}`,before:null,after:null,detail:c.steps[stepIdx].label,src:'Patch Management'});
  }
  // Check if last step
  if (c.steps.every(s=>s.done)) {
    c.status='completed'; c.patched=c.asset_count;
    toast(`Campanha ${campId} concluída! Todos os ${c.asset_count} ativos patched.`,'ts');
  } else {
    toast(`Etapa ${stepIdx+1} concluída — ${c.name}`,'ts');
  }
  render();
};
window.patchSchedule = mwId => {
  const mw = MAINTENANCE_WINDOWS.find(m=>m.id===mwId);
  toast(`Janela ${mwId} confirmada — ${mw?.date} ${mw?.start}–${mw?.end}. CAB e squads notificados.`,'ts');
};



// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 5 — REPORTS & EVIDENCE EXPORT
// ══════════════════════════════════════════════════════════════════════════════

// ── REPORT TYPES DEFINITION ──────────────────────────────────────────────────
const RPT_TYPES = [
  { id:'executive',   icon:'ti-briefcase',      color:'var(--accent)', bg:'rgba(79,122,255,.1)',
    name:'Sumário Executivo',      audience:'CISO · Diretoria · Comitê de Risco',
    desc:'Postura de risco, KEVs ativas, SLA compliance, exposição financeira, tendência de MTTR, recomendações executivas e plano de ação.' },
  { id:'compliance',  icon:'ti-certificate',    color:'#a084ff',       bg:'rgba(160,132,255,.1)',
    name:'Compliance / Auditoria', audience:'GRC · Auditor Externo · BACEN',
    desc:'Mapeamento NIST CSF 2.0, PCI DSS 4.0, ISO 27001:2022, LGPD e CMN 4.893 com status de controles, evidências e gaps.' },
  { id:'squad',       icon:'ti-users',          color:'var(--success)', bg:'rgba(64,200,122,.1)',
    name:'Técnico por Squad',      audience:'Tech Lead · Gestor de Engenharia',
    desc:'Vulnerabilidades abertas por squad, MTTR real vs. meta, SLA compliance, campanhas de patch ativas e ações pendentes.' },
  { id:'evidence',    icon:'ti-shield-check',   color:'var(--high)',   bg:'rgba(255,140,56,.1)',
    name:'Pacote de Evidências',   audience:'Auditor Externo · Regulatório · GRC',
    desc:'Audit trail completo por vulnerabilidade, confirmações de rescan, exceções aprovadas e cadeia de custódia auditável.' },
  { id:'asm',         icon:'ti-radar-2',        color:'var(--crit)',   bg:'rgba(255,76,76,.1)',
    name:'Attack Surface Report',  audience:'SOC · CISO · SecOps',
    desc:'Ativos internet-facing, shadow IT detectado, certificados SSL/TLS, scores de exposição e recomendações de hardening.' },
];

// ── SHARED REPORT HTML WRAPPER ────────────────────────────────────────────────
function rptWrap(title, subtitle, audience, body) {
  const now = new Date().toLocaleDateString('pt-BR', {day:'2-digit',month:'long',year:'numeric'});
  const ts  = new Date().toLocaleString('pt-BR');
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>RBVM Platform — ' + title + '</title>'
    + '<style>'
    + '*{margin:0;padding:0;box-sizing:border-box}'
    + 'body{font-family:"Segoe UI",system-ui,sans-serif;background:#f1f5f9;color:#1e293b;font-size:13px;line-height:1.5}'
    + '.page{max-width:960px;margin:0 auto;background:#fff;padding:48px;min-height:100vh;position:relative}'
    + '.rh{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #1e293b;padding-bottom:18px;margin-bottom:28px}'
    + '.logo{font-size:18px;font-weight:800;color:#1e293b;letter-spacing:-.5px}'
    + '.logo-sub{font-size:11px;color:#64748b;margin-top:2px}'
    + '.rh-right{text-align:right}'
    + '.conf{background:#dc2626;color:#fff;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.06em}'
    + '.rdate{font-size:11px;color:#64748b;margin-top:6px}'
    + '.rtitle{font-size:22px;font-weight:700;color:#1e293b;margin-bottom:4px}'
    + '.rsubtitle{font-size:13px;color:#64748b}'
    + '.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}'
    + '.metric{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px}'
    + '.ml{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}'
    + '.mv{font-size:24px;font-weight:800}'
    + '.ms{font-size:10px;color:#94a3b8;margin-top:3px}'
    + '.crit{color:#dc2626}.high{color:#d97706}.ok{color:#059669}.info{color:#3b82f6}'
    + '.sh{font-size:14px;font-weight:700;color:#1e293b;margin:24px 0 10px;padding-bottom:8px;border-bottom:2px solid #e2e8f0;display:flex;align-items:center;gap:8px}'
    + 'table{width:100%;border-collapse:collapse;margin:8px 0;font-size:12px}'
    + 'th{background:#1e293b;color:#fff;padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.04em;font-weight:600}'
    + 'td{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}'
    + 'tr:nth-child(even) td{background:#f8fafc}'
    + '.pill{display:inline-block;padding:2px 8px;border-radius:12px;font-size:10px;font-weight:700}'
    + '.pc{background:#fee2e2;color:#dc2626}.ph{background:#fef3c7;color:#d97706}'
    + '.pm{background:#fef9c3;color:#ca8a04}.pl{background:#d1fae5;color:#059669}'
    + '.pd{background:#d1fae5;color:#059669}.pi{background:#dbeafe;color:#1d4ed8}'
    + '.pb-wrap{height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden;width:100%}'
    + '.pb-fill{height:100%;border-radius:3px}'
    + '.nt{background:#fef3c7;border:1px solid #fbbf24;border-radius:6px;padding:10px 14px;font-size:12px;color:#92400e;margin:8px 0}'
    + '.nt-crit{background:#fee2e2;border-color:#fca5a5;color:#991b1b}'
    + '.nt-ok{background:#d1fae5;border-color:#6ee7b7;color:#065f46}'
    + '.at-row{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:11px}'
    + '.at-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}'
    + '.sig{margin-top:32px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px}'
    + '.sig-box{border-top:1px solid #1e293b;padding-top:8px;font-size:11px;color:#64748b}'
    + '.sig-lbl{font-weight:600;color:#1e293b}'
    + '.rf{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;color:#94a3b8;font-size:10px}'
    + '.print-btn{position:fixed;top:20px;right:20px;background:#1e293b;color:#fff;border:none;padding:10px 18px;border-radius:8px;cursor:pointer;font-size:13px;z-index:999;box-shadow:0 4px 12px rgba(0,0,0,.2)}'
    + '.print-btn:hover{background:#334155}'
    + '.audit-block{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;margin-bottom:12px}'
    + '.audit-vuln{font-size:14px;font-weight:700;color:#1e293b;margin-bottom:8px;border-bottom:1px solid #e2e8f0;padding-bottom:8px}'
    + '@media print{.print-btn{display:none!important}.page{padding:24px;max-width:none}body{background:#fff}tr{page-break-inside:avoid}.sh{page-break-before:avoid}}'
    + '</style></head><body>'
    + '<button class="print-btn" onclick="window.print()">🖨 Imprimir / Salvar PDF</button>'
    + '<div class="page">'
    + '<div class="rh"><div><div class="logo">RBVM Platform</div><div class="logo-sub">Enterprise Vulnerability &amp; Exposure Management</div></div>'
    + '<div class="rh-right"><span class="conf">CONFIDENCIAL</span><div class="rdate">Gerado em: ' + ts + '</div><div class="rdate">Público: ' + audience + '</div></div></div>'
    + '<div class="rtitle">' + title + '</div><div class="rsubtitle">' + subtitle + '</div>'
    + body
    + '<div class="rf"><span>RBVM Platform — Corporação XPTO · ' + now + '</span><span>Dados demonstrativos · © 2026 Andrews Ferreira · Todos os direitos reservados</span></div>'
    + '</div></body></html>';
}

// ── 1. EXECUTIVE SUMMARY ──────────────────────────────────────────────────────
function buildExecReport() {
  const active = VULNS.filter(v => v.status !== 'Resolved' && v.status !== 'Closed with Evidence');
  const crit   = active.filter(v => v.sev === 'CRITICAL').length;
  const kev    = active.filter(v => v.kev).length;
  const breach = active.filter(v => v.sla_used >= v.sla_max).length;
  const lm     = MONTHLY_TRENDS[MONTHLY_TRENDS.length - 1];
  const fin    = FMT(totalFinancialExposure(VULNS));
  const shadow = EXTERNAL_ASSETS ? EXTERNAL_ASSETS.filter(a => a.shadow).length : 0;
  const debt   = getPatchDebt(PATCH_RECORDS, VULNS);

  const topVulns = [...active].sort((a,b) => b.final_score - a.final_score).slice(0, 8);
  const sevColor = s => s==='CRITICAL'?'#dc2626':s==='HIGH'?'#d97706':s==='MEDIUM'?'#ca8a04':'#059669';
  const sevPillStr = s => '<span class="pill ' + (s==='CRITICAL'?'pc':s==='HIGH'?'ph':s==='MEDIUM'?'pm':'pl') + '">' + s + '</span>';
  const scoreStr = n => '<span style="font-weight:700;color:' + (n>=75?'#dc2626':n>=55?'#d97706':'#059669') + '">' + n + '</span>';

  // SLA by team
  const teams = [...new Set(active.map(v => v.team))];
  const slaRows = teams.map(t => {
    const tv = active.filter(v => v.team === t);
    const tb = tv.filter(v => v.sla_used >= v.sla_max).length;
    const pct = Math.round((1 - tb/Math.max(tv.length,1))*100);
    return '<tr><td>' + t + '</td><td>' + tv.length + '</td><td>' + tb + '</td>'
      + '<td><div class="pb-wrap"><div class="pb-fill" style="width:' + pct + '%;background:' + (pct>=80?'#059669':pct>=60?'#d97706':'#dc2626') + '"></div></div></td>'
      + '<td style="font-weight:700;color:' + (pct>=80?'#059669':pct>=60?'#d97706':'#dc2626') + '">' + pct + '%</td></tr>';
  }).join('');

  let body = '';

  // Metrics
  body += '<div class="metrics" style="margin-top:20px">'
    + '<div class="metric"><div class="ml">Vulns Abertas</div><div class="mv crit">' + active.length + '</div><div class="ms">Requerem ação</div></div>'
    + '<div class="metric"><div class="ml">Críticas</div><div class="mv crit">' + crit + '</div><div class="ms">Risco máximo</div></div>'
    + '<div class="metric"><div class="ml">CISA KEV Ativas</div><div class="mv crit">' + kev + '</div><div class="ms">Exploração confirmada</div></div>'
    + '<div class="metric"><div class="ml">SLA Vencido</div><div class="mv crit">' + breach + '</div><div class="ms">Ação imediata</div></div>'
    + '<div class="metric"><div class="ml">MTTR Críticas</div><div class="mv high">' + lm.mttr_crit + 'd</div><div class="ms">Meta: ≤ 7d</div></div>'
    + '<div class="metric"><div class="ml">Exposição Fin.</div><div class="mv crit" style="font-size:16px">' + fin + '</div><div class="ms">Risco estimado BRL</div></div>'
    + '<div class="metric"><div class="ml">Patch Debt</div><div class="mv high">' + debt + '</div><div class="ms">Ativo-dias acum.</div></div>'
    + '<div class="metric"><div class="ml">Shadow IT</div><div class="mv crit">' + shadow + '</div><div class="ms">Fora do CMDB</div></div>'
    + '</div>';

  if (kev > 0) body += '<div class="nt nt-crit">⚠ ' + kev + ' vulnerabilidade(s) CISA KEV ativa(s). Exploração confirmada em ambiente real. SLA máximo: 72h para ativos internet-facing.</div>';

  // Top vulnerabilities
  body += '<div class="sh">🎯 Top ' + topVulns.length + ' Vulnerabilidades — Maior Risco</div>';
  body += '<table><thead><tr><th>CVE / ID</th><th>Título</th><th>Sev.</th><th>Score</th><th>KEV</th><th>Ativo</th><th>Impacto</th><th>SLA</th></tr></thead><tbody>';
  body += topVulns.map(v =>
    '<tr><td style="font-family:monospace;font-size:11px">' + v.id + '</td>'
    + '<td style="max-width:200px">' + v.title.substring(0,55) + (v.title.length>55?'…':'') + '</td>'
    + '<td>' + sevPillStr(v.sev) + '</td>'
    + '<td>' + scoreStr(v.final_score) + '</td>'
    + '<td>' + (v.kev?'<span class="pill pc">KEV</span>':'—') + '</td>'
    + '<td style="font-size:11px">' + v.asset + '</td>'
    + '<td style="font-size:11px;color:#d97706;font-weight:600">' + v._fin.label + '</td>'
    + '<td><span style="color:' + (v.sla_used>=v.sla_max?'#dc2626':'#94a3b8') + ';font-size:11px">' + v.sla_used + '/' + v.sla_max + 'd</span></td></tr>'
  ).join('') + '</tbody></table>';

  // SLA compliance by team
  body += '<div class="sh">📊 SLA Compliance por Time</div>';
  body += '<table><thead><tr><th>Time</th><th>Vulns Abertas</th><th>SLA Vencido</th><th>Compliance</th><th>%</th></tr></thead><tbody>' + slaRows + '</tbody></table>';

  // Patch campaigns
  const activeCamps = PATCH_CAMPAIGNS.filter(c => c.status !== 'completed');
  if (activeCamps.length) {
    body += '<div class="sh">🔧 Campanhas de Patch Ativas (' + activeCamps.length + ')</div>';
    body += '<table><thead><tr><th>Campanha</th><th>Tipo</th><th>Priority</th><th>Ativos</th><th>Progresso</th><th>Due Date</th></tr></thead><tbody>';
    body += activeCamps.map(c => {
      const pct = Math.round(c.patched/Math.max(c.asset_count,1)*100);
      return '<tr><td>' + c.name.substring(0,45) + '</td><td style="font-size:11px">' + c.type + '</td>'
        + '<td><span class="pill ' + (c.priority==='P0'?'pc':'ph') + '">' + c.priority + '</span></td>'
        + '<td>' + c.patched + '/' + c.asset_count + '</td>'
        + '<td><div class="pb-wrap"><div class="pb-fill" style="width:' + pct + '%;background:' + (pct>=80?'#059669':'#3b82f6') + '"></div></div> ' + pct + '%</td>'
        + '<td>' + c.due + '</td></tr>';
    }).join('') + '</tbody></table>';
  }

  // Recommendations
  body += '<div class="sh">💡 Recomendações Executivas</div>';
  const recs = [
    { priority:'CRÍTICO', text:'Corrigir todas as CISA KEV abertas em até 72h em ativos internet-facing (SLA regulatório)' },
    { priority:'CRÍTICO', text:'Resolver os ' + breach + ' SLAs vencidos com escalonamento formal para gestores dos times' },
    { priority:'ALTO',    text:'Investigar e registrar os ' + shadow + ' ativos Shadow IT descobertos na ASM — risco desconhecido' },
    { priority:'ALTO',    text:'Concluir campanhas de patch P0 (OpenSSH, FortiOS) dentro dos prazos emergenciais definidos' },
    { priority:'MÉDIO',   text:'Atingir compliance de SLA ≥ 90% em todos os times — meta para próximos 30 dias' },
    { priority:'MÉDIO',   text:'Reduzir patch debt de ' + debt + ' ativo-dias priorizando vulnerabilidades críticas com SLA vencido' },
  ];
  body += '<table><thead><tr><th>Prioridade</th><th>Recomendação</th></tr></thead><tbody>';
  body += recs.map(r => '<tr><td><span class="pill ' + (r.priority==='CRÍTICO'?'pc':r.priority==='ALTO'?'ph':'pm') + '">' + r.priority + '</span></td><td>' + r.text + '</td></tr>').join('');
  body += '</tbody></table>';

  // Signature
  body += '<div class="sig" style="margin-top:32px">'
    + '<div class="sig-box"><div class="sig-lbl">CISO</div><div>ciso@corp.example</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Gerente de Segurança</div><div>sec-manager@corp.example</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Data</div><div>' + new Date().toLocaleDateString('pt-BR') + '</div><div style="margin-top:20px">Classificação: CONFIDENCIAL</div></div>'
    + '</div>';

  return rptWrap('Sumário Executivo de Risco', 'Período: ' + new Date().toLocaleDateString('pt-BR', {month:'long',year:'numeric'}), 'CISO · Diretoria · Comitê de Risco', body);
}

// ── 2. COMPLIANCE REPORT ──────────────────────────────────────────────────────
function buildComplianceReport(fw) {
  const controls = COMPLIANCE_CONTROLS.filter(c => !fw || fw === 'ALL' || c.fw.includes(fw));
  const implemented = controls.filter(c => c.status === 'implemented').length;
  const partial     = controls.filter(c => c.status === 'partial').length;
  const gap         = controls.filter(c => c.status === 'gap').length;
  const pct         = Math.round(implemented / Math.max(controls.length,1) * 100);

  let body = '<div class="metrics" style="margin-top:20px">'
    + '<div class="metric"><div class="ml">Controles Analisados</div><div class="mv info">' + controls.length + '</div></div>'
    + '<div class="metric"><div class="ml">Implementados</div><div class="mv ok">' + implemented + '</div></div>'
    + '<div class="metric"><div class="ml">Parciais</div><div class="mv high">' + partial + '</div></div>'
    + '<div class="metric"><div class="ml">Gaps</div><div class="mv crit">' + gap + '</div></div>'
    + '<div class="metric"><div class="ml">Compliance Geral</div><div class="mv ' + (pct>=80?'ok':pct>=60?'high':'crit') + '">' + pct + '%</div></div>'
    + '</div>';

  if (gap > 0) body += '<div class="nt nt-crit">⚠ ' + gap + ' controle(s) com GAP identificado. Requerem plano de remediação documentado para próxima auditoria.</div>';

  const fws = [...new Set(controls.map(c => c.fw.split(' ')[0]))];
  fws.forEach(f => {
    const fc = controls.filter(c => c.fw.includes(f));
    const fpct = Math.round(fc.filter(c=>c.status==='implemented').length/Math.max(fc.length,1)*100);
    body += '<div class="sh">📋 ' + f + ' — ' + fpct + '% compliance</div>';
    body += '<table><thead><tr><th>Controle</th><th>Descrição</th><th>Status</th><th>Evidência</th><th>Gap / Ação</th></tr></thead><tbody>';
    body += fc.map(c =>
      '<tr><td style="font-family:monospace;font-size:11px;white-space:nowrap">' + c.control + '</td>'
      + '<td>' + c.desc + '</td>'
      + '<td><span class="pill ' + (c.status==='implemented'?'pd':c.status==='partial'?'ph':'pc') + '">' + (c.status==='implemented'?'OK':c.status==='partial'?'Parcial':'GAP') + '</span></td>'
      + '<td style="font-size:11px;color:#64748b">' + (c.evidence||'—') + '</td>'
      + '<td style="font-size:11px;color:' + (c.gap?'#dc2626':'#059669') + '">' + (c.gap||'Conforme') + '</td></tr>'
    ).join('') + '</tbody></table>';
  });

  body += '<div class="sig" style="margin-top:32px">'
    + '<div class="sig-box"><div class="sig-lbl">Responsável GRC</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Auditor Interno</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Data da Revisão</div><div>' + new Date().toLocaleDateString('pt-BR') + '</div></div>'
    + '</div>';

  return rptWrap('Relatório de Compliance e GRC', (fw&&fw!=='ALL'?fw:'NIST CSF 2.0 · PCI DSS 4.0 · ISO 27001:2022 · LGPD · CMN 4.893'), 'GRC · Auditor Externo · BACEN', body);
}

// ── 3. SQUAD TECHNICAL REPORT ─────────────────────────────────────────────────
function buildSquadReport(squad) {
  const active = VULNS.filter(v => v.status !== 'Resolved' && v.status !== 'Closed with Evidence');
  const filtered = squad && squad !== 'ALL' ? active.filter(v => v.squad === squad || v.team === squad) : active;
  const squads = squad && squad !== 'ALL' ? [squad] : [...new Set(active.map(v => v.squad||v.team))];

  let body = '';
  squads.forEach(sq => {
    const sv = active.filter(v => (v.squad||v.team) === sq);
    if (!sv.length) return;
    const breach = sv.filter(v => v.sla_used >= v.sla_max).length;
    const critCount = sv.filter(v => v.sev === 'CRITICAL').length;
    const camp = PATCH_CAMPAIGNS.find(c => c.squad === sq && c.status === 'in_progress');

    body += '<div class="sh">👥 Squad: ' + sq + '</div>';
    body += '<div class="metrics">'
      + '<div class="metric"><div class="ml">Vulns Abertas</div><div class="mv high">' + sv.length + '</div></div>'
      + '<div class="metric"><div class="ml">Críticas</div><div class="mv crit">' + critCount + '</div></div>'
      + '<div class="metric"><div class="ml">SLA Vencido</div><div class="mv ' + (breach>0?'crit':'ok') + '">' + breach + '</div></div>'
      + (camp?'<div class="metric"><div class="ml">Campanha Patch</div><div class="mv info">' + camp.patched + '/' + camp.asset_count + '</div></div>':'')
      + '</div>';

    body += '<table><thead><tr><th>ID</th><th>Vulnerabilidade</th><th>Sev.</th><th>Score</th><th>Ativo</th><th>SLA</th><th>Status</th><th>Correção</th></tr></thead><tbody>';
    body += sv.sort((a,b) => b.final_score - a.final_score).map(v =>
      '<tr><td style="font-family:monospace;font-size:10px">' + (v.ticket||v.id) + '</td>'
      + '<td style="max-width:180px">' + v.title.substring(0,50) + (v.title.length>50?'…':'') + '</td>'
      + '<td><span class="pill ' + (v.sev==='CRITICAL'?'pc':v.sev==='HIGH'?'ph':v.sev==='MEDIUM'?'pm':'pl') + '">' + v.sev + '</span></td>'
      + '<td style="font-weight:700;color:' + (v.final_score>=75?'#dc2626':v.final_score>=55?'#d97706':'#059669') + '">' + v.final_score + '</td>'
      + '<td style="font-size:11px">' + v.asset + '</td>'
      + '<td style="color:' + (v.sla_used>=v.sla_max?'#dc2626':'#64748b') + ';font-size:11px">' + v.sla_used + '/' + v.sla_max + 'd</td>'
      + '<td style="font-size:10px">' + v.status + '</td>'
      + '<td style="font-size:10px;max-width:140px">' + v.remediation.substring(0,70) + '…</td></tr>'
    ).join('') + '</tbody></table>';
  });

  return rptWrap('Relatório Técnico por Squad', (squad&&squad!=='ALL'?squad:'Todos os Squads'), 'Tech Lead · Gestor de Engenharia · DevSecOps', body);
}

// ── 4. EVIDENCE PACKAGE ───────────────────────────────────────────────────────
function buildEvidencePackage(vulnIds) {
  let body = '<div class="nt nt-ok">✅ Este documento constitui o pacote oficial de evidências de remediação gerado pela plataforma RBVM. Adequado para auditorias PCI DSS 4.0, ISO 27001:2022, SOC 2 Type II, CMN 4.893/2021 e BACEN.</div>';

  body += '<div class="sh">📋 Sumário das Vulnerabilidades</div>';
  body += '<table><thead><tr><th>ID</th><th>Título</th><th>Sev.</th><th>Score</th><th>Status Final</th><th>MTTR</th></tr></thead><tbody>';
  body += vulnIds.map(id => {
    const v = VULNS.find(x => x.id === id);
    const pr = PATCH_RECORDS.find(r => r.vuln_id === id && r.status === 'validated');
    return v ? '<tr><td style="font-family:monospace;font-size:11px">' + id + '</td><td>' + v.title.substring(0,60) + '</td>'
      + '<td><span class="pill ' + (v.sev==='CRITICAL'?'pc':v.sev==='HIGH'?'ph':'pm') + '">' + v.sev + '</span></td>'
      + '<td style="font-weight:700">' + v.final_score + '</td>'
      + '<td style="color:' + (pr?'#059669':'#d97706') + ';font-weight:600">' + (pr?'VALIDADO ✓':'Em remediação') + '</td>'
      + '<td>' + (pr?pr.mttr_days+'d':'—') + '</td></tr>' : '';
  }).join('') + '</tbody></table>';

  vulnIds.forEach(id => {
    const v = VULNS.find(x => x.id === id);
    if (!v) return;
    const events = getAuditTrail(id, AUDIT_ADDED);
    const pr = PATCH_RECORDS.filter(r => r.vuln_id === id);

    body += '<div style="page-break-before:auto;margin-top:24px">';
    body += '<div class="sh">🔍 Vulnerabilidade: ' + id + '</div>';
    body += '<div class="audit-block">';
    body += '<div class="audit-vuln">' + v.title + ' — Score: ' + v.final_score + ' — ' + v.sev + '</div>';
    body += '<table><thead><tr><th colspan="2">Detalhes Técnicos</th></tr></thead><tbody>'
      + '<tr><td style="width:140px;color:#64748b">Ativo</td><td>' + v.asset + ' (' + v.env + ')</td></tr>'
      + '<tr><td style="color:#64748b">Owner</td><td>' + v.owner + '</td></tr>'
      + '<tr><td style="color:#64748b">Squad / BU</td><td>' + v.squad + ' / ' + v.bu + '</td></tr>'
      + '<tr><td style="color:#64748b">CVSS / EPSS</td><td>' + v.cvss + ' / ' + (v.epss?Math.round(v.epss*100)+'%':'—') + '</td></tr>'
      + '<tr><td style="color:#64748b">KEV / Exploit</td><td>' + (v.kev?'SIM — CISA KEV':'NÃO') + ' / ' + (v.exploit?'SIM':'NÃO') + '</td></tr>'
      + '<tr><td style="color:#64748b">SLA</td><td>' + v.sla_used + '/' + v.sla_max + ' dias (' + (v.sla_used>=v.sla_max?'VENCIDO':'em prazo') + ')</td></tr>'
      + '<tr><td style="color:#64748b">Status</td><td style="font-weight:700">' + v.status + '</td></tr>'
      + '</tbody></table>';

    if (events.length) {
      body += '<div style="margin-top:12px;font-size:12px;font-weight:700;color:#1e293b;margin-bottom:6px">Audit Trail Completo</div>';
      body += events.map(e =>
        '<div class="at-row"><div class="at-dot" style="background:' + (e.actor==='system'?'#3b82f6':e.actor==='ai'?'#06b6d4':'#059669') + '"></div>'
        + '<div><span style="font-family:monospace;font-size:10px;color:#94a3b8">' + e.ts + '</span> — <strong>' + e.action + '</strong>'
        + (e.before&&e.after?' [' + e.before + ' → ' + e.after + ']':'')
        + '<br><span style="color:#64748b">' + (e.detail||'') + '</span> — <em>' + (e.name||e.actor) + ' · ' + (e.src||'—') + '</em></div></div>'
      ).join('');
    }

    if (pr.length) {
      body += '<div style="margin-top:12px;font-size:12px;font-weight:700;color:#1e293b;margin-bottom:6px">Registros de Patch</div>';
      body += pr.map(r =>
        '<div style="background:#f1f5f9;border-radius:4px;padding:8px 12px;margin-bottom:4px;font-size:11px">'
        + '<strong>' + r.asset + '</strong> — Patch: ' + r.patch + ' — Status: <span style="font-weight:700;color:' + (r.status==='validated'?'#059669':'#d97706') + '">' + r.status.toUpperCase() + '</span>'
        + (r.deployed?'<br>Deployado: ' + r.deployed + (r.deployed_by?' por ' + r.deployed_by:''):'')
        + (r.validated_at?'<br>Validado: ' + r.validated_at + ' por ' + (r.validated_by||'—'):'')
        + (r.mttr_days!=null?'<br>MTTR: ' + r.mttr_days + ' dias':'')
        + '</div>'
      ).join('');
    }

    body += '</div></div>';
  });

  body += '<div class="sig" style="margin-top:32px">'
    + '<div class="sig-box"><div class="sig-lbl">Analista de Segurança</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Aprovador / CISO</div><div style="margin-top:20px">Assinatura: ___________________</div></div>'
    + '<div class="sig-box"><div class="sig-lbl">Data do Pacote</div><div>' + new Date().toLocaleDateString('pt-BR') + '</div><div style="font-size:10px;color:#64748b">Hash de integridade: SHA256-DEMO-' + Math.random().toString(36).substring(2,10).toUpperCase() + '</div></div>'
    + '</div>';

  return rptWrap('Pacote de Evidências de Remediação', vulnIds.length + ' vulnerabilidade(s) · Auditoria oficial', 'Auditor Externo · GRC · BACEN · Regulatório', body);
}

// ── 5. ATTACK SURFACE REPORT ──────────────────────────────────────────────────
function buildASMReport() {
  if (!EXTERNAL_ASSETS || !EXTERNAL_ASSETS.length) return '<html><body>Dados ASM indisponíveis</body></html>';
  const shadow = EXTERNAL_ASSETS.filter(a => a.shadow);
  const monitored = EXTERNAL_ASSETS.filter(a => !a.shadow);
  const certWarn = EXTERNAL_ASSETS.filter(a => a.ssl && a.ssl.days !== null && a.ssl.days < 90);
  const risky = EXTERNAL_ASSETS.filter(a => a.risk_score >= 60);
  const score = getAsmScore(EXTERNAL_ASSETS);

  let body = '<div class="metrics" style="margin-top:20px">'
    + '<div class="metric"><div class="ml">Exposure Score</div><div class="mv ' + (score>=60?'crit':'high') + '">' + score + '/100</div></div>'
    + '<div class="metric"><div class="ml">Ativos Externos</div><div class="mv info">' + monitored.length + '</div></div>'
    + '<div class="metric"><div class="ml">Shadow IT</div><div class="mv crit">' + shadow.length + '</div></div>'
    + '<div class="metric"><div class="ml">Risco Alto+</div><div class="mv crit">' + risky.length + '</div></div>'
    + '<div class="metric"><div class="ml">Certs < 90d</div><div class="mv high">' + certWarn.length + '</div></div>'
    + '</div>';

  body += '<div class="sh">🌐 Ativos Externos Monitorados</div>';
  body += '<table><thead><tr><th>Hostname</th><th>IP</th><th>Tipo</th><th>SSL Grade</th><th>Cert</th><th>Headers</th><th>Score</th><th>CVEs</th></tr></thead><tbody>';
  body += monitored.sort((a,b) => b.risk_score - a.risk_score).map(a =>
    '<tr><td style="font-family:monospace;font-size:11px">' + a.hostname + '</td>'
    + '<td style="font-family:monospace;font-size:11px;color:#94a3b8">' + a.ip + '</td>'
    + '<td style="font-size:11px">' + a.category + '</td>'
    + '<td style="font-weight:800;color:' + (a.ssl.grade==='A+'||a.ssl.grade==='A'?'#059669':a.ssl.grade==='B'?'#ca8a04':a.ssl.grade==='F'?'#dc2626':'#d97706') + '">' + a.ssl.grade + '</td>'
    + '<td style="font-size:11px;color:' + (a.ssl.days===null?'#dc2626':a.ssl.days<30?'#dc2626':a.ssl.days<90?'#d97706':'#059669') + '">' + (a.ssl.days===null?'Sem cert':a.ssl.days+'d') + '</td>'
    + '<td style="font-weight:700;color:' + (a.headers.score>=70?'#059669':a.headers.score>=40?'#d97706':'#dc2626') + '">' + a.headers.score + '/100</td>'
    + '<td style="font-weight:800;color:' + (a.risk_score>=75?'#dc2626':a.risk_score>=55?'#d97706':'#059669') + '">' + a.risk_score + '</td>'
    + '<td>' + (a.vuln_ids.length?'<span class="pill pc">'+a.vuln_ids.length+' CVE</span>':'<span class="pill pd">OK</span>') + '</td></tr>'
  ).join('') + '</tbody></table>';

  if (shadow.length) {
    body += '<div class="sh">👻 Shadow IT — Ativos Não Catalogados</div>';
    body += '<div class="nt nt-crit">⚠ ' + shadow.length + ' ativo(s) descobertos fora do CMDB. Sem owner, sem patch management, sem monitoramento. Requerem investigação e ação imediata.</div>';
    body += shadow.map(a =>
      '<div class="audit-block" style="border-left:3px solid #dc2626">'
      + '<div class="audit-vuln">👻 ' + a.hostname + ' (' + a.ip + ') — Risk Score: ' + a.risk_score + '</div>'
      + '<strong>Método de descoberta:</strong> ' + a.discovery + '<br>'
      + '<strong>Portas abertas:</strong> ' + a.ports.join(', ') + '<br>'
      + '<strong>Observações:</strong> ' + a.notes + '</div>'
    ).join('');
  }

  return rptWrap('Relatório de Attack Surface Management', 'Superfície de Ataque Externa — Análise Completa', 'SOC · CISO · SecOps · Threat Intelligence', body);
}

// ── OPEN REPORT IN NEW TAB ────────────────────────────────────────────────────
function openReport(htmlContent, title) {
  const win = window.open('', '_blank');
  if (!win) { toast('Popup bloqueado. Permita popups para esta página.','te'); return; }
  win.document.write(htmlContent);
  win.document.close();
  const entry = { id:'RPT-'+String(RPT_HISTORY.length+1).padStart(3,'0'), title, ts:new Date().toISOString(), type:RPT_TYPE };
  RPT_HISTORY.unshift(entry);
  if (RPT_HISTORY.length > 20) RPT_HISTORY.pop();
  saveReportHistory(RPT_HISTORY);
  toast('Relatório aberto em nova aba — use Ctrl+P para salvar como PDF','ts');
  render();
}

// ── MAIN REPORTS VIEW ─────────────────────────────────────────────────────────
function rptexport() {
  const allActive = VULNS.filter(v => v.status !== 'Resolved' && v.status !== 'Closed with Evidence');
  const squads = [...new Set(allActive.map(v => v.squad||v.team))];

  const generateTab = () => `<div class="content">
    <div class="nt ni-"><i class="ti ti-info-circle" style="font-size:16px;flex-shrink:0"></i>Selecione o tipo de relatório, configure os filtros e clique em <strong>Gerar Relatório</strong>. O documento abre em nova aba em formato HTML pronto para impressão ou export como PDF (Ctrl+P → Salvar como PDF).</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:16px">
      ${RPT_TYPES.map(t => `<div class="rpt-card ${RPT_TYPE===t.id?'active':''}" onclick="RPT_TYPE='${t.id}';render()">
        <div class="rpt-icon" style="background:${t.bg};color:${t.color}"><i class="ti ${t.icon}"></i></div>
        <div class="rpt-name">${t.name}</div>
        <div class="rpt-desc">${t.desc.substring(0,90)}${t.desc.length>90?'…':''}</div>
        <div class="rpt-audience" style="color:${t.color}">${t.audience}</div>
      </div>`).join('')}
    </div>
    <div class="rpt-config">
      <div class="ds" style="margin-bottom:12px">Configuração — ${RPT_TYPES.find(t=>t.id===RPT_TYPE)?.name||''}</div>
      <div class="g2" style="gap:12px;margin-bottom:12px">
        ${RPT_TYPE==='squad'?`<div class="ff"><div class="fl">Squad</div><select class="fi" id="rpt-squad"><option value="ALL">Todos os Squads</option>${squads.map(s=>`<option>${s}</option>`).join('')}</select></div>`:''}
        ${RPT_TYPE==='compliance'?`<div class="ff"><div class="fl">Framework</div><select class="fi" id="rpt-fw"><option value="ALL">Todos</option><option>NIST</option><option>PCI</option><option>ISO</option><option>LGPD</option><option>CMN</option></select></div>`:''}
        <div class="ff"><div class="fl">Período de Referência</div><select class="fi" id="rpt-period"><option>Maio 2024</option><option>Abril 2024</option><option>Q1 2024</option></select></div>
        <div class="ff"><div class="fl">Classificação</div><select class="fi"><option>CONFIDENCIAL</option><option>RESTRITO</option><option>INTERNO</option></select></div>
      </div>
      <div class="btn-g">
        <button class="btn btn-p" onclick="execGenerateReport()"><i class="ti ti-file-analytics"></i> Gerar Relatório — Abrir em Nova Aba</button>
        <button class="btn" onclick="quickMsg('Com base nos dados atuais da plataforma, gere o conteúdo completo para um ${RPT_TYPES.find(t=>t.id===RPT_TYPE)?.name||'Relatório'} de segurança. Inclua: métricas atuais, análise de risco, recomendações priorizadas e próximos passos.')"><i class="ti ti-robot"></i> Rascunho via Agente IA</button>
      </div>
    </div>
  </div>`;

  const evidenceTab = () => `<div class="content">
    <div class="nt nw"><i class="ti ti-shield-check" style="font-size:16px;flex-shrink:0"></i>Selecione as vulnerabilidades para incluir no pacote de evidências. O documento gerado inclui audit trail completo, registros de patch e confirmações de rescan — adequado para PCI DSS, ISO 27001, SOC 2, BACEN.</div>
    <div class="g2">
      <div>
        <div class="ds" style="margin-bottom:8px">Selecionar Vulnerabilidades (${RPT_EV_SEL.length} selecionadas)</div>
        ${VULNS.map(v=>`<div class="ev-sel ${RPT_EV_SEL.includes(v.id)?'selected':''}" onclick="rptEvToggle('${v.id}')">
          <i class="ti ti-${RPT_EV_SEL.includes(v.id)?'circle-check':'circle'}" style="color:${RPT_EV_SEL.includes(v.id)?'var(--accent)':'var(--text3)'};font-size:14px;flex-shrink:0"></i>
          ${SP(v.sev)}
          <div style="flex:1;min-width:0"><div class="mono" style="font-size:11px">${v.id}</div><div style="font-size:10px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.title}</div></div>
          <span style="font-size:10px;color:${v.status==='Closed with Evidence'?'var(--success)':'var(--text3)'}">${v.status}</span>
        </div>`).join('')}
      </div>
      <div>
        <div class="ds" style="margin-bottom:8px">Conteúdo do Pacote</div>
        ${[['ti-list-check','Audit trail cronológico completo'],['ti-refresh','Evidências de rescan técnico'],['ti-ticket','Registros de ticketing e SLA'],['ti-shield-x','Exceções aprovadas'],['ti-package','Registros de patch aplicado'],['ti-lock','Cadeia de custódia com hash de integridade']].map(([icon,label])=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);font-size:11px"><i class="ti ${icon}" style="color:var(--success);font-size:13px"></i>${label}</div>`).join('')}
        <div class="btn-g" style="margin-top:12px">
          <button class="btn btn-p" onclick="execEvidencePackage()" ${RPT_EV_SEL.length===0?'disabled':''}>
            <i class="ti ti-shield-check"></i> Gerar Pacote (${RPT_EV_SEL.length} vulns)
          </button>
          <button class="btn" onclick="RPT_EV_SEL=VULNS.map(v=>v.id);render()"><i class="ti ti-select-all"></i> Selecionar Todas</button>
          <button class="btn" onclick="RPT_EV_SEL=[];render()"><i class="ti ti-deselect"></i> Limpar</button>
        </div>
      </div>
    </div>
  </div>`;

  const historyTab = () => `<div class="content">
    ${RPT_HISTORY.length===0?`<div class="nt ni-"><i class="ti ti-info-circle" style="font-size:16px;flex-shrink:0"></i>Nenhum relatório gerado ainda nesta sessão. Acesse a aba "Gerar Relatório" para criar o primeiro.</div>`:''}
    ${RPT_HISTORY.map(r=>`<div class="rpt-hist-item" onclick="rptRegenerate('${r.id}')">
      <i class="ti ti-file-analytics" style="color:var(--accent);font-size:20px;flex-shrink:0"></i>
      <div style="flex:1">
        <div style="font-size:12px;font-weight:600">${r.title}</div>
        <div style="font-size:10px;color:var(--text3)">${new Date(r.ts).toLocaleString('pt-BR')} · Tipo: ${r.type}</div>
      </div>
      <button class="btn btn-s"><i class="ti ti-refresh"></i> Regerar</button>
    </div>`).join('')}
    ${RPT_HISTORY.length>0?`<button class="btn btn-s" style="margin-top:8px" onclick="RPT_HISTORY=[];localStorage.removeItem('rbvm_reports');render()"><i class="ti ti-trash"></i> Limpar histórico</button>`:''}
  </div>`;

  const tabs = { generate:'Gerar Relatório', evidence:'Pacote de Evidências', history:`Histórico (${RPT_HISTORY.length})` };
  const tabFns = { generate:generateTab, evidence:evidenceTab, history:historyTab };
  const body = (tabFns[RPT_TAB]||generateTab)();

  return `<div>
  <div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${RPT_TAB===k?'active':''}" onclick="rptTab('${k}')">${v}</div>`).join('')}
  </div>
  ${body}
  </div>`;
}

window.rptTab      = t => { RPT_TAB = t; render(); };
window.rptEvToggle = id => { RPT_EV_SEL.includes(id) ? RPT_EV_SEL.splice(RPT_EV_SEL.indexOf(id),1) : RPT_EV_SEL.push(id); render(); };
window.execGenerateReport = () => {
  const sq  = document.getElementById('rpt-squad')?.value || 'ALL';
  const fw  = document.getElementById('rpt-fw')?.value    || 'ALL';
  let html;
  if      (RPT_TYPE==='executive')  html = buildExecReport();
  else if (RPT_TYPE==='compliance') html = buildComplianceReport(fw);
  else if (RPT_TYPE==='squad')      html = buildSquadReport(sq);
  else if (RPT_TYPE==='evidence')   { RPT_TAB='evidence'; render(); return; }
  else if (RPT_TYPE==='asm')        html = buildASMReport();
  else                              html = buildExecReport();
  const title = RPT_TYPES.find(t=>t.id===RPT_TYPE)?.name || RPT_TYPE;
  openReport(html, title);
};
window.execEvidencePackage = () => {
  if (!RPT_EV_SEL.length) { toast('Selecione ao menos uma vulnerabilidade','te'); return; }
  openReport(buildEvidencePackage(RPT_EV_SEL), 'Pacote de Evidências (' + RPT_EV_SEL.length + ' vulns)');
};
window.rptRegenerate = id => {
  const r = RPT_HISTORY.find(x=>x.id===id);
  if (!r) return;
  RPT_TYPE = r.type;
  execGenerateReport();
};



// ══════════════════════════════════════════════════════════════════════════════
//  SPRINT 6 — OFFENSIVE FINDINGS (Red Team + Bug Bounty)
// ══════════════════════════════════════════════════════════════════════════════
function offensive() {
  const allRTF  = RT_FINDINGS;
  const allBBF  = BB_FINDINGS;
  const allGaps = CONTROL_GAPS;
  const rtCrit  = allRTF.filter(f=>f.severity==='CRITICAL').length;
  const bbCrit  = allBBF.filter(f=>f.severity==='CRITICAL').length;
  const cjImpacted = allRTF.filter(f=>f.crown_jewel_impacted).length;
  const exploitable= allRTF.filter(f=>f.status==='Still Exploitable').length;
  const awaitRetest= allRTF.filter(f=>f.retest_status==='Scheduled'||f.retest_status==='Not Started'&&f.status==='Resolved by Team').length
                   + allBBF.filter(f=>f.retest_status==='Scheduled'||f.retest_status==='Not Started'&&f.status==='Resolved by Team').length;
  const detGaps = allGaps.filter(g=>g.gap_type==='detection_gap').length;
  const ctrlGaps= allGaps.filter(g=>g.gap_type!=='detection_gap').length;
  const bbPending = allBBF.filter(f=>f.triage_status==='Triage'||f.triage_status==='Submitted').length;

  const sevPillS= s => `<span class="pill ${s==='CRITICAL'?'pc':s==='HIGH'?'ph':'pm'}" style="font-size:9px">${s}</span>`;
  const detBadge= d => `<span class="det-badge ${d==='Not Detected'?'det-none':d==='Partially Detected'?'det-partial':'det-full'}">${d}</span>`;
  const mitreBadge=t=>`<span class="mitre-badge">${t}</span>`;
  const retestBadge=r=>({
    'Passed':'<span class="pill pd" style="font-size:9px">Retest Passed ✓</span>',
    'Failed':'<span class="pill pc" style="font-size:9px">Retest FAILED ✗</span>',
    'Scheduled':'<span class="pill ph" style="font-size:9px">Retest Agendado</span>',
    'Not Started':'<span class="pill pn" style="font-size:9px">Sem Retest</span>',
    'In Progress':'<span class="pill pp" style="font-size:9px">Retest em Prog.</span>',
    'Not Applicable':'<span class="pill pn" style="font-size:9px">N/A</span>',
  }[r]||`<span class="pill pn" style="font-size:9px">${r}</span>`);

  // ── OVERVIEW TAB ────────────────────────────────────────────────────────────
  const overviewTab=()=>`<div class="content">
    <div class="off-banner"><i class="ti ti-shield-exclamation" style="font-size:16px;flex-shrink:0"></i><div><strong>Findings ofensivos representam evidência validada de ataque, não apenas vulnerabilidades teóricas.</strong> Eles devem ser triados, correlacionados, corrigidos, retestados e convertidos em inteligência de risco de negócio.<br><em style="font-size:10px;opacity:.8">Offensive findings represent validated attack evidence, not only theoretical vulnerabilities. They must be triaged, correlated, remediated, retested and converted into business risk intelligence.</em></div></div>
    <div class="san-notice"><i class="ti ti-lock" style="font-size:14px;flex-shrink:0"></i>As evidências exibidas são sanitizadas. Detalhes ofensivos, payloads, segredos, URLs internas e etapas sensíveis de exploração foram intencionalmente omitidos. <em>Evidence shown is sanitized. Offensive details, payloads, secrets and sensitive exploitation steps are intentionally omitted.</em></div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr) repeat(4,1fr);gap:10px;grid-template-rows:auto auto;margin-bottom:10px">
      <div class="mt"><div class="mt-l">RT Findings</div><div class="mt-v vi">${allRTF.length}</div><div class="mt-s">${rtCrit} críticos</div></div>
      <div class="mt"><div class="mt-l">Bug Bounty</div><div class="mt-v vi">${allBBF.length}</div><div class="mt-s">${bbCrit} críticos</div></div>
      <div class="mt"><div class="mt-l">Crown Jewel Impact</div><div class="mt-v vc">${cjImpacted}</div><div class="mt-s">RT → crown jewel</div></div>
      <div class="mt"><div class="mt-l">Aguardando Retest</div><div class="mt-v vh">${awaitRetest}</div><div class="mt-s">antes de fechar</div></div>
      <div class="mt"><div class="mt-l">Detection Gaps</div><div class="mt-v vc">${detGaps}</div><div class="mt-s">SOC não detectou</div></div>
      <div class="mt"><div class="mt-l">Control Gaps</div><div class="mt-v vh">${ctrlGaps}</div><div class="mt-s">controle falhou</div></div>
      <div class="mt"><div class="mt-l">BB Triagem Pendente</div><div class="mt-v vh">${bbPending}</div><div class="mt-s">aguardando resp.</div></div>
      <div class="mt"><div class="mt-l">Bounties Aprovados</div><div class="mt-v vk">R$ ${allBBF.reduce((s,f)=>s+(f.bounty_amount||0),0).toLocaleString('pt-BR')}</div><div class="mt-s">total pago</div></div>
    </div>
    <div class="g2">
      <div class="card"><div class="card-hd"><i class="ti ti-sword" style="color:var(--crit)"></i><div><div class="card-t">Red Team — Top Risk</div><div class="card-s">Por score ofensivo</div></div></div><div class="card-bd" style="padding-top:4px">
        ${allRTF.sort((a,b)=>b.risk_score-a.risk_score).map(f=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="OFT_TAB='redteam';OFT_RT_EXP='${f.id}';render()">
          ${sevPillS(f.severity)}<span style="font-size:11px;font-weight:500;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.title}</span>
          ${f.crown_jewel_impacted?rpill('pc','👑 CJ'):''}${detBadge(f.detection_status)}
          <span style="color:${RC(f.risk_score)};font-weight:700">${f.risk_score}</span>
        </div>`).join('')}
      </div></div>
      <div class="card"><div class="card-hd"><i class="ti ti-bug-off" style="color:var(--accent)"></i><div><div class="card-t">Bug Bounty — Submissões</div><div class="card-s">Por severidade</div></div></div><div class="card-bd" style="padding-top:4px">
        ${allBBF.sort((a,b)=>b.risk_score-a.risk_score).map(f=>`<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="OFT_TAB='bugbounty';OFT_BB_EXP='${f.id}';render()">
          ${sevPillS(f.severity)}<span style="font-size:11px;font-weight:500;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.title}</span>
          ${getBBStatusMeta(f.status).label?`<span class="pill ${getBBStatusMeta(f.status).cls}" style="font-size:9px">${getBBStatusMeta(f.status).label}</span>`:''}
        </div>`).join('')}
      </div></div>
    </div>
  </div>`;

  // ── RED TEAM TAB ────────────────────────────────────────────────────────────
  const rtTab=()=>`<div>
    <div style="padding:10px 16px 4px"><div class="san-notice"><i class="ti ti-lock" style="font-size:12px;flex-shrink:0"></i>Evidências sanitizadas. Payloads, endpoints internos e detalhes ofensivos omitidos nesta demo pública.</div></div>
    <div style="padding:0 16px;display:flex;flex-direction:column;gap:8px">
    ${allRTF.map(f=>{
      const tp=getRTTypeLabel(f.finding_type);
      const isExp=OFT_RT_EXP===f.id;
      return `<div class="off-finding ${isExp?'expanded':''}" onclick="OFT_RT_EXP=OFT_RT_EXP==='${f.id}'?null:'${f.id}';render()">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
          <span class="off-type-rt">Red Team</span>${sevPillS(f.severity)}<span style="font-weight:700;color:${RC(f.risk_score)}">${f.risk_score}</span>
          ${mitreBadge(f.mitre_technique)}<span class="pill pai" style="font-size:9px">${f.mitre_tactic}</span>
          ${f.crown_jewel_impacted?`<span class="pill pc" style="font-size:9px">👑 Crown Jewel: ${f.crown_jewel_name}</span>`:''}
          ${detBadge(f.detection_status)}${retestBadge(f.retest_status)}
          <span class="mono" style="font-size:10px;color:var(--text3);margin-left:auto">${f.id}</span>
        </div>
        <div style="font-size:13px;font-weight:600;margin-bottom:3px">${f.title}</div>
        <div style="font-size:10px;color:var(--text3)">${f.asset_impacted} · ${f.squad} · Ticket: ${f.ticket} · SLA: ${f.sla}d · Status: ${f.status}</div>
        ${isExp?`<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
          <div class="san-notice" style="margin-bottom:10px"><i class="ti ti-lock" style="font-size:12px;flex-shrink:0"></i>Evidência sanitizada — ${f.evidence_summary_sanitized}</div>
          <div class="dg" style="margin-bottom:10px">
            <div class="di"><div class="di-l">Executive Summary</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.executive_summary}</div></div>
            <div class="di"><div class="di-l">Business Risk</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.business_risk}</div></div>
          </div>
          <div class="dg3" style="margin-bottom:10px">
            <div class="di"><div class="di-l">MITRE Tactic</div><div class="di-v">${mitreBadge(f.mitre_tactic)}</div></div>
            <div class="di"><div class="di-l">Technique</div><div class="di-v">${mitreBadge(f.mitre_technique)}</div></div>
            <div class="di"><div class="di-l">Kill Chain Phase</div><div class="di-v" style="font-size:11px">${f.kill_chain_phase}</div></div>
            <div class="di"><div class="di-l">Detection</div><div class="di-v">${detBadge(f.detection_status)}</div></div>
            <div class="di"><div class="di-l">Prevention</div><div class="di-v"><span class="det-badge ${f.prevention_status==='Not Prevented'?'det-none':'det-full'}">${f.prevention_status}</span></div></div>
            <div class="di"><div class="di-l">Privilege Obtained</div><div class="di-v" style="font-size:11px">${f.privilege_level_obtained}</div></div>
          </div>
          ${f.crown_jewel_impacted?`<div class="cj-impact" style="margin-bottom:10px"><i class="ti ti-crown" style="font-size:14px"></i><div><strong>Crown Jewel Impactado: ${f.crown_jewel_name}</strong><br><span style="font-size:10px">Proximidade: ${f.crown_jewel_proximity}</span></div></div>`:''}
          <div style="margin-bottom:10px"><div class="ds">Gaps Identificados</div>
            <div style="display:flex;flex-direction:column;gap:4px;margin-top:4px">
              ${f.control_failure?`<div style="font-size:11px;color:var(--crit)"><i class="ti ti-x" style="font-size:11px"></i> <strong>Control:</strong> ${f.control_failure}</div>`:''}
              ${f.detection_gap?`<div style="font-size:11px;color:var(--crit)"><i class="ti ti-eye-off" style="font-size:11px"></i> <strong>Detection:</strong> ${f.detection_gap}</div>`:''}
              ${f.prevention_gap?`<div style="font-size:11px;color:var(--high)"><i class="ti ti-shield-off" style="font-size:11px"></i> <strong>Prevention:</strong> ${f.prevention_gap}</div>`:''}
              ${f.response_gap?`<div style="font-size:11px;color:var(--high)"><i class="ti ti-clock-x" style="font-size:11px"></i> <strong>Response:</strong> ${f.response_gap}</div>`:''}
            </div>
          </div>
          <div class="dg" style="margin-bottom:10px">
            <div class="di"><div class="di-l">Correção Recomendada</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.recommended_fix}</div></div>
            <div class="di"><div class="di-l">Recomendação Estratégica</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.strategic_recommendation}</div></div>
          </div>
          <div class="btn-g">
            <button class="btn btn-p btn-s" onclick="event.stopPropagation();offCreateTicket('${f.id}','rt')"><i class="ti ti-ticket"></i> Criar Ticket</button>
            <button class="btn btn-s" onclick="event.stopPropagation();offScheduleRetest('${f.id}')"><i class="ti ti-refresh"></i> Agendar Retest</button>
            <button class="btn btn-s" onclick="event.stopPropagation();quickMsg('Red Team finding ${f.id}: ${f.title.replace(/'/g,"\'")}. Risk score: ${f.risk_score}. MITRE: ${f.mitre_technique}. Crown Jewel: ${f.crown_jewel_name||'N/A'}. Detection: ${f.detection_status}. Gaps: ${(f.control_failure||'')}. Gere plano de remediação priorizado considerando o risco ofensivo comprovado, os gaps identificados e o impacto regulatório.')"><i class="ti ti-robot"></i> Plano via IA</button>
          </div>
        </div>`:''}
      </div>`;
    }).join('')}
    </div></div>`;

  // ── BUG BOUNTY TAB ─────────────────────────────────────────────────────────
  const bbTab=()=>`<div>
    <div style="padding:10px 16px 4px"><div class="san-notice"><i class="ti ti-lock" style="font-size:12px;flex-shrink:0"></i>Relatórios de pesquisadores sanitizados. Passos de reprodução, payloads e endpoints específicos omitidos.</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
      ${['In Scope','Out of Scope','Needs Review'].map(sc=>{const n=allBBF.filter(f=>f.scope_status===sc).length;return n?`<span class="pill pn" style="font-size:10px">${sc}: ${n}</span>`:''}).join('')}
      ${['Unique','Duplicate','Known Issue'].map(d=>{const n=allBBF.filter(f=>f.duplicate_status===d).length;return n?`<span class="pill pn" style="font-size:10px">${d}: ${n}</span>`:''}).join('')}
    </div></div>
    <div style="padding:8px 16px;display:flex;flex-direction:column;gap:8px">
    ${allBBF.map(f=>{
      const st=getBBStatusMeta(f.status);
      const disc=getDisclosureDays(f);
      const isExp=OFT_BB_EXP===f.id;
      return `<div class="off-finding ${isExp?'expanded':''}" onclick="OFT_BB_EXP=OFT_BB_EXP==='${f.id}'?null:'${f.id}';render()">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px">
          <span class="off-type-bb">Bug Bounty</span>${sevPillS(f.severity)}
          <span class="pill ${f.scope_status==='In Scope'?'pd':f.scope_status==='Out of Scope'?'pc':'ph'}" style="font-size:9px">${f.scope_status}</span>
          <span class="pill ${f.triage_status==='Validated'?'pd':f.triage_status==='Accepted'?'pi':'ph'}" style="font-size:9px">${f.triage_status}</span>
          ${retestBadge(f.retest_status)}
          ${disc!==null?`<span class="${disc<=30?'disclosure-timer':'pill pd'}" style="font-size:9px">${disc<=0?'DISCLOSURE HOJE!':disc+'d p/ disclosure'}</span>`:''}
          ${f.bounty_amount?`<span class="bounty-amount">R$ ${f.bounty_amount.toLocaleString('pt-BR')}</span>`:''}
          <span class="researcher-badge" style="margin-left:auto">@${f.reporter_alias}</span>
          <span class="mono" style="font-size:10px;color:var(--text3)">${f.id}</span>
        </div>
        <div style="font-size:12px;font-weight:600;margin-bottom:3px">${f.title}</div>
        <div style="font-size:10px;color:var(--text3)">${f.owasp_category} · CWE-${f.cwe.replace('CWE-','')} · ${f.asset} · SLA resp: ${f.sla_response}h · rem: ${f.sla_remediation}d</div>
        ${isExp?`<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
          <div class="san-notice" style="margin-bottom:8px"><i class="ti ti-lock" style="font-size:12px;flex-shrink:0"></i>${f.evidence_summary_sanitized}</div>
          <div class="dg" style="margin-bottom:10px">
            <div class="di"><div class="di-l">Executive Summary</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.executive_summary}</div></div>
            <div class="di"><div class="di-l">Business Impact</div><div class="di-v" style="font-size:11px;line-height:1.5">${f.business_impact}</div></div>
          </div>
          <div class="dg3" style="margin-bottom:10px">
            <div class="di"><div class="di-l">OWASP Category</div><div class="di-v" style="font-size:10px">${f.owasp_category}</div></div>
            <div class="di"><div class="di-l">CWE</div><div class="di-v" style="font-size:11px">${f.cwe}</div></div>
            <div class="di"><div class="di-l">Vulnerability Class</div><div class="di-v" style="font-size:11px">${f.vulnerability_class}</div></div>
            <div class="di"><div class="di-l">Bounty Status</div><div class="di-v"><span class="pill ${f.bounty_status==='Paid'?'pd':f.bounty_status==='Approved'?'pi':'ph'}" style="font-size:9px">${f.bounty_status}</span>${f.bounty_amount?` R$ ${f.bounty_amount.toLocaleString('pt-BR')}`:''}</div></div>
            <div class="di"><div class="di-l">Disclosure Status</div><div class="di-v" style="font-size:11px">${f.disclosure_status}</div></div>
            <div class="di"><div class="di-l">Safe Harbor</div><div class="di-v">${rpill('pd',f.safe_harbor_status)}</div></div>
          </div>
          <div class="btn-g">
            ${f.triage_status==='Triage'||f.triage_status==='Submitted'?`<button class="btn btn-o btn-s" onclick="event.stopPropagation();bbValidate('${f.id}')"><i class="ti ti-check"></i> Validar</button><button class="btn btn-d btn-s" onclick="event.stopPropagation();bbReject('${f.id}')"><i class="ti ti-x"></i> Rejeitar</button>`:''}
            <button class="btn btn-s" onclick="event.stopPropagation();offCreateTicket('${f.id}','bb')"><i class="ti ti-ticket"></i> Ticket</button>
            <button class="btn btn-s" onclick="event.stopPropagation();quickMsg('Bug Bounty ${f.id}: ${f.title.replace(/'/g,"\'")}. OWASP: ${f.owasp_category}. CWE: ${f.cwe}. Severity: ${f.severity}. Business impact: ${f.business_impact.replace(/'/g,"\'")}. Gere: (1) análise de impacto real, (2) plano de correção, (3) avaliação de risco residual e (4) se representa padrão sistêmico.')"><i class="ti ti-robot"></i> Análise IA</button>
          </div>
        </div>`:''}
      </div>`;
    }).join('')}
    </div></div>`;

  // ── ATTACK PATHS TAB ────────────────────────────────────────────────────────
  const apTab=()=>`<div class="content">
    <div class="nt ni-"><i class="ti ti-route" style="font-size:16px;flex-shrink:0"></i>Caminhos de ataque identificados pelo Red Team mapeados contra Crown Jewels. Técnicas e passos intermediários sanitizados.</div>
    ${allRTF.filter(f=>f.lateral_movement||f.crown_jewel_impacted).map(f=>{
      const steps=f.id==='RT-2026-001'?[{label:'Dev Foothold',detail:'CI/CD access',type:'entry'},{label:'Runner Abuse',detail:f.mitre_technique,type:'technique'},{label:'Secret Exfil',detail:'Deployment creds',type:'node'},{label:'Crown Jewel',detail:f.crown_jewel_name||'Secrets Vault',type:'target'}]:
                  f.id==='RT-2026-002'?[{label:'Std User',detail:'Employee cred',type:'entry'},{label:'Kerberoast',detail:'T1558.003',type:'technique'},{label:'Service Acc.',detail:'Hash cracked',type:'node'},{label:'Tier-0 Admin',detail:'DCSync',type:'technique'},{label:'Crown Jewel',detail:'Domain Admin',type:'target'}]:
                  [{label:'Initial Access',detail:f.initial_access_vector?.substring(0,20),type:'entry'},{label:f.mitre_tactic,detail:f.mitre_technique,type:'technique'},{label:'Impact',detail:f.crown_jewel_name||f.asset_impacted,type:'target'}];
      return `<div class="card" style="margin-bottom:10px"><div class="card-hd"><i class="ti ti-${f.crown_jewel_impacted?'crown':'route'}" style="color:${f.crown_jewel_impacted?'var(--crit)':'var(--high)'}"></i><div><div class="card-t">${f.id} — ${f.title}</div><div class="card-s">${f.mitre_tactic} · ${f.mitre_technique} · Crown Jewel proximity: ${f.crown_jewel_proximity}</div></div><div class="card-ac">${sevPillS(f.severity)}<span style="color:${RC(f.risk_score)};font-weight:700;margin-left:8px">${f.risk_score}</span></div></div>
      <div class="card-bd"><div style="overflow-x:auto">${attackPathSVG({steps})}</div></div></div>`;
    }).join('')}
  </div>`;

  // ── RETEST QUEUE TAB ────────────────────────────────────────────────────────
  const retestTab=()=>{
    const rtRetest=allRTF.filter(f=>f.retest_status!=='Passed'&&f.retest_status!=='Not Applicable'&&f.retest_status!=='Not Started');
    const bbRetest=allBBF.filter(f=>f.retest_status==='Scheduled'||f.retest_status==='Not Started'&&f.status==='Resolved by Team');
    const all=[...rtRetest,...bbRetest];
    return `<div class="content">
    <div class="nt nw"><i class="ti ti-refresh" style="font-size:16px;flex-shrink:0"></i><strong>Retest é obrigatório</strong> antes de fechar findings ofensivos críticos ou altos. Sem retest confirmado, a correção não é validada tecnicamente.</div>
    ${all.length===0?`<div class="nt nok"><i class="ti ti-check" style="font-size:16px;flex-shrink:0"></i>Fila de retest vazia — todos os findings retestados ou sem retest pendente.</div>`:''}
    ${rtRetest.map(f=>`<div class="retest-card ${f.retest_status==='Passed'?'passed':f.retest_status==='Failed'?'failed':''}">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px"><span class="off-type-rt">Red Team</span>${sevPillS(f.severity)}${retestBadge(f.retest_status)}<span class="mono" style="font-size:10px;color:var(--text3);margin-left:auto">${f.id}</span></div>
      <div style="font-size:12px;font-weight:600;margin-bottom:4px">${f.title}</div>
      <div style="font-size:10px;color:var(--text3)">Owner: ${f.owner} · Squad: ${f.squad} · Retest by: ${f.retest_by||'—'} · Data: ${f.retest_date||'TBD'} · Ticket: ${f.ticket}</div>
      <div class="btn-g" style="margin-top:8px">
        <button class="btn btn-o btn-s" onclick="offRetestPassed('${f.id}','rt')"><i class="ti ti-shield-check"></i> Passed — Fixed</button>
        <button class="btn btn-d btn-s" onclick="offRetestFailed('${f.id}','rt')"><i class="ti ti-refresh-alert"></i> Failed — Reopen</button>
      </div>
    </div>`).join('')}
    </div>`;
  };

  // ── GAPS TAB ────────────────────────────────────────────────────────────────
  const gapsTab=()=>`<div class="content">
    <div class="g4">
      <div class="mt"><div class="mt-l">Detection Gaps</div><div class="mt-v vc">${allGaps.filter(g=>g.gap_type==='detection_gap').length}</div><div class="mt-s">SOC não detectou</div></div>
      <div class="mt"><div class="mt-l">Control Gaps</div><div class="mt-v vh">${allGaps.filter(g=>g.gap_type==='control_gap').length}</div><div class="mt-s">controle falhou</div></div>
      <div class="mt"><div class="mt-l">Prevention Gaps</div><div class="mt-v vh">${allGaps.filter(g=>g.gap_type==='prevention_gap').length}</div><div class="mt-s">não prevenido</div></div>
      <div class="mt"><div class="mt-l">Process/Resp Gaps</div><div class="mt-v vh">${allGaps.filter(g=>g.gap_type==='response_gap'||g.gap_type==='process_gap').length}</div><div class="mt-s">processo/resposta</div></div>
    </div>
    ${allGaps.map(g=>{const gm=getGapTypeMeta(g.gap_type);return`<div class="gap-row" style="border-left:3px solid ${gm.color};margin-bottom:0">
      <div style="flex-shrink:0;width:36px;height:36px;border-radius:var(--r);background:var(--bg4);display:flex;align-items:center;justify-content:center"><i class="ti ${gm.icon}" style="color:${gm.color}"></i></div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;gap:6px;align-items:center;margin-bottom:4px;flex-wrap:wrap"><span class="pill ${gm.cls}" style="font-size:9px">${gm.label}</span><span class="mono" style="font-size:10px;color:var(--text3)">${g.id}</span><span class="pill ${g.severity==='CRITICAL'?'pc':'ph'}" style="font-size:9px">${g.severity}</span><span style="font-size:10px;color:var(--text3);margin-left:auto">→ ${g.metric_affected}</span></div>
        <div style="font-size:12px;font-weight:600;margin-bottom:4px">${g.title}</div>
        <div style="font-size:11px;color:var(--high);margin-bottom:2px"><strong>Controle Esperado:</strong> ${g.control_expected}</div>
        <div style="font-size:11px;color:var(--crit);margin-bottom:4px"><strong>Controle que Falhou:</strong> ${g.control_failed}</div>
        <div style="font-size:10px;color:var(--text3)">Evidência: ${g.evidence_sanitized}</div>
        <div style="font-size:10px;color:var(--accent);margin-top:3px">→ ${g.improvement_plan}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:2px">Owner: ${g.owner} · Status: ${g.status} · SLA: ${g.sla}d · Finding: ${g.finding_id}</div>
      </div>
    </div>`}).join('')}
  </div>`;

  // ── EXEC SUMMARY TAB ───────────────────────────────────────────────────────
  const execTab=()=>`<div class="content">
    <div class="card"><div class="card-hd"><i class="ti ti-briefcase" style="color:var(--accent)"></i><div><div class="card-t">Resumo Executivo — Risco Ofensivo</div></div><div class="card-ac"><button class="btn btn-s btn-p" onclick="quickMsg('Gere resumo executivo de findings ofensivos para o CISO. Red Team: ${allRTF.length} findings (${rtCrit} críticos, ${allRTF.filter(f=>f.crown_jewel_impacted).length} impactaram Crown Jewels, ${allRTF.filter(f=>f.detection_status===\'Not Detected\').length} não detectados). Bug Bounty: ${allBBF.length} reports (${bbCrit} críticos, R$ ${allBBF.reduce((s,f)=>s+(f.bounty_amount||0),0).toLocaleString(\'pt-BR\')} pagos). Gaps: ${allGaps.length} identificados. Inclua: (1) quais findings exigem decisão executiva, (2) quais controles precisam de investimento imediato, (3) tendência de risco e (4) métricas de programa de segurança ofensiva.')"><i class="ti ti-robot"></i> Gerar via IA</button></div></div>
    <div class="card-bd">
      ${[
        {icon:'ti-sword',color:'var(--crit)',    text:`${rtCrit} findings críticos do Red Team abertos — ${allRTF.filter(f=>f.crown_jewel_impacted).length} atingiram Crown Jewels diretamente`},
        {icon:'ti-eye-off',color:'var(--crit)',  text:`${allRTF.filter(f=>f.detection_status==='Not Detected').length}/${allRTF.length} findings do Red Team não foram detectados pelo SOC durante o exercício`},
        {icon:'ti-refresh',color:'var(--high)',  text:`${awaitRetest} findings aguardando retest — não podem ser encerrados sem validação técnica`},
        {icon:'ti-bug-off',color:'var(--accent)',text:`${allBBF.filter(f=>f.owasp_category.includes('A01')).length} reports de Bug Bounty indicam padrão sistêmico de Broken Access Control (A01:2021) em APIs`},
        {icon:'ti-gap',color:'var(--med)',       text:`${allGaps.length} gaps de controle e detecção identificados — ${allGaps.filter(g=>g.gap_type==='detection_gap').length} o SOC não teria detectado em ambiente real`},
      ].map(i=>`<div style="display:flex;gap:10px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--border)">
        <i class="ti ${i.icon}" style="color:${i.color};font-size:18px;flex-shrink:0"></i>
        <span style="font-size:12px;line-height:1.5">${i.text}</span>
      </div>`).join('')}
    </div></div>
  </div>`;

  const tabs={overview:'Overview',redteam:`Red Team (${allRTF.length})`,bugbounty:`Bug Bounty (${allBBF.length})`,attackpaths:'Attack Paths',retest:`Retest Queue`,gaps:`Gaps (${allGaps.length})`,exec:'Executive Summary'};
  const tabFns={overview:overviewTab,redteam:rtTab,bugbounty:bbTab,attackpaths:apTab,retest:retestTab,gaps:gapsTab,exec:execTab};
  const body=(tabFns[OFT_TAB]||overviewTab)();
  return `<div><div class="sbom-tabs">
    ${Object.entries(tabs).map(([k,v])=>`<div class="sbom-tab ${OFT_TAB===k?'active':''}" onclick="oftTab('${k}')">${v}</div>`).join('')}
  </div>${body}</div>`;
}

window.oftTab = t => { OFT_TAB=t; OFT_RT_EXP=null; OFT_BB_EXP=null; render(); };
window.offCreateTicket = (id,type) => { toast(`Ticket de ${type==='rt'?'Red Team Finding':'Bug Bounty'} ${id} criado — evidências sanitizadas incluídas`,'ts'); addAuditEvent(id,{actor:'user',name:'Security Manager',icon:'ti-ticket',action:`Ticket criado para ${type.toUpperCase()} finding ${id}`,before:null,after:'Ticket Created',detail:'Evidências sanitizadas incluídas. Retest obrigatório antes de fechar.',src:'Offensive Findings'}); };
window.offScheduleRetest = id => { const f=RT_FINDINGS.find(x=>x.id===id); if(f){f.retest_status='Scheduled';f.retest_date='2026-06-15';} toast(`Retest agendado para ${id} — 2026-06-15`,'ts'); render(); };
window.offRetestPassed = (id,type) => { const f=type==='rt'?RT_FINDINGS.find(x=>x.id===id):BB_FINDINGS.find(x=>x.id===id); if(f){f.retest_status='Passed';f.status='Fixed Confirmed';} toast(`Retest PASSED — ${id} encerrado com evidência`,'ts'); render(); };
window.offRetestFailed = (id,type) => { const f=type==='rt'?RT_FINDINGS.find(x=>x.id===id):BB_FINDINGS.find(x=>x.id===id); if(f){f.retest_status='Failed';f.status='Reopened';} toast(`Retest FAILED — ${id} reaberto`,'te'); render(); };
window.bbValidate = id => { const f=BB_FINDINGS.find(x=>x.id===id); if(f){f.triage_status='Validated';f.status='Ticket Created';} toast(`${id} validado — ticket de correção criado`,'ts'); render(); };
window.bbReject   = id => { const f=BB_FINDINGS.find(x=>x.id===id); if(f){f.triage_status='Rejected';f.bounty_status='Not Eligible';} toast(`${id} rejeitado`,'ts'); render(); };



// ── START ─────────────────────────────────────────────────────────────────────
function initApp() {
  // Load preferences and apply before first paint
  const prefs = loadPreferences();
  if (prefs.theme)    { document.documentElement.setAttribute('data-theme', prefs.theme); }
  if (prefs.language) { setLang(prefs.language); }

  // Build app shell
  document.getElementById('app').innerHTML = `
    <div class="app">
      <div class="topbar">
        <div class="logo"><i class="ti ti-shield-search"></i>RBVM Platform<span class="logo-badge">AI</span></div>
        <div class="topbar-mid">
          <div class="tb-sw"><i class="ti ti-search"></i><input class="tb-search" id="gs" placeholder="${t('topbar.search')}" oninput="gS(this.value)"/></div>
          <button class="tb-pill cr" onclick="fBySev('CRITICAL')"><i class="ti ti-alert-triangle" style="font-size:12px"></i><span id="pc-n">—</span> ${t('topbar.critical')}</button>
          <button class="tb-pill wa" onclick="setView('sla')"><i class="ti ti-clock-x" style="font-size:12px"></i><span id="ps-n">—</span> ${t('topbar.slaBreached')}</button>
          <button class="tb-pill md" onclick="setView('cicd')"><i class="ti ti-player-stop" style="font-size:12px"></i><span id="pb-n">—</span> ${t('topbar.blocked')}</button>
        </div>
        <div class="topbar-right">
          <div class="tb-ic" onclick="openModal('report')" title="Relatório"><i class="ti ti-file-analytics"></i></div>
          <div class="tb-ic" onclick="setTheme(document.documentElement.getAttribute('data-theme')==='dark'?'white':'dark')" title="Alternar Tema"><i class="ti ti-sun"></i></div>
          <div class="tb-ic" onclick="setView('settings')"><i class="ti ti-settings"></i></div>
          <div class="av" title="CISO">SC</div>
        </div>
      </div>
      <div class="sidebar"><div id="sidebar-inner"></div></div>
      <div class="main-area" id="main"></div>
      <div class="app-footer">${t('footer.copyright')} &nbsp;·&nbsp; ${t('footer.demoData')}</div>
    </div>
    <div class="dov" id="dov">
      <div class="dov-cl" onclick="closeDov()"><i class="ti ti-x"></i></div>
      <div id="dov-c" style="display:flex;flex-direction:column;height:100%;overflow:hidden"></div>
    </div>
    <div class="modal-bg" id="mbg">
      <div class="modal"><div id="mc"></div></div>
    </div>
  `;

  // Handle initial hash route
  const hash = window.location.hash.replace('#/', '').split('?')[0];
  const initialView = HASH_TO_VIEW[hash] || 'dashboard';
  if (initialView !== 'dashboard') {
    setView(initialView, false);
  } else {
    render();
  }

  // Hash change listener
  window.addEventListener('hashchange', () => {
    const h = window.location.hash.replace('#/', '').split('?')[0];
    const v = HASH_TO_VIEW[h] || 'dashboard';
    setView(v, false);
  });
}

// Theme & language actions
window.setTheme = theme => {
  document.documentElement.setAttribute('data-theme', theme);
  savePreference('theme', theme);
  render();
};

window.setLanguage = lang => {
  setLang(lang);
  savePreference('language', lang);
  render(); // re-render updates nav labels + topbar
};

window.resetPreferences = () => {
  resetAllPreferences();
  document.documentElement.setAttribute('data-theme', 'dark');
  setLang('pt-BR');
  toast(t('settings.resetConfirm'), 'ts');
  render();
};

initApp();

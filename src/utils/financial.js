// =============================================================================
// RBVM Platform — Financial Impact Estimation (BRL)
// Referências: IBM Cost of Data Breach 2023 (Brasil ~R$6.75M médio),
//              LGPD Art.52 (até 2% faturamento, máx R$50M/infração),
//              PCI DSS fines (USD 5k–100k/mês em não conformidade),
//              Downtime estimado (BACEN SLA: 4h máx para sistemas críticos)
// =============================================================================

export function estimateFinancialImpact(v) {
  // Base por criticidade do ativo (R$)
  const base = { critical: 9000000, high: 3500000, medium: 900000, low: 120000 }[v.asset_criticality] || 120000;

  let multiplier = 1.0;

  // Exploitability (maior impacto)
  if (v.kev)     multiplier *= 3.8;   // KEV = exploração ativa confirmada
  if (v.exploit) multiplier *= 2.2;   // Exploit público disponível
  if (v.rce)     multiplier *= 2.8;   // RCE — acesso completo ao sistema

  // Exposição
  if (v.internet_facing)        multiplier *= 1.9;
  if (v.env === 'production')   multiplier *= 1.4;

  // Regulatório
  if (v.pci_scope)      multiplier *= 1.7;   // PCI fines + remediation + forensics
  if (v.lgpd_scope)     multiplier *= 1.5;   // LGPD fines + notificação ANPD
  if (v.data_sensitive) multiplier *= 1.3;   // Breach cost + reputational

  // Redutores
  if (v.compensating_controls) multiplier *= 0.55; // Controles reduzem exposição
  if (!v.internet_facing && v.env !== 'production') multiplier *= 0.7;

  const raw = Math.round(base * multiplier);

  let label, category;
  if (raw >= 10000000) { label = `R$ ${(raw/1000000).toFixed(1)}M`;   category = 'Crítico'; }
  else if (raw >= 1000000)  { label = `R$ ${(raw/1000000).toFixed(1)}M`; category = 'Alto'; }
  else if (raw >= 100000)   { label = `R$ ${(raw/1000).toFixed(0)}K`;    category = 'Médio'; }
  else                       { label = `R$ ${raw.toLocaleString('pt-BR')}`;category = 'Baixo'; }

  return { value: raw, label, category };
}

export function totalFinancialExposure(vulns) {
  return vulns
    .filter(v => v.status !== 'Resolved')
    .reduce((sum, v) => sum + (estimateFinancialImpact(v).value || 0), 0);
}

export function formatBRL(value) {
  if (value >= 1000000000) return `R$ ${(value/1000000000).toFixed(1)}B`;
  if (value >= 1000000)    return `R$ ${(value/1000000).toFixed(1)}M`;
  if (value >= 1000)       return `R$ ${(value/1000).toFixed(0)}K`;
  return `R$ ${value.toLocaleString('pt-BR')}`;
}

// =============================================================================
// Deduplication Engine
// =============================================================================

export function detectDuplicates(vulns) {
  // Same CVE across different scanners on same asset = potential duplicate
  const groups = {};
  vulns.forEach(v => {
    if (!v.id.startsWith('CVE-')) return;
    const key = `${v.id}::${v.asset}`;
    if (!groups[key]) groups[key] = [];
    groups[key].push(v);
  });
  return Object.entries(groups)
    .filter(([, g]) => g.length > 1)
    .map(([key, group]) => ({ key, group }));
}

export function groupByCVE(vulns) {
  const groups = {};
  vulns.forEach(v => {
    const cveKey = v.id.startsWith('CVE-') ? v.id : 'MISC';
    if (!groups[cveKey]) groups[cveKey] = [];
    groups[cveKey].push(v);
  });
  return groups;
}

export function groupBySquad(vulns) {
  const groups = {};
  vulns.filter(v => v.status !== 'Resolved').forEach(v => {
    if (!groups[v.squad]) groups[v.squad] = [];
    groups[v.squad].push(v);
  });
  return groups;
}

export function suggestTicketGrouping(vulns) {
  // Group candidates: same CVE across multiple assets → bulk ticket
  const byCVE = {};
  vulns.filter(v => v.status === 'New' && v.id.startsWith('CVE-')).forEach(v => {
    if (!byCVE[v.id]) byCVE[v.id] = [];
    byCVE[v.id].push(v);
  });
  return Object.entries(byCVE)
    .filter(([, g]) => g.length > 1)
    .map(([cve, group]) => ({
      cve, count: group.length,
      suggestion: `Agrupar ${group.length} findings de ${cve} em 1 epic no Jira — atribuir a múltiplos squads via subtasks`,
      squads: [...new Set(group.map(v => v.squad))],
    }));
}

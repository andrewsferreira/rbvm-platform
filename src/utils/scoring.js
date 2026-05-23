// =============================================================================
// RBVM Platform — Risk Scoring Engine (Multicritério)
// Modelo: Severidade Técnica + Exploitability + Exposição + Criticidade do Ativo
//         + Contexto de Negócio + Threat Intelligence + Risco Regulatório
//         - Controles Compensatórios
// =============================================================================

export function computeRiskScore(v) {
  let score = 0;

  // 1. BASE TÉCNICA (0-25)
  const cvssNorm = (v.cvss || 0) / 10 * 25;
  score += cvssNorm;

  // 2. EXPLOITABILITY (0-30)
  if (v.kev)     score += 15;  // CISA KEV = exploração confirmada
  if (v.exploit) score += 10;  // Exploit público disponível
  if (v.rce)     score += 5;   // RCE aumenta criticidade

  // 3. EPSS (0-10)
  if (v.epss != null) score += v.epss * 10;

  // 4. EXPOSIÇÃO (0-15)
  if (v.internet_facing)       score += 10;
  if (v.env === 'production')  score += 5;
  else if (v.env === 'homologation') score += 2;

  // 5. CRITICIDADE DO ATIVO (0-10)
  const critMap = { critical: 10, high: 7, medium: 4, low: 1 };
  score += critMap[v.asset_criticality] || 0;

  // 6. CONTEXTO DE NEGÓCIO (0-10)
  if (v.pci_scope)      score += 4;
  if (v.lgpd_scope)     score += 3;
  if (v.data_sensitive) score += 3;

  // 7. CONTROLES COMPENSATÓRIOS (-10)
  if (v.compensating_controls) score -= 10;

  // 8. SLA VENCIDO (+5)
  if (v.sla_used > v.sla_max) score += 5;

  // Normalizar 0-100
  const raw = Math.min(100, Math.max(0, Math.round(score)));
  return raw;
}

export function getRiskLabel(score) {
  if (score >= 90) return { label: 'CRÍTICO EMERGENCIAL', color: 'var(--crit)', cls: 'p-crit' };
  if (score >= 75) return { label: 'CRÍTICO',             color: 'var(--crit)', cls: 'p-crit' };
  if (score >= 60) return { label: 'ALTO',                color: 'var(--high)', cls: 'p-high' };
  if (score >= 40) return { label: 'MÉDIO',               color: 'var(--med)',  cls: 'p-med'  };
  if (score >= 20) return { label: 'BAIXO',               color: 'var(--low)',  cls: 'p-low'  };
  return              { label: 'INFORMATIVO',          color: 'var(--text3)','cls': 'p-info' };
}

export function getRiskColor(score) {
  if (score >= 75) return 'var(--crit)';
  if (score >= 60) return 'var(--high)';
  if (score >= 40) return 'var(--med)';
  return 'var(--success)';
}

export function getScoreClass(score) {
  if (score >= 75) return 'mv-crit';
  if (score >= 60) return 'mv-high';
  if (score >= 40) return 'mv-text';
  return 'mv-ok';
}

export function explainScore(v) {
  const parts = [];
  const cvssNorm = Math.round((v.cvss || 0) / 10 * 25);
  parts.push({ factor: 'CVSS Base', value: cvssNorm, desc: `CVSS ${v.cvss} → ${cvssNorm} pts` });
  if (v.kev)     parts.push({ factor: 'CISA KEV',          value: 15, desc: 'Exploração confirmada em ambiente real (+15)' });
  if (v.exploit) parts.push({ factor: 'Exploit público',   value: 10, desc: 'Exploit disponível publicamente (+10)' });
  if (v.rce)     parts.push({ factor: 'RCE',               value: 5,  desc: 'Remote Code Execution confirmado (+5)' });
  if (v.epss)    parts.push({ factor: 'EPSS',              value: Math.round(v.epss * 10), desc: `EPSS ${(v.epss * 100).toFixed(0)}% de probabilidade de exploração (+${Math.round(v.epss * 10)})` });
  if (v.internet_facing) parts.push({ factor: 'Internet-facing', value: 10, desc: 'Ativo exposto à internet (+10)' });
  if (v.env === 'production') parts.push({ factor: 'Produção', value: 5, desc: 'Ambiente produtivo (+5)' });
  const critMap = { critical: 10, high: 7, medium: 4, low: 1 };
  if (v.asset_criticality) parts.push({ factor: 'Criticidade do ativo', value: critMap[v.asset_criticality] || 0, desc: `Ativo ${v.asset_criticality} (+${critMap[v.asset_criticality] || 0})` });
  if (v.pci_scope)      parts.push({ factor: 'Escopo PCI DSS',  value: 4, desc: 'Ativo em escopo PCI (+4)' });
  if (v.lgpd_scope)     parts.push({ factor: 'Escopo LGPD',     value: 3, desc: 'Ativo com dados pessoais LGPD (+3)' });
  if (v.data_sensitive) parts.push({ factor: 'Dados sensíveis',  value: 3, desc: 'Ativo com dados sensíveis (+3)' });
  if (v.compensating_controls) parts.push({ factor: 'Controle compensatório', value: -10, desc: 'Controle compensatório ativo (-10)' });
  if (v.sla_used > v.sla_max) parts.push({ factor: 'SLA vencido', value: 5, desc: 'SLA expirado — risco remanescente aumentado (+5)' });
  return parts;
}

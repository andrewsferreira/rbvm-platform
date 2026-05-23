// =============================================================================
// RBVM Platform — SLA Engine & Escalation Rules
// =============================================================================

export const SLA_POLICY = {
  CRITICAL_EMERGENCY: { days: 3,   label: 'Crítico Emergencial', desc: 'KEV + exploit ativo + internet-facing' },
  CRITICAL_INTERNET:  { days: 7,   label: 'Crítico Internet',    desc: 'Crítico em ativo exposto' },
  CRITICAL_INTERNAL:  { days: 15,  label: 'Crítico Interno',     desc: 'Crítico em rede interna' },
  HIGH_INTERNET:      { days: 15,  label: 'Alto Internet',       desc: 'Alto em ativo exposto' },
  HIGH_INTERNAL:      { days: 30,  label: 'Alto Interno',        desc: 'Alto em rede interna' },
  MEDIUM:             { days: 60,  label: 'Médio',               desc: 'Severidade média' },
  LOW:                { days: 90,  label: 'Baixo',               desc: 'Severidade baixa' },
  INFORMATIONAL:      { days: 180, label: 'Informativo',         desc: 'Backlog controlado' },
};

export function getSlaClass(v) {
  const p = v.sla_used / v.sla_max;
  if (p >= 1)    return { cls: 'sf-crit', label: 'VENCIDO',    color: 'var(--crit)' };
  if (p >= 0.75) return { cls: 'sf-warn', label: 'ALERTA',     color: 'var(--high)' };
  return              { cls: 'sf-ok',  label: 'NO PRAZO',   color: 'var(--success)' };
}

export function getSlaRemaining(v) {
  return v.sla_max - v.sla_used;
}

export function getEscalationLevel(v) {
  const remaining = getSlaRemaining(v);
  const p = v.sla_used / v.sla_max;
  if (p >= 1)     return { level: 3, label: 'Escalado — Liderança + GRC', color: 'var(--crit)' };
  if (remaining <= 3) return { level: 2, label: 'Alerta — Gestor + Squad', color: 'var(--high)' };
  if (remaining <= 7) return { level: 1, label: 'Lembrete — Owner técnico', color: 'var(--med)' };
  return              { level: 0, label: 'No prazo', color: 'var(--success)' };
}

export function getNotificationMessage(v, level) {
  const remaining = getSlaRemaining(v);
  const msgs = {
    1: `🔔 *Lembrete SLA* — ${v.id}\nOlá, time ${v.team}. A vulnerabilidade "${v.title}" vence em *${remaining} dias*.\nRisco: ${v.sev} | Ativo: ${v.asset} | Ticket: ${v.ticket}\n→ Recomendação: ${v.remediation}`,
    2: `⚠️ *Alerta SLA Crítico* — ${v.id}\nTime ${v.team}, a vulnerabilidade "${v.title}" vence em *${remaining} dias* e ainda não possui evidência de correção.\nRisco permanece ativo em ambiente ${v.env}. Favor atualizar o ticket ${v.ticket} com plano de ação.`,
    3: `🚨 *SLA VENCIDO — ESCALAÇÃO* — ${v.id}\nA vulnerabilidade "${v.title}" venceu o SLA há *${Math.abs(remaining)} dias*.\nRisco ativo em ambiente ${v.env} — impacto potencial sobre dados sensíveis e exposição regulatória.\nO ticket ${v.ticket} foi escalado para liderança, Governança e GRC.\n→ Decisão necessária: correção emergencial, mitigação ou aceite formal de risco.`
  };
  return msgs[level] || '';
}

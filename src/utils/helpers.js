// =============================================================================
// RBVM Platform — UI Helpers
// =============================================================================

export function sevPill(s) {
  const map = { CRITICAL: ['p-crit','Crítica'], HIGH: ['p-high','Alta'], MEDIUM: ['p-med','Média'], LOW: ['p-low','Baixa'] };
  const [cls, label] = map[s] || ['p-info', s];
  return `<span class="pill ${cls}">${label}</span>`;
}

export function statusPill(s) {
  const map = { 'New': ['p-new','Novo'], 'In Progress': ['p-progress','Em andamento'], 'Resolved': ['p-done','Resolvido'], 'Awaiting Validation': ['p-info','Aguard. Validação'] };
  const [cls, label] = map[s] || ['p-new', s];
  return `<span class="pill ${cls}">${label}</span>`;
}

export function fwTags(fw = []) {
  const cfg = { 'NIST':'p-nist', 'OWASP-API':'p-owasp', 'OWASP-AI':'p-ai', 'OWASP-2025':'p-owasp', 'CVE':'p-cve', 'CIS':'p-nist' };
  return fw.map(f => `<span class="fw-tag ${cfg[f]||'p-info'}">${f}</span>`).join('');
}

export function slaBar(v) {
  const p = Math.min(1, v.sla_used / v.sla_max);
  const cls = p >= 1 ? 'sf-crit' : p >= 0.75 ? 'sf-warn' : 'sf-ok';
  return `<div class="sla-bar"><div class="sla-fill ${cls}" style="width:${Math.round(p*100)}%"></div></div> <span style="font-size:10px;color:var(--text3)">${v.sla_used}/${v.sla_max}d</span>`;
}

export function envPill(env) {
  const map = { production:'p-crit', homologation:'p-med', development:'p-low', internal:'p-info' };
  const label = { production:'Produção', homologation:'Homolog.', development:'Dev', internal:'Interno' };
  return `<span class="pill ${map[env]||'p-info'}" style="font-size:9px">${label[env]||env}</span>`;
}

export function assetTypeBadge(type) {
  const icons = { server:'ti-server', application:'ti-app-window', network:'ti-network', cloud:'ti-cloud', container:'ti-box', repository:'ti-brand-github', ad:'ti-users-group', iac:'ti-file-code', endpoint:'ti-device-laptop', database:'ti-database' };
  return `<i class="ti ${icons[type]||'ti-device-unknown'}" title="${type}"></i>`;
}

export function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('pt-BR');
}

export function toast(msg, type = 'default') {
  const el = document.getElementById('toast');
  const msgEl = document.getElementById('toast-msg');
  if (!el || !msgEl) return;
  msgEl.textContent = msg;
  el.className = 'toast show' + (type === 'error' ? ' toast-error' : type === 'success' ? ' toast-success' : '');
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => el.classList.remove('show'), 3500);
}

// =============================================================================
// RBVM Platform — Persistence (localStorage)
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

const SCHEMA_VERSION = '1.0';
const KEY_PREFIX = 'rbvm_';

const KEYS = {
  theme:     KEY_PREFIX + 'theme',
  language:  KEY_PREFIX + 'lang',
  view:      KEY_PREFIX + 'view',
  reports:   KEY_PREFIX + 'reports',
  fp:        KEY_PREFIX + 'fp_records',
  schema:    KEY_PREFIX + 'schema_v',
};

/** Load all persisted preferences. Returns safe defaults if corrupted. */
export function loadPreferences() {
  try {
    const stored_v = localStorage.getItem(KEYS.schema);
    if (stored_v !== SCHEMA_VERSION) {
      // Schema mismatch — keep theme/lang, clear rest
      const theme = localStorage.getItem(KEYS.theme);
      const lang  = localStorage.getItem(KEYS.language);
      localStorage.setItem(KEYS.schema, SCHEMA_VERSION);
      return { theme: theme || 'dark', language: lang || 'pt-BR' };
    }
    return {
      theme:    localStorage.getItem(KEYS.theme)    || 'dark',
      language: localStorage.getItem(KEYS.language) || 'pt-BR',
      lastView: localStorage.getItem(KEYS.view)     || 'dashboard',
    };
  } catch {
    return { theme: 'dark', language: 'pt-BR', lastView: 'dashboard' };
  }
}

export function savePreference(key, value) {
  try {
    if (KEYS[key]) localStorage.setItem(KEYS[key], value);
  } catch { /* quota exceeded or private mode */ }
}

export function loadReportHistory() {
  try { return JSON.parse(localStorage.getItem(KEYS.reports) || '[]'); }
  catch { return []; }
}

export function saveReportHistory(history) {
  try { localStorage.setItem(KEYS.reports, JSON.stringify(history.slice(0, 20))); }
  catch { /* ignore */ }
}

export function loadFPRecords() {
  try { return JSON.parse(localStorage.getItem(KEYS.fp) || '[]'); }
  catch { return []; }
}

export function saveFPRecords(records) {
  try { localStorage.setItem(KEYS.fp, JSON.stringify(records)); }
  catch { /* ignore */ }
}

/** Reset all preferences to defaults */
export function resetAllPreferences() {
  try {
    Object.values(KEYS).forEach(k => localStorage.removeItem(k));
  } catch { /* ignore */ }
}

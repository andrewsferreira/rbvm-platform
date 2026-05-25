// =============================================================================
// RBVM Platform — Global State Store
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const store = {
  // ── Navigation ───────────────────────────────────────────────────────────────
  view:     'dashboard',
  prevView: null,

  // ── Filters ──────────────────────────────────────────────────────────────────
  filterSev:    'ALL',
  filterStatus: 'ALL',
  filterQuery:  '',

  // ── Preferences ──────────────────────────────────────────────────────────────
  theme:    'dark',
  language: 'pt-BR',

  // ── Module tabs (all tracked centrally) ──────────────────────────────────────
  tabs: {
    OFT_TAB:     'overview',
    PATCH_TAB:   'campaigns',
    RPT_TAB:     'generate',
    RPT_TYPE:    'executive',
    BB_TAB:      'program',
    SBOM_TAB:    'overview',
    FP_TAB:      'queue',
    ASM_TAB:     'overview',
    WR_INC:      null,
    CJ_SEL:      null,
    ASM_CAT:     'ALL',
    ASM_EXPAND:  null,
    OFT_RT_EXP:  null,
    OFT_BB_EXP:  null,
    PATCH_CAMP_SEL: null,
    RPT_EV_SEL:  [],
  },

  // ── Mutable runtime data ──────────────────────────────────────────────────────
  auditAdded: [],
  ticketsCreated: [],
  rpHistory: [],
};

export function getTab(key)         { return store.tabs[key]; }
export function setTab(key, val)    { store.tabs[key] = val; }
export function resetTabs()         { Object.keys(store.tabs).forEach(k => { store.tabs[k] = Array.isArray(store.tabs[k]) ? [] : null; }); }

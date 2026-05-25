// =============================================================================
// RBVM Platform — i18n Engine
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

import { PT_BR } from '../i18n/pt-BR.js';
import { EN_US } from '../i18n/en-US.js';

const DICTIONARIES = { 'pt-BR': PT_BR, 'en-US': EN_US };

let _lang = 'pt-BR';

export function setLang(lang) {
  if (DICTIONARIES[lang]) { _lang = lang; }
}

export function getLang() { return _lang; }

/** Translate a key. Falls back to key itself if not found. */
export function t(key) {
  const dict = DICTIONARIES[_lang] || DICTIONARIES['pt-BR'];
  return dict[key] ?? DICTIONARIES['pt-BR'][key] ?? key;
}

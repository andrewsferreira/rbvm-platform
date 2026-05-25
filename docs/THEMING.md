# RBVM Platform — Theming

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Temas disponíveis

| Tema | `data-theme` | Descrição |
|---|---|---|
| Dark (padrão) | `dark` | Interface escura, enterprise, fundo `#0d0f14` |
| White | `white` | Interface clara, corporativa, fundo `#f1f5fb`, cards brancos |

---

## Como funciona

O tema é aplicado via atributo `data-theme` no elemento `<html>`:

```html
<html data-theme="dark">   <!-- dark (padrão) -->
<html data-theme="white">  <!-- white/light -->
```

As variáveis CSS em `src/styles/themes.css` definem os valores para cada tema:

```css
[data-theme="dark"]  { --bg: #0d0f14; --text: #e8eaf0; --accent: #4f7aff; }
[data-theme="white"] { --bg: #f1f5fb; --text: #1e293b; --accent: #3b5bff; }
```

---

## Como trocar de tema

**Via UI:** Settings → Tema da Interface → clicar em Dark ou White.

**Via código:**
```javascript
window.setTheme('white'); // ou 'dark'
```

**Internamente (app.js):**
```javascript
window.setTheme = theme => {
  document.documentElement.setAttribute('data-theme', theme);
  savePreference('theme', theme);
  render();
};
```

---

## Persistência

O tema escolhido é salvo em `localStorage` com a chave `rbvm_theme` e restaurado em cada carregamento da página por `initApp()`.

---

## Arquivos CSS

| Arquivo | Conteúdo |
|---|---|
| `src/styles/tokens.css` | Design tokens — fontes, espaçamentos, radius, z-index |
| `src/styles/themes.css` | Variáveis de cor por tema (dark/white) |
| `src/styles/layout.css` | App shell, topbar, sidebar, grid |
| `src/styles/components.css` | Cards, tabelas, botões, pills, modais, toasts |
| `src/styles/modules.css` | Estilos específicos de cada módulo |

---

## Como adicionar uma nova variável de tema

1. Adicionar em `src/styles/tokens.css` se for um token fixo (sem variação por tema).
2. Adicionar em `src/styles/themes.css` sob `[data-theme="dark"]` e `[data-theme="white"]` se variar por tema.
3. Usar via `var(--nome-da-variavel)` no CSS ou nas template strings JS.

# RBVM Platform — Architecture

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Por que a aplicação foi modularizada

A plataforma RBVM cresceu de um monolito de ~3.600 linhas em um único `index.html` para uma arquitetura modular com separação clara de responsabilidades. Isso foi necessário para:

- **Manutenção**: CSS e JS misturados em um arquivo único dificultam evolução.
- **Escalabilidade**: Novos módulos devem ser adicionados em seus próprios arquivos.
- **Clareza de produto**: Navegação por domínio de negócio, sem labels de sprint.
- **Percepção enterprise**: Código organizado transmite maturidade técnica.
- **Evolução futura**: Estrutura pronta para backend, auth, RBAC e integrações reais.

---

## Como o entrypoint funciona

```
index.html (42 linhas — shell mínimo)
  └── src/main.js (entrypoint ES Module)
        └── src/app.js (toda a lógica da aplicação)
              ├── src/config/navigation.js (config de nav)
              ├── src/config/i18n.js (engine de tradução)
              ├── src/state/persistence.js (localStorage)
              ├── src/data/*.js (dados mockados)
              └── src/utils/*.js (utilitários)
```

1. O browser carrega `index.html` que aplica CSS e dispara `src/main.js` como ES Module.
2. `main.js` importa `app.js`.
3. `app.js` importa todos os dados, utilitários, config e chama `initApp()`.
4. `initApp()` lê preferências do localStorage, aplica tema/idioma, monta o shell HTML em `#app` e renderiza a view inicial.

---

## Como os módulos são carregados

Todos os módulos (views) estão em `src/app.js` como funções JavaScript. O despacho é feito pelo mapa `M{}` na função `render()`:

```javascript
const M = { dashboard, threatintel, vulns, offensive, ... };
document.getElementById('main').innerHTML = (M[VIEW] || dashboard)();
```

**Dívida técnica**: Os módulos individuais ainda não foram extraídos para arquivos em `src/modules/`. A estrutura de pastas está criada e pronta para uma segunda fase de modularização progressiva.

---

## Como a navegação funciona

A navegação é configurada em `src/config/navigation.js` como um array de seções e itens. A sidebar é renderizada dinamicamente pela função `renderSidebar()` em `app.js`:

```javascript
NAVIGATION.map(section => `
  <div class="sb-lbl">${t(section.labelKey)}</div>
  ${section.items.map(item => `<div class="sb-it" onclick="setView('${item.id}')">...</div>`)}
`)
```

Rotas com alias (ex: `bugbounty` → view `offensive` com tab `bugbounty`) são resolvidas em `setView()` via `ROUTE_ALIASES`.

---

## Como o estado global funciona

O estado é mantido em variáveis JavaScript no escopo do módulo `app.js`:

- `VIEW` — view atual
- `FS`, `FST`, `FSQ` — filtros de severidade, status, busca
- `OFT_TAB`, `PATCH_TAB`, `RPT_TAB`, etc. — tabs ativos por módulo
- `AH`, `EXCS`, `FP_LOCAL`, `RPT_HISTORY` — dados mutáveis em runtime

O arquivo `src/state/store.js` define a estrutura esperada para eventual migração a um store formal.

---

## Como a persistência local funciona

`src/state/persistence.js` gerencia `localStorage` com:

- Versionamento de schema (`rbvm_schema_v`) — evita quebra por dados antigos.
- Chaves prefixadas (`rbvm_theme`, `rbvm_lang`, `rbvm_reports`, `rbvm_fp_records`).
- Funções: `loadPreferences()`, `savePreference(key, value)`, `resetAllPreferences()`.

---

## Como os temas funcionam

Ver `docs/THEMING.md`.

---

## Como o i18n funciona

Ver `docs/I18N.md`.

---

## Como adicionar novos módulos

1. Criar função `meuModulo()` em `src/app.js` que retorna uma string HTML.
2. Adicionar `meuModulo` ao mapa `M{}` em `render()`.
3. Adicionar item ao array `NAVIGATION` em `src/config/navigation.js`.
4. Adicionar chaves de tradução em `src/i18n/pt-BR.js` e `src/i18n/en-US.js`.
5. Adicionar rota hash em `HASH_ROUTES` e `HASH_TO_VIEW` em `navigation.js`.

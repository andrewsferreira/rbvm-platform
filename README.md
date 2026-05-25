# RBVM Platform

**Enterprise Vulnerability & Exposure Management**

> © 2026 Andrews Ferreira. Todos os direitos reservados.  
> Projeto proprietário. Reprodução ou uso sem autorização expressa é proibido.

---

## Visão Geral

O RBVM Platform é uma plataforma de gestão de vulnerabilidades e exposição de risco voltada para ambientes enterprise. Cobre o ciclo completo de segurança ofensiva e defensiva: da detecção de vulnerabilidades ao fechamento com evidência auditável.

**Stack**: SPA estática com JavaScript ES Modules · GitHub Pages · Zero backend

---

## Módulos (29 ao total)

| Domínio | Módulos |
|---|---|
| **Executive** | Dashboard · Exec Intelligence · Reports & Evidence |
| **Exposure Management** | Threat Intelligence · Attack Surface · Crown Jewels · Zero-day War Room |
| **Vulnerability Operations** | Vulnerabilities · Lifecycle · SLA · Smart Grouping · Patch · Metrics · Reclassification |
| **Application Security** | CI/CD Security · SBOM · Bug Bounty · False Positives |
| **Offensive Risk** | Offensive Findings · Red Team · Detection Gaps · Retest Queue |
| **Governance** | Assets · Suppliers · Compliance/GRC · Exceptions · Data Quality · Playbooks · Risk |
| **Platform** | Integrations · AI Agent · Communications · Settings |

---

## Estrutura de Pastas

```
rbvm-platform/
├── index.html                  ← Shell mínimo (42 linhas)
├── LICENSE
├── README.md
├── src/
│   ├── main.js                 ← Entrypoint ES Module
│   ├── app.js                  ← Toda a lógica da aplicação (views, render, state, actions)
│   ├── config/
│   │   ├── navigation.js       ← Config de navegação por domínio (sem labels de sprint)
│   │   └── i18n.js             ← Engine i18n + função t()
│   ├── state/
│   │   ├── store.js            ← Definição do estado global
│   │   └── persistence.js      ← localStorage helpers
│   ├── i18n/
│   │   ├── pt-BR.js            ← Traduções em português
│   │   └── en-US.js            ← Traduções em inglês
│   ├── modules/                ← Estrutura pronta para modularização progressiva
│   │   ├── executive/
│   │   ├── exposure/
│   │   ├── vulnerability-operations/
│   │   ├── application-security/
│   │   ├── offensive-risk/
│   │   ├── governance/
│   │   └── platform/
│   ├── data/                   ← 17 arquivos de dados mockados (~160KB)
│   │   ├── vulns.js · assets.js · trends.js · audit.js
│   │   ├── redteam.js · bugbounty.js · gaps.js
│   │   ├── patches.js · asm.js · sbom.js · fpw.js
│   │   ├── warroom.js · crownj.js · cicd.js
│   │   ├── suppliers.js · playbooks.js · integrations.js
│   ├── utils/
│   │   ├── scoring.js · sla.js · helpers.js · financial.js
│   └── styles/
│       ├── tokens.css          ← Design tokens (fontes, espaçamentos, z-index)
│       ├── themes.css          ← Dark / White theme (CSS variables)
│       ├── layout.css          ← App shell, topbar, sidebar, grid
│       ├── components.css      ← Cards, tabelas, botões, pills, modais
│       └── modules.css         ← Estilos específicos de módulos
└── docs/
    ├── ARCHITECTURE.md
    ├── MODULES.md
    ├── NAVIGATION.md
    ├── THEMING.md
    └── I18N.md
```

---

## Como rodar localmente

```bash
# Python (recomendado — sem instalação)
python3 -m http.server 8080

# Node.js
npx serve .

# Depois abrir: http://localhost:8080
```

> **Importante**: A aplicação usa ES Modules. Não funciona com `file://` — é necessário um servidor HTTP local.

---

## Como publicar no GitHub Pages

1. Push para branch `main`.
2. Ativar GitHub Pages em Settings → Pages → Source: main / (root).
3. Aguardar deploy (~1-2 min).
4. Acessar: `https://andrewsferreira.github.io/rbvm-platform/`

---

## Temas

| Tema | Como ativar |
|---|---|
| Dark (padrão) | Settings → Tema → Dark |
| White | Settings → Tema → White |

A preferência é salva em `localStorage` e restaurada a cada visita.

---

## Idiomas

| Idioma | Como ativar |
|---|---|
| Português (padrão) | Settings → Idioma → Português |
| English | Settings → Language → English |

A preferência é salva em `localStorage`.

---

## Como criar um novo módulo

1. Criar função `meuModulo()` em `src/app.js` que retorna HTML string.
2. Adicionar ao mapa `M{}` em `render()`.
3. Adicionar entrada em `NAVIGATION` em `src/config/navigation.js`.
4. Adicionar hash em `HASH_ROUTES` e `HASH_TO_VIEW`.
5. Adicionar traduções em `src/i18n/pt-BR.js` e `en-US.js`.

---

## Como adicionar uma tradução

1. Abrir `src/i18n/pt-BR.js`, adicionar: `'modulo.chave': 'Texto PT'`
2. Abrir `src/i18n/en-US.js`, adicionar: `'modulo.chave': 'Text EN'`
3. Usar nos templates: `${t('modulo.chave')}`

---

## Dados Mockados

⚠️ **Todos os dados são fictícios para fins de demonstração.**

- Domínios: `*.example.com`, `*.example.internal`
- E-mails: `*@corp.example`, `*@appsec.example`
- CVEs: misturam IDs reais (formato) com dados simulados
- Nenhum dado real de vulnerabilidade ou ativo está exposto

---

## Limitações Atuais

- Os 29 módulos ainda estão em `src/app.js` — a extração para arquivos individuais em `src/modules/` é a próxima fase de modularização.
- Não há backend, autenticação ou RBAC real.
- Dados são mockados e resetam a cada reload (exceto preferências de tema/idioma).

---

## Próximos Passos

- [ ] Extrair módulos individuais para `src/modules/`
- [ ] Lazy loading de módulos via dynamic import
- [ ] Backend REST API
- [ ] Autenticação (SSO/SAML)
- [ ] RBAC por perfil (CISO, Analista, DevSecOps, Auditor)
- [ ] Integrações reais (Jira, ServiceNow, Qualys, Tenable)
- [ ] Versão comercial B2B SaaS

---

## Propriedade Intelectual

Este projeto é propriedade exclusiva de **Andrews Ferreira**.  
Todos os direitos reservados © 2026.  
Proibida reprodução, distribuição ou uso comercial sem autorização prévia e expressa do autor.

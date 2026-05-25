# RBVM Platform — Navigation

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Estrutura de Navegação por Domínio

A navegação é organizada por domínio de produto — **sem labels de sprint ou linguagem técnica interna**.

| Seção | Módulos |
|---|---|
| **Executive** | Dashboard · Exec Intelligence · Reports & Evidence |
| **Exposure Management** | Threat Intelligence · Attack Surface · Crown Jewels · Zero-day War Room |
| **Vulnerability Operations** | Vulnerabilities · Remediation Lifecycle · SLA Management · Smart Grouping · Patch Management · Metrics & MTTR · Reclassification |
| **Application Security** | CI/CD Security · SBOM · Bug Bounty · False Positives |
| **Offensive Risk** | Offensive Findings · Red Team Findings · Control & Detection Gaps · Retest Queue |
| **Governance** | Assets · Suppliers · Compliance/GRC · Exceptions · Data Quality · Playbooks · Risk Analysis |
| **Platform** | Integrations · AI Agent · Communications · Settings |

---

## Arquivo de Configuração

**`src/config/navigation.js`** — fonte única de verdade para toda a navegação.

```javascript
export const NAVIGATION = [
  {
    section: 'executive',
    labelKey: 'nav.executive',
    items: [
      { id: 'dashboard', labelKey: 'nav.dashboard', icon: 'ti-layout-dashboard' },
      // ...
    ],
  },
  // ...
];
```

---

## Rotas Hash

| Módulo | Hash Route |
|---|---|
| Dashboard | `#/dashboard` |
| Exec Intelligence | `#/exec-intelligence` |
| Reports & Evidence | `#/reports-evidence` |
| Threat Intelligence | `#/threat-intelligence` |
| Attack Surface | `#/attack-surface` |
| Crown Jewels | `#/crown-jewels` |
| Zero-day War Room | `#/zero-day-war-room` |
| Vulnerabilities | `#/vulnerabilities` |
| Remediation Lifecycle | `#/remediation-lifecycle` |
| SLA Management | `#/sla-management` |
| Smart Grouping | `#/smart-grouping` |
| Patch Management | `#/patch-management` |
| CI/CD Security | `#/cicd-security` |
| SBOM | `#/sbom` |
| Bug Bounty | `#/bug-bounty` |
| False Positives | `#/false-positives` |
| Offensive Findings | `#/offensive-findings` |
| Red Team Findings | `#/red-team` |
| Control & Detection Gaps | `#/control-detection-gaps` |
| Retest Queue | `#/retest-queue` |
| Assets | `#/assets` |
| Suppliers | `#/suppliers` |
| Compliance/GRC | `#/compliance-grc` |
| Exceptions | `#/exceptions` |
| Data Quality | `#/data-quality` |
| Settings | `#/settings` |

---

## Route Aliases

Alguns itens de navegação são aliases que abrem uma view com uma tab específica pré-selecionada:

| Nav ID | View | Tab |
|---|---|---|
| `bugbounty` | `offensive` | `bugbounty` |
| `redteam` | `offensive` | `redteam` |
| `gaps` | `offensive` | `gaps` |
| `retestqueue` | `offensive` | `retest` |

---

## Como adicionar um item de navegação

1. Adicionar entrada no array `NAVIGATION` em `src/config/navigation.js`.
2. Adicionar `HASH_ROUTES[id]` e `HASH_TO_VIEW[hash]`.
3. Adicionar chaves `nav.labelKey` em `src/i18n/pt-BR.js` e `en-US.js`.
4. Criar a função de view correspondente em `src/app.js`.

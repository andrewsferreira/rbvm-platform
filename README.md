# RBVM Platform — Enterprise Vulnerability & Exposure Management

> **Enterprise Vulnerability & Exposure Management Platform powered by AI, risk-based prioritization, automated ticket orchestration, SLA governance, remediation validation and executive intelligence.**

---

## 🎯 Visão Geral

Plataforma corporativa de **Gestão de Vulnerabilidades Baseada em Risco** e **Continuous Threat Exposure Management (CTEM)**, projetada para ambientes de grande porte, regulados e com alta criticidade operacional.

A plataforma atua como **camada de inteligência, orquestração, governança e automação** acima de ferramentas como Tenable, Qualys, Rapid7, Veracode, Snyk, Wiz, Prisma Cloud, entre outras.

---

## ⚡ Funcionalidades Atuais (MVP v1)

- **Dashboard Executivo** — risco global, KEVs abertas, SLA vencidos, tendência
- **Gestão de Vulnerabilidades** — filtros, busca, detalhe completo, risk scoring multicritério
- **Reclassificação de Risco** — ajuste contextual por exposição, dados sensíveis, ambiente e controles
- **Gestão de SLA** — régua de cobrança, alertas preventivos, escalonamento automático
- **Análise de Risco** — scoring por ativo, área, framework e tendência histórica
- **Comunicados Automatizados** — templates por severidade e canal (Teams/Slack/e-mail)
- **Integrações** — painel de status de conectores (Tenable, Veracode, Snyk, GitHub Actions)
- **Agente IA (GenAI)** — Claude Sonnet com contexto real das vulnerabilidades ativas
- **Módulo de Exceções** — aceite de risco com aprovação, evidência e expiração
- **Gestão de Ativos** — inventário com owner, ambiente, criticidade e cobertura de scan

---

## 🧱 Arquitetura

```
rbvm-platform/
├── index.html              # Entry point — SPA completo
├── src/
│   ├── data/
│   │   ├── vulns.js        # Dataset de vulnerabilidades
│   │   ├── assets.js       # Inventário de ativos
│   │   └── integrations.js # Configuração de integrações
│   ├── modules/
│   │   ├── dashboard.js    # View: Dashboard Executivo
│   │   ├── vulns.js        # View: Vulnerabilidades
│   │   ├── assets.js       # View: Gestão de Ativos
│   │   ├── reclassify.js   # View: Reclassificação de Risco
│   │   ├── sla.js          # View: Gestão de SLA
│   │   ├── risk.js         # View: Análise de Risco
│   │   ├── comms.js        # View: Comunicados
│   │   ├── exceptions.js   # View: Exceções e Aceite de Risco
│   │   ├── integrations.js # View: Integrações
│   │   ├── agent.js        # View: Agente IA
│   │   └── settings.js     # View: Configurações
│   ├── utils/
│   │   ├── scoring.js      # Motor de Risk Scoring multicritério
│   │   ├── sla.js          # Lógica de SLA e escalonamento
│   │   ├── notify.js       # Motor de notificações
│   │   └── helpers.js      # Utilitários e formatação
│   └── styles/
│       └── main.css        # Design system completo
└── docs/
    ├── ARCHITECTURE.md
    ├── RISK_MODEL.md
    └── SLA_POLICY.md
```

---

## 🔧 Stack Técnica

| Camada | Tecnologia |
|--------|-----------|
| Frontend | HTML5 + CSS3 + JavaScript (ES Modules) |
| IA | Claude Sonnet 4 via Anthropic API |
| Ícones | Tabler Icons |
| Storage | LocalStorage (MVP) → API REST (roadmap) |
| Deploy | GitHub Pages / Nginx / Docker |

---

## 🚀 Como Executar

### Opção 1 — Direto no browser
Abra `index.html` em qualquer browser moderno. Sem dependências de build.

### Opção 2 — Servidor local
```bash
# Python
python3 -m http.server 8080

# Node
npx serve .
```

Acesse: `http://localhost:8080`

---

## 🗺️ Roadmap

| Fase | Status | Descrição |
|------|--------|-----------|
| MVP v1 | ✅ Concluído | Dashboard, Vulns, SLA, Agente IA |
| v1.1 | 🔄 Em andamento | Ativos, Exceções, Risk Scoring v2 |
| v1.2 | 📋 Planejado | Tickets Jira/ServiceNow (API real) |
| v1.3 | 📋 Planejado | Enriquecimento EPSS/KEV/NVD ao vivo |
| v2.0 | 📋 Planejado | Backend + persistência + RBAC |

---

## 📐 Frameworks e Referências

- NIST CSF 2.0 / SP 800-40 / SP 800-53
- CIS Controls v8
- OWASP Top 10 / ASVS / API Security / SAMM
- MITRE ATT&CK / CVE
- CVSS v3.1 e v4.0 / EPSS / CISA KEV
- PCI DSS 4.0 / ISO 27001:2022 / LGPD
- Resolução CMN 4.893/2021

---

## 📄 Licença

MIT — Uso corporativo, acadêmico e pessoal permitido.

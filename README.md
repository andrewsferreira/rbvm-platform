# RBVM Platform
### Enterprise Vulnerability & Exposure Management

> **Plataforma proprietária de Gestão de Vulnerabilidades Baseada em Risco, concebida, arquitetada e desenvolvida por Andrews Ferreira.**

🔗 **Demo:** [andrewsferreira.github.io/rbvm-platform](https://andrewsferreira.github.io/rbvm-platform)

---

## Autoria e Propriedade Intelectual

**RBVM Platform** é um projeto proprietário criado por **Andrews Ferreira**.

Este projeto representa uma plataforma conceitual e demonstrativa de **Enterprise Vulnerability & Exposure Management**, com foco em Risk-Based Vulnerability Management (RBVM), Continuous Threat Exposure Management (CTEM), automação de SLAs, orquestração de tickets, validação técnica de correção e inteligência executiva com IA generativa.

Todo o conteúdo deste repositório — código, design, arquitetura, fluxos, documentação, telas, lógica de produto e organização funcional — é protegido por direitos autorais.

O acesso público tem finalidade **exclusivamente demonstrativa e de portfólio profissional**.

Nenhuma permissão é concedida para copiar, modificar, redistribuir, revender, explorar comercialmente, incorporar em produto de terceiros ou criar trabalhos derivados sem autorização expressa do autor.

**© 2026 Andrews Ferreira. Todos os direitos reservados.**

> *RBVM Platform is a proprietary cybersecurity product concept created by Andrews Ferreira.*

---

## Disclaimer

Este MVP utiliza **dados mockados** exclusivamente para demonstração:
- Vulnerabilidades são exemplos públicos (CVEs) adaptados — não representam ambientes reais
- Ativos, owners (`@corp.example`), squads, fornecedores, valores financeiros e tickets são simulados
- A plataforma não está conectada a ambientes reais de produção
- Estimativas financeiras são apenas ilustrativas
- Qualquer integração real requer ambiente privado com controle de acesso adequado

---

## Visão Geral

A plataforma demonstra o ciclo completo de orquestração de vulnerabilidades:

```
Detectar → Normalizar → Enriquecer → Priorizar → Ticketar →
Cobrar → Escalar → Validar Tecnicamente → Evidenciar → Fechar → Reportar
```

### Diferencial: Criar ticket ≠ corrigido. Resolvido ≠ fechado. Validação técnica é obrigatória.

---

## Módulos (17 total)

| Categoria | Módulo | Descrição |
|-----------|--------|-----------|
| Análise | Dashboard Executivo | Exposição financeira, KEVs, SLA, pipeline RBVM |
| Análise | Threat Intelligence | CISA KEV, EPSS, exploits, MITRE ATT&CK |
| Análise | Métricas & MTTR | MTTR por time/severidade, KRIs, tendência 6 meses |
| Gestão | Vulnerabilidades | Score, EPSS, KEV, impacto BRL, filtros completos |
| Gestão | Ativos | Inventário com owner, EOL, PCI/LGPD scope |
| Gestão | Fornecedores | Supply chain Tier 1/2, assessments, SLA |
| Orquestração | **Remediation Lifecycle** | Jornada visual completa com audit trail |
| Orquestração | **Data Quality** | Indicadores de qualidade de dados |
| Orquestração | **Exec Intelligence** | Decisões pendentes, plano executivo |
| Orquestração | **Smart Grouping** | Agrupamento inteligente de tickets |
| Automação | Playbooks | Workflows automatizados por tipo de ameaça |
| Automação | Reclassificação | Ajuste contextual de score auditável |
| Automação | Exceções | Aceite de risco formal com aprovação |
| Automação | Gestão SLA | Escalonamento automático, MTTR, cobrança |
| Dev Sec | CI/CD Security | Gates, secrets, SAST/SCA/IaC/container |
| Governança | Compliance/GRC | NIST/PCI/ISO/LGPD/CMN 4.893 |
| Plataforma | Agente IA | Claude Sonnet + fontes rastreáveis + guardrails |

---

## Ciclo de Status (Remediation)

```
New → Ticket Created → In Progress → Resolved by Team
    → Awaiting Technical Validation → Rescan Requested
    → Validation Running → Fixed Confirmed → Closed with Evidence
                        ↘ Still Vulnerable → Reopened
```

---

## Arquitetura

```
rbvm-platform/
├── index.html          # SPA (1500+ linhas, 17 módulos)
├── LICENSE             # Licença proprietária
├── src/
│   ├── data/           # vulns, assets, cicd, suppliers, playbooks, trends, audit
│   └── utils/          # scoring, sla, helpers, financial
└── docs/
```

---

## Tecnologia

HTML5 + CSS3 + JavaScript ES Modules · Claude Sonnet 4 · Tabler Icons · localStorage · GitHub Pages

---

*© 2026 Andrews Ferreira. Todos os direitos reservados. Projeto proprietário. Acesso público apenas para fins demonstrativos.*

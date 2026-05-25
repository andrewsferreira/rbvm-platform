# RiskBridge

**Vulnerability & Exposure Management Command Center**

> © 2026 Andrews Ferreira. Todos os direitos reservados.
> Projeto proprietário. Reprodução ou uso sem autorização expressa é proibido.
> RiskBridge é um conceito proprietário de produto de cibersegurança.
> Demonstração pública apenas para fins de portfólio.

---

## O que é o RiskBridge

**RiskBridge** is a Vulnerability & Exposure Management Command Center designed to connect vulnerability scanners, AppSec, cloud, Red Team, Bug Bounty and remediation workflows into a risk-driven governance layer.

**PT-BR**: RiskBridge é um Centro de Comando para Gestão de Vulnerabilidades e Exposição, criado para conectar scanners, AppSec, cloud, Red Team, Bug Bounty e fluxos de remediação em uma camada de governança orientada a risco.

---

## Demo pública

🔗 **https://andrewsferreira.github.io/rbvm-platform/**

> Todos os dados são fictícios para fins de demonstração.
> Domínios: `*.example.com`, `*.example.internal`.
> Nenhum dado real de vulnerabilidade ou ativo está exposto.

---

## Módulos disponíveis na demo (29 módulos)

| Domínio | Módulos |
|---|---|
| **Executive** | Dashboard · Exec Intelligence · Reports & Evidence |
| **Exposure Management** | Threat Intelligence · Attack Surface · Crown Jewels · Zero-day War Room |
| **Vulnerability Operations** | Vulnerabilities · Lifecycle · SLA · Smart Grouping · Patch Management · Metrics · Reclassification |
| **Application Security** | CI/CD Security · SBOM · Bug Bounty · False Positives |
| **Offensive Risk** | Offensive Findings · Red Team · Detection Gaps · Retest Queue |
| **Governance** | Assets · Suppliers · Compliance/GRC · Exceptions · Data Quality · Playbooks · Risk Analysis |
| **Platform** | Integrations · AI Agent · Communications · Settings |

---

## Stack técnica

| Camada | Tecnologia |
|---|---|
| **Frontend** | Vanilla JS · ES Modules · HTML5 |
| **Styling** | CSS Variables · Dark/White themes |
| **Icons** | Tabler Icons |
| **Data** | Mock JSON files (no backend) |
| **Hosting (public)** | GitHub Pages |
| **Hosting (private)** | Vercel |
| **Auth (private)** | Supabase Auth (Magic Link + OAuth) |
| **Database (private)** | Supabase PostgreSQL (RLS) |

---

## RBVM como conceito técnico

O termo **RBVM** (Risk-Based Vulnerability Management) é usado internamente como referência técnica:

- **RBVM Engine** — Motor de cálculo de score de risco
- **RBVM Scoring Model** — Modelo de pontuação: CVSS + EPSS + KEV + contexto de negócio
- **RBVM Lifecycle** — Ciclo: Descoberta → Priorização → Remediação → Validação → Fechamento
- **RBVM Workflow** — Fluxo de automação de playbooks e escalonamento
- **Agente RBVM** — Agente de IA integrado à plataforma

> RBVM não é mais usado como nome de produto. O nome oficial é **RiskBridge**.

---

## Estrutura de repositórios

```
rbvm-platform (PÚBLICO — GitHub Pages)
├── Demo sanitizada completa
├── Dados 100% mockados
├── CSS e design system
└── Documentação arquitetural

riskbridge-app (PRIVADO — Vercel)
├── Aplicação completa com auth
├── Supabase Auth (Magic Link + OAuth)
├── Proteção de rotas internas
└── Deploy em Vercel
```

Ver: `docs/SEPARATION.md` para o plano completo de separação.

---

## Como rodar localmente

```bash
# Python (sem instalação)
python3 -m http.server 8080
# Abrir: http://localhost:8080

# Node.js
npx serve .
# Abrir: http://localhost:3000
```

> Requer servidor HTTP local — ES Modules não funcionam com `file://`.

---

## Documentação

| Documento | Descrição |
|---|---|
| `docs/ARCHITECTURE.md` | Arquitetura modular da aplicação |
| `docs/MODULES.md` | Catálogo dos 29 módulos |
| `docs/NAVIGATION.md` | Estrutura de navegação e rotas |
| `docs/THEMING.md` | Sistema de temas dark/white |
| `docs/I18N.md` | Internacionalização pt-BR / en-US |
| `docs/DEPLOYMENT.md` | Deploy público (GitHub Pages) e privado (Vercel) |
| `docs/AUTH.md` | Autenticação com Supabase |
| `docs/SEPARATION.md` | Plano de separação público/privado |

---

## Próximos passos (roadmap)

- [ ] **Fase 2**: Landing pública com CTAs (Request Access, Sign In)
- [ ] **Fase 3**: Auth guard no repo privado (Supabase + Vercel)
- [ ] **Fase 4**: Tabelas Supabase: profiles, access_requests + RLS
- [ ] **Fase 5**: Request Access flow com aprovação manual
- [ ] **Fase 6**: Branding consistente em todos os relatórios exportados
- [ ] **Fase 7**: RBAC por role (admin, ciso, analyst, developer, viewer)
- [ ] **Fase 8**: Domínio customizado `app.riskbridge.com`
- [ ] **Fase 9**: CI/CD pipeline com GitHub Actions → Vercel
- [ ] **Fase 10**: Edge Functions para lógica server-side sensível

---

## Limitações da demo pública

- Todos os dados são mockados e resetam a cada reload
- Sem persistência real (exceto preferências de tema/idioma em localStorage)
- Sem autenticação real
- Sem backend
- AI Agent simula respostas (não conecta a LLM real)
- Integrações mostram status mockado (sem API real conectada)

---

## Propriedade Intelectual

Este projeto é propriedade exclusiva de **Andrews Ferreira**.
**RiskBridge** é um conceito proprietário de produto de cibersegurança.
Todos os direitos reservados © 2026.
Proibida reprodução, distribuição ou uso comercial sem autorização prévia e expressa do autor.

**Contato**: Para parcerias, licensing ou acesso à versão privada, entre em contato via GitHub.

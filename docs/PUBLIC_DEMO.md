# RiskBridge — Public Demo Guide

© 2026 Andrews Ferreira. All rights reserved.

---

## Surface Strategy

| Surface | URL | Purpose |
|---|---|---|
| **Landing pública** | `andrewsferreira.github.io/rbvm-platform/` | Product page, portfolio |
| **Demo pública** | `andrewsferreira.github.io/rbvm-platform/demo.html` | Sanitized limited preview |
| **App privada** | `riskbridge-app.vercel.app/auth/` | Full platform, authorized access only |

---

## demo.html — O que é permitido

### ✅ Exibir (preview sanitizado)
- Executive Snapshot (5 cards demonstrativos)
- Remediation Lifecycle Preview (1 finding fictício, steps visuais)
- Offensive Risk Preview (1 finding com evidência redacted)
- Integration Preview (4 cards mockados: Tenable, Snyk, Jira, Teams)
- Executive Insight Preview (1 insight demonstrativo)
- Locked Features (cards com curiosidade controlada)
- Request Access CTA (modal demo — sem backend)

### ❌ Não exibir
- Sidebar completa com todos os módulos
- Datasets completos (VULNS, RT_FINDINGS, BB_FINDINGS, etc.)
- Red Team details completos (payloads, IPs, comandos)
- Bug Bounty triage workflow completo
- Crown Jewels completos com attack paths
- Reports & Evidence completo
- Settings interno
- Data Quality completo
- Smart Grouping completo
- Agente IA interativo
- Qualquer secret, token, API key, service_role
- Supabase connection
- Backend real

---

## Security Principles for Public Demo

1. **Não usar ofuscação como controle principal**: removemos o conteúdo, não apenas o escondemos.
2. **Zero secrets no frontend**: nem anon key, nem service_role, nem tokens.
3. **Zero conexão com backend**: a demo é 100% estática e autocontida.
4. **Dados 100% fictícios**: domínios `*.example.com`, CVEs com sufixo `-DEMO`.
5. **Offensive data sempre redacted**: `████████` onde haveria evidência técnica.

---

## Acesso à app privada

A aplicação completa está em: **https://riskbridge-app.vercel.app/auth/**

Autenticação: **Magic Link** (email sem senha)

Após login, o usuário é direcionado ao **Workspace** com módulos conforme sua permissão.

---

## Como testar localmente

```bash
# Landing + demo
cd rbvm-platform/
python3 -m http.server 8080
# → http://localhost:8080/        (landing)
# → http://localhost:8080/demo.html (public demo)

# App privada
cd riskbridge-app/
python3 -m http.server 8081
# → http://localhost:8081/auth/
# → http://localhost:8081/app/workspace (requires auth)
```

---

## Atualizar os CTAs

Se a URL da Vercel mudar, atualizar a constante no topo de `demo.html`:

```javascript
const PRIVATE_APP_URL = 'https://riskbridge-app.vercel.app/auth/';
// Alt: 'https://riskbridge-app.vercel.app/#/login' (if hash routing)
```

E em `index.html`, atualizar o href do botão "Sign In".

---

## Próximos passos recomendados

- [ ] Conectar Supabase Auth na app privada (Magic Link ativo)
- [ ] Validar auth flow end-to-end (login → workspace → módulos)
- [ ] Adicionar Google OAuth como alternativa
- [ ] Criar Request Access real (form → Supabase `access_requests` table)
- [ ] Configurar email templates no Supabase Auth
- [ ] Adicionar domínio customizado na Vercel

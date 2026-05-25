# RiskBridge — Public vs Private Separation Plan

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Estratégia de separação

### Repositório público (GitHub Pages) — `rbvm-platform`

**Propósito**: Portfolio showcase, landing pública, demo sanitizada

**URL**: `https://andrewsferreira.github.io/rbvm-platform/`

| Arquivo | Status | Motivo |
|---|---|---|
| `index.html` (landing) | ✅ Público | Marketing/portfolio |
| `demo.html` (demo limitada) | ✅ Público | Showcase sanitizado |
| `src/data/vulns.js` | ✅ Público | Dados 100% mockados |
| `src/data/*.js` | ✅ Público | Todos mockados/fictícios |
| `src/utils/*.js` | ✅ Público | Lógica não proprietária |
| `src/styles/*.css` | ✅ Público | Design system |
| `docs/*.md` | ✅ Público | Documentação arquitetural |
| `.env.example` | ✅ Público | Template sem secrets |
| `vercel.json` | ✅ Público | Config não sensível |
| `LICENSE` | ✅ Público | Licença proprietária |
| `README.md` | ✅ Público | Descrição do produto |

**O que NÃO vai no repositório público**:
- `.env`, `.env.local` (secrets reais)
- Chaves Supabase reais
- Dados de usuários reais
- Lógica de scoring proprietária avançada
- Módulos internos completos (quando houver dados reais)

---

### Repositório privado (Vercel) — `riskbridge-app`

**Propósito**: Aplicação completa com auth e dados reais

**URL**: `https://riskbridge.vercel.app` (ou domínio customizado)

**Estrutura**:
```
riskbridge-app/ (PRIVADO)
├── index.html          ← Landing (idêntica ao público)
├── auth/
│   ├── index.html      ← Shell de auth
│   ├── login.js        ← Supabase Magic Link + OAuth
│   └── request-access.js
├── app/
│   ├── index.html      ← App shell (PROTEGIDA)
│   ├── guard.js        ← Auth guard
│   └── main.js         ← Todos os módulos (do repo público)
├── src/                ← Cópia do src/ público
├── supabase/
│   ├── migrations/
│   └── functions/
├── .env.example        ← Template
├── .env.local          ← (NO .gitignore — NUNCA commitar)
└── vercel.json
```

---

## Plano de execução faseado

### Fase 1 — Rebranding (CONCLUÍDO)
- [x] "RBVM Platform" → "RiskBridge" em todos os lugares visíveis
- [x] RBVM mantido como referência técnica
- [x] Footer proprietário atualizado
- [x] README atualizado

### Fase 2 — Landing pública (PRÓXIMO PASSO — requer confirmação)
Criar `landing.html` ou transformar `index.html` em landing com:
- Hero com RiskBridge branding
- Descrição do produto
- Features highlights
- CTA "Request Access" e "Sign In"
- Link para "View Demo →"
- Footer proprietário

> ⚠️ Esta fase substitui o `index.html` atual (demo completa) por uma landing.
> A demo completa passa para `demo.html` ou URL diferente.
> **Aguarda confirmação antes de executar.**

### Fase 3 — Auth guard básico (PRÓXIMO PASSO — requer repo privado)
1. Criar repositório privado `riskbridge-app`
2. Copiar todos os arquivos do repo público
3. Adicionar `app/guard.js` com Supabase Auth
4. Configurar redirect: não autenticado → `/auth/login`
5. Deploy na Vercel

### Fase 4 — Supabase integration
1. Criar projeto no Supabase
2. Executar migrations (profiles, access_requests)
3. Configurar RLS
4. Conectar auth flow
5. Testar com conta demo

### Fase 5 — Request Access flow
1. Criar `auth/request-access.html`
2. Formulário: nome, email, empresa, cargo, use case
3. Salvar em `access_requests` no Supabase
4. Email de confirmação automático
5. Interface admin para aprovar/rejeitar

---

## Decisão a tomar

> Antes de executar a Fase 2, confirmar:
>
> **Opção A**: Transformar o `index.html` atual em landing + demo em `/demo`
> - Prós: URL principal limpa, produto bem apresentado
> - Contras: Demo atual sai do root URL
>
> **Opção B**: Manter demo completa no root + adicionar landing como `/landing.html`
> - Prós: Demo mantida no mesmo URL
> - Contras: Landing não é o primeiro impacto
>
> **Opção C**: Criar branch `landing` no GitHub e configurar Pages para servir a landing da branch `main` e a demo da branch `demo`
> - Prós: Separação limpa sem alterar URLs
> - Contras: Requer configuração adicional de Pages


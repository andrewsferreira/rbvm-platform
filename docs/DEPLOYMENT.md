# RiskBridge — Deployment Guide

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Arquitetura de publicação

```
┌─────────────────────────────────────────────────────────────┐
│  PÚBLICO (GitHub Pages)                                      │
│  github.com/andrewsferreira/rbvm-platform                   │
│                                                             │
│  / → Landing page RiskBridge                               │
│  /demo → Demo sanitizada (módulos limitados)               │
│  Sem auth · Sem módulos internos completos                  │
└─────────────────────────────────────────────────────────────┘
                          │ CTA: Sign In / Request Access
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  PRIVADO (Vercel + Supabase)                                │
│  riskbridge.vercel.app                                      │
│                                                             │
│  / → Landing (redirect se autenticado → /app/dashboard)    │
│  /auth/login → Login com Supabase Auth                     │
│  /auth/request-access → Formulário de acesso               │
│  /app/* → Todos os módulos internos (auth guard)           │
└─────────────────────────────────────────────────────────────┘
```

---

## Deploy público (GitHub Pages)

O deploy público acontece automaticamente via GitHub Actions ao fazer push na branch `main`.

**Configuração**:
1. Repositório: público
2. Settings → Pages → Source: `main` / `(root)`
3. URL: `https://andrewsferreira.github.io/rbvm-platform/`

**O que fica público**:
- Landing page com branding RiskBridge
- Demo sanitizada com dados mockados (sem lógica completa)
- CTA para Request Access e Sign In
- Documentação pública

**O que NÃO fica público**:
- Módulos internos completos
- Auth logic
- Supabase credentials
- Lógica de scoring proprietária detalhada

---

## Deploy privado (Vercel)

### Pré-requisitos
- Conta Vercel (vercel.com)
- Projeto Supabase criado
- Node.js ≥ 18

### Passos

```bash
# 1. Clonar o repositório PRIVADO
git clone git@github.com:andrewsferreira/riskbridge-app.git
cd riskbridge-app

# 2. Instalar Vercel CLI
npm install -g vercel

# 3. Login na Vercel
vercel login

# 4. Configurar variáveis de ambiente
cp .env.example .env.local
# Editar .env.local com as credenciais reais do Supabase

# 5. Deploy de preview
vercel

# 6. Deploy de produção
vercel --prod
```

### Variáveis de ambiente na Vercel

No dashboard da Vercel, configurar em:
`Project → Settings → Environment Variables`

| Variável | Valor | Escopo |
|---|---|---|
| `VITE_SUPABASE_URL` | URL do projeto Supabase | All |
| `VITE_SUPABASE_ANON_KEY` | Anon key (segura para frontend) | All |
| `VITE_APP_ENV` | `production` | Production |
| `VITE_ENABLE_MOCK_DATA` | `true` (demo) ou `false` (produção real) | All |

> **NUNCA** adicionar `SUPABASE_SERVICE_ROLE_KEY` a variáveis do frontend.
> Usar apenas em Edge Functions com escopo servidor.

---

## Estrutura do repositório privado

```
riskbridge-app/
├── index.html              ← Landing page pública
├── vercel.json             ← Configuração de rotas Vercel
├── .env.example            ← Template de variáveis
├── .gitignore              ← Inclui .env.local, .env
│
├── auth/
│   ├── index.html          ← Auth shell (login, request-access)
│   ├── login.js            ← Supabase Auth login flow
│   └── request-access.js   ← Formulário de acesso
│
├── app/
│   ├── index.html          ← App shell (protegida por auth guard)
│   ├── guard.js            ← Auth guard — redireciona se não autenticado
│   └── main.js             ← App principal (todos os módulos)
│
├── src/
│   ├── data/               ← Dados mockados (mesmos do repo público)
│   ├── utils/              ← Utilitários
│   ├── config/             ← Navegação, i18n, routes
│   └── styles/             ← CSS modular
│
├── supabase/
│   ├── migrations/         ← SQL migrations
│   │   ├── 001_profiles.sql
│   │   ├── 002_access_requests.sql
│   │   └── 003_rls_policies.sql
│   └── functions/          ← Edge Functions (se necessário)
│
└── docs/
    ├── DEPLOYMENT.md       ← Este arquivo
    ├── AUTH.md             ← Guia de autenticação
    └── ARCHITECTURE.md     ← Arquitetura do sistema
```

---

## Supabase — Setup inicial

```sql
-- Executar no SQL Editor do Supabase

-- 1. Profiles (estende auth.users)
CREATE TABLE profiles (
  id UUID REFERENCES auth.users(id) PRIMARY KEY,
  full_name TEXT,
  company TEXT,
  role TEXT DEFAULT 'analyst',
  plan TEXT DEFAULT 'demo',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Access Requests
CREATE TABLE access_requests (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT NOT NULL,
  full_name TEXT,
  company TEXT,
  reason TEXT,
  status TEXT DEFAULT 'pending',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users see own profile" ON profiles
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users update own profile" ON profiles
  FOR UPDATE USING (auth.uid() = id);
```

---

## .gitignore recomendado

```gitignore
# Secrets — NUNCA commitar
.env
.env.local
.env.production
.env.*.local

# Vercel
.vercel/

# Node
node_modules/
dist/
build/

# OS
.DS_Store
Thumbs.db
```

---

## Domínio customizado (opcional)

Para usar `app.riskbridge.com`:

1. Vercel → Project → Settings → Domains → Add `app.riskbridge.com`
2. No DNS: adicionar `CNAME app → cname.vercel-dns.com`
3. Atualizar `VITE_AUTH_REDIRECT_URL` para `https://app.riskbridge.com/app/dashboard`
4. Adicionar URL no Supabase Auth → URL Configuration → Redirect URLs

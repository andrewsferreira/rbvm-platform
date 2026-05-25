# RiskBridge — Authentication & Authorization

© 2026 Andrews Ferreira. Todos os direitos reservados.

---

## Visão geral

```
Usuário → Landing → Login → Supabase Auth → JWT → App Shell → Auth Guard → Módulos
                         ↑
                   Request Access → Email de aprovação → Convite
```

---

## Auth Guard

O auth guard (`app/guard.js`) verifica a sessão Supabase antes de renderizar qualquer módulo interno.

```javascript
// app/guard.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
);

export async function guardRoute() {
  const { data: { session }, error } = await supabase.auth.getSession();

  if (!session) {
    // Não autenticado → redirecionar para login
    const currentPath = window.location.pathname + window.location.hash;
    const redirect = encodeURIComponent(currentPath);
    window.location.replace(`/auth/login?redirect=${redirect}`);
    return null;
  }

  return session;
}

// Listener para mudanças de sessão
supabase.auth.onAuthStateChange((event, session) => {
  if (event === 'SIGNED_OUT') {
    window.location.replace('/auth/login');
  }
  if (event === 'TOKEN_REFRESHED') {
    console.info('[RiskBridge] Token refreshed');
  }
});
```

---

## Login Flow

```javascript
// auth/login.js
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Magic Link (passwordless — recomendado para B2B)
async function loginWithMagicLink(email) {
  const { error } = await supabase.auth.signInWithOtp({
    email,
    options: {
      emailRedirectTo: `${window.location.origin}/app/dashboard`,
    },
  });
  if (error) throw error;
  return 'Email enviado — verifique sua caixa de entrada';
}

// OAuth (Google, GitHub — opcional)
async function loginWithGoogle() {
  const { error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/app/dashboard`,
    },
  });
  if (error) throw error;
}

// Logout
async function logout() {
  await supabase.auth.signOut();
  window.location.replace('/auth/login');
}
```

---

## Rotas públicas vs. protegidas

| Rota | Tipo | Descrição |
|---|---|---|
| `/` | Pública | Landing page RiskBridge |
| `/demo` | Pública | Demo sanitizada (dados mockados) |
| `/auth/login` | Pública | Tela de login |
| `/auth/request-access` | Pública | Formulário de acesso |
| `/app/dashboard` | **Protegida** | Dashboard principal |
| `/app/*` | **Protegida** | Todos os módulos internos |

---

## Supabase — Tabelas e RLS

### profiles

```sql
CREATE TABLE profiles (
  id UUID REFERENCES auth.users(id) ON DELETE CASCADE PRIMARY KEY,
  full_name TEXT,
  company TEXT,
  job_title TEXT,
  role TEXT DEFAULT 'analyst' CHECK (role IN ('admin', 'ciso', 'analyst', 'developer', 'viewer')),
  plan TEXT DEFAULT 'demo' CHECK (plan IN ('demo', 'pro', 'enterprise')),
  avatar_url TEXT,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- RLS
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own profile"
  ON profiles FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  USING (auth.uid() = id);

-- Auto-criar profile ao registrar
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO profiles (id, full_name, avatar_url)
  VALUES (
    NEW.id,
    NEW.raw_user_meta_data->>'full_name',
    NEW.raw_user_meta_data->>'avatar_url'
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();
```

### access_requests

```sql
CREATE TABLE access_requests (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email TEXT NOT NULL,
  full_name TEXT NOT NULL,
  company TEXT,
  job_title TEXT,
  use_case TEXT,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by UUID REFERENCES auth.users(id),
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Qualquer um pode inserir (formulário público)
-- Apenas admins podem visualizar e atualizar
ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can submit access request"
  ON access_requests FOR INSERT
  WITH CHECK (true);

CREATE POLICY "Only admins can view requests"
  ON access_requests FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM profiles
      WHERE id = auth.uid() AND role = 'admin'
    )
  );
```

---

## Permissões por role

| Role | Módulos acessíveis | Ações permitidas |
|---|---|---|
| `viewer` | Dashboard, Vulns, SLA | Somente leitura |
| `analyst` | Todos exceto Settings admin | Criar tickets, comentar |
| `developer` | Vulns, CI/CD, SBOM, Lifecycle | Atualizar status próprio |
| `ciso` | Todos | Ver relatórios executivos |
| `admin` | Todos | Configurar plataforma, aprovar acessos |

---

## Segurança — checklist

- [ ] `SUPABASE_SERVICE_ROLE_KEY` nunca no frontend
- [ ] RLS ativo em todas as tabelas
- [ ] JWT TTL configurado (padrão Supabase: 1h)
- [ ] Refresh token rotation ativo
- [ ] Redirect URLs configuradas no Supabase (sem wildcards em prod)
- [ ] HTTPS obrigatório (Vercel enforça automaticamente)
- [ ] Rate limiting no login (Supabase enforça)
- [ ] Logs de auth monitorados

---

## Request Access Flow

```
1. Usuário acessa /auth/request-access
2. Preenche: nome, email, empresa, cargo, caso de uso
3. Dados salvos em access_requests (status: pending)
4. Admin recebe email (Supabase webhook ou cron)
5. Admin aprova → envia invite via Supabase Admin API
6. Usuário recebe magic link → acessa /app/dashboard
```

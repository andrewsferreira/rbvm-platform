// =============================================================================
// RBVM Platform — CI/CD Security Findings
// =============================================================================

export const CICD_FINDINGS = [
  // ── SECRETS ───────────────────────────────────────────────────────────────
  { id:'CICD-SEC-001', repo:'corp/backend-api',    pipeline:'build-prod',    type:'secret',    tool:'GitHub Secret Scanning', sev:'CRITICAL', title:'AWS_ACCESS_KEY_ID válida exposta em commit',   blocking:true,  status:'open',     pr:'PR-842',  branch:'feature/auth-refactor', created:'2024-05-22', env:'development', detail:'Chave ativa detectada — revogar imediatamente no AWS IAM e rotacionar.' },
  { id:'CICD-SEC-002', repo:'corp/data-pipeline',  pipeline:'deploy-stg',    type:'secret',    tool:'Gitleaks',               sev:'HIGH',     title:'POSTGRES_PASSWORD em arquivo de config',       blocking:true,  status:'open',     pr:'PR-801',  branch:'main',                  created:'2024-05-21', env:'staging',      detail:'Senha de banco em texto plano. Migrar para Vault ou Secret Manager.' },
  { id:'CICD-SEC-003', repo:'corp/mobile-app',     pipeline:'ci-checks',     type:'secret',    tool:'TruffleHog',             sev:'HIGH',     title:'Firebase Service Account key em repositório',  blocking:true,  status:'resolved', pr:'PR-789',  branch:'hotfix-push',           created:'2024-05-19', env:'development', detail:'Chave removida e rotacionada. Monitorar acesso ao Firebase.' },

  // ── SAST ──────────────────────────────────────────────────────────────────
  { id:'CICD-SAST-001', repo:'corp/payment-api',   pipeline:'security-scan', type:'sast',      tool:'Semgrep',                sev:'HIGH',     title:'SQL Injection em endpoint /orders',            blocking:true,  status:'open',     pr:'PR-850',  branch:'feat/order-search',     created:'2024-05-22', env:'development', detail:'Concatenação direta de input em query SQL sem parametrização.' },
  { id:'CICD-SAST-002', repo:'corp/user-service',  pipeline:'code-quality',  type:'sast',      tool:'SonarQube',              sev:'MEDIUM',   title:'Deserialização insegura em UserController',    blocking:false, status:'open',     pr:null,      branch:'main',                  created:'2024-05-18', env:'production',  detail:'Objeto desserializado sem validação de tipo. Pode levar a RCE.' },
  { id:'CICD-SAST-003', repo:'corp/admin-panel',   pipeline:'pr-check',      type:'sast',      tool:'GitHub Advanced Security',sev:'HIGH',     title:'Path traversal em file upload handler',        blocking:true,  status:'open',     pr:'PR-835',  branch:'feat/document-upload',  created:'2024-05-20', env:'development', detail:'Validação insuficiente do nome do arquivo permite acesso a diretórios.' },

  // ── SCA / DEPENDÊNCIAS ────────────────────────────────────────────────────
  { id:'CICD-SCA-001', repo:'corp/frontend',       pipeline:'sca-scan',      type:'sca',       tool:'Snyk',                   sev:'CRITICAL', title:'lodash@4.17.15 — Prototype Pollution (CVE-2021-23337)', blocking:true, status:'open', pr:'PR-820', branch:'main', created:'2024-05-15', env:'production', detail:'Dependência direta com exploit público. Atualizar para lodash@4.17.21+.' },
  { id:'CICD-SCA-002', repo:'corp/backend-api',    pipeline:'sca-scan',      type:'sca',       tool:'Dependabot',             sev:'HIGH',     title:'axios@0.21.1 — SSRF via URL redirection',     blocking:false, status:'open',     pr:null,      branch:'main',                  created:'2024-05-10', env:'production',  detail:'Dependência indireta. Atualizar para axios@1.6.0+.' },
  { id:'CICD-SCA-003', repo:'corp/ml-service',     pipeline:'ci',            type:'sca',       tool:'Snyk',                   sev:'MEDIUM',   title:'PyYAML@5.4 — arbitrary code via load()',       blocking:false, status:'open',     pr:null,      branch:'main',                  created:'2024-05-12', env:'production',  detail:'Usar yaml.safe_load() ou atualizar para PyYAML@6.0+.' },
  { id:'CICD-SCA-004', repo:'corp/data-pipeline',  pipeline:'sca-scan',      type:'sca',       tool:'Snyk',                   sev:'HIGH',     title:'numpy@1.22.0 — Buffer Overflow',               blocking:false, status:'resolved', pr:null,      branch:'main',                  created:'2024-05-01', env:'production',  detail:'Atualizado para numpy@1.26.0. Rescan confirmou correção.' },

  // ── IaC ───────────────────────────────────────────────────────────────────
  { id:'CICD-IAC-001', repo:'corp/infra-tf',       pipeline:'tf-plan',       type:'iac',       tool:'Checkov',                sev:'HIGH',     title:'S3 bucket sem Block Public Access',            blocking:true,  status:'open',     pr:'PR-815',  branch:'feat/new-bucket',       created:'2024-05-20', env:'production',  detail:'Checkov CKV_AWS_53 — habilitar Block Public Access em todos os buckets.' },
  { id:'CICD-IAC-002', repo:'corp/infra-tf',       pipeline:'tf-plan',       type:'iac',       tool:'tfsec',                  sev:'MEDIUM',   title:'EC2 sem IMDSv2 obrigatório',                   blocking:false, status:'open',     pr:null,      branch:'main',                  created:'2024-05-15', env:'production',  detail:'Habilitar aws_ec2_instance.metadata_options.http_tokens = required.' },
  { id:'CICD-IAC-003', repo:'corp/k8s-manifests',  pipeline:'k8s-validate',  type:'iac',       tool:'KICS',                   sev:'HIGH',     title:'Container rodando como root (runAsNonRoot: false)', blocking:true, status:'open', pr:'PR-809', branch:'feat/new-service', created:'2024-05-19', env:'production', detail:'Definir securityContext.runAsNonRoot: true em todos os containers.' },

  // ── CONTAINER ─────────────────────────────────────────────────────────────
  { id:'CICD-CTR-001', repo:'corp/api-gateway',    pipeline:'build-image',   type:'container', tool:'Trivy',                  sev:'CRITICAL', title:'python:3.9-slim — 14 CVEs (3 críticas)',      blocking:true,  status:'open',     pr:null,      branch:'main',                  created:'2024-05-17', env:'production',  detail:'Atualizar para python:3.12-slim. CVE-2023-27043, CVE-2024-0450, CVE-2023-24329.' },
  { id:'CICD-CTR-002', repo:'corp/worker-service', pipeline:'build-image',   type:'container', tool:'Grype',                  sev:'HIGH',     title:'ubuntu:20.04 — openssl vulnerável',           blocking:true,  status:'open',     pr:null,      branch:'main',                  created:'2024-05-14', env:'production',  detail:'Rebuild com ubuntu:22.04 ou alpine:3.19. OpenSSL atualizado nessas bases.' },
];

export const PIPELINE_GATES = [
  { repo:'corp/payment-api',  gates:['SAST','SCA','Secret Scan'],  status:'blocked',  reason:'SQL Injection detectado (CICD-SAST-001)', last_run:'2024-05-22 09:15', env:'production' },
  { repo:'corp/backend-api',  gates:['SAST','SCA','Secret Scan','Container'],  status:'blocked', reason:'AWS Key exposta (CICD-SEC-001)', last_run:'2024-05-22 08:30', env:'production' },
  { repo:'corp/frontend',     gates:['SAST','SCA'],                status:'blocked',  reason:'lodash Prototype Pollution (CICD-SCA-001)', last_run:'2024-05-22 07:45', env:'production' },
  { repo:'corp/infra-tf',     gates:['IaC Scan','Policy Check'],   status:'blocked',  reason:'S3 sem Block Public Access (CICD-IAC-001)', last_run:'2024-05-22 06:00', env:'production' },
  { repo:'corp/user-service', gates:['SAST','SCA','Secret Scan'],  status:'passing',  reason:'',  last_run:'2024-05-22 09:00', env:'production' },
  { repo:'corp/admin-panel',  gates:['SAST','SCA','Secret Scan'],  status:'warning',  reason:'Path traversal (CICD-SAST-003) — aprovação manual pendente', last_run:'2024-05-22 08:00', env:'staging' },
  { repo:'corp/ml-service',   gates:['SCA','Container'],           status:'warning',  reason:'PyYAML vulnerável (CICD-SCA-003)', last_run:'2024-05-21 22:00', env:'production' },
  { repo:'corp/mobile-app',   gates:['SAST','SCA','Secret Scan'],  status:'passing',  reason:'',  last_run:'2024-05-22 07:00', env:'production' },
];

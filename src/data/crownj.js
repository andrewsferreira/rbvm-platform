// =============================================================================
// RBVM Platform — Crown Jewels & Attack Path Analysis
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const CROWN_JEWELS = [
  {
    id:'CJ-001', name:'Active Directory — Domain Controllers',
    category:'Identidade & Acesso', icon:'ti-users-group', color:'#ff4c4c',
    description:'Comprometer os DCs significa comprometer 100% das identidades, GPOs e acessos da organização. Ponto de controle central de toda autenticação.',
    asset:'active-directory-prod', protection_score:62, open_vulns:1, vuln_ids:['AD-2024-001'],
    blast_radius:['~2.400 identidades corporativas afetadas','Todas as GPOs e políticas de segurança','Todos os servidores Windows-domain joined','Sistemas integrados via LDAP/Kerberos/RADIUS','Certificados ADCS e autenticação de rede'],
    attack_paths:[{
      id:'AP-001', name:'Kerberoasting → Domain Admin', difficulty:'medium', epss_like:0.72,
      steps:[
        {label:'Acesso Inicial',  detail:'Phishing / cred. vazada', type:'entry'},
        {label:'Domain User',     detail:'Conta sem privilégio',    type:'node'},
        {label:'Kerberoast',      detail:'T1558.003 — TGS de SPN',  type:'technique'},
        {label:'Service Account', detail:'Hash crack offline',       type:'node'},
        {label:'Domain Admin',    detail:'DCSync → all hashes',      type:'node'},
        {label:'Crown Jewel',     detail:'Domínio comprometido',     type:'target'},
      ],
      mitre:['T1558.003','T1003.006','TA0004'],
      gaps:['gMSA não implementado','AES-256 não obrigatório','SPNs desnecessários ativos'],
    }],
    recommendations:['Implementar gMSA para todas as service accounts','Obrigar AES-256 no Kerberos (desabilitar RC4)','Remover SPNs desnecessários — auditar com Bloodhound','Ativar Protected Users Security Group para contas privilegiadas','Habilitar Credential Guard nos DCs'],
  },
  {
    id:'CJ-002', name:'Core Banking System',
    category:'Negócio Crítico', icon:'ti-building-bank', color:'#ff8c38',
    description:'Processamento de transações financeiras. Downtime ou comprometimento impacta diretamente operações e obrigações regulatórias BACEN/CMN 4.893.',
    asset:'app-legacy-payments', protection_score:55, open_vulns:1, vuln_ids:['SCA-2024-LOG4J'],
    blast_radius:['100% das transações financeiras diárias (R$ ~2B/dia)','Dados de ~2M clientes PCI DSS em escopo','Obrigações regulatórias BACEN — risco de intervenção','Integração com ISPB, SPB e câmaras de compensação','Multa BACEN estimada > R$ 10M + dano reputacional'],
    attack_paths:[{
      id:'AP-002', name:'Log4j RCE → Core Banking DB', difficulty:'high', epss_like:0.86,
      steps:[
        {label:'Acesso Inicial',  detail:'JNDI payload via input',    type:'entry'},
        {label:'RCE via Log4j',   detail:'T1190 — payments app',      type:'technique'},
        {label:'Foothold DMZ',    detail:'Shell reverso interno',      type:'node'},
        {label:'Lateral Move',    detail:'T1021 — creds em memória',   type:'technique'},
        {label:'DB Admin',        detail:'Banco de pagamentos',         type:'node'},
        {label:'Crown Jewel',     detail:'PCI data + fraude',          type:'target'},
      ],
      mitre:['T1190','T1021','T1078','TA0010'],
      gaps:['Log4j 1.x EOL — sem patch disponível','Segmentação de rede insuficiente entre DMZ e DB','Credenciais de serviço sem rotação'],
    }],
    recommendations:['URGENTE: migrar Log4j 1.x → 2.23.1+ (SCA-2024-LOG4J)','Micro-segmentação entre DMZ de aplicação e DB layer','Rotacionar credenciais de serviço trimestralmente','Monitorar queries SQL anômalas via SIEM (UBA)','Implementar DAM (Database Activity Monitoring)'],
  },
  {
    id:'CJ-003', name:'Secrets Vault — HashiCorp',
    category:'Infraestrutura Crítica', icon:'ti-lock', color:'#f0c040',
    description:'Centraliza todos os secrets, certificados e credenciais de produção. Comprometimento concede acesso imediato a todos os sistemas integrados.',
    asset:'secrets-vault-prod', protection_score:78, open_vulns:0, vuln_ids:[],
    blast_radius:['1.200+ secrets de produção exfiltráveis em segundos','Chaves de API AWS/Azure/GCP e todos os cloud accounts','Certificados TLS de todos os 200+ serviços internos','Credenciais de banco de dados de produção','Tokens de service accounts e automações críticas'],
    attack_paths:[{
      id:'AP-003', name:'AWS Key Exposta → Vault Admin', difficulty:'medium', epss_like:0.91,
      steps:[
        {label:'Secret Exposto',  detail:'AWS Key em repo GitHub',    type:'entry'},
        {label:'AWS API Access',  detail:'T1552.001 — cred válida',   type:'technique'},
        {label:'IAM Escalation',  detail:'T1078.004 — assume-role',   type:'technique'},
        {label:'Vault Token',     detail:'Admin token via AWS auth',   type:'node'},
        {label:'Crown Jewel',     detail:'Todos os secrets dump',      type:'target'},
      ],
      mitre:['T1552.001','T1078.004','TA0006'],
      gaps:['AWS Key exposta em repo público (CICD-2024-001 — ainda aberto)','MFA não habilitado na IAM role do Vault','Vault audit log sem alertas em tempo real'],
    }],
    recommendations:['CRÍTICO: revogar e rotacionar AWS Key do CICD-2024-001','Habilitar MFA em todas as IAM roles com acesso ao Vault','Reduzir TTL dos tokens para máximo 1 hora','Configurar alertas para bulk-read de secrets no Vault audit log','Implementar break-glass procedure para emergências'],
  },
  {
    id:'CJ-004', name:'PKI — Certificate Authority Interna',
    category:'Criptografia & Confiança', icon:'ti-certificate', color:'#a084ff',
    description:'Emite e revoga certificados para toda a infraestrutura. Comprometimento permite forjar identidades e interceptar tráfego criptografado (MITM em escala).',
    asset:'pki-ca-root', protection_score:84, open_vulns:0, vuln_ids:[],
    blast_radius:['800+ certificados TLS internos forjáveis','Autenticação mútua de todos os microserviços','Certificados de code signing comprometidos','VPN corporativa e autenticação 802.1x','Integração AD/ADCS — acesso root ao domínio via PKINIT'],
    attack_paths:[{
      id:'AP-004', name:'AD Compromise → ADCS ESC1 Abuse', difficulty:'high', epss_like:0.55,
      steps:[
        {label:'Domain User',    detail:'Acesso inicial ao AD',       type:'entry'},
        {label:'ADCS Enum',      detail:'Certipy — templates vuln',   type:'technique'},
        {label:'ESC1 Exploit',   detail:'T1649 — cert como DA',       type:'technique'},
        {label:'PKINIT Auth',    detail:'Autenticação via cert',       type:'node'},
        {label:'Crown Jewel',    detail:'CA raiz comprometida',        type:'target'},
      ],
      mitre:['T1649','T1558','TA0006'],
      gaps:['Templates ADCS não auditados desde 2023','ESC1 não detectado no último pentest','Nenhuma alerta de certificate request anômalo no SIEM'],
    }],
    recommendations:['Auditar templates ADCS com Certipy agora','Desabilitar enrollment irrestrito no template "User"','Implementar CA issuance policy restritiva por tipo de certificado','Criar SIEM alert para certificate requests fora do padrão','Segregar CA Root offline (air-gapped) da CA Subordinada'],
  },
  {
    id:'CJ-005', name:'LLM Gateway — IA com Acesso a Dados PII',
    category:'IA & Dados Sensíveis', icon:'ti-robot', color:'#00d4d4',
    description:'Gateway de IA com acesso a dados de clientes via RAG. Prompt injection pode exfiltrar PII de centenas de milhares de clientes sem trace convencional.',
    asset:'llm-gateway-prod', protection_score:45, open_vulns:1, vuln_ids:['AI-2025-001'],
    blast_radius:['PII de ~450.000 clientes (LGPD — notificação ANPD obrigatória)','Histórico financeiro via RAG context window','Dados KYC e documentos de identidade','Multa LGPD: até 2% faturamento anual','Dano reputacional: cliente exposto pela IA da empresa'],
    attack_paths:[{
      id:'AP-005', name:'Prompt Injection → PII Exfiltration', difficulty:'low', epss_like:0.95,
      steps:[
        {label:'Usuário Externo', detail:'Interface de chat pública',   type:'entry'},
        {label:'Prompt Inject',   detail:'LLM01 — ignore sys prompt',  type:'technique'},
        {label:'RAG Access',      detail:'Contexto de dados do cliente',type:'node'},
        {label:'Indirect Inject', detail:'LLM02 — dados manipulam LLM',type:'technique'},
        {label:'Crown Jewel',     detail:'PII exfiltrada via resposta', type:'target'},
      ],
      mitre:['LLM01','LLM02','TA0010'],
      gaps:['Guardrails de input/output ausentes (AI-2025-001)','Sem privilege separation no RAG pipeline','Sem rate limiting por usuário','Sem anomaly detection em queries de contexto'],
    }],
    recommendations:['URGENTE: implementar input/output guardrails (AI-2025-001)','Privilege separation no RAG — acesso mínimo por sessão','Rate limiting e detecção de anomalias em queries','Data minimization — expor ao LLM apenas campos necessários','Logging completo de prompts para auditoria LGPD'],
  },
];

export function getProtectionColor(score) {
  if (score >= 80) return 'var(--success)';
  if (score >= 65) return 'var(--med)';
  if (score >= 50) return 'var(--high)';
  return 'var(--crit)';
}

export function getDifficultyLabel(d) {
  return {low:'FÁCIL — Risco Crítico', medium:'MÉDIO — Risco Alto', high:'DIFÍCIL — Risco Moderado'}[d] || d;
}

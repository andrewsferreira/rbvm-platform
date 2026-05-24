// =============================================================================
// RBVM Platform — False Positive Workflow
// © 2026 Andrews Ferreira. Todos os direitos reservados.
// =============================================================================

export const FP_RECORDS = [
  {
    id:'FP-001', vuln_id:'CVE-2024-27198', scanner:'Rapid7',
    status:'accepted', // accepted = confirmed false positive
    contestant:'camila.gomes@corp.example',
    reviewer:'security-lead@corp.example',
    justification:'TeamCity está em rede completamente isolada (VLAN privada sem rota para internet) com MFA obrigatório em todos os acessos. O scanner flagou baseado apenas na versão do software sem verificar acessibilidade real do endpoint vulnerável.',
    evidence:'Diagrama de rede (VLAN-diagram-2024.pdf) · Política MFA confirmada por Identity Team · Nmap mostrando porta 8111 acessível apenas via VPN com MFA',
    reviewer_note:'FP aceito. Ativo em rede isolada + MFA reduz o risco a aceitável. Mantido como exceção formal (EXC-002) com validade de 60 dias.',
    created:'2024-04-25', resolved:'2024-04-26',
    time_to_resolve:'< 24h', scanner_confidence:'high',
  },
  {
    id:'FP-002', vuln_id:'IAC-2024-001', scanner:'Checkov',
    status:'rejected', // rejected = confirmed true positive
    contestant:'isadora.pinto@corp.example',
    reviewer:'security-lead@corp.example',
    justification:'O Security Group com porta 22 aberta é necessário para deploy automatizado. Está documentado como exceção no nosso runbook.',
    evidence:'Referência ao runbook interno de deploy.',
    reviewer_note:'FP rejeitado. O runbook não justifica exposição à internet. Alternativa adequada é SSM Session Manager. Vuln permanece aberta com ação de remediação atualizada.',
    created:'2024-05-01', resolved:'2024-05-02',
    time_to_resolve:'< 24h', scanner_confidence:'high',
  },
  {
    id:'FP-003', vuln_id:'LOW-2024-001', scanner:'SonarQube',
    status:'accepted',
    contestant:'vitor.carvalho@corp.example',
    reviewer:'appsec-lead@corp.example',
    justification:'O header X-Frame-Options está sendo setado via Cloudflare (CDN layer) e não diretamente no servidor. O SonarQube só analisa o servidor de origem e não enxerga a camada CDN.',
    evidence:'Screenshot do Cloudflare mostrando X-Frame-Options ativado · cURL com headers reais da origem via CDN',
    reviewer_note:'FP aceito para este header específico. Mas CSP e HSTS ainda estão ausentes mesmo na camada CDN. Vuln modificada: escopo reduzido a 2 headers.',
    created:'2024-05-13', resolved:'2024-05-14',
    time_to_resolve:'< 24h', scanner_confidence:'medium',
  },
  {
    id:'FP-004', vuln_id:'CONTAINER-2024-001', scanner:'Trivy',
    status:'under_review',
    contestant:'rafael.moura@corp.example',
    reviewer:null,
    justification:'As CVEs flagadas estão presentes na imagem base mas o código da aplicação não executa nenhum dos caminhos de código vulneráveis. Os componentes vulneráveis são bibliotecas do sistema não expostas à aplicação.',
    evidence:'Análise manual de reachability com govulncheck · Relatório indicando que as funções vulneráveis não estão no call graph da aplicação',
    reviewer_note:null,
    created:'2024-05-18', resolved:null,
    time_to_resolve:null, scanner_confidence:'low',
  },
  {
    id:'FP-005', vuln_id:'CVE-2024-38063', scanner:'Microsoft Defender',
    status:'under_review',
    contestant:'patricia.lima@corp.example',
    reviewer:null,
    justification:'Nossos servidores Windows têm IPv6 completamente desabilitado a nível de registro desde 2022 (HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\DisabledComponents=0xFF). A CVE é para sistemas com IPv6 ativo.',
    evidence:'Script PowerShell de auditoria mostrando IPv6 desabilitado em todos os 47 servidores · Política de GPO de hardening IPv6',
    reviewer_note:null,
    created:'2024-05-20', resolved:null,
    time_to_resolve:null, scanner_confidence:'medium',
  },
  {
    id:'FP-006', vuln_id:'LOW-2024-002', scanner:'Snyk',
    status:'rejected',
    contestant:'juliana.campos@corp.example',
    reviewer:'appsec-lead@corp.example',
    justification:'Python 3.9 continua recebendo security fixes backportados pelo nosso fornecedor de OS (RHEL). Não precisamos atualizar a versão do runtime.',
    evidence:'Referência ao RHEL Extended Lifecycle Support para Python 3.9.',
    reviewer_note:'FP rejeitado. O RHEL ELS não cobre todas as CVEs e tem cobertura parcial. A versão upstream 3.9 é EOL e o risco aumenta mensalmente. Manter como vuln LOW com SLA estendido para 180 dias.',
    created:'2024-05-16', resolved:'2024-05-17',
    time_to_resolve:'< 24h', scanner_confidence:'medium',
  },
];

export const FP_SCANNER_STATS = [
  { scanner:'Tenable VM',          total_findings:412, fp_contested:8,  fp_accepted:2,  fp_rate:0.49, precision:0.995 },
  { scanner:'Qualys VMDR',         total_findings:389, fp_contested:12, fp_accepted:4,  fp_rate:1.03, precision:0.990 },
  { scanner:'Rapid7 InsightVM',    total_findings:147, fp_contested:6,  fp_accepted:2,  fp_rate:1.36, precision:0.986 },
  { scanner:'Snyk',                total_findings:88,  fp_contested:14, fp_accepted:5,  fp_rate:5.68, precision:0.943 },
  { scanner:'SonarQube',           total_findings:203, fp_contested:28, fp_accepted:11, fp_rate:5.42, precision:0.946 },
  { scanner:'Checkov',             total_findings:71,  fp_contested:9,  fp_accepted:3,  fp_rate:4.23, precision:0.958 },
  { scanner:'Microsoft Defender',  total_findings:95,  fp_contested:7,  fp_accepted:3,  fp_rate:3.16, precision:0.968 },
  { scanner:'Trivy',               total_findings:62,  fp_contested:11, fp_accepted:4,  fp_rate:6.45, precision:0.935 },
];

export function getFPStats() {
  const total   = FP_RECORDS.length;
  const pending = FP_RECORDS.filter(r=>r.status==='under_review').length;
  const accepted= FP_RECORDS.filter(r=>r.status==='accepted').length;
  const rejected= FP_RECORDS.filter(r=>r.status==='rejected').length;
  const avgRate = (FP_SCANNER_STATS.reduce((s,x)=>s+x.fp_rate,0)/FP_SCANNER_STATS.length).toFixed(2);
  return { total, pending, accepted, rejected, avgRate };
}

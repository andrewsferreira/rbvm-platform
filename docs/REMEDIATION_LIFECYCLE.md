# Remediation Lifecycle — Jornada da Vulnerabilidade

**© 2026 Andrews Ferreira. Projeto proprietário.**

## Visão Geral

O Remediation Lifecycle é o principal diferencial da RBVM Platform. Demonstra que o ciclo de gestão de vulnerabilidades é muito mais do que detectar e criar um ticket.

## O Ciclo Completo

```
1. Finding Detectado          → Scanner (Tenable/Qualys/Snyk/Wiz/GHAS)
2. Normalizado & Deduplicado  → RBVM Normalizer Engine
3. Enriquecido com TI         → CVSS, EPSS, KEV, MITRE ATT&CK, exposição
4. Risk Score Calculado       → Motor multicritério (10+ fatores)
5. Owner & Squad Identificados→ CMDB Integration
6. Ticket Criado              → Jira / ServiceNow
7. SLA Iniciado               → SLA Engine conforme política corporativa
8. Alerta Enviado             → Slack / Teams / PagerDuty / E-mail
9. Acompanhamento de SLA      → Cobrança preventiva + escalonamento automático
10. Resolvido pelo Time       → Owner marca ticket (NÃO fecha a vulnerabilidade)
11. Aguardando Validação      → RBVM move para validação obrigatória
12. Rescan / Validação via API→ Scanner de origem confirma ou nega
13. Resultado da Validação    → Fixed Confirmed ou Still Vulnerable
14a. Fechado com Evidência    → Vulnerabilidade encerrada com prova técnica
14b. Reaberto                 → Finding persistente → ticket reaberto → ciclo reinicia
```

## Estados Possíveis

| Status | Descrição |
|--------|-----------|
| New | Finding detectado, aguardando triagem |
| Ticket Created | Ticket criado no Jira/ServiceNow |
| In Progress | Time técnico trabalhando na correção |
| Resolved by Team | Owner marcou como resolvido — aguarda validação |
| Awaiting Technical Validation | RBVM aguarda rescan técnico obrigatório |
| Rescan Requested | Rescan solicitado via API do scanner |
| Validation Running | Scanner executando nova varredura |
| Fixed Confirmed | Scanner confirmou que finding não existe mais |
| Still Vulnerable | Scanner confirmou finding ainda presente |
| Reopened | Ticket reaberto — SLA reiniciado |
| Closed with Evidence | Encerrado com evidência de rescan |
| Recurrence Detected | Mesmo finding reapareceu após fechamento |

## Regras de Governança

1. **Criar ticket ≠ vulnerabilidade corrigida**
2. **Resolvido pelo time ≠ vulnerabilidade encerrada**
3. **Validação técnica via rescan é OBRIGATÓRIA** antes de fechar
4. **A plataforma NUNCA fecha uma vulnerabilidade sem evidência técnica**
5. **Toda ação gera evento auditável** com timestamp, ator e evidência
6. **Reincidência é detectada e registrada** automaticamente

## Audit Trail

Cada vulnerabilidade possui um Audit Trail completo com:
- Timestamp de cada evento
- Ator: sistema (scanner, RBVM engine, integrações) ou usuário
- Ação executada
- Status anterior → Status novo
- Detalhe técnico e evidência
- Fonte do evento

---

*© 2026 Andrews Ferreira. Todos os direitos reservados.*

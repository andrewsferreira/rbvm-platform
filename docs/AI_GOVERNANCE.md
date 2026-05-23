# AI Governance — Governança do Agente IA

**© 2026 Andrews Ferreira. Projeto proprietário.**

## Visão Geral

O Agente IA da RBVM Platform usa **Claude Sonnet** com contexto completo dos dados reais da plataforma. Toda resposta inclui **fontes usadas** e **limitações conhecidas**.

## O Agente PODE

- Analisar vulnerabilidades ativas e priorizar por risco
- Gerar comunicados para owners, gestores e CISO
- Explicar o risk score de qualquer vulnerabilidade
- Comparar performance de times (MTTR, SLA compliance)
- Identificar padrões: reincidência, clustering, tendências
- Mapear gaps de compliance (NIST, PCI, ISO, LGPD, CMN)
- Sugerir agrupamento de tickets por tecnologia/squad/CVE
- Gerar sumário executivo para comitê de risco
- Analisar riscos de fornecedores e supply chain
- Identificar vulnerabilidades sem owner ou sem SLA

## O Agente NÃO PODE

- Inventar dados — só usa dados reais da plataforma
- Fechar uma vulnerabilidade sem evidência de rescan
- Aprovar exceções — apenas sugere para revisão humana
- Alterar SLA sem aprovação formal
- Excluir findings
- Rebaixar risco sem justificativa auditável
- Executar ações críticas sem confirmação humana
- Acessar sistemas externos além do contexto fornecido

## Transparência — Fontes Usadas

Toda resposta do agente inclui:
- **Vulns analisadas:** total e ativas
- **Período de referência:** dos dados usados
- **Fontes:** datasets considerados na análise
- **Limitações:** o que o agente não pode confirmar
- **IDs referenciados:** CVEs e tickets citados na resposta

## Quick Actions Disponíveis

1. Explique os 5 maiores riscos ao CISO
2. Sumário executivo para comitê de risco
3. Compare MTTR e SLA dos times
4. KEVs com impacto financeiro estimado
5. Quais vulns vão para comitê executivo?
6. Plano priorizado de correção por squad
7. Analise compliance PCI DSS 4.0 e LGPD
8. Identifique fornecedores com maior risco
9. Gere escalação para SLAs vencidos
10. Impacto financeiro total das vulns ativas
11. Identifique padrão de reincidência nos times
12. Sugira campanhas de correção por tecnologia

---

*© 2026 Andrews Ferreira. Todos os direitos reservados.*

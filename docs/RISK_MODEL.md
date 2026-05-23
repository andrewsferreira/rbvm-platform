# Risk Model — Modelo de Risco Multicritério

**© 2026 Andrews Ferreira. Projeto proprietário.**

## Fórmula

```
Score = CVSS_norm(0-25) + KEV(+15) + Exploit(+10) + RCE(+5)
      + EPSS(0-10) + Internet-facing(+10) + Produção(+5)
      + Criticidade_Ativo(0-10) + PCI(+4) + LGPD(+3)
      + Dados_Sensíveis(+3) - Controle_Compensatório(-10)
      + SLA_Vencido(+5)
```

Score normalizado: 0–100

## Escala de Risco

| Score | Label | SLA |
|-------|-------|-----|
| ≥ 90 | CRÍTICO EMERGENCIAL | 72h |
| ≥ 75 | CRÍTICO | 7–15 dias |
| ≥ 60 | ALTO | 15–30 dias |
| ≥ 40 | MÉDIO | 60 dias |
| ≥ 20 | BAIXO | 90 dias |
| < 20 | INFORMATIVO | Backlog |

## Fatores Detalhados

| Fator | Pontos | Condição |
|-------|--------|----------|
| CVSS Base | 0–25 | CVSS/10 × 25 |
| CISA KEV | +15 | Exploração confirmada em ambiente real |
| Exploit público | +10 | PoC ou exploit disponível |
| RCE | +5 | Remote Code Execution confirmado |
| EPSS | 0–10 | EPSS% × 10 |
| Internet-facing | +10 | Ativo exposto externamente |
| Produção | +5 | Ambiente produtivo |
| Crítico/High/Med/Low | +10/7/4/1 | Criticidade do ativo no CMDB |
| PCI DSS scope | +4 | Ativo em escopo PCI |
| LGPD scope | +3 | Dados pessoais de titulares |
| Dados sensíveis | +3 | Dados confidenciais |
| Controle compensatório | −10 | Mitigação formal ativa |
| SLA vencido | +5 | Risco remanescente aumentado |

---

*© 2026 Andrews Ferreira. Todos os direitos reservados.*

"""
modules/injection_correlator.py

O módulo que decide se um parâmetro é candidato forte o suficiente pra
virar Finding -- junta os sinais independentes de
modules/injection_heuristics.py (erro, booleano, diferencial) por
(url, method, param) e só reporta quando a combinação passa um limiar.

Mesma filosofia do wp_known_vulnerable_assets.py do WRAITH: Requirement
wildcard, cost=0 (matching local puro, sem HTTP), reentrância alta porque
sinais chegam em momentos diferentes do scan, dedup por atributo de
CLASSE (não de instância -- instância é recriada a cada reentrância).

NUNCA confirma exploração sozinho. O Finding inclui o comando sqlmap
pronto pra rodar, mas rodar é decisão humana -- essa ferramenta identifica
candidato, não explora. Ver docstring completa do motivo em
injection_correlator (seção "por que não auto-invocar sqlmap") na
conversa que originou este módulo.
"""

from __future__ import annotations

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult


# combinação de confiança dos sinais -- não é média simples, de propósito:
# 1 sinal de erro sozinho (0.9) já é forte o bastante pra virar candidato;
# 2 sinais fracos concordando (0.35 + 0.3) não deveriam somar tanto quanto
# parece à primeira vista, porque os dois podem estar errados pela MESMA
# razão (ex.: página com conteúdo dinâmico de verdade, não injeção).
# Fórmula: 1 - produto das probabilidades de "não ser vulnerável" -- é
# como se cada sinal fosse uma chance independente de detectar o mesmo
# problema real; múltiplos sinais concordando aumenta a confiança combinada
# sem nunca simplesmente somar (e passar de 1.0).
def combine_confidences(confidences: list[float]) -> float:
    if not confidences:
        return 0.0
    produto_de_nao_deteccao = 1.0
    for c in confidences:
        produto_de_nao_deteccao *= (1.0 - c)
    return 1.0 - produto_de_nao_deteccao


THRESHOLD = 0.7


def _group_by_endpoint(signal_facts: list) -> dict[str, dict]:
    """Agrupa sinais pela mesma tripla (url, method, param) -- a fact_key
    tem o technique no final (ex.: injection.signal.abc123.error_based),
    então dois sinais do MESMO parâmetro têm fact_keys diferentes mas o
    mesmo hash no meio; agrupamos pelo hash, não pela chave inteira."""
    grouped: dict[str, dict] = {}
    for f in signal_facts:
        hash_id = str(f.key).split(".")[2]
        grouped.setdefault(hash_id, {"info": f.value, "signals": []})
        grouped[hash_id]["signals"].append({
            "technique": f.value.get("technique"),
            "confidence": f.confidence,
            "evidence": f.value.get("evidence"),
        })
    return grouped


def _sqlmap_command(url: str, method: str, param: str) -> str:
    if method.upper() == "GET":
        return f'sqlmap -u "{url}" -p {param} --batch --level=2 --risk=1'
    return f'sqlmap -u "{url}" --data="{param}=1" -p {param} --batch --level=2 --risk=1'


@discovery_module(
    requires=[Requirement("injection.*", min_confidence=0.1)],
    produces=[],
    cost=0,
    max_reentries=25,
    category="correlation",
    display_name="Correlação de Sinais de Injeção",
    summary="Combina os sinais independentes por parâmetro e reporta candidato forte quando a confiança combinada passa o limiar -- nunca confirma exploração sozinho.",
)
class InjectionCorrelator:
    name = "injection_correlator"

    # de classe de propósito -- instância nova a cada reentrância (ver
    # wp_known_vulnerable_assets.py no WRAITH pra mesma discussão)
    _reported: set[tuple] = set()

    def run(self, target, facts_in):
        signal_facts = facts_in.get("injection.*", [])
        if not signal_facts:
            return None

        grouped = _group_by_endpoint(signal_facts)
        findings = []

        for hash_id, data in grouped.items():
            info = data["info"]
            confidences = [s["confidence"] for s in data["signals"]]
            combined = combine_confidences(confidences)

            if combined < THRESHOLD:
                continue

            dedup_key = (target, hash_id)
            if dedup_key in self._reported:
                continue
            self._reported.add(dedup_key)

            url, method, param = info["url"], info["method"], info["param"]
            techniques = ", ".join(sorted({s["technique"] for s in data["signals"]}))
            evidencias = "\n".join(f"- [{s['technique']}] {s['evidence']} (confiança {s['confidence']:.2f})" for s in data["signals"])

            findings.append({
                "title": f"Candidato a SQL Injection: parâmetro '{param}' em {url}",
                "severity": "high" if combined >= 0.85 else "medium",
                "module": self.name,
                "category": "injection_candidate",
                "endpoint": url,
                "description": (
                    f"O parâmetro '{param}' (via {method}) apresentou {len(data['signals'])} "
                    f"sinal(is) independente(s) de possível SQL injection ({techniques}), "
                    f"com confiança combinada de {combined:.2f}."
                ),
                "business_impact": (
                    "SQL Injection pode permitir leitura/modificação não autorizada de dados, "
                    "bypass de autenticação, ou em casos graves execução de comando no servidor."
                ),
                "remediation": (
                    "Usar queries parametrizadas (prepared statements) para este parâmetro. "
                    "NÃO CONFIRMADO AINDA -- validar manualmente ou com sqlmap antes de reportar como vulnerabilidade real."
                ),
                "evidence": {
                    "url": url,
                    "method": method,
                    "param": param,
                    "combined_confidence": round(combined, 2),
                    "signals": evidencias,
                    "comando_sugerido": _sqlmap_command(url, method, param),
                },
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)

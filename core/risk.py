"""
core/risk.py

Cálculo de risco agregado por alvo.

Substitui as duas cópias divergentes de `risk_score()` que existiam soltas
em utils/pdf_reporter.py e utils/html_reporter.py (mesmos pesos, duplicados
em dois arquivos -- qualquer ajuste de peso ou de fórmula exigia lembrar de
mudar nos dois lugares, e um relatório podia silenciosamente ficar
desatualizado em relação ao outro).

A fórmula antiga (soma de pesos por severidade, capada em 100) tem um
problema real: 10 findings "critical" (soma 100) e 40 findings "info"
(soma 40, capada... não, 40) davam a impressão de que só o primeiro caso
era grave -- mas 5 criticals (50) e 15 criticals (150->capado em 100)
ficavam INDISTINGUÍVEIS um do outro, porque o cap escondia a diferença
justamente na faixa mais crítica, que é a que mais importa mostrar.

A curva de saturação exponencial abaixo resolve isso: poucos achados
graves já levam o score para perto do topo rapidamente (reflete "o alvo
está comprometido"), mas cada crítico adicional além do primeiro ainda
empurra o score visivelmente para cima até chegar bem perto de 100 --
nunca esconde "1 crítico" atrás do mesmo número que "5 críticos".
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 1,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# quanto menor, mais rápido o score satura perto de 100 com poucos achados
# graves. k=40 foi calibrado para que 1 critical + 2 high (raw=24) já
# produza ~45/100 ("Médio" alto / beira de "Alto"), e 3 criticals (raw=30)
# cheguem a ~53/100 ("Alto").
_SATURATION_K = 40


@dataclass
class RiskAssessment:
    target: str
    raw_score: float
    score: int                       # 0-100, normalizado
    level: str                       # "Baixo" | "Médio" | "Alto" | "Crítico"
    severity_counts: dict            # {"critical": N, "high": N, ...}
    category_counts: dict            # {"woocommerce": N, "auth": N, ...}
    total_findings: int

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "raw_score": self.raw_score,
            "score": self.score,
            "level": self.level,
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "total_findings": self.total_findings,
        }


def _severity_counts(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev not in counts:
            sev = "info"
        counts[sev] += 1
    return counts


def _category_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        cat = f.get("category") or "general"
        counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def _level_for(score: int, counts: dict) -> str:
    """
    O score numérico (curva de saturação) é bom pra RANQUEAR alvos entre si,
    mas sozinho ele pode subestimar um caso isolado grave -- 1 único finding
    "critical" dá score baixo na curva (pouco raw score acumulado), o que
    rotularia como "Baixo" um alvo com, por exemplo, credencial de banco de
    dados exposta. Isso é inaceitável num relatório de pentest: a etiqueta
    nunca pode subestimar a pior coisa encontrada, só a quantidade pode
    empurrar pra cima. Por isso o nível textual usa um "piso" pela pior
    severidade presente, e só o score numérico fica livre pra refletir volume.
    """
    if counts.get("critical", 0) >= 3 or score >= 75:
        return "Crítico"
    if counts.get("critical", 0) >= 1 or counts.get("high", 0) >= 3 or score >= 50:
        return "Alto"
    if counts.get("high", 0) >= 1 or counts.get("medium", 0) >= 1 or score >= 25:
        return "Médio"
    return "Baixo"


def calculate_risk(findings: list[dict], target: str = "") -> RiskAssessment:
    counts = _severity_counts(findings)
    raw = sum(SEVERITY_WEIGHTS[sev] * n for sev, n in counts.items())
    normalized = round(100 * (1 - math.exp(-raw / _SATURATION_K))) if raw > 0 else 0
    normalized = min(normalized, 100)

    return RiskAssessment(
        target=target,
        raw_score=raw,
        score=normalized,
        level=_level_for(normalized, counts),
        severity_counts=counts,
        category_counts=_category_counts(findings),
        total_findings=len(findings),
    )

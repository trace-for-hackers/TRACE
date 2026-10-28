"""
knowledge/result.py

Resolve um problema prático: os ~25 módulos existentes hoje têm a assinatura

    def run(self, target) -> list[dict] | None

Reescrever todos para devolver fatos quebraria retrocompatibilidade e geraria
um diff gigante e arriscado pouco antes da apresentação. Em vez disso, o
runner aceita DOIS formatos de retorno, e os dois continuam válidos para sempre:

    1) Legado:        return findings                  (list[dict] | None)
    2) Knowledge-aware: return ModuleResult(findings=[...], facts=[...])

Módulos novos ou módulos antigos que eu queira "upgradar" para produzir
fatos usam o formato 2. Módulos que ninguém tocar continuam no formato 1
e simplesmente nunca alimentam o blackboard com fatos próprios — o que é
aceitável: eles seguem rodando como "módulos de folha", sem desbloquear nada,
exatamente como fazem hoje.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from knowledge.fact import Fact


@dataclass
class ModuleResult:
    findings: list[dict] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)


def normalize_result(raw) -> ModuleResult:
    """Normaliza o retorno de qualquer módulo (legado ou novo) para ModuleResult."""
    if raw is None:
        return ModuleResult()
    if isinstance(raw, ModuleResult):
        return raw
    if isinstance(raw, list):
        return ModuleResult(findings=raw)
    if isinstance(raw, dict):
        return ModuleResult(findings=[raw])
    # qualquer outra coisa inesperada: trata como finding único bruto, não quebra o scan
    return ModuleResult(findings=[{"raw": raw}])

"""
knowledge/priority.py

Cálculo de prioridade de execução entre módulos ELEGÍVEIS (a ordem só importa
dentro da fronteira que o ActivationEngine já filtrou — prioridade não torna
um módulo elegível, apenas decide a ORDEM de execução dentro do que já é
elegível, otimizando para "descobrir o máximo com o mínimo de requisições").

Combina 4 sinais, cada um em [0, 1], com pesos configuráveis:

    1. hit_rate histórico (já existe em MemoryManager.get_module_priority)
       -> módulos que historicamente acham algo nesse tipo de site sobem.

    2. confiança média dos fatos que satisfazem seus requires
       -> se o fato gatilho tem confiança 0.95, vale mais investigar agora
          do que um módulo cujo gatilho está em 0.5 (pode ser falso positivo).

    3. custo inverso (1 / cost declarado no ModuleSpec)
       -> módulos baratos (poucas requisições) sobem, dado empate nos outros
          sinais -- alinhado ao objetivo "máxima descoberta, mínima requisição".

    4. profundidade na cadeia (quão "específico"/profundo o fato-gatilho é)
       -> fatos mais profundos (ex.: endpoint.upload.confirmed) tendem a
          indicar módulos de exploração mais direcionada, que valem subir
          na fila antes de módulos de varredura genérica ainda pendentes.

Pesos default refletem a filosofia "minimizar requisições, priorizar sinal
forte": hit_rate e confiança pesam mais que custo e profundidade, mas todos
contam. Pesos são fixos no código hoje (ver abaixo) -- parametrização via
variável de ambiente ainda não foi implementada; seria natural evolução
pra permitir otimizar por outro objetivo (ex.: scan furtivo priorizando
custo baixo acima de tudo), mas não existe hoje, não confundir com feature
disponível.
"""

from __future__ import annotations

from dataclasses import dataclass

from knowledge.contracts import ModuleSpec, Requirement
from knowledge.engine import RegisteredModule
from knowledge.store import KnowledgeStore


@dataclass
class PriorityWeights:
    hit_rate: float = 0.4
    trigger_confidence: float = 0.3
    inverse_cost: float = 0.2
    depth: float = 0.1

    def normalized(self) -> "PriorityWeights":
        total = self.hit_rate + self.trigger_confidence + self.inverse_cost + self.depth
        if total == 0:
            return PriorityWeights(0.25, 0.25, 0.25, 0.25)
        return PriorityWeights(
            self.hit_rate / total,
            self.trigger_confidence / total,
            self.inverse_cost / total,
            self.depth / total,
        )


class PriorityCalculator:
    def __init__(
        self,
        store: KnowledgeStore,
        hit_rates: dict[str, float],
        weights: PriorityWeights | None = None,
    ):
        self.store = store
        self.hit_rates = hit_rates          # vem de MemoryManager.get_module_priority(site_type)
        self.weights = (weights or PriorityWeights()).normalized()

    def _trigger_confidence(self, requires: tuple[Requirement, ...]) -> float:
        if not requires:
            return 1.0  # módulo raiz: confiança máxima, sempre prioritário no início
        confidences = []
        for req in requires:
            f = self.store.get(req.fact_key)
            if f:
                confidences.append(f.confidence)
        return sum(confidences) / len(confidences) if confidences else 0.0

    def _depth(self, requires: tuple[Requirement, ...]) -> float:
        """Profundidade aproximada = número de segmentos no namespace mais
        específico exigido. 'tech.woocommerce.present' (3) é mais profundo
        que 'cms.wordpress.detected' (3) — em geral, mais segmentos = mais
        específico = mais perto da "ponta" da cadeia de descoberta."""
        if not requires:
            return 0.0
        max_segments = max(len(r.fact_key.split(".")) for r in requires)
        return min(max_segments / 5.0, 1.0)  # normalizado, cap em 5 segmentos

    def score(self, rm: RegisteredModule) -> float:
        spec: ModuleSpec = rm.spec

        hit_rate = self.hit_rates.get(rm.name, 0.0)
        trigger_conf = self._trigger_confidence(spec.requires)
        inverse_cost = 1.0 / max(spec.cost, 1)
        depth = self._depth(spec.requires)

        w = self.weights
        return (
            w.hit_rate * hit_rate +
            w.trigger_confidence * trigger_conf +
            w.inverse_cost * inverse_cost +
            w.depth * depth
        )

    def rank(self, modules: list[RegisteredModule]) -> list[RegisteredModule]:
        return sorted(modules, key=self.score, reverse=True)

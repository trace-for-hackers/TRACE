"""
knowledge/engine.py

O ActivationEngine é o "motor de regras" (Production System) do TRACE.

Responsabilidade única: dado o estado atual do KnowledgeStore e o conjunto de
ModuleSpecs registrados, responder à pergunta "quais módulos estão elegíveis
para rodar AGORA, e que ainda não rodaram (ou podem reentrar)?".

Ele NÃO executa módulos (isso é responsabilidade do Scheduler, seção 7).
Ele NÃO sabe HTTP, requests, ou nada de rede. Pura lógica de decisão sobre
fatos — o que o torna trivialmente testável com fixtures.

── Prevenção de loops ───────────────────────────────────────────────────────

Loops podem acontecer de duas formas:

(a) Loop ESTRUTURAL: módulo A produz um fato que módulo B consome, e módulo B
    produz um fato que módulo A consome -> ciclo A->B->A.
    Isso é detectado em tempo de REGISTRO (carregamento dos módulos), construindo
    um grafo de dependências produces->requires entre specs e rodando detecção
    de ciclo (DFS com cores). Se um ciclo for encontrado, o engine RECUSA
    carregar o conjunto e levanta CyclicDependencyError com o caminho do ciclo
    — erro de configuração, pego antes do scan começar, nunca em runtime.

(b) Loop de REENTRÂNCIA: um módulo já rodou, um fato novo aparece que também
    satisfaz seu requires (ex.: confiança de um fato subiu de 0.5 para 0.9
    depois de outra verificação), o que tecnicamente o tornaria "elegível de novo".
    Isso é controlado por orçamento: cada módulo tem `max_reentries` (default 1,
    ou seja, NUNCA reroda). Cada execução consome 1 do orçamento. Quando o
    orçamento chega a 0, o módulo nunca mais é elegível nesta sessão, independente
    de quais fatos apareçam — isso garante TERMINAÇÃO GARANTIDA do scheduler:
    o número total de execuções possíveis é finito e conhecido a priori
    (soma de max_reentries de todos os módulos), então o scan SEMPRE termina.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json

from knowledge.contracts import ModuleSpec, Requirement, RequirementMode, get_spec
from knowledge.store import KnowledgeStore


class CyclicDependencyError(Exception):
    def __init__(self, cycle_path: list[str]):
        self.cycle_path = cycle_path
        super().__init__(
            "Dependência cíclica detectada entre módulos: " + " -> ".join(cycle_path)
        )


@dataclass
class RegisteredModule:
    module_class: type
    name: str
    spec: ModuleSpec
    executions_used: int = 0
    # Assinatura do conhecimento que estava disponível NO MOMENTO da última
    # seleção/execução. Não é atualizada no fim da execução porque outros
    # módulos da mesma onda podem produzir fatos que este módulo ainda não viu.
    last_trigger_signature: tuple = ()

    @property
    def executions_remaining(self) -> int:
        return self.spec.max_reentries - self.executions_used

    def can_still_run(self) -> bool:
        return self.executions_remaining > 0


class ActivationEngine:
    def __init__(self, store: KnowledgeStore, site_type: str | None = None):
        self.store = store
        self.site_type = site_type
        self._registry: dict[str, RegisteredModule] = {}
        self._already_run_at_least_once: set[str] = set()

    # ── registro ─────────────────────────────────────────────────────────────

    def register(self, module_classes: list[type]) -> None:
        registered = []
        for cls in module_classes:
            name = getattr(cls, "name", cls.__name__)
            spec = get_spec(cls)
            registered.append(RegisteredModule(module_class=cls, name=name, spec=spec))

        self._detect_structural_cycles(registered)

        for rm in registered:
            self._registry[rm.name] = rm

    def _detect_structural_cycles(self, registered: list[RegisteredModule]) -> None:
        """
        Constrói grafo produces -> requires entre módulos e roda DFS com
        3 cores (white/gray/black) para detectar ciclo. Falha rápido e alto.
        """
        producers_of: dict[str, list[str]] = defaultdict(list)
        for rm in registered:
            for produced in rm.spec.produces:
                producers_of[produced.fact_key].append(rm.name)

        edges: dict[str, set[str]] = defaultdict(set)  # A -> B significa "A precisa de algo que B produz"
        for rm in registered:
            for req in rm.spec.requires:
                for producer_name in producers_of.get(req.fact_key, []):
                    if producer_name != rm.name:
                        edges[rm.name].add(producer_name)

        WHITE, GRAY, BLACK = 0, 1, 2
        color = {rm.name: WHITE for rm in registered}
        path: list[str] = []

        def dfs(node: str):
            color[node] = GRAY
            path.append(node)
            for neighbor in edges.get(node, []):
                if color.get(neighbor, WHITE) == GRAY:
                    cycle_start = path.index(neighbor)
                    raise CyclicDependencyError(path[cycle_start:] + [neighbor])
                if color.get(neighbor, WHITE) == WHITE:
                    dfs(neighbor)
            path.pop()
            color[node] = BLACK

        for rm in registered:
            if color[rm.name] == WHITE:
                dfs(rm.name)

    # ── avaliação de elegibilidade ───────────────────────────────────────────

    def _requirement_satisfied(self, req: Requirement) -> bool:
        if req.fact_key.endswith(".*"):
            prefix = req.fact_key[:-2]
            facts = self.store.query_prefix(prefix)
            return any(f.confidence >= req.min_confidence for f in facts)

        f = self.store.get(req.fact_key)
        if f is None or f.confidence < req.min_confidence:
            return False
        if req.expected_value is not None and f.value != req.expected_value:
            return False
        return True

    def _site_type_allowed(self, spec: ModuleSpec) -> bool:
        if spec.site_types is None or self.site_type is None:
            return True
        return self.site_type in spec.site_types

    @staticmethod
    def _value_signature(value) -> str:
        """Normaliza valores de Fact para uma assinatura estável.

        IDs e timestamps não entram: dois asserts idênticos representam o mesmo
        conhecimento e não devem, sozinhos, provocar uma reentrada.
        """
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
        except Exception:
            return repr(value)

    def _fact_signature(self, key: str):
        fact = self.store.get(key)
        if fact is None:
            return (key, None)
        return (key, round(float(fact.confidence), 6), self._value_signature(fact.value))

    def requirement_signature(self, rm: RegisteredModule) -> tuple:
        """Snapshot semântico e determinístico do conhecimento relevante ao módulo.

        A assinatura muda somente quando a evidência observável muda: existência,
        confiança ou valor do fato. Um novo UUID/timestamp para o MESMO fato não
        conta como conhecimento novo e, portanto, não provoca reentrada.
        """
        parts = []
        for req in rm.spec.requires:
            if req.fact_key.endswith(".*"):
                prefix = req.fact_key[:-2]
                facts = self.store.query_prefix(prefix)
                parts.append((
                    req.fact_key,
                    tuple(sorted(
                        (str(f.key), round(float(f.confidence), 6), self._value_signature(f.value))
                        for f in facts
                    )),
                ))
            else:
                parts.append(self._fact_signature(req.fact_key))
        return tuple(parts)

    def has_new_requirement_evidence(self, rm: RegisteredModule) -> bool:
        # Raiz não possui evidência de entrada; depois da primeira execução não
        # há motivo de reentrância puramente por elegibilidade.
        if rm.spec.is_root():
            return rm.executions_used == 0

        return self.requirement_signature(rm) != rm.last_trigger_signature

    def is_eligible(self, rm: RegisteredModule) -> bool:
        if not rm.can_still_run():
            return False
        if not self._site_type_allowed(rm.spec):
            return False

        if rm.spec.is_root():
            # Raiz: elegível somente antes da primeira execução. Reentrância de
            # raiz não tem gatilho de conhecimento e portanto só desperdiçaria ondas.
            return rm.executions_used == 0

        checks = [self._requirement_satisfied(r) for r in rm.spec.requires]
        if rm.spec.requirement_mode == RequirementMode.ALL:
            return all(checks)
        return any(checks)

    def get_eligible_modules(self) -> list[RegisteredModule]:
        """Fronteira atual: todos os módulos elegíveis e ainda não executados
        (ou com orçamento de reentrância disponível), ordenados por prioridade
        (ver knowledge/priority.py — injetado externamente pelo Scheduler)."""
        return [
            rm for rm in self._registry.values()
            if self.is_eligible(rm) and self.has_new_requirement_evidence(rm)
        ]

    def mark_executed(self, module_name: str, trigger_signature: tuple | None = None) -> None:
        rm = self._registry.get(module_name)
        if rm:
            rm.executions_used += 1
            rm.last_trigger_signature = (
                self.requirement_signature(rm)
                if trigger_signature is None else trigger_signature
            )
            self._already_run_at_least_once.add(module_name)

    def explain(self, module_name: str) -> dict:
        """Explicabilidade: por que este módulo está (ou não está) elegível agora.
        Usado no relatório final e em modo --verbose para o pentester entender
        a cadeia de decisão do scan."""
        rm = self._registry.get(module_name)
        if not rm:
            return {"module": module_name, "error": "não registrado"}

        requirement_status = []
        for req in rm.spec.requires:
            satisfied = self._requirement_satisfied(req)
            current = self.store.get(req.fact_key)
            requirement_status.append({
                "fact_key": req.fact_key,
                "min_confidence": req.min_confidence,
                "satisfied": satisfied,
                "current_confidence": current.confidence if current else None,
                "current_value": current.value if current else None,
            })

        return {
            "module": module_name,
            "is_root": rm.spec.is_root(),
            "eligible_now": self.is_eligible(rm),
            "executions_used": rm.executions_used,
            "executions_remaining": rm.executions_remaining,
            "requirement_mode": rm.spec.requirement_mode.value,
            "requirements": requirement_status,
        }

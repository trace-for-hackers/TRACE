"""
knowledge/contracts.py

O contrato declarativo que cada módulo expõe sobre si mesmo. Isso é o que
permite "adicionar módulos sem alterar o resto da arquitetura": o scheduler
nunca conhece um módulo específico, ele só lê o ModuleSpec via introspecção.

Um módulo SEMPRE pode ser executado sem nenhum fato (ex.: WPVersion,
WAFDetector — módulos de "primeira camada" que rodam sempre). Esses
simplesmente declaram requires=[] (lista vazia = elegível desde o início).

Forma de uso (decorator sobre a classe do módulo já existente):

    from knowledge.contracts import discovery_module, Requirement, Produces

    @discovery_module(
        requires=[Requirement("tech.woocommerce.present", min_confidence=0.6)],
        produces=[Produces("surface.woocommerce.logs_dir", durable=False)],
        cost=2,           # custo estimado em requisições HTTP
        category="woocommerce",
    )
    class WPWooCommerceLogs:
        name = "wp_woocommerce_logs"
        def run(self, target): ...

O decorator NÃO modifica o comportamento de run() — apenas anexa um atributo
`__wraith_spec__` à classe, lido pelo ActivationEngine. Módulos legados sem
decorator continuam funcionando: ganham um ModuleSpec default (requires=[],
sempre elegível), preservando 100% de retrocompatibilidade com main.py atual.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RequirementMode(str, Enum):
    ALL = "all"   # todos os requirements devem ser satisfeitos (AND)
    ANY = "any"   # ao menos um requirement deve ser satisfeito (OR)


@dataclass(frozen=True)
class Requirement:
    """Um fato que o módulo consome como pré-condição de elegibilidade."""
    fact_key: str               # pode ser exato ("tech.woocommerce.present")
                                 # ou prefixo com wildcard ("surface.*")
    min_confidence: float = 0.5
    expected_value: object | None = None  # se setado, exige que o valor seja igual (ex.: True)


@dataclass(frozen=True)
class Produces:
    """Um fato que o módulo é capaz de produzir, quando encontra algo."""
    fact_key: str
    durable: bool = False        # se True, é persistido em Postgres via MemoryManager
    ttl_seconds: int | None = None


@dataclass(frozen=True)
class ModuleSpec:
    requires: tuple[Requirement, ...] = field(default_factory=tuple)
    requirement_mode: RequirementMode = RequirementMode.ALL
    produces: tuple[Produces, ...] = field(default_factory=tuple)
    cost: int = 1                 # estimativa de nº de requisições HTTP (para o scheduler)
    category: str = "general"     # agrupamento livre (woocommerce, rest_api, auth, infra...)
    site_types: tuple[str, ...] | None = None   # compat com o filtro existente em main_gui.py
    max_reentries: int = 1        # quantas vezes o módulo pode re-rodar se novos fatos
                                   # relevantes aparecerem depois (ver seção anti-loop)
    # metadado de exibição (consumido por knowledge/decision_graph.py para o
    # painel de detalhes ao clicar num módulo no grafo) -- AMBOS opcionais
    # de propósito: Quando ausentes,
    # describe() abaixo cai para fallback automático via docstring/__name__.
    display_name: str | None = None   # nome amigável para humano (ex.: "Exposição de Logs do WooCommerce")
    summary: str | None = None        # 1-2 frases do que o módulo busca e por quê

    def is_root(self) -> bool:
        """Módulo de primeira camada: não depende de nenhum fato, sempre elegível
        desde o início do scan (ex.: WPVersion, WAFDetector)."""
        return len(self.requires) == 0

    def describe(self, module_class) -> dict:
        """
        Resolve o metadado de exibição com fallback em cascata, nunca devolve
        campo vazio:

            display_name: self.display_name -> module_class.name -> module_class.__name__
            summary:      self.summary -> primeira linha não vazia da docstring
                          da classe -> string genérica indicando ausência de
                          descrição (não inventa conteúdo, é honesto sobre o
                          que falta)

        Chamado por knowledge/decision_graph.py ao montar o JSON de metadados
        embutido no HTML do grafo -- não pelo scheduler/engine, que nunca
        precisam disso para decidir nada.
        """
        display_name = self.display_name or getattr(module_class, "name", None) or module_class.__name__

        if self.summary:
            summary = self.summary
        else:
            doc = (module_class.__doc__ or "").strip()
            first_line = doc.splitlines()[0].strip() if doc else ""
            summary = first_line or "Sem descrição disponível para este módulo ainda."

        return {
            "display_name": display_name,
            "summary": summary,
            "category": self.category,
            "cost": self.cost,
            "requires": [r.fact_key for r in self.requires],
            "produces": [p.fact_key for p in self.produces],
            "is_root": self.is_root(),
        }


_DEFAULT_SPEC = ModuleSpec()  # módulos legados sem decorator: sempre elegíveis, custo 1


def discovery_module(
    requires: list[Requirement] | None = None,
    produces: list[Produces] | None = None,
    requirement_mode: RequirementMode = RequirementMode.ALL,
    cost: int = 1,
    category: str = "general",
    site_types: list[str] | None = None,
    max_reentries: int = 1,
    display_name: str | None = None,
    summary: str | None = None,
):
    """Decorator que anexa um ModuleSpec à classe do módulo."""
    spec = ModuleSpec(
        requires=tuple(requires or []),
        requirement_mode=requirement_mode,
        produces=tuple(produces or []),
        cost=cost,
        category=category,
        site_types=tuple(site_types) if site_types else None,
        max_reentries=max_reentries,
        display_name=display_name,
        summary=summary,
    )

    def wrapper(cls):
        cls.__wraith_spec__ = spec
        return cls

    return wrapper


def get_spec(module_class) -> ModuleSpec:
    """Lê o spec de um módulo via introspecção. Módulos legados (sem decorator)
    recebem o spec default — continuam funcionando exatamente como hoje.

    Compatibilidade extra: se o módulo definir `site_types` como atributo de
    classe direto (o hook que já existia em main_gui.py, antes deste sistema),
    isso é respeitado mesmo sem o decorator — ninguém precisa adicionar
    @discovery_module só para usar um filtro de site_types já suportado."""
    spec = getattr(module_class, "__wraith_spec__", None)
    if spec is not None:
        return spec

    legacy_site_types = getattr(module_class, "site_types", None)
    if legacy_site_types:
        return ModuleSpec(site_types=tuple(legacy_site_types))

    return _DEFAULT_SPEC
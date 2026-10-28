"""
knowledge/packs.py

Um "pacote" é um conjunto nomeado de módulos que fazem sentido juntos --
"wordpress", "sqli", "bac". Isso NÃO é um novo mecanismo de orquestração:
o motor de fatos (engine + scheduler) continua sendo o único orquestrador.
Pacote é só uma etiqueta de agrupamento em cima da `category` que cada
módulo já declara no @discovery_module -- serve pra duas coisas:

  1. o operador escolher quais famílias de módulo rodar (--pack sqli,bac)
     sem ter que listar módulo por módulo;
  2. a classificação de alvo (ver orchestrator) decidir automaticamente
     quais pacotes valem a pena pra cada URL da fila.

Por que category e não uma lista hardcoded de nome de módulo: se você
escrever um módulo novo de BAC amanhã e marcar category="access_control",
ele entra no pacote "bac" sozinho, sem editar este arquivo. A etiqueta
segue o módulo, não uma lista central que envelhece.

Um módulo pode estar em mais de um pacote (uma category pode ser mapeada
por vários pacotes) -- e um módulo cuja category não está em nenhum
pacote é considerado "sempre relevante" (roda em qualquer pacote), o que
é o comportamento certo pra coisas como o crawler base.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Pack:
    name: str
    # categorias (do @discovery_module) que pertencem a este pacote
    categories: frozenset[str]
    # descrição curta pro --help / listagem
    description: str = ""


# Registro central. Categorias vêm direto do que os módulos já declaram
# (ver `grep category= modules/`). "discovery" e "correlation" aparecem em
# vários pacotes de propósito -- crawler e correlator são compartilhados.
_PACKS: dict[str, Pack] = {
    # BUG ENCONTRADO E CORRIGIDO (ver nota abaixo): "sqli" e "injection"
    # referenciavam categorias que nenhum módulo declara de verdade
    # ("sqli_heuristics", "xss", "ssti", "ldap_injection", "command_injection").
    # Todo módulo de heurística de injeção (SQL, XSS refletido, SSTI, LDAP,
    # command injection) compartilha UMA categoria real: "injection_heuristics"
    # (ver modules/injection_heuristics.py, xss_reflection_heuristic.py,
    # ssti_heuristic.py, ldap_injection_heuristic.py,
    # command_injection_heuristic.py). Como essas categorias inventadas não
    # batiam com nada, e "injection_heuristics" nunca era reivindicada por
    # nenhum pacote, a regra de "categoria órfã roda sempre" (ver
    # filter_modules_by_packs) fazia esses 8 módulos rodarem em QUALQUER
    # --pack, inclusive --pack wordpress ou --pack bac -- "sqli" e
    # "injection" nunca filtravam nada de fato. sqli agora só existe como
    # alias histórico do pacote "injection" (não dá pra separar SQL de
    # XSS/SSTI/LDAP/command no nível de categoria, já que o módulo não
    # distingue isso sozinho).
    "sqli": Pack(
        name="sqli",
        categories=frozenset({"discovery_injection", "injection_heuristics", "correlation"}),
        description="Alias de 'injection' (SQLi não é separável das outras heurísticas no nível de categoria).",
    ),
    "injection": Pack(
        name="injection",
        categories=frozenset({"discovery_injection", "injection_heuristics", "correlation"}),
        description="Família completa de injeções (SQLi, XSS refletido, SSTI, LDAP e command injection).",
    ),
    "bac": Pack(
        name="bac",
        categories=frozenset({"discovery_bac", "access_control"}),
        description="Broken Access Control / IDOR (crawler autenticado, provisionamento via OpenAPI, correlação).",
    ),
    # Mesma classe de bug de novo: session_fixation_checker.py e
    # password_reset_token_predictability.py usam "authentication_generic",
    # categoria também órfã antes desta correção (sempre rodavam,
    # independente do --pack).
    "authentication": Pack(
        name="authentication",
        categories=frozenset({"authentication", "authentication_generic"}),
        description="Falhas de autenticação, sessão e validação de tokens (ex.: JWT, fixação de sessão).",
    ),
    "crypto": Pack(
        name="crypto",
        categories=frozenset({"cryptographic_failures"}),
        description="Falhas criptográficas e proteção insuficiente de transporte/segredos.",
    ),
    "misconfig": Pack(
        name="misconfig",
        categories=frozenset({"misconfiguration_general"}),
        description="Configurações inseguras e controles HTTP defensivos ausentes.",
    ),
    # Mesma classe de bug: os 4 módulos de heurística SSRF genérica
    # (callback/internal-ip/redirect-chain/webhook) usam category=
    # "ssrf_generic", diferente do "ssrf" que só o wp_ssrf_detection.py usa.
    # "ssrf_generic" era órfã (nenhum pacote a reivindicava) -> mesma regra
    # de fallback fazia esses 4 módulos rodarem sempre, independente do
    # --pack escolhido. Unificado aqui.
    "ssrf": Pack(
        name="ssrf",
        categories=frozenset({"ssrf", "ssrf_generic"}),
        description="Detecção de Server-Side Request Forgery e superfícies relacionadas.",
    ),
    "privilege": Pack(
        name="privilege",
        categories=frozenset({"privilege_escalation"}),
        description="Sondagem de escalação vertical de privilégio.",
    ),
    "mass-assignment": Pack(
        name="mass-assignment",
        categories=frozenset({"mass_assignment"}),
        description="Detecção de superfícies de mass assignment / over-posting.",
    ),
    "recon": Pack(
        name="recon",
        categories=frozenset({"site_profiling", "recon", "service_enumeration"}),
        description="Reconhecimento e classificação inicial da superfície do alvo.",
    ),
    "vulnerability": Pack(
        name="vulnerability",
        # "vulnerable_components" (dependency_confusion_scanner.py) também
        # era órfã antes desta correção -- reivindicada aqui pra parar de
        # vazar pra dentro de pacotes que não pedem correlação com base
        # pública de vulnerabilidade (ex.: --pack bounty).
        categories=frozenset({"vulnerability_matching", "vulnerable_components"}),
        description="Correlação de componentes/versões detectados contra bases públicas de vulnerabilidades.",
    ),
    # Pensado pro fluxo de bug bounty (ex.: Wordfence Bug Bounty Program):
    # o objetivo ali é achar vulnerabilidade NOVA num plugin/tema, não
    # confirmar CVE já catalogado -- por isso "vulnerability_matching" e
    # "vulnerable_components" ficam de fora de propósito (correlação com
    # NVD/Wordfence Intelligence não paga bounty, só reconfirma o que já é
    # público). Inclui reconhecimento (pra saber contra o que está rodando)
    # + toda classe de achado que o programa efetivamente recompensa:
    # injeção, BAC/IDOR, mass assignment, auth/token, cripto, SSRF, CORS,
    # upload sem restrição e misconfiguração geral.
    "bounty": Pack(
        name="bounty",
        categories=frozenset({
            # reconhecimento / contexto do alvo
            "site_profiling", "recon", "cms_detection", "plugin_detection", "rest_api",
            # classes de achado que pagam
            "discovery_injection", "injection_heuristics", "correlation",
            "discovery_bac", "access_control", "mass_assignment",
            "authentication", "authentication_generic",
            "cryptographic_failures",
            "ssrf", "ssrf_generic", "cors",
            "upload_surface", "misconfiguration_general",
            "privilege_escalation",
        }),
        description="Modo bug bounty: acha vulnerabilidade nova (sem CVE matching) -- injeção, BAC, auth, cripto, SSRF, upload.",
    ),
    "wordpress": Pack(
        name="wordpress",
        categories=frozenset({
            "aio_migration", "cms_detection", "contact_form_7", "cors",
            "duplicator", "elementor", "exposed_backup", "form_entries",
            "general", "mailpoet", "multisite", "object_cache", "plugin_detection",
            "recon", "rest_api", "ssrf", "trackback", "upload_surface",
            "vulnerability_matching", "woocommerce", "wp_statistics",
            "wpgraphql", "xmlrpc", "yoast_seo",
        }),
        description="Scanner de WordPress (detecção de plugin/tema, exposição, CVE matching).",
    ),
}


def all_pack_names() -> list[str]:
    return sorted(_PACKS.keys())


def get_pack(name: str) -> Pack | None:
    return _PACKS.get(name)


def categories_for_packs(pack_names: list[str]) -> frozenset[str] | None:
    """União das categorias de todos os pacotes pedidos. Retorna None se
    a lista estiver vazia -- None significa 'sem filtro de pacote, roda
    tudo' (distingue de frozenset() vazio, que seria 'nenhuma categoria',
    ou seja, nada rodaria)."""
    if not pack_names:
        return None
    cats: set[str] = set()
    for name in pack_names:
        pack = _PACKS.get(name)
        if pack:
            cats |= pack.categories
    return frozenset(cats)


def filter_modules_by_packs(module_classes: list[type], pack_names: list[str]) -> list[type]:
    """Filtra classes de módulo pelas categorias dos pacotes pedidos.

    Um módulo passa se:
      - nenhum pacote foi pedido (roda tudo), OU
      - a category dele está na união das categorias dos pacotes pedidos, OU
      - a category dele não pertence a NENHUM pacote conhecido (módulo
        "sempre relevante" -- não deixamos ele de fora só porque não foi
        classificado; melhor rodar a mais que a menos numa ferramenta de
        segurança).
    """
    wanted = categories_for_packs(pack_names)
    if wanted is None:
        return module_classes

    # todas as categorias que QUALQUER pacote reivindica -- usado pra
    # detectar módulo "órfão" (category que nenhum pacote conhece)
    all_claimed: set[str] = set()
    for pack in _PACKS.values():
        all_claimed |= pack.categories

    result = []
    for cls in module_classes:
        spec = getattr(cls, "__wraith_spec__", None)
        category = getattr(spec, "category", None) if spec else None

        if category is None:
            result.append(cls)          # sem spec/category -> sempre roda
        elif category in wanted:
            result.append(cls)          # categoria pedida explicitamente
        elif category not in all_claimed:
            result.append(cls)          # órfã -> sempre relevante

    return result

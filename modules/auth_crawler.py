"""
modules/auth_crawler.py

Crawler autenticado, um por identidade configurada. Diferente do
crawler.py anônimo (que descobre PARÂMETRO testável), este descobre
RECURSO com identificador -- URL cujo path ou query tem um segmento que
parece ID (inteiro positivo ou UUID) -- e registra qual identidade
tocou nele durante navegação NORMAL, autenticada, sem nenhum payload.

É essa observação (não adivinhação sequencial de ID) que faz o IDOR
resultante generalizar pra qualquer esquema de identificador -- inclusive
UUID, que um scanner de "tenta id=1,2,3..." nunca pegaria.

Um módulo por identidade: cada identidade registrada em
utils.requester.registered_identities() gera uma instância lógica de
varredura (mesma classe, requires vazio -- roda uma vez por identidade
dentro do próprio run(), não uma vez por módulo registrado, porque o
número de identidades só é conhecido em tempo de execução, não de
importação de módulo).
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.requester import get_as, registered_identities
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

MAX_PAGES_PER_IDENTITY = 15
MAX_DEPTH = 2

# path segment ou valor de query puramente numérico (id sequencial) ou
# formato de UUID -- os dois esquemas de identificador mais comuns em app
# real. Deliberadamente NÃO tenta adivinhar/gerar IDs -- só reconhece os
# que já apareceram organicamente na navegação.
_ID_PATTERN = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)


def _resource_hash(url_template: str, resource_id: str) -> str:
    return hashlib.sha1(f"{url_template}:{resource_id}".encode()).hexdigest()[:10]


def _extract_resources(url: str) -> list[dict]:
    """Encontra todo segmento de path ou valor de query que parece ID
    nessa URL específica. Retorna uma entrada por ID encontrado, com um
    "template" da URL (ID substituído por um placeholder) que serve pra
    agrupar "o mesmo tipo de recurso" entre identidades diferentes."""
    parsed = urlparse(url)
    resources = []

    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if _ID_PATTERN.match(seg):
            template_segments = segments.copy()
            template_segments[i] = "{id}"
            template = parsed._replace(path="/".join(template_segments), query="").geturl()
            resources.append({"url_template": template, "resource_id": seg, "id_location": "path", "concrete_url": url})

    if parsed.query:
        from urllib.parse import parse_qs
        for key, values in parse_qs(parsed.query).items():
            for v in values:
                if _ID_PATTERN.match(v):
                    template = parsed._replace(query="").geturl()
                    resources.append({
                        "url_template": template, "resource_id": v,
                        "id_location": f"query:{key}", "concrete_url": url,
                    })

    return resources


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


@discovery_module(
    requires=[Requirement("config.identity_available", min_confidence=0.5)],
    produces=[Produces("surface.resource.*.owned_by.*", durable=True)],
    cost=MAX_PAGES_PER_IDENTITY * 3,  # estimativa -- multiplicado pelo nº de identidades em tempo real
    category="discovery_bac",
    display_name="Varredura Autenticada por Identidade",
    summary="Rastreia o alvo uma vez por identidade configurada, registrando qual recurso com identificador (path/query) cada identidade tocou durante navegação normal.",
)
class AuthenticatedCrawler:
    name = "auth_crawler"

    def run(self, target: str):
        identities = registered_identities()
        if not identities:
            print("[auth_crawler] nenhuma identidade registrada -- nada a fazer "
                  "(configure com register_identity() antes do scan).")
            return None

        all_facts = []

        for identity in identities:
            visited: set[str] = set()
            queue: list[tuple[str, int]] = [(target, 0)]
            found_this_identity: dict[str, dict] = {}

            while queue and len(visited) < MAX_PAGES_PER_IDENTITY:
                url, depth = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                r = get_as(identity, url)
                if not r or r.status_code != 200:
                    continue

                for res in _extract_resources(url):
                    h = _resource_hash(res["url_template"], res["resource_id"])
                    found_this_identity[h] = res

                content_type = r.headers.get("Content-Type", "")
                if "html" not in content_type and content_type != "":
                    continue

                # BUG REAL encontrado testando contra um alvo com navegação
                # mais profunda (29/08/2026): extração de recurso E
                # enfileiramento pra continuar o BFS estavam os dois presos
                # dentro do MESMO "if depth < MAX_DEPTH" -- então um link
                # que aparecia numa página exatamente no limite de
                # profundidade nunca tinha seu recurso examinado, mesmo sem
                # precisar seguir esse link mais fundo ainda. Num fluxo
                # real de app (home -> minha conta -> meus pedidos -> pedido
                # específico), isso é o suficiente pra nunca achar nada --
                # exatamente o que aconteceu no teste. Agora são duas
                # decisões separadas: extrair recurso de todo link
                # encontrado, sempre; enfileirar pra seguir crawleando só
                # se ainda há profundidade de sobra.
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    next_url = urljoin(url, a["href"]).split("#")[0]
                    if not _same_origin(target, next_url):
                        continue

                    for res in _extract_resources(next_url):
                        h = _resource_hash(res["url_template"], res["resource_id"])
                        found_this_identity[h] = res

                    if depth < MAX_DEPTH and next_url not in visited:
                        queue.append((next_url, depth + 1))

            for h, res in found_this_identity.items():
                key = f"surface.resource.{h}.owned_by.{identity}"
                all_facts.append(fact(
                    key, {**res, "identity": identity}, 0.9, self.name, target, identity=identity,
                ))

            print(f"[auth_crawler] identidade '{identity}': {len(found_this_identity)} recurso(s) com ID encontrado(s).")

        if not all_facts:
            return None
        return ModuleResult(facts=all_facts)

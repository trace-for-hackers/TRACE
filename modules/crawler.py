"""
modules/crawler.py

Módulo raiz do TRACE -- sem ele, nada mais roda. Faz uma varredura BFS
limitada (mesma origem, profundidade e nº de páginas com teto) e extrai
todo PARÂMETRO testável que encontrar: query string de qualquer link, e
campo de formulário (GET ou POST). Cada parâmetro vira um fato
`surface.param.<hash>` -- é isso que os módulos de heurística de injeção
consomem via Requirement("surface.param.*") wildcard (mesmo padrão já
validado no WRAITH com tech.*).

Por que hash e não o nome do parâmetro na fact_key: dois endpoints
diferentes podem ter parâmetro com o mesmo nome ("id" aparece em
praticamente todo app) -- a fact_key precisa ser única por (url, method,
param), não só pelo nome do parâmetro.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from utils.requester import get
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

MAX_PAGES = 15
MAX_DEPTH = 2


def _param_hash(url: str, method: str, param: str) -> str:
    raw = f"{method.upper()}:{url}:{param}"
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


@discovery_module(
    requires=(),
    produces=[Produces("surface.param.*", durable=True)],
    cost=MAX_PAGES,
    category="discovery_injection",
    display_name="Varredura de Superfície de Ataque",
    summary="Rastreia o alvo (BFS limitado, mesma origem) extraindo todo parâmetro testável: query string e campo de formulário, GET ou POST.",
)
class Crawler:
    name = "crawler"

    def run(self, target: str):
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(target, 0)]
        discovered: dict[str, dict] = {}   # hash -> {url, method, param}

        while queue and len(visited) < MAX_PAGES:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            r = get(url)
            if not r or r.status_code != 200:
                continue

            content_type = r.headers.get("Content-Type", "")
            if "html" not in content_type and content_type != "":
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            # query string da própria URL visitada -- guarda a URL BASE (sem
            # a query), não a URL com "?param=valor" ainda grudado. BUG REAL
            # encontrado testando contra um alvo de verdade: se a URL salva
            # já tem "?id=1" e o _send() de injection_heuristics.py manda
            # params={"id": "1'"}, requests NÃO substitui -- ele ANEXA,
            # resultando em "?id=1&id=1'" (parâmetro duplicado). Diferentes
            # stacks de backend tratam isso de forma diferente (PHP pega o
            # ÚLTIMO valor, outros pegam o primeiro) -- o payload de teste
            # podia silenciosamente nunca chegar a valer nada, de forma
            # inconsistente por alvo. Guardando só a URL base, o params=
            # do _send() controla a query inteira, sem duplicata.
            base_url = url.split("?")[0]
            for param in parse_qs(urlparse(url).query):
                h = _param_hash(base_url, "GET", param)
                discovered[h] = {"url": base_url, "method": "GET", "param": param}

            # formulários
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                if not _same_origin(target, action):
                    continue
                for field in form.find_all(["input", "select", "textarea"]):
                    name = field.get("name")
                    if not name:
                        continue
                    h = _param_hash(action, method, name)
                    discovered[h] = {"url": action, "method": method, "param": name}

            # links pra continuar o BFS + capturar query string deles também
            if depth < MAX_DEPTH:
                for a in soup.find_all("a", href=True):
                    next_url = urljoin(url, a["href"]).split("#")[0]
                    if _same_origin(target, next_url) and next_url not in visited:
                        queue.append((next_url, depth + 1))
                        next_base = next_url.split("?")[0]
                        for param in parse_qs(urlparse(next_url).query):
                            h = _param_hash(next_base, "GET", param)
                            discovered[h] = {"url": next_base, "method": "GET", "param": param}

        if not discovered:
            return None

        facts = [
            fact(f"surface.param.{h}", info, 0.9, self.name, target)
            for h, info in discovered.items()
        ]
        return ModuleResult(facts=facts)

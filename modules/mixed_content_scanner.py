"""
modules/mixed_content_scanner.py

Pagina servida em HTTPS carregando script/imagem/CSS/iframe via HTTP
puro -- "mixed content". Passivo, uma requisicao so. So faz sentido
rodar contra alvo HTTPS (pagina HTTP nao tem "mixed" nenhum, e tudo
inseguro igual).

Script/iframe em HTTP dentro de pagina HTTPS e o caso mais grave
(navegador moderno BLOQUEIA isso -- "active mixed content" -- mas
indica que o codigo-fonte ainda referencia recurso HTTP, e nem todo
navegador/config bloqueia); imagem/CSS e "passive mixed content"
(navegador geralmente so avisa, nao bloqueia) -- menos grave, mas ainda
sinal de configuracao incompleta de HTTPS.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

# tag -> (atributo de URL, e "ativo" -- navegador bloqueia -- ou "passivo")
_TAGS_TO_CHECK = {
    "script": ("src", True),
    "iframe": ("src", True),
    "link": ("href", True),   # CSS via <link> pode carregar JS via @import, tratado como ativo
    "img": ("src", False),
    "audio": ("src", False),
    "video": ("src", False),
}


def find_mixed_content(html: str, page_url: str) -> list[dict]:
    """Funcao pura -- recebe HTML ja baixado (a pagina tem que ja ser
    HTTPS, checagem de esquema e do run()) e devolve todo recurso
    referenciado via HTTP puro. Testavel sem rede."""
    soup = BeautifulSoup(html or "", "html.parser")
    results = []

    for tag_name, (attr, is_active) in _TAGS_TO_CHECK.items():
        for tag in soup.find_all(tag_name):
            url = tag.get(attr)
            if not url:
                continue
            resolved = urljoin(page_url, url)
            if urlparse(resolved).scheme == "http":
                results.append({"tag": tag_name, "url": resolved, "active": is_active})

    return results


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="cryptographic_failures",
    display_name="Scanner de Conteudo Misto (Mixed Content)",
    summary="Pagina HTTPS carregando script/imagem/CSS via HTTP puro -- passivo, uma requisicao so, so roda contra alvo HTTPS.",
)
class MixedContentScanner:
    name = "mixed_content_scanner"

    def run(self, target: str):
        if not target.startswith("https://"):
            return None  # nao existe "misto" numa pagina que ja e toda HTTP

        r = get(target)
        if r is None:
            return None

        mixed = find_mixed_content(r.text, target)
        if not mixed:
            return None

        findings = []
        for item in mixed:
            block_note = "navegador moderno costuma BLOQUEAR isso (conteudo ativo)" if item["active"] else "navegador costuma permitir com aviso (conteudo passivo)"
            findings.append({
                "title": f"Conteudo misto: <{item['tag']}> carregado via HTTP em pagina HTTPS",
                "severity": "high" if item["active"] else "medium",
                "module": self.name,
                "category": "cryptographic_failures",
                "endpoint": item["url"],
                "description": (
                    f"A pagina HTTPS {target} carrega <{item['tag']}> a partir de '{item['url']}', "
                    f"em HTTP puro -- {block_note}."
                ),
                "business_impact": (
                    "Recurso carregado via HTTP pode ser interceptado/modificado em transito -- "
                    "se for script, um atacante na rede pode injetar codigo arbitrario na pagina, "
                    "mesmo com o restante do site em HTTPS."
                ),
                "remediation": "Trocar a referencia pra HTTPS, ou usar URL relativa ao protocolo (//) em vez de 'http://' fixo.",
                "evidence": {"tag": item["tag"], "resource_url": item["url"], "blocked_by_modern_browsers": item["active"]},
            })

        return ModuleResult(findings=findings)

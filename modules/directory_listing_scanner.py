"""
modules/directory_listing_scanner.py

Testa uma lista curta de caminho comum (uploads, backup, assets...) por
listagem de diretorio aberta -- servidor mal configurado que devolve o
indice de arquivo em vez de 403/404 quando nao ha index.html/index.php
na pasta.

Deteccao por MARCADOR de texto (nao por parsing de HTML complexo): os
tres formatos mais comuns (Apache "Index of /", nginx autoindex,
"Directory listing for" do http.server/SimpleHTTPRequestHandler do
Python) todos usam frase fixa reconhecivel no título/cabeçalho da
página -- suficiente pra identificar sem falso positivo.
"""

from __future__ import annotations

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_COMMON_PATHS = [
    "/images/", "/img/", "/uploads/", "/upload/", "/backup/", "/backups/",
    "/files/", "/assets/", "/static/", "/tmp/", "/temp/", "/logs/", "/log/",
    "/config/", "/data/", "/db/", "/old/", "/test/", "/private/", "/media/",
]

_LISTING_MARKERS = (
    "index of /",
    "directory listing for",
    "parent directory",
    "[to parent directory]",
)


def is_directory_listing(html: str) -> bool:
    if not html:
        return False
    lower = html.lower()
    return any(marker in lower for marker in _LISTING_MARKERS)


@discovery_module(
    requires=(),
    produces=[],
    cost=len(_COMMON_PATHS),
    category="misconfiguration_general",
    display_name="Scanner de Listagem de Diretorio",
    summary="Testa caminho comum (uploads, backup, assets, etc.) por listagem de diretorio aberta -- reconhece Apache, nginx e Python http.server pelo marcador de texto no cabecalho da pagina.",
)
class DirectoryListingScanner:
    name = "directory_listing_scanner"

    def run(self, target: str):
        findings = []

        for path in _COMMON_PATHS:
            r = get(target.rstrip("/") + path)
            if r is None or r.status_code != 200:
                continue

            if is_directory_listing(r.text):
                findings.append({
                    "title": f"Listagem de diretorio aberta: {path}",
                    "severity": "medium",
                    "module": self.name,
                    "category": "security_misconfiguration",
                    "endpoint": target.rstrip("/") + path,
                    "description": (
                        f"O caminho {path} devolve listagem de arquivo do diretorio em vez "
                        f"de 403/404 -- qualquer arquivo ali dentro fica navegavel sem link direto."
                    ),
                    "business_impact": "Arquivo que deveria ficar oculto (backup, log, config, dado temporario) pode ser descoberto e baixado so navegando a listagem.",
                    "remediation": "Desabilitar listagem de diretorio no servidor web (Apache: Options -Indexes; nginx: autoindex off;), ou colocar um index.html vazio em cada pasta.",
                    "evidence": {"path": path, "status": r.status_code},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)

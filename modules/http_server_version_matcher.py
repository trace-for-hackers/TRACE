"""
modules/http_server_version_matcher.py

Extrai versao do header Server/X-Powered-By e cruza contra uma tabela
pequena e CURADA A MAO de CVE conhecido e bem documentado -- nao e um
feed ao vivo tipo Wordfence Intelligence (core/vuln_db.py), e uma lista
pequena de propósito, cada entrada verificada contra fonte primaria
antes de entrar aqui (ver comentario por entrada).

Match por versao EXATA (nao faixa), de proposito: e mais conservador,
sem falso positivo por causa de logica de comparacao de versao errada.
Servidor com versao fora da lista simplesmente nao gera achado aqui --
nao significa que esta seguro, so que nao ha CVE conhecido e exato
nessa tabela pra essa versao especifica.
"""

from __future__ import annotations

import re

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

# (regex do header, nome do produto) -> lista de (versao exata, cve, severidade, descricao)
# cada entrada verificada via busca antes de entrar aqui (09/2026)
_KNOWN_VULNERABLE_VERSIONS = {
    "apache": [
        ("2.4.49", "CVE-2021-41773", "critical", "Path traversal / RCE -- corrigido incompleto na 2.4.50, corrigido de verdade só na 2.4.51."),
        ("2.4.50", "CVE-2021-42013", "critical", "Mesma falha de path traversal/RCE do CVE-2021-41773, correção anterior era incompleta -- atualizar direto pra 2.4.51+."),
    ],
    "nginx": [
        ("1.3.9", "CVE-2013-2028", "high", "Stack buffer overflow via chunked transfer encoding malformado."),
    ],
    "openssl": [
        ("1.0.1f", "CVE-2014-0160", "critical", "Heartbleed -- vazamento de memória do processo via extensão heartbeat do TLS."),
    ],
}

_HEADER_NAMES_TO_CHECK = ("server", "x-powered-by")


def extract_product_and_version(header_value: str) -> tuple[str, str] | None:
    """Extrai (produto_em_minusculo, versao) de um valor de header tipo
    'Apache/2.4.49 (Unix) OpenSSL/1.0.1f' -- retorna só o PRIMEIRO
    produto/versão reconhecido (um header pode declarar vários, ex.
    Apache E OpenSSL no mesmo valor -- o caller itera por produto
    conhecido pra pegar todos, ver find_version_for_product).

    BUG REAL encontrado testando: versão do OpenSSL usa sufixo de letra
    (1.0.1f, 1.0.2a) -- regex só com dígito+ponto cortava o sufixo,
    virando "1.0.1" em vez de "1.0.1f", quebrando o match exato contra
    a tabela de CVE (que usa a versão completa com letra)."""
    match = re.search(r"([a-zA-Z][a-zA-Z0-9_-]*)/(\d+(?:\.\d+)*[a-zA-Z]?)", header_value or "")
    if not match:
        return None
    return match.group(1).lower(), match.group(2)


def find_version_for_product(header_value: str, product: str) -> str | None:
    """Diferente de extract_product_and_version (que pega só o
    primeiro match) -- procura especificamente o PRODUTO pedido em
    qualquer posição do header, pra casos como
    'Apache/2.4.49 (Unix) OpenSSL/1.0.1f' onde os dois importam."""
    pattern = re.escape(product) + r"/(\d+(?:\.\d+)*[a-zA-Z]?)"
    match = re.search(pattern, header_value or "", re.IGNORECASE)
    return match.group(1) if match else None


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="vulnerability_matching",
    display_name="Correlator de Versão de Servidor HTTP",
    summary="Extrai versão de Server/X-Powered-By e cruza contra tabela curada de CVE conhecido e bem documentado -- match exato de versão, não faixa.",
)
class HTTPServerVersionMatcher:
    name = "http_server_version_matcher"

    def run(self, target: str):
        r = get(target)
        if r is None:
            return None

        findings = []
        headers = {k.lower(): v for k, v in r.headers.items()}

        for header_name in _HEADER_NAMES_TO_CHECK:
            header_value = headers.get(header_name)
            if not header_value:
                continue

            for product, vulnerable_versions in _KNOWN_VULNERABLE_VERSIONS.items():
                detected_version = find_version_for_product(header_value, product)
                if not detected_version:
                    continue

                for vuln_version, cve, severity, description in vulnerable_versions:
                    if detected_version == vuln_version:
                        findings.append({
                            "title": f"{product.capitalize()} {detected_version} com CVE conhecido: {cve}",
                            "severity": severity,
                            "module": self.name,
                            "category": "vulnerable_components",
                            "endpoint": target,
                            "description": (
                                f"O header '{header_name}' declara {product} {detected_version} -- "
                                f"versão exata com vulnerabilidade documentada ({cve}). {description}"
                            ),
                            "business_impact": description,
                            "remediation": f"Atualizar {product} para uma versão sem o CVE {cve} documentado.",
                            "evidence": {"header": header_name, "header_value": header_value,
                                         "product": product, "version": detected_version, "cve": cve},
                        })

        if not findings:
            return None
        return ModuleResult(findings=findings)

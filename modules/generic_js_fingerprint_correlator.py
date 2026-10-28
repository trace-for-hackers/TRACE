"""
modules/generic_js_fingerprint_correlator.py

Generaliza wp_assets_extractor.py (que só reconhece plugin/tema
WordPress) pra biblioteca JS de front-end em QUALQUER stack -- jQuery,
Bootstrap, Lodash, etc. Extrai versao do NOME DO ARQUIVO ou do
querystring "?ver=" (convencao comum, inclusive fora do WordPress) e
cruza contra tabela pequena e curada de CVE de biblioteca JS conhecida,
usando comparacao de FAIXA de versao (packaging.version, ja usado em
core/vuln_db.py) -- diferente de http_server_version_matcher.py, que
usa match exato.

Dados de CVE verificados via busca antes de escrever (09/2026):
jQuery <3.5.0 (CVE-2020-11022/11023), jQuery <1.9.0 (CVE-2020-7656),
Lodash <4.17.12 (CVE-2019-10744).
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup
from packaging.version import Version, InvalidVersion

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

# nome da lib -> regex que reconhece o nome de arquivo (com ou sem
# ".min", separador "-" ou ".") -- versao vem do grupo capturado
_LIBRARY_FILENAME_PATTERNS = {
    "jquery": r"jquery[.-](\d+\.\d+\.\d+)",
    "bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
    "lodash": r"lodash[.-](\d+\.\d+\.\d+)",
    "angular": r"angular[.-](\d+\.\d+\.\d+)",
    "moment": r"moment[.-](\d+\.\d+\.\d+)",
}

# lib -> lista de (versao_maxima_exclusiva, cve, severidade, descricao)
_VULNERABLE_RANGES = {
    "jquery": [
        ("3.5.0", "CVE-2020-11022/11023", "high", "XSS via .html()/.append() com HTML de fonte não confiável, mesmo após sanitização prévia."),
        ("1.9.0", "CVE-2020-7656", "medium", "XSS via método .load() não removendo tag <script> com espaço no fechamento."),
    ],
    "lodash": [
        ("4.17.12", "CVE-2019-10744", "critical", "Prototype pollution via _.defaultsDeep, permite modificar Object.prototype globalmente."),
    ],
}


def extract_library_version_from_url(url: str) -> tuple[str, str] | None:
    """Tenta casar o nome do arquivo contra cada padrão de biblioteca
    conhecida; se não achar no nome, tenta o querystring '?ver=' (mesma
    convenção que wp_assets_extractor.py já usa pra WordPress, mas
    aqui não depende de wp-content/ no caminho)."""
    for lib, pattern in _LIBRARY_FILENAME_PATTERNS.items():
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            return lib, match.group(1)

    ver_match = re.search(r"[?&]ver=(\d+\.\d+\.\d+)", url)
    if ver_match:
        for lib in _LIBRARY_FILENAME_PATTERNS:
            if lib in url.lower():
                return lib, ver_match.group(1)

    return None


def find_vulnerable_ranges(library: str, version: str) -> list[tuple[str, str, str]]:
    """Retorna [(cve, severidade, descricao), ...] pra toda faixa
    vulneravel que a versao detectada cai dentro -- pode ser mais de
    uma (ex.: jQuery 1.5 cai em duas faixas diferentes ao mesmo tempo)."""
    ranges = _VULNERABLE_RANGES.get(library, [])
    try:
        detected = Version(version)
    except InvalidVersion:
        return []

    matches = []
    for max_exclusive, cve, severity, description in ranges:
        try:
            if detected < Version(max_exclusive):
                matches.append((cve, severity, description))
        except InvalidVersion:
            continue
    return matches


def find_script_urls(html: str, page_url: str) -> list[str]:
    from urllib.parse import urljoin
    soup = BeautifulSoup(html or "", "html.parser")
    urls = []
    for tag in soup.find_all("script", src=True):
        urls.append(urljoin(page_url, tag["src"]))
    return urls


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="vulnerability_matching",
    display_name="Correlator de Fingerprint de Biblioteca JS",
    summary="Extrai versão de biblioteca JS front-end (jQuery, Bootstrap, Lodash...) via nome de arquivo/querystring, generalizado além de WordPress, e cruza contra tabela curada de CVE por faixa de versão.",
)
class GenericJSFingerprintCorrelator:
    name = "generic_js_fingerprint_correlator"

    def run(self, target: str):
        r = get(target)
        if r is None:
            return None

        script_urls = find_script_urls(r.text, target)
        findings = []
        already_reported = set()

        for url in script_urls:
            detected = extract_library_version_from_url(url)
            if not detected:
                continue
            library, version = detected

            if (library, version) in already_reported:
                continue
            already_reported.add((library, version))

            for cve, severity, description in find_vulnerable_ranges(library, version):
                findings.append({
                    "title": f"{library.capitalize()} {version} com CVE conhecido: {cve}",
                    "severity": severity,
                    "module": self.name,
                    "category": "vulnerable_components",
                    "endpoint": url,
                    "description": (
                        f"A página carrega {library} versão {version} (de '{url}') -- "
                        f"faixa com vulnerabilidade documentada ({cve}). {description}"
                    ),
                    "business_impact": description,
                    "remediation": f"Atualizar {library} para uma versão acima da faixa vulnerável documentada em {cve}.",
                    "evidence": {"script_url": url, "library": library, "version": version, "cve": cve},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)

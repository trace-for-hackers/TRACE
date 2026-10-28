"""
modules/api_gateway_fingerprint_correlator.py

Diferente de http_server_version_matcher.py (que le o header Server,
facil de esconder/trocar) -- este modulo reconhece Kong especificamente
via headers CARACTERISTICOS que o gateway adiciona por padrao
(X-Kong-*, Via: kong/x.x.x), que continuam presentes mesmo quando o
operador escondeu o Server header por seguranca.

Dado de CVE verificado via busca antes de escrever (09/2026):
Kong < 2.3.2.0 -- CVE-2021-27306, bypass de rota autenticada via
heranca indevida de configuracao de plugin JWT em subrota.
"""

from __future__ import annotations

import re

from packaging.version import Version, InvalidVersion

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_KONG_VERSION_PATTERN = re.compile(r"kong/(\d+\.\d+\.\d+)", re.IGNORECASE)

_KONG_VULNERABLE_RANGES = [
    ("2.3.2.0", "CVE-2021-27306", "high",
     "Bypass de rota autenticada: subrota herda config de plugin JWT da rota pai de forma "
     "que uma rota irmã sem autenticação pode acessar dado que deveria exigir token, "
     "quando há proxy normalizando path entre o Kong e a aplicação."),
]


def has_kong_signature(headers: dict) -> bool:
    """True se qualquer header X-Kong-* estiver presente, OU se 'kong'
    aparecer no header Via -- os dois continuam presentes mesmo se o
    operador esconder o header Server por segurança."""
    lower_keys = {k.lower() for k in headers}
    if any(k.startswith("x-kong-") for k in lower_keys):
        return True
    via = headers.get("Via") or headers.get("via", "")
    return "kong" in via.lower()


def extract_kong_version(headers: dict) -> str | None:
    via = headers.get("Via") or headers.get("via", "")
    match = _KONG_VERSION_PATTERN.search(via)
    return match.group(1) if match else None


def find_kong_vulnerabilities(version: str) -> list[tuple[str, str, str]]:
    try:
        detected = Version(version)
    except InvalidVersion:
        return []

    matches = []
    for max_exclusive, cve, severity, description in _KONG_VULNERABLE_RANGES:
        try:
            if detected < Version(max_exclusive):
                matches.append((cve, severity, description))
        except InvalidVersion:
            continue
    return matches


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="vulnerability_matching",
    display_name="Correlator de Fingerprint de API Gateway",
    summary="Reconhece Kong via headers característicos (X-Kong-*, Via: kong/) mesmo quando o Server header está escondido, e cruza versão detectada contra CVE conhecido.",
)
class APIGatewayFingerprintCorrelator:
    name = "api_gateway_fingerprint_correlator"

    def run(self, target: str):
        r = get(target)
        if r is None:
            return None

        headers = dict(r.headers)
        if not has_kong_signature(headers):
            return None

        version = extract_kong_version(headers)
        if not version:
            return None  # Kong confirmado, mas sem versão -- nada pra correlacionar com CVE

        findings = []
        for cve, severity, description in find_kong_vulnerabilities(version):
            findings.append({
                "title": f"Kong {version} com CVE conhecido: {cve}",
                "severity": severity,
                "module": self.name,
                "category": "vulnerable_components",
                "endpoint": target,
                "description": (
                    f"Detectado Kong {version} via header característico (Via/X-Kong-*), não "
                    f"pelo Server header -- {description}"
                ),
                "business_impact": description,
                "remediation": f"Atualizar Kong para versão acima da faixa vulnerável documentada em {cve}.",
                "evidence": {"detected_version": version, "cve": cve, "headers": headers},
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)

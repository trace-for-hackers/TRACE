"""
modules/security_headers_baseline.py

Checagem de header de segurança GENÉRICA -- diferente de
modules/security_headers.py (que hoje existe só dentro do pacote
WordPress). Roda contra QUALQUER alvo, sem depender de identidade nem
spec OpenAPI -- é o módulo mais barato e mais raiz possível: uma
requisição, sete headers checados.

Categoria "misconfiguration_general" de propósito, separada do
"security_headers" original do WordPress -- evita rodar dobrado quando
--pack wordpress também estiver ativo (os dois vão coexistir até o
original ser generalizado/aposentado, ver MODULES.md).
"""

from __future__ import annotations

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult


# nome do header -> (severidade se AUSENTE, o que checar no valor quando
# presente, mensagem). "presence_only" significa que só a ausência
# importa; alguns headers têm validação de valor além de presença.
_HEADER_CHECKS = {
    "Content-Security-Policy": {
        "severity_missing": "medium",
        "description": "Sem CSP, o navegador não tem nenhuma restrição extra contra XSS refletido/DOM-based.",
    },
    "X-Frame-Options": {
        "severity_missing": "low",
        "description": "Sem X-Frame-Options (ou CSP frame-ancestors), a página pode ser embutida em iframe de terceiro -- risco de clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity_missing": "low",
        "description": "Sem 'nosniff', navegador pode reinterpretar o Content-Type da resposta, abrindo espaço pra ataque de MIME sniffing.",
    },
    "Strict-Transport-Security": {
        "severity_missing": "medium",
        "description": "Sem HSTS, a primeira visita (ou qualquer link http:// antigo) fica vulnerável a downgrade/SSL stripping.",
        "https_only": True,  # só faz sentido cobrar isso se o alvo já é HTTPS
    },
    "Referrer-Policy": {
        "severity_missing": "info",
        "description": "Sem Referrer-Policy, a URL completa (às vezes com token/parâmetro sensível) pode vazar no header Referer pra terceiro.",
    },
}


def check_headers(headers: dict, is_https: bool) -> list[dict]:
    """Função pura -- recebe os headers já normalizados (case-insensitive,
    ver run()) e devolve a lista de checagens que falharam. Testável sem
    rede nenhuma."""
    missing = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, rule in _HEADER_CHECKS.items():
        if rule.get("https_only") and not is_https:
            continue
        if header_name.lower() not in lower_headers:
            missing.append({
                "header": header_name,
                "severity": rule["severity_missing"],
                "description": rule["description"],
            })

    # X-Frame-Options não conta como ausente se CSP já tem frame-ancestors
    csp = lower_headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        missing = [m for m in missing if m["header"] != "X-Frame-Options"]

    return missing


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="misconfiguration_general",
    display_name="Baseline de Headers de Segurança",
    summary="Checa presença de CSP, X-Frame-Options, HSTS, X-Content-Type-Options e Referrer-Policy numa única requisição -- genérico, não depende de identidade nem WordPress.",
)
class SecurityHeadersBaseline:
    name = "security_headers_baseline"

    def run(self, target: str):
        r = get(target)
        if r is None:
            return None

        is_https = target.startswith("https://")
        missing = check_headers(dict(r.headers), is_https)

        if not missing:
            return None

        findings = [{
            "title": f"Header de segurança ausente: {m['header']}",
            "severity": m["severity"],
            "module": self.name,
            "category": "security_misconfiguration",
            "endpoint": target,
            "description": m["description"],
            "business_impact": m["description"],
            "remediation": f"Adicionar o header '{m['header']}' na resposta do servidor.",
            "evidence": {"missing_header": m["header"], "all_response_headers": dict(r.headers)},
        } for m in missing]

        return ModuleResult(findings=findings)

"""
modules/cors_misconfiguration_scanner.py

Manda uma requisição com Origin claramente forjado e vê se o servidor
REFLETE esse Origin de volta em Access-Control-Allow-Origin -- combinado
com Access-Control-Allow-Credentials: true, isso significa que
QUALQUER site (não só os autorizados) pode fazer requisição autenticada
(com cookie) contra esse alvo e ler a resposta. Sinal limpo, uma
requisição só, sem precisar de identidade nem spec.
"""

from __future__ import annotations

from utils.requester import get_with_headers
from knowledge.contracts import discovery_module, Produces
from knowledge.result import ModuleResult

_PROBE_ORIGIN = "https://surfacer-cors-probe.invalid"


def evaluate_cors_response(headers: dict) -> dict | None:
    """Função pura -- recebe os headers de resposta já normalizados
    (case-insensitive) e devolve o veredito, ou None se não há CORS
    perigoso. Testável sem rede."""
    lower = {k.lower(): v for k, v in headers.items()}
    acao = lower.get("access-control-allow-origin")
    acac = lower.get("access-control-allow-credentials", "").lower()

    if acao is None:
        return None  # sem CORS nenhum -- não é achado (é o padrão seguro)

    reflects_arbitrary_origin = acao == _PROBE_ORIGIN
    is_wildcard_with_credentials = acao == "*" and acac == "true"

    if reflects_arbitrary_origin and acac == "true":
        return {
            "severity": "critical",
            "reason": f"Origin arbitrário ('{_PROBE_ORIGIN}') refletido de volta em Access-Control-Allow-Origin, COM Access-Control-Allow-Credentials: true",
        }
    if reflects_arbitrary_origin:
        return {
            "severity": "medium",
            "reason": f"Origin arbitrário ('{_PROBE_ORIGIN}') refletido de volta em Access-Control-Allow-Origin (sem credentials -- menos grave, mas ainda permissivo demais)",
        }
    if is_wildcard_with_credentials:
        # combinação tecnicamente inválida pela spec CORS (navegador
        # deveria rejeitar '*' junto com credentials=true), mas alguns
        # proxies/gateways mal configurados deixam passar -- vale reportar
        return {
            "severity": "high",
            "reason": "Access-Control-Allow-Origin: * combinado com Access-Control-Allow-Credentials: true -- combinação que navegador deveria rejeitar, indica configuração de CORS mal feita a mão",
        }
    return None


@discovery_module(
    requires=(),
    produces=[],
    cost=1,
    category="misconfiguration_general",
    display_name="Scanner de CORS Mal Configurado",
    summary="Envia Origin forjado e verifica se é refletido em Access-Control-Allow-Origin combinado com Allow-Credentials: true -- sinal limpo, uma requisição só.",
)
class CORSMisconfigurationScanner:
    name = "cors_misconfiguration_scanner"

    def run(self, target: str):
        r = get_with_headers(target, {"Origin": _PROBE_ORIGIN})
        if r is None:
            return None

        veredito = evaluate_cors_response(dict(r.headers))
        if veredito is None:
            return None

        return ModuleResult(findings=[{
            "title": "CORS mal configurado: Origin refletido de forma perigosa",
            "severity": veredito["severity"],
            "module": self.name,
            "category": "cors_misconfiguration",
            "endpoint": target,
            "description": veredito["reason"],
            "business_impact": (
                "Um site malicioso qualquer pode fazer requisição autenticada (com cookie da "
                "vítima) contra este alvo a partir do navegador dela, e ler a resposta -- "
                "efetivamente quebrando o isolamento entre origens que o CORS deveria garantir."
            ),
            "remediation": (
                "Nunca refletir o Origin recebido sem validar contra uma allowlist explícita "
                "de domínios confiáveis. Não combinar '*' com Allow-Credentials: true."
            ),
            "evidence": {"probe_origin": _PROBE_ORIGIN, "response_headers": dict(r.headers)},
        }])

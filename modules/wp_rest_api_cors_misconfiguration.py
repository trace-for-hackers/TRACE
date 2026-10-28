from utils.requester import get_with_headers
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


# Origin claramente não-relacionado ao alvo, usado para testar se o servidor
# faz reflect-and-allow (o padrão de falha mais comum) em vez de validar
# contra uma allowlist real de domínios confiáveis.
PROBE_ORIGIN = "https://wraith-cors-probe.invalid"


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5)],
    cost=1,
    category="cors",
    display_name="Má Configuração de CORS na REST API",
    summary="Envia um Origin arbitrário à REST API e verifica se ele é refletido em Access-Control-Allow-Origin, especialmente combinado com Allow-Credentials, que permite requisições autenticadas cross-origin de qualquer site.",
)
class WPRestAPICorsMisconfiguration:
    """
    Testa se a REST API do WordPress reflete um Origin arbitrário no header
    Access-Control-Allow-Origin -- padrão de falha comum em sites headless
    (WP como backend para Next.js/Gatsby/Astro), onde plugins de CORS são
    configurados de forma permissiva demais para "fazer funcionar rápido"
    durante o desenvolvimento, e a configuração nunca é revisitada em produção.

    Só roda depois que surface.rest_api.present é confirmado (wp_rest_routes
    ou rest_routes.py) -- testar CORS num endpoint que nem responde não tem
    sentido.

    A falha real não é "ter CORS" (CORS existe para permitir cross-origin de
    forma controlada) -- é refletir QUALQUER Origin enviado, especialmente
    quando combinado com Access-Control-Allow-Credentials: true, o que
    permite que QUALQUER site na internet faça requisições autenticadas
    (com cookie de sessão do visitante) contra a API em nome dele.
    """
    name = "wp_rest_api_cors_misconfiguration"

    def run(self, target):
        r = get_with_headers(f"{target}/wp-json/", {"Origin": PROBE_ORIGIN})
        if not r or not hasattr(r, "headers"):
            return None

        allow_origin = r.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        reflects_arbitrary_origin = allow_origin == PROBE_ORIGIN or allow_origin == "*"

        if not reflects_arbitrary_origin:
            return None

        severity = "high" if allow_credentials and allow_origin == PROBE_ORIGIN else "medium"

        f = Finding(
            module=self.name,
            title="REST API CORS Misconfiguration",
            severity=severity,
            description=(
                "The WordPress REST API reflects an arbitrary Origin header in the "
                "Access-Control-Allow-Origin response header, instead of validating "
                "against an allowlist of trusted domains."
            ),
            endpoint="/wp-json/",
            evidence={
                "probe_origin_sent": PROBE_ORIGIN,
                "access_control_allow_origin_received": allow_origin,
                "access_control_allow_credentials": allow_credentials,
            },
        )

        if allow_credentials and allow_origin == PROBE_ORIGIN:
            f.business_impact = (
                "This is the most severe CORS misconfiguration: reflecting an "
                "arbitrary Origin together with Allow-Credentials: true means any "
                "website on the internet can make authenticated, credentialed "
                "requests to this API on behalf of a logged-in visitor, reading or "
                "modifying data as that user -- a full cross-origin account takeover "
                "primitive."
            )
        else:
            f.business_impact = (
                "Reflecting an arbitrary Origin (or using a wildcard) allows any "
                "website to read non-credentialed API responses cross-origin, which "
                "can leak data not intended for public/third-party consumption."
            )

        f.remediation = (
            "Validate the Origin header against an explicit allowlist of trusted "
            "domains instead of reflecting whatever Origin is sent. Never combine "
            "a wildcard or reflected Origin with Access-Control-Allow-Credentials: true."
        )

        f.exploitability = "Easy" if allow_credentials else "Moderate"

        return [f.to_dict()]
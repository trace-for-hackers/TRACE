from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    produces=[Produces("surface.rest_api.present", durable=False)],
    cost=1,
    category="rest_api",
    display_name="Mapeamento de Rotas da REST API",
    summary="Consulta /wp-json e mapeia as rotas expostas, sinalizando quando rotas não-padrão (de plugins) ficam acessíveis sem autenticação. Libera módulos dependentes da REST API, como CORS e upload surface.",
)
class WPRestRoutes:
    name = "wp_rest_routes"

    def run(self, target):
        url = f"{target}/wp-json"
        r = get(url)

        if not r or r.status_code != 200:
            return None

        try:
            data = r.json()
        except:
            return None

        routes = data.get("routes", {})
        if not routes:
            return None

        # fato produzido sempre que a REST API responde com rotas -- mesmo
        # que sejam só as rotas padrão do core (/wp/v2/*), a API EXISTE e
        # está acessível, o que já basta para liberar módulos dependentes
        # como wp_rest_api_cors_misconfiguration.py. O Finding abaixo, por
        # outro lado, continua só sendo gerado quando há rotas NÃO-padrão
        # (achado de segurança real), preservando o comportamento original.
        facts = [fact("surface.rest_api.present", True, 1.0, self.name, target)]

        interesting_routes = []

        for route in routes.keys():

            if route.startswith("/wp/v2"):
                continue

            interesting_routes.append(route)

        if not interesting_routes:
            return ModuleResult(findings=[], facts=facts)

        findings = []

        if interesting_routes:
            f = Finding(
                module=self.name,
                title="WordPress REST API Routes Exposed",
                severity="medium",
                description="Non-standard WordPress REST API routes are exposed without authentication.",
                endpoint="/wp-json/",
                evidence=interesting_routes
            )

            f.business_impact = (
                "An attacker can explore exposed REST API routes to gather information or exploit vulnerabilities."
            )

            f.remediation = (
                "Restrict REST API access to authenticated users or disable unnecessary endpoints using security plugins or server-level rules."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return ModuleResult(findings=findings, facts=facts)
        return ModuleResult(findings=[], facts=facts)
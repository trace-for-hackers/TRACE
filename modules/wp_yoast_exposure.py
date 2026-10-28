from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5),
              Requirement("tech.yoast_seo.present", min_confidence=0.5),
],
    cost=1,
    category="yoast_seo",
    display_name="Exposição de Dados via Yoast SEO",
    summary="Testa endpoints específicos do Yoast SEO que podem vazar dados internos de configuração ou estrutura do site através da REST API.",
)
class WPYoastExposure:
    name = "wp_yoast_exposure"

    def run(self, target):
        # Endpoint que o Yoast utiliza para indexação interna
        url = f"{target}/wp-json/yoast/v1/get_head?url={target}"
        r = get(url)

        if r and r.status_code == 200 and "html" in r.text:
            f = Finding(
                module=self.name,
                title="Yoast SEO REST API Information Disclosure",
                severity="low",
                description="The Yoast SEO REST API endpoint is accessible, revealing internal SEO structure and metadata.",
                endpoint="/wp-json/yoast/v1/get_head",
                evidence="Successful JSON response with HTML head data"
            )
            f.business_impact = "Reveals architectural information and potentially private SEO configurations to attackers."
            f.remediation = "Restrict REST API access for non-authenticated users or specific namespaces."
            f.exploitability = "Easy"

            return [f.to_dict()]
        return None
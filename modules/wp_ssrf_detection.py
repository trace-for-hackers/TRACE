from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement, RequirementMode

@discovery_module(
    requires=[
        Requirement("cms.wordpress.detected", min_confidence=0.5),
        Requirement("tech.elementor.present", min_confidence=0.5),
        Requirement("tech.jetpack.present", min_confidence=0.5),
        Requirement("surface.rest_api.present", min_confidence=0.5)
    ],
    requirement_mode=RequirementMode.ANY,  # testa endpoint do Elementor OU do Jetpack --
                                            # qualquer um dos dois já justifica rodar
    cost=2,
    category="ssrf",
    display_name="SSRF Interno via Elementor/Jetpack",
    summary="Testa endpoints internos do Elementor e do Jetpack que podem ser abusados para forçar o servidor a fazer requisições arbitrárias (SSRF).",
)
class WPSSRFInternal:
    name = "wp_ssrf_detection"

    def run(self, target):
        # Endpoint comum do Elementor para carregar bibliotecas externas
        # O teste tenta forçar o servidor a olhar para si mesmo (localhost)
        payload = "http://127.0.0.1:80"
        endpoints = [
            f"{target}/wp-json/elementor/v1/get-main-template/?url={payload}",
            f"{target}/wp-content/plugins/jetpack/modules/theme-tools/responsive-videos/responsive-videos.php?src={payload}"
        ]

        for url in endpoints:
            r = get(url)
            # Se o servidor responder com algo que indique processamento da requisição interna
            if r and (r.status_code == 200 or "localhost" in r.text):
                f = Finding(
                    module=self.name,
                    title="Potential Server-Side Request Forgery (SSRF)",
                    severity="high",
                    description="The application appears to process external URLs provided via parameters, which can lead to SSRF.",
                    endpoint=url,
                    evidence="Server attempted to process internal loopback address"
                )
                f.business_impact = "Attackers can scan internal networks, access metadata services (AWS/GCP), or bypass firewalls."
                f.remediation = "Implement a whitelist for allowed domains in URL parameters and disable access to internal IP ranges."
                f.exploitability = "Hard" # Requer validação manual do retorno

                return [f.to_dict()]
        return None
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5),
              Requirement("tech.wp_statistics.present", min_confidence=0.5)],
    cost=2,
    category="wp_statistics",
    display_name="Exploração do WP Statistics",
    summary="Tenta acessar o endpoint de exportação do plugin WP Statistics, historicamente alvo de SQL injection em versões antigas.",
)
class WPStatisticsExploit:
    name = "wp_statistics_exposure"

    def run(self, target):
        # Tenta acessar o endpoint de exportação que costuma ser alvo de SQLi em versões antigas
        url = f"{target}/wp-admin/admin.php?page=wps_optimization_page"
        r = get(url)

        # Se o site redirecionar para o login, ele está protegido. 
        # Se responder 200 (raro mas acontece em certas configs), é crítico.
        # Aqui vamos checar se o endpoint da API dele está aberto
        api_url = f"{target}/wp-json/wp-statistics/v1/hit"
        r_api = get(api_url)

        if r_api and r_api.status_code == 200:
            f = Finding(
                module=self.name,
                title="WP Statistics API Endpoint Active",
                severity="low",
                description="WP Statistics REST API endpoint is responding, which can be used to probe for SQLi.",
                endpoint="/wp-json/wp-statistics/v1/hit",
                evidence="API responded with status 200"
            )
            f.business_impact = "Provides an entry point for time-based SQL injection attacks in vulnerable versions of the plugin."
            f.remediation = "Update WP Statistics to the latest version and restrict REST API access."
            f.exploitability = "Medium"

            return [f.to_dict()]
        return None
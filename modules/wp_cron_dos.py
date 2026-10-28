import time
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="WP-Cron Acessível Publicamente",
    summary="Verifica se wp-cron.php é acionado via requisição HTTP pública (em vez de cron real do servidor), o que permite a qualquer visitante disparar tarefas agendadas.",
)
class WPCronDoS:
    name = "wp_cron_dos"

    def run(self, target):
        url = f"{target}/wp-cron.php"
        
        # Mede o tempo de resposta inicial
        start = time.time()
        r = get(url)
        end = time.time()

        # Se o wp-cron responde (geralmente 200 vazio) e demora para processar
        if r and r.status_code == 200:
            response_time = end - start
            f = Finding(
                module=self.name,
                title="Publicly Accessible wp-cron.php",
                severity="medium",
                description="The wp-cron.php file is accessible without authentication, allowing potential DoS attacks.",
                endpoint="/wp-cron.php",
                evidence=f"Response time: {response_time:.2f}s"
            )
            f.business_impact = "An attacker can flood this endpoint to exhaust server resources, leading to a Denial of Service."
            f.remediation = "Disable WP-Cron in wp-config.php (define('DISABLE_WP_CRON', true);) and use a real system cron job."
            f.exploitability = "Easy"

            return [f.to_dict()]
        return None
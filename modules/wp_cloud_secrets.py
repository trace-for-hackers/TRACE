from utils.requester import get
from core.finding import Finding
import re
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Arquivos de Segredo/Configuração de Cloud Expostos",
    summary="Testa arquivos que desenvolvedores costumam esquecer no root do site (.env, .env.local, wp-config.php.dist, docker-compose.yml), que podem vazar credenciais de serviços cloud.",
)
class WPCloudSecretLeak:
    name = "wp_cloud_secrets"

    def run(self, target):
        # Arquivos que desenvolvedores costumam esquecer no root do WP
        secret_files = [".env", ".env.local", "wp-config.php.dist", "docker-compose.yml"]
        # Regex para detectar chaves reais (AWS Access Key por exemplo)
        aws_regex = r"AKIA[0-9A-Z]{16}"
        
        for s_file in secret_files:
            url = f"{target}/{s_file}"
            r = get(url)
            
            if r and r.status_code == 200:
                # Verifica se há segredos reais no conteúdo
                if re.search(aws_regex, r.text) or "DB_PASSWORD" in r.text or "STRIPE_SECRET" in r.text:
                    f = Finding(
                        module=self.name,
                        title="Cloud Secrets & Environment Files Exposed",
                        severity="critical",
                        description=f"Sensitive environment file {s_file} found exposing credentials.",
                        endpoint=f"/{s_file}",
                        evidence=f"Matched secret pattern in {url}"
                    )
                    f.business_impact = "Total takeover of cloud infrastructure, databases, or payment gateways."
                    f.remediation = "Immediately remove .env and .dist files from the public web root."
                    f.exploitability = "Easy"

                    return [f.to_dict()]
        return None
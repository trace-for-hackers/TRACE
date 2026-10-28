from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("tech.woocommerce.present", min_confidence=0.5)],
    cost=1,
    category="woocommerce",
    display_name="Exposição de Logs do WooCommerce",
    summary="Testa se o diretório wc-logs (logs de transações/sistema do WooCommerce) está acessível publicamente, sem autenticação.",
)
class WPWooCommerceLogs:
    name = "wp_woocommerce_logs"

    def run(self, target):
        # O WooCommerce gera logs com nomes baseados em datas e hashes
        # Mas o diretório às vezes permite listagem ou tem nomes previsíveis
        url = f"{target}/wp-content/uploads/wc-logs/"
        r = get(url)

        # Verifica se o diretório de logs do WC está exposto
        if r and r.status_code == 200 and "Log" in r.text:
            f = Finding(
                module=self.name,
                title="WooCommerce Logs Exposed",
                severity="high",
                description="Sensitive WooCommerce transaction/system logs are publicly accessible.",
                endpoint="/wp-content/uploads/wc-logs/",
                evidence="Found wc-logs directory with accessible files"
            )
            f.business_impact = "Can reveal customer data, transaction details, or API keys used for payment gateways."
            f.remediation = "Add an index.php file to the directory or use .htaccess to deny access."
            f.exploitability = "Medium"

            return [f.to_dict()]
        return None
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.contact_form_7.present", min_confidence=0.5)],
    cost=1,
    category="contact_form_7",
    display_name="Exposição de Uploads do Contact Form 7",
    summary="Testa a pasta temporária onde o Contact Form 7 armazena arquivos enviados antes do envio por e-mail, buscando arquivos ainda acessíveis publicamente.",
)
class WPContactForm7Leak:
    name = "wp_cf7_leak"

    def run(self, target):
        # Pasta temporária onde o CF7 armazena arquivos antes do envio por e-mail
        url = f"{target}/wp-content/uploads/wpcf7_uploads/"
        r = get(url)

        # Verifica se o diretório permite listagem (comum em Nginx mal configurado)
        if r and r.status_code == 200 and "Index of" in r.text:
            f = Finding(
                module=self.name,
                title="Contact Form 7 Temporary Storage Exposed",
                severity="high",
                description="The temporary upload directory for Contact Form 7 is accessible.",
                endpoint="/wp-content/uploads/wpcf7_uploads/",
                evidence="Directory listing enabled on CF7 uploads folder"
            )
            f.business_impact = "Attackers can intercept sensitive documents or images uploaded by users via contact forms."
            f.remediation = "Ensure directory listing is disabled and check if .htaccess is working."
            f.exploitability = "Medium"

            return [f.to_dict()]
        return None
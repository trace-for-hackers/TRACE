from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.mailpoet.present", min_confidence=0.5)],
    cost=1,
    category="mailpoet",
    display_name="Exposição de Logs do MailPoet",
    summary="Testa o diretório onde o MailPoet armazena logs e exports de newsletter, buscando arquivos acessíveis sem autenticação.",
)
class WPMailPoetLeak:
    name = "wp_mailpoet_leak"

    def run(self, target):
        # O MailPoet armazena logs e as vezes exports nesta estrutura
        url = f"{target}/wp-content/uploads/mailpoet/logs/"
        r = get(url)

        if r and r.status_code == 200 and ("Index of" in r.text or "Log" in r.text):
            f = Finding(
                module=self.name,
                title="MailPoet Logs/Data Exposed",
                severity="high",
                description="The MailPoet upload directory is accessible, potentially leaking subscriber logs.",
                endpoint="/wp-content/uploads/mailpoet/logs/",
                evidence="Directory accessible"
            )
            f.business_impact = "GDPR violation and privacy leak. Subscriber emails and activity logs may be exposed."
            f.remediation = "Disable directory listing and protect the mailpoet uploads folder."
            f.exploitability = "Medium"
            return [f.to_dict()]
        return None
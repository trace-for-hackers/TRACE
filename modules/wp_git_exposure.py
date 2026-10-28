from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Repositório Git Exposto",
    summary="Testa se /.git/config está acessível, o que pode permitir reconstruir o histórico completo do repositório, incluindo código-fonte e credenciais antigas commitadas.",
)
class WPGitExposure:
    name = "wp_git_exposure"

    def run(self, target):
        # Tenta acessar o config do Git
        url = f"{target}/.git/config"
        r = get(url)

        if r and r.status_code == 200 and "[core]" in r.text:
            f = Finding(
                module=self.name,
                title="Git Repository Exposed",
                severity="critical",
                description="The .git directory is publicly accessible.",
                endpoint="/.git/config",
                evidence="Git config file content detected"
            )
            f.business_impact = "Full source code leak, including database credentials in wp-config.php if it was ever committed."
            f.remediation = "Remove the .git folder from production or block access to dot-files in server config."
            f.exploitability = "Easy"
            return [f.to_dict()]
        return None
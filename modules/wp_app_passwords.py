from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5)],
    cost=1,
    display_name="Application Passwords Habilitado",
    summary="Verifica se o namespace authentication/application-passwords aparece no índice da REST API, indicando um vetor alternativo de autenticação que pode ser alvo de força bruta.",
)
class WPAppPasswords:
    name = "wp_app_passwords"

    def run(self, target):
        # A API de Application Passwords é exposta no index da REST API
        url = f"{target}/wp-json/"
        r = get(url)

        if r and r.status_code == 200:
            data = r.json()
            # Verifica se o namespace de application-passwords está presente
            if "authentication" in data and "application-passwords" in data["authentication"]:
                f = Finding(
                    module=self.name,
                    title="WordPress Application Passwords Enabled",
                    severity="low",
                    description="The site has Application Passwords enabled, which can be an alternative vector for brute-force attacks via REST API.",
                    endpoint="/wp-json/",
                    evidence="application-passwords found in authentication namespaces"
                )
                f.business_impact = "Attackers can bypass traditional 2FA or target specific users via the REST API if credentials are leaked."
                f.remediation = "If not in use, disable Application Passwords using a plugin or the 'wp_is_application_passwords_available' filter."
                f.exploitability = "Medium"

                return [f.to_dict()]
        return None
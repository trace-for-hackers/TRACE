from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5)],
    cost=1,
    display_name="Exposição de Configurações Internas via REST API",
    summary="Consulta /wp-json/wp/v2/settings e verifica se configurações internas (título, e-mail, timezone) ficam acessíveis sem autenticação.",
)
class WPInternalTasks:
    name = "wp_settings_exposure"

    def run(self, target):
        findings = []

        url = f"{target}/wp-json/wp/v2/settings"
        r = get(url)

        if not r or r.status_code != 200:
            return None

        try:
            data = r.json()
        except:
            return None

        if "rest_cannot_view" in str(data).lower():
            return None

        interesting = {}

        for key in ["title", "description", "email", "timezone", "url"]:
            if key in data:
                interesting[key] = data[key]

        if not interesting:
            return None

        if interesting:

            f = Finding(
                module=self.name,
                title="WordPress Internal Settings Exposed via REST API",
                severity="high",
                description="Sensitive WordPress settings exposed via REST API without authentication.",
                endpoint="/wp-json/",
                evidence=interesting
            )

            f.business_impact = (
                "An attacker can gather configuration details that assist in targeted "
                "attacks such as privilege escalation or exploitation of vulnerable plugins."
            )

            f.remediation = (
                "Restrict REST API access to authenticated users or disable unnecessary "
                "endpoints using security plugins or server-level rules."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
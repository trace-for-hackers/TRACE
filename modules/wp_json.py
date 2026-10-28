from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Produces, Requirement
from knowledge.fact import fact
from knowledge.result import ModuleResult

@discovery_module(
    produces=[Produces("tech.jsonapi.enable")],
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
)
class WPRestRoutes:
    name = "wp_rest_routes"

    def run(self, target):
        url = f"{target}/wp-json"
        r = get(url)

        if not r or r.status_code != 200:
            return None

        try:
            data = r.json()
        except:
            return None

        findings = []
        facts = []

        if data:
            f = Finding(
                module=self.name,
                title="WordPress JSON API",
                severity="low",
                description="WordPress JSON API exposed",
                endpoint="/wp-json/",
                evidence=data
            )

            f.business_impact = (
                "An attacker can explore JSON API to gather information or exploit vulnerabilities."
            )

            f.remediation = (
                "Restrict API access to authenticated users or disable unnecessary endpoints using security plugins or server-level rules."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            facts.append(fact(
                "tech.jsonapi.enable", True, 1.0, self.name, target
            ))

            return ModuleResult(findings=findings, facts=facts)
        return None

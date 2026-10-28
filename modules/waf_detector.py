from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Detecção de WAF",
    summary="Identifica a presença de um Web Application Firewall via headers característicos (Cloudflare, Sucuri, Akamai, Imperva, Fastly, AWS) e por comportamento ao receber um payload de teste.",
)
class WAFDetector:
    name = "waf_detector"

    WAF_HEADERS = {
        "cloudflare": ["cf-ray", "server"],
        "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "akamai": ["x-akamai", "akamai"],
        "imperva": ["x-iinfo"],
        "fastly": ["fastly", "x-served-by"],
        "aws": ["x-amzn-"]
    }

    def run(self, target):
        interesting = []

        r = get(target)
        if not r:
            return None

        headers = {k.lower(): v.lower() for k, v in r.headers.items()}

        for waf, sigs in self.WAF_HEADERS.items():
            for sig in sigs:
                for h in headers:
                    if sig in h or sig in headers[h]:
                        interesting.append(waf)

        test = get(target + "/?id=<script>alert(1)</script>")
        if test and test.status_code in [403, 406, 501]:
            interesting.append("generic_waf_behavior")

        if not interesting:
            return None

        findings = []

        if interesting:
            f = Finding(
                module=self.name,
                title="WordPress WAF Detected",
                severity="medium",
                description="Possible Web Application Firewall (WAF) detected.",
                endpoint=target,
                evidence=interesting
            )

            f.business_impact = (
                "The presence of a WAF may indicate that the application is protected against common web attacks."
            )

            f.remediation = (
                "Ensure that WAF rules are properly configured and do not block legitimate traffic."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
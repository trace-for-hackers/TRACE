from utils.requester import get
from core.finding import Finding

HEADERS_TO_CHECK = {
    "X-Frame-Options": "Mitigates clickjacking attacks",
    "Content-Security-Policy": "Mitigates XSS and injection attacks",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Referrer-Policy": "Controls referrer data leakage",
    "Permissions-Policy": "Restricts access to browser features"
}

from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Cabeçalhos de Segurança HTTP Ausentes",
    summary="Verifica a presença de cabeçalhos de segurança recomendados (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) e reporta os que estão ausentes.",
)
class WPSecurityHeaders:
    name = "security_headers"

    def run(self, target):
        findings = []

        try:
            r = get(target, timeout=10)
        except:
            return findings

        missing_headers = []

        for header, purpose in HEADERS_TO_CHECK.items():
            if header not in r.headers:
                missing_headers.append({
                    "header": header,
                    "purpose": purpose
                })

        if missing_headers:
            f = Finding(
                module=self.name,
                title="Missing Important Security Headers",
                severity=self._calculate_severity(missing_headers),
                description=(
                    "The application does not implement several recommended HTTP "
                    "security headers that help browsers enforce client-side "
                    "protections against common web attacks."
                ),
                endpoint="/",
                evidence=missing_headers
            )

            f.category = "Security Misconfiguration"
            f.exploitability = "Moderate"

            f.business_impact = (
                "The absence of security headers may increase exposure to "
                "client-side attacks such as clickjacking, cross-site scripting (XSS), "
                "content injection and sensitive data leakage via browser behavior. "
                "While not a direct vulnerability, this weakens the application's "
                "defense-in-depth posture."
            )

            f.remediation = (
                "Implement recommended HTTP security headers at the web server or "
                "application level. For WordPress, this can be achieved via server "
                "configuration (.htaccess, nginx config) or security plugins. "
                "Ensure proper CSP configuration to avoid breaking functionality."
            )

            findings.append(f.to_dict())

            return findings
        return None

    def _calculate_severity(self, missing_headers):
        names = [h["header"] for h in missing_headers]

        if "Content-Security-Policy" in names and "X-Frame-Options" in names:
            return "medium"
        if len(names) >= 4:
            return "medium"
        return "low"
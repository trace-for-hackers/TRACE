from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

PATHS = [
    "/wp-content/debug.log",
    "/wp-config.php.bak",
    "/wp-config.old",
    "/.env"
]

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Exposição de Arquivos de Debug e Configuração",
    summary="Testa caminhos comuns de debug.log, backups de wp-config e arquivos .env esquecidos no webroot, que podem vazar credenciais de banco e chaves secretas.",
)
class WPDebugLeaks:
    name = "debug_leaks"

    def run(self, target):
        findings = []

        exposed_files = []

        for path in PATHS:
            url = target.rstrip("/") + path
            try:
                r = get(url, timeout=10)

                if r.status_code == 200 and len(r.text) > 50:
                    exposed_files.append({
                        "file": path,
                        "url": url,
                        "length": len(r.text)
                    })

            except:
                pass

        if exposed_files:
            f = Finding(
                module=self.name,
                title="Sensitive WordPress Configuration/Debug Files Exposed",
                severity="critical",
                description=(
                    "Sensitive files related to WordPress configuration or debugging "
                    "are publicly accessible. These files may contain database credentials, "
                    "API keys, filesystem paths, or internal error logs."
                ),
                endpoint="/",
                evidence=exposed_files
            )

            f.business_impact = (
                "An attacker could extract database credentials, secret keys or "
                "internal paths, potentially leading to full site compromise, "
                "data breach, or remote code execution."
            )

            f.remediation = (
                "Remove backup and debug files from the web root. Ensure wp-config "
                "and environment files are never publicly accessible. Configure the "
                "server to block access to sensitive extensions such as .log, .bak, "
                ".env and disable WordPress debug logging in production."
            )

            f.exploitability = "Easy"
            f.category = "WordPress Misconfiguration"

            findings.append(f.to_dict())

            return findings
        return None
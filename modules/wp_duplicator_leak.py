from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.duplicator.present", min_confidence=0.5)],
    cost=3,  # testa 3 caminhos de instalador -- mais caro que os detectores raiz
    category="duplicator",
    display_name="Exposição de Backup do Duplicator",
    summary="Testa arquivos de instalador e backup gerados pelo plugin Duplicator, que podem conter um dump completo do site e do banco de dados.",
)
class WPDuplicatorLeak:
    name = "wp_duplicator_leak"

    def run(self, target):
        # Nomes de arquivos gerados pelo Duplicator
        files = ["installer.php", "installer-backup.php", "dup-installer/main.installer.php"]
        findings = []

        for f_name in files:
            url = f"{target}/{f_name}"
            r = get(url)
            if r and r.status_code == 200 and "Duplicator" in r.text:
                f = Finding(
                    module=self.name,
                    title="Duplicator Installer File Detected",
                    severity="critical",
                    description=f"The Duplicator installer file was found at {url}.",
                    endpoint=f"/{f_name}",
                    evidence="Duplicator installer signature found"
                )
                f.business_impact = "Attackers can hijack the installation process or gain access to backup archives."
                f.remediation = "Delete Duplicator installer files immediately after use."
                f.exploitability = "Easy"
                findings.append(f.to_dict())
        
        return findings if findings else None
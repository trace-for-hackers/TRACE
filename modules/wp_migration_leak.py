from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.aio_migration.present", min_confidence=0.5)],
    cost=1,
    category="aio_migration",
    display_name="Exposição de Backup do All-in-One WP Migration",
    summary="Testa a pasta ai1wm-backups onde o plugin All-in-One WP Migration salva backups completos do site, buscando arquivos ainda acessíveis publicamente.",
)
class WPAllInOneMigration:
    name = "wp_migration_leak"

    def run(self, target):
        # O plugin salva backups nesta pasta específica
        url = f"{target}/wp-content/ai1wm-backups/"
        r = get(url)

        # Verifica se a pasta existe e se contém arquivos de extensão .wpress
        if r and r.status_code == 200 and ".wpress" in r.text:
            f = Finding(
                module=self.name,
                title="Full Site Backup Exposed (All-in-One WP Migration)",
                severity="critical",
                description="The site's full backup files (.wpress) are publicly accessible.",
                endpoint="/wp-content/ai1wm-backups/",
                evidence="Backup files found in directory listing"
            )
            f.business_impact = "Total site compromise. Attackers can download the entire database, source code, and configuration."
            f.remediation = "Delete old backups and protect the ai1wm-backups directory via server rules."
            f.exploitability = "Easy"

            return [f.to_dict()]
        return None
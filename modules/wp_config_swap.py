from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Arquivos Temporários de Editor Expostos",
    summary="Testa arquivos .swp/.swo/~ deixados por editores Linux (vim, nano) ao editar wp-config.php, que podem conter o conteúdo do arquivo original.",
)
class WPConfigSwap:
    name = "wp_config_swap"

    def run(self, target):
        # Arquivos temporários comuns de editores Linux
        swaps = [".wp-config.php.swp", "wp-config.php.swp", ".wp-config.php.swo", "wp-config.php~"]
        
        for s in swaps:
            url = f"{target}/{s}"
            r = get(url)
            # Esses arquivos são binários, mas contêm strings legíveis como DB_USER
            if r and r.status_code == 200 and "DB_PASSWORD" in r.text:
                f = Finding(
                    module=self.name,
                    title="WP-Config Editor Swap File Found",
                    severity="critical",
                    description=f"A temporary editor file ({s}) was found, leaking database credentials.",
                    endpoint=f"/{s}",
                    evidence=f"Sensitive strings found in {s}"
                )
                f.business_impact = "Critical credential leak. The database can be accessed remotely."
                f.remediation = "Delete all swap and backup files from the root directory."
                f.exploitability = "Easy"
                return [f.to_dict()]
        return None
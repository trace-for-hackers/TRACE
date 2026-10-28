from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("tech.elementor.present", min_confidence=0.5)],
    cost=1,
    category="elementor",
    display_name="Exposição de Logs do Elementor",
    summary="Testa o caminho padrão onde o Elementor salva logs de sistema, buscando informação interna exposta sem autenticação.",
)
class WPElementorLog:
    name = "wp_elementor_log"

    def run(self, target):
        # O Elementor salva logs de sistema neste caminho padrão
        url = f"{target}/wp-content/uploads/elementor/forms/system-info.txt"
        r = get(url)

        if r and r.status_code == 200 and "Elementor Status" in r.text:
            f = Finding(
                module=self.name,
                title="Elementor System Info Exposed",
                severity="medium",
                description="The Elementor system information log is publicly accessible.",
                endpoint="/wp-content/uploads/elementor/forms/system-info.txt",
                evidence="Found 'Elementor Status' header in the file"
            )
            f.business_impact = "Reveals server paths, PHP version, and active plugins, aiding in the reconnaissance phase of an attack."
            f.remediation = "Delete the system-info.txt file and restrict access to the elementor uploads folder."
            f.exploitability = "Easy"

            return [f.to_dict()]
        return None
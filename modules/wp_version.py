from utils.requester import get
from bs4 import BeautifulSoup
from core.finding import Finding
from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

@discovery_module(
    requires=[],  # raiz: sempre elegível, é quem inicia toda a cadeia de descoberta
    produces=[Produces("cms.wordpress.detected", durable=True)],
    cost=1,
    category="cms_detection",
    display_name="Detecção de Versão do WordPress",
    summary="Confirma se o alvo é WordPress via meta tag generator e extrai a versão exposta. Produz o fato raiz que libera toda a cadeia de descoberta seguinte.",
)
class WPVersion:
    name = "wp_version"

    def run(self, target):
        r = get(target)
        if not r:
            return None

        soup = BeautifulSoup(r.text, "html.parser")
        meta = soup.find("meta", {"name": "generator"})

        if not meta:
            return None

        version = meta.get("content", "")

        findings = []
        facts = []

        if version:
            f = Finding(
                module=self.name,
                title="WordPress Version Detected",
                severity="info",
                description="WordPress version detected via meta generator tag.",
                endpoint="/",
                evidence=version
            )

            f.business_impact = (
                "An attacker can explore exposed WordPress version to gather sensitive information or exploit vulnerabilities."
            )

            f.remediation = (
                "Restrict access to the meta generator tag or disable unnecessary actions via server configuration."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            # único fato novo: confirma que o alvo é WordPress, com confiança
            # máxima -- a tag generator é uma confirmação direta, não heurística.
            #
            # Redundância intencional: modules/wp_detect.py também produz este
            # mesmo fato, via múltiplos sinais (wp-json, wp-login.php, cookies,
            # paths de asset), justamente para cobrir os casos em que a meta
            # tag foi removida do site. Os dois rodam sempre (ambos são raiz);
            # qual confiança "vence" é resolvido automaticamente pelo
            # KnowledgeStore.assert_fact (a maior confiança permanece como
            # versão atual do fato, e a outra fica preservada no histórico
            # para explicabilidade). Não remover este bloco achando que é
            # duplicação esquecida -- é a camada de defesa contra falso
            # negativo do wp_detect.
            facts.append(fact(
                "cms.wordpress.detected", True, 1.0, self.name, target,
            ))

            return ModuleResult(findings=findings, facts=facts)
        return None
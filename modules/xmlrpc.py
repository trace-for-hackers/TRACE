from utils.requester import post
from core.finding import Finding
from knowledge.contracts import discovery_module, Produces, Requirement
from knowledge.fact import fact
from knowledge.result import ModuleResult

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    produces=[Produces("surface.xmlrpc.enabled", durable=True)],
    cost=1,
    category="xmlrpc",
    display_name="Detecção de XML-RPC Habilitado",
    summary="Verifica se /xmlrpc.php responde a chamadas XML-RPC. Produz o fato que libera os módulos de força bruta e SSRF via pingback, evitando testá-los em sites com XML-RPC desabilitado.",
)
class XMLRPC:
    name = "xmlrpc"

    def run(self, target):
        body = """<?xml version="1.0"?>
        <methodCall>
          <methodName>system.listMethods</methodName>
        </methodCall>"""

        r = post(f"{target}/xmlrpc.php", body)


        findings = []
        if r and "methodResponse" in r.text:
            f = Finding(
                module=self.name,
                title="WordPress XML-RPC Enabled",
                severity="low",
                description="WordPress XML-RPC interface is enabled.",
                endpoint="/xmlrpc.php",
                evidence=r.text
            )

            f.business_impact = (
                "An attacker can exploit the XML-RPC endpoint to perform attacks on WordPress."
            )

            f.remediation = (
                "Disable XML-RPC access or implement rate limiting and authentication restrictions."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            # fato que libera xmlrpc_bruteforce.py e xmlrpc_ssrf.py -- sem ele,
            # esses dois módulos ficam pendentes para sempre, economizando as
            # requisições de força bruta/SSRF em todo site com XML-RPC desabilitado
            # (a maioria hoje, dado o histórico de ataques contra esse endpoint).
            facts = [fact("surface.xmlrpc.enabled", True, 1.0, self.name, target)]

            return ModuleResult(findings=findings, facts=facts)

        return None
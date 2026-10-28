from utils.requester import post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.xmlrpc.enabled", min_confidence=0.5)],
    cost=1,
    display_name="SSRF via Pingback do XML-RPC",
    summary="Consulta system.listMethods do XML-RPC e verifica se pingback.ping está disponível na lista, método historicamente abusado para forçar o servidor a fazer requisições arbitrárias (SSRF).",
)
class XMLRPC_SSRF:
    name = "xmlrpc_ssrf"

    def run(self, target):
        xmlrpc_url = f"{target}/xmlrpc.php"
        payload = """<?xml version="1.0"?>
        <methodCall>
          <methodName>system.listMethods</methodName>
        </methodCall>"""

        r = post(xmlrpc_url, payload)

        findings = []
        if r and 'pingback.ping' in r.text:  
            f = Finding(
                module=self.name,
                title="WordPress XML-RPC SSRF Vulnerability",
                severity="high",
                description="WordPress XML-RPC SSRF vulnerability detected.",
                endpoint="/xmlrpc.php",
                evidence=r.text
            )

            f.business_impact = (
                "An attacker can exploit the XML-RPC endpoint to perform SSRF attacks on WordPress users."
            )

            f.remediation = (
                "Disable XML-RPC access or implement rate limiting and authentication restrictions."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
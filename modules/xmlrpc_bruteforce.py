from utils.requester import post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.xmlrpc.enabled", min_confidence=0.5)],
    cost=1,
    display_name="Força Bruta via XML-RPC",
    summary="Testa o método wp.getUsersBlogs do XML-RPC com uma credencial de teste, verificando se a mensagem de erro retornada confirma tentativa de autenticação processada pelo endpoint.",
)
class XMLRPC_BRUTEFORCE:
    name = "xmlrpc_bruteforce"

    def run(self, target):
        xmlrpc_url = f"{target}/xmlrpc.php"
        payload = """<?xml version="1.0"?>
        <methodCall>
          <methodName>wp.getUsersBlogs</methodName>
          <params>
            <param><value><string>admin</string></value></param>
            <param><value><string>wrongpassword</string></value></param>
          </params>
        </methodCall>"""

        r = post(xmlrpc_url, payload)

        findings = []
        if r and 'Incorrect username or password' in r.text:  
            f = Finding(
                module=self.name,
                title="WordPress XML-RPC Brute Force Vulnerability",
                severity="high",
                description="WordPress XML-RPC brute force vulnerability detected.",
                endpoint="/xmlrpc.php",
                evidence=r.text
            )

            f.business_impact = (
                "An attacker can exploit the XML-RPC endpoint to perform brute force attacks on WordPress users."
            )

            f.remediation = (
                "Disable XML-RPC access or implement rate limiting and authentication restrictions."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
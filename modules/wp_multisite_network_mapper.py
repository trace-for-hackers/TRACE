from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


@discovery_module(
    requires=[Requirement("cms.wordpress.multisite", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5)],
    cost=1,
    category="multisite",
    display_name="Mapeamento de Sub-sites da Rede Multisite",
    summary="Lista todos os sub-sites de uma rede WordPress Multisite via /wp-json/wp/v2/sites, revelando domínios e subdiretórios hospedados na mesma instalação.",
)
class WPMultisiteNetworkMapper:
    """
    Em uma rede WordPress Multisite, a rota /wp-json/wp/v2/sites (quando
    habilitada para a rede) lista todos os sub-sites -- domínios e/ou
    subdiretórios -- hospedados na mesma instalação. Isso é reconhecimento
    gratuito: cada sub-site listado é um novo alvo em potencial, geralmente
    compartilhando a mesma base de código/plugins e, portanto, as mesmas
    vulnerabilidades já mapeadas no site principal.

    Só roda depois que WPDetectMultisite confirma que é multisite -- testar
    essa rota num site single-site comum (a grande maioria) sempre devolve
    404 ou rest_no_route, então o gate evita essa requisição desperdiçada.
    """
    name = "wp_multisite_network_mapper"

    def run(self, target):
        r = get(f"{target}/wp-json/wp/v2/sites")
        if not r or r.status_code != 200:
            return None

        try:
            data = r.json()
        except Exception:
            return None

        if not isinstance(data, list) or not data:
            return None

        sites = []
        for site in data:
            if isinstance(site, dict):
                sites.append({
                    "id": site.get("id"),
                    "name": site.get("name"),
                    "url": site.get("url"),
                })

        if not sites:
            return None

        f = Finding(
            module=self.name,
            title="WordPress Multisite Network Sites Exposed",
            severity="medium",
            description=(
                "The /wp-json/wp/v2/sites REST endpoint is publicly accessible and "
                "lists every sub-site in the WordPress Multisite network, including "
                "their domains/subdirectories."
            ),
            endpoint="/wp-json/wp/v2/sites",
            evidence={"site_count": len(sites), "sites": sites[:50]},
        )

        f.business_impact = (
            "Reveals the full attack surface of the network at once: every sub-site is "
            "a potential target, and since sub-sites in a Multisite network typically "
            "share the same WordPress core, plugins, and themes, a vulnerability found "
            "on one sub-site likely affects all of them."
        )

        f.remediation = (
            "Restrict the /wp-json/wp/v2/sites endpoint to authenticated network "
            "administrators, or disable public listing of network sites via a "
            "REST API filter (rest_endpoints)."
        )

        f.exploitability = "Easy"

        return [f.to_dict()]
import re
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult


# Paths em Disallow que sinalizam que o admin queria escondê-los -- presença
# por si só já é informação (o admin sabe que existe algo sensível ali), e
# alguns são diretamente interessantes para outros módulos investigarem.
INTERESTING_DISALLOW_KEYWORDS = [
    "admin", "backup", "private", "staging", "dev", "test",
    "old", "tmp", "temp", "internal", "secret", "config",
]


@discovery_module(
    requires=[],
    produces=[Produces("surface.disallowed_paths", durable=False)],
    cost=2,
    category="recon",
    display_name="Reconhecimento via robots.txt e sitemap.xml",
    summary="Lê robots.txt e sitemap.xml para revelar caminhos sensíveis que o admin tentou esconder (Disallow) e mapear a estrutura de conteúdo indexável do site.",
)
class WPRobotsSitemapRecon:
    """
    Lê robots.txt e sitemap.xml -- nenhum dos dois é, por si só, uma falha de
    segurança (são arquivos públicos por design), mas ambos costumam revelar
    informação que o próprio administrador não pretendia destacar:

    - robots.txt: linhas "Disallow:" frequentemente listam exatamente os
      paths que o admin considera sensíveis (áreas de staging, backups,
      painéis alternativos) -- a presença da entrada já é um sinal, mesmo
      que o crawler "respeite" o Disallow (um atacante não respeita).

    - sitemap.xml: revela a estrutura completa de conteúdo indexável do site
      (todas as URLs que o WP/Yoast/RankMath geraram), útil para mapear a
      superfície de conteúdo sem precisar fazer crawling manual.

    O fato produzido (surface.disallowed_paths) é deliberadamente leve --
    apenas a lista de paths interessantes encontrados -- para que módulos
    futuros possam consumir essa lista e testar cada path diretamente, sem
    precisar reimplementar a leitura de robots.txt.
    """
    name = "wp_robots_sitemap_recon"

    def run(self, target):
        interesting_disallows = []
        sitemap_urls_found = []
        sitemap_total_urls = 0

        # ── robots.txt ──────────────────────────────────────────────────────
        r_robots = get(f"{target}/robots.txt")
        if r_robots and r_robots.status_code == 200:
            for line in r_robots.text.splitlines():
                line = line.strip()
                if not line.lower().startswith("disallow:"):
                    continue
                path = line.split(":", 1)[1].strip()
                if not path or path == "/":
                    continue
                if any(kw in path.lower() for kw in INTERESTING_DISALLOW_KEYWORDS):
                    interesting_disallows.append(path)

        # ── sitemap.xml ─────────────────────────────────────────────────────
        r_sitemap = get(f"{target}/sitemap.xml")
        if r_sitemap and r_sitemap.status_code == 200 and "<urlset" in r_sitemap.text.lower() or (
            r_sitemap and r_sitemap.status_code == 200 and "<sitemapindex" in r_sitemap.text.lower()
        ):
            urls = re.findall(r"<loc>(.*?)</loc>", r_sitemap.text)
            sitemap_total_urls = len(urls)
            sitemap_urls_found = urls[:10]  # amostra, não a lista inteira no Finding

        if not interesting_disallows and sitemap_total_urls == 0:
            return None

        findings = []
        if interesting_disallows:
            f = Finding(
                module=self.name,
                title="Sensitive Paths Revealed via robots.txt",
                severity="low",
                description=(
                    "robots.txt Disallow entries reveal paths the site administrator "
                    "considers sensitive, which crawlers will skip but attackers will not."
                ),
                endpoint="/robots.txt",
                evidence={"disallowed_paths": interesting_disallows},
            )
            f.business_impact = (
                "Disallow entries act as a hint map for where to look for staging "
                "environments, backups, or internal panels -- information the "
                "administrator did not intend to highlight, but inadvertently did."
            )
            f.remediation = (
                "Do not rely on robots.txt to hide sensitive paths; restrict access "
                "via authentication or server-level rules instead."
            )
            f.exploitability = "Easy"
            findings.append(f.to_dict())

        facts = []
        if interesting_disallows:
            facts.append(fact(
                "surface.disallowed_paths", interesting_disallows, 0.9, self.name, target,
            ))

        return ModuleResult(findings=findings, facts=facts)
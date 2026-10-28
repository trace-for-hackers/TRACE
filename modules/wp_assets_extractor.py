"""
modules/wp_assets_extractor.py

Detecção AMPLA de plugins/temas: em vez dos ~12 detectores individuais em
plugin_detectors.py (um por plugin específico, cada um sabendo o endpoint
certo pra checar), este módulo faz varredura passiva no HTML da home procurando
QUALQUER referência a wp-content/plugins/<slug>/ ou wp-content/themes/<slug>/
em tags <link>/<script> -- pega o que os detectores individuais não cobrem,
com a vantagem de que o WordPress geralmente enfileira assets com
?ver=X.X.X, o que dá a VERSÃO de graça, sem request extra.

Limitação inerente (por isso "perto de todos", não "todos"): só pega
plugins que enfileiram algum asset público (CSS/JS) na home. Plugin
100% backend (só roda em wp-admin, nunca no front-end) não deixa rastro
aqui -- esses continuam dependendo de detecção individual ou de outro
sinal (endpoint REST, AJAX action, etc.).

BUG CORRIGIDO em 29/08/2026: o summary do decorator já dizia "produz o
fato consumido pelo cruzamento de CVEs conhecidos", mas o run() só
devolvia uma lista de Finding (dict) -- nunca um ModuleResult com facts.
Ou seja, wp_known_vulnerable_assets NUNCA enxergava nada que este módulo
encontrasse, apesar da documentação afirmar o contrário. Documentação
prometendo uma integração que o código não fazia -- agora corrigido pra
valer: cada plugin/tema com versão identificável agora também vira um
fato tech.<slug>.version no mesmo formato que plugin_detectors.py usa
({"slug": ..., "version": ...}), pronto pro wp_known_vulnerable_assets
consumir sem nenhuma mudança lá.
"""

import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

# aceita sufixos tipo "5.9.5-beta1", não só dígitos.pontos puros -- mesma
# tolerância que _extract_version usa em plugin_detectors.py pro Stable tag
_VERSION_RE = r"([0-9][0-9a-zA-Z.\-]*)"

# BUG REAL encontrado rodando contra site real (07/09/2026): slug de
# plugin/tema era capturado com [^/]+ (qualquer caractere que não seja
# barra) -- isso aceita aspas, vírgula, asterisco. Um site com plugin de
# cache/PWA que gera um array JS de exclusão tipo
# `exclude: ["wp-content/plugins/*","wp-content/cache/*"]` fazia o regex
# capturar `*","` como se fosse slug de plugin de verdade, virando o
# fato `tech.*",".present` -- lixo puro, nunca deveria ter sido tratado
# como identificador. Slug de plugin/tema do WordPress.org só usa
# minúscula, número, hífen e underscore (é o nome da pasta em
# wp-content/plugins/<slug>/) -- restringir a esse conjunto de
# caracteres rejeita esse tipo de falso positivo na fonte, em vez de
# tentar filtrar depois.
_SLUG_RE = r"([a-zA-Z0-9_-]+)"


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    produces=[Produces("tech.*.version", durable=True)],  # documental -- ver nota abaixo
    cost=1,
    category="plugin_detection",
    display_name="Extração de Temas e Plugins Instalados",
    summary="Varre <link>/<script> da home por qualquer wp-content/plugins|themes/<slug>, extraindo versão do querystring ?ver= quando presente. Cobre plugins fora da lista fixa de plugin_detectors.py.",
)
class WPAssetsExtractor:
    """
    Nota sobre o Produces("tech.*.version") acima: é documental/informativo
    para quem lê o grafo de decisão -- o ActivationEngine não usa Produces
    pra nada além de detecção de ciclo estrutural (produces -> requires
    entre módulos), e "tech.*.version" nunca vai bater literalmente contra
    o Requirement("tech.*") de outro módulo em _detect_structural_cycles
    (que compara fact_key exato). Ou seja: seguro de declarar, não cria
    ciclo falso, e documenta a intenção real do módulo no painel de
    detalhes do grafo.
    """
    name = "wp_assets_extractor"

    def run(self, target):
        r = get(target)
        if not r:
            return None

        soup = BeautifulSoup(r.text, "html.parser")

        themes = {}
        plugins = {}

        for tag in soup.find_all(["link", "script"]):
            src = tag.get("href") or tag.get("src")
            if not src:
                continue

            theme_match = re.search(r"wp-content/themes/" + _SLUG_RE + r"/.*?ver=" + _VERSION_RE, src)
            if theme_match:
                name, version = theme_match.groups()
                themes[name] = version
                continue

            plugin_match = re.search(r"wp-content/plugins/" + _SLUG_RE + r"/.*?ver=" + _VERSION_RE, src)
            if plugin_match:
                name, version = plugin_match.groups()
                plugins[name] = version

        page_content = str(soup)

        theme_names = re.findall(r"wp-content/themes/" + _SLUG_RE + r"/", page_content)
        plugin_names = re.findall(r"wp-content/plugins/" + _SLUG_RE + r"/", page_content)

        for t in theme_names:
            themes.setdefault(t, "unknown")

        for p in plugin_names:
            plugins.setdefault(p, "unknown")

        for theme in list(themes.keys()):
            css_url = urljoin(target, f"/wp-content/themes/{theme}/style.css")
            css_resp = get(css_url)
            if css_resp and "Version:" in css_resp.text:
                v_match = re.search(r"Version:\s*([\d\.]+)", css_resp.text)
                if v_match:
                    themes[theme] = v_match.group(1)

        if not themes and not plugins:
            return None

        # ── fatos: o que alimenta wp_known_vulnerable_assets ────────────────
        # confiança 0.7 -- é detecção passiva por regex em HTML público, mais
        # forte que "keyword solta" (0.6, usado em plugin_detectors.py) porque
        # o caminho do asset é uma prova estrutural (o arquivo realmente está
        # ali, não é só uma menção em texto), mas mais fraca que um endpoint
        # específico do plugin respondendo (0.9), que é uma confirmação ativa.
        new_facts = []
        for slug, version in plugins.items():
            new_facts.append(fact(f"tech.{slug}.present", True, 0.7, self.name, target))
            if version != "unknown":
                new_facts.append(fact(
                    f"tech.{slug}.version", {"slug": slug, "version": version}, 0.7, self.name, target,
                ))
        for slug, version in themes.items():
            new_facts.append(fact(f"tech.{slug}.present", True, 0.7, self.name, target))
            if version != "unknown":
                new_facts.append(fact(
                    f"tech.{slug}.version", {"slug": slug, "version": version}, 0.7, self.name, target,
                ))

        # ── finding informativo, como já era antes -- continua útil pro
        # relatório mesmo com os fatos agora existindo separadamente ──────
        findings = []
        f = Finding(
            module=self.name,
            title="WordPress Themes and Plugins Detected",
            severity="info",
            description="WordPress themes and plugins detected with versions.",
            evidence={"themes": themes, "plugins": plugins},
        )
        f.business_impact = (
            "An attacker can use this information to identify potentially vulnerable WordPress themes and plugins."
        )
        f.remediation = "Ensure all WordPress themes and plugins are up to date."
        f.exploitability = "Easy"
        findings.append(f.to_dict())

        return ModuleResult(findings=findings, facts=new_facts)

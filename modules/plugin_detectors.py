"""
modules/plugin_detectors.py

Detectores "raiz" de tecnologia/plugin. Cada um custa 1 requisição HTTP e
produz um único fato tech.<plugin>.present, que é o gatilho consumido pelos
módulos de folha já existentes (wp_cf7_leak, wp_elementor_log, etc. — ver
o decorator adicionado a cada um deles).

Sem estes detectores, os módulos de folha decorados com
Requirement("tech.X.present") nunca ficariam elegíveis — então este arquivo
é a peça que efetivamente liga a cadeia: sem ele, decorar os módulos de
folha sozinho não tem efeito nenhum.

Todos seguem o mesmo padrão de confiança:
    0.9  -> resposta JSON/endpoint específico do plugin respondeu como esperado
    0.6  -> keyword do plugin encontrada solta no HTML da homepage (mais fraco,
            pode ser falso positivo por menção em texto, não instalação real)

Todos são requires=[Requirement("cms.wordpress.detected", ...)] — só faz
sentido procurar plugin de WordPress depois de confirmar que é WordPress
(reaproveita o fato que knowledge/examples/woocommerce_chain_example.py já
produz via WPVersion decorado).
"""

from utils.requester import get, post
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult
import re


_REQUIRES_WORDPRESS = [Requirement("cms.wordpress.detected", min_confidence=0.5)]

# regex do cabeçalho padrão de todo readme.txt de plugin do WordPress.org --
# "Stable tag: 5.9.5" é como o WPScan e o próprio Wordfence identificam a
# versão publicada de um plugin sem precisar autenticar ou baixar o plugin
# inteiro. Case-insensitive porque alguns plugins escrevem "stable tag"
# minúsculo.
_STABLE_TAG_RE = re.compile(r"stable\s+tag\s*:\s*([0-9][0-9a-zA-Z.\-]*)", re.IGNORECASE)


def _extract_version(readme_text: str) -> str | None:
    """Extrai a versão do 'Stable tag:' de um readme.txt de plugin do
    WordPress.org. Retorna None se não achar -- alguns plugins usam
    'trunk' como stable tag (versão de desenvolvimento, não numérica),
    que não serve pra matching de CVE por faixa de versão."""
    m = _STABLE_TAG_RE.search(readme_text or "")
    if not m:
        return None
    version = m.group(1).strip()
    if version.lower() == "trunk":
        return None
    return version


def _version_fact(fact_key: str, slug: str, version: str, confidence: float, produced_by: str, target: str):
    """Fato de versão -- valor é um dict {slug, version} em vez de só a
    string da versão, porque o slug interno do fato (ex. 'contact_form_7')
    usa underscore por convenção de namespace (ver knowledge/fact.py), mas
    o slug real do WordPress.org (ex. 'contact-form-7') é o que a Wordfence
    usa pra indexar o feed de vulnerabilidades -- carregar os dois juntos
    evita o módulo de matching (wp_known_vulnerable_assets) precisar de uma
    tabela de tradução separada."""
    return fact(
        fact_key, {"slug": slug, "version": version}, confidence, produced_by, target,
    )


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.woocommerce.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de WooCommerce",
    summary="Confirma a presença do WooCommerce via /wp-json/wc/store/v1/products, com fallback para keyword no HTML da homepage.",
)
class DetectWooCommerce:
    name = "detect_woocommerce"

    def run(self, target):
        r = get(f"{target}/wp-json/wc/store/v1/products")
        if r and r.status_code == 200:
            return ModuleResult(facts=[fact(
                "tech.woocommerce.present", True, 0.9, self.name, target,
            )])

        home = get(target)
        if home and "woocommerce" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.woocommerce.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.contact_form_7.present", durable=True),
        Produces("tech.contact_form_7.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Contact Form 7",
    summary="Confirma a presença do Contact Form 7 via readme.txt do plugin (extraindo também a versão do Stable tag), com fallback para o marcador wpcf7 no HTML da homepage.",
)
class DetectContactForm7:
    name = "detect_contact_form_7"

    def run(self, target):
        r = get(f"{target}/wp-content/plugins/contact-form-7/readme.txt")
        if r and r.status_code == 200 and "contact form 7" in r.text.lower():
            facts = [fact("tech.contact_form_7.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.contact_form_7.version", "contact-form-7", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)

        home = get(target)
        if home and "wpcf7" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.contact_form_7.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.elementor.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Elementor",
    summary="Confirma a presença do Elementor verificando se a rota /wp-json/elementor/v1/get-main-template existe, com fallback para keyword no HTML.",
)
class DetectElementor:
    name = "detect_elementor"

    def run(self, target):
        r = get(f"{target}/wp-json/elementor/v1/get-main-template")
        if r and r.status_code in (200, 400):
            # Elementor responde 400 sem o parâmetro `url`, mas a rota existir já confirma
            return ModuleResult(facts=[fact(
                "tech.elementor.present", True, 0.9, self.name, target,
            )])

        home = get(target)
        if home and "elementor" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.elementor.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.jetpack.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Jetpack",
    summary="Confirma a presença do Jetpack via /wp-json/jetpack/v4/settings (aceita 200 ou 401, já que a rota existir confirma o plugin mesmo exigindo auth), com fallback para keyword no HTML.",
)
class DetectJetpack:
    name = "detect_jetpack"

    def run(self, target):
        r = get(f"{target}/wp-json/jetpack/v4/settings")
        if r and r.status_code in (200, 401):
            # 401 ainda confirma que a rota existe (exige auth, mas o plugin está lá)
            return ModuleResult(facts=[fact(
                "tech.jetpack.present", True, 0.9, self.name, target,
            )])

        home = get(target)
        if home and "jetpack" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.jetpack.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.yoast_seo.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Yoast SEO",
    summary="Confirma a presença do Yoast SEO via /wp-json/yoast/v1, com fallback para keyword/schema graph no HTML.",
)
class DetectYoastSEO:
    name = "detect_yoast_seo"

    def run(self, target):
        r = get(f"{target}/wp-json/yoast/v1")
        if r and r.status_code == 200:
            return ModuleResult(facts=[fact(
                "tech.yoast_seo.present", True, 0.9, self.name, target,
            )])

        home = get(target)
        if home and ("yoast" in home.text.lower() or "yoast-schema-graph" in home.text.lower()):
            return ModuleResult(facts=[fact(
                "tech.yoast_seo.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.mailpoet.present", durable=True),
        Produces("tech.mailpoet.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de MailPoet",
    summary="Confirma a presença do MailPoet via readme.txt (extraindo também a versão), com fallback para keyword no HTML da homepage.",
)
class DetectMailPoet:
    name = "detect_mailpoet"

    def run(self, target):
        r = get(f"{target}/wp-content/plugins/mailpoet/readme.txt")
        if r and r.status_code == 200 and "mailpoet" in r.text.lower():
            facts = [fact("tech.mailpoet.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.mailpoet.version", "mailpoet", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)

        home = get(target)
        if home and "mailpoet" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.mailpoet.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.duplicator.present", durable=True),
        Produces("tech.duplicator.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Duplicator",
    summary="Confirma a presença do plugin Duplicator via readme.txt (extraindo também a versão), sem tocar nos arquivos de instalador sensíveis ainda.",
)
class DetectDuplicator:
    name = "detect_duplicator"

    def run(self, target):
        # readme.txt do plugin é o sinal mais barato e confiável de instalação,
        # sem precisar tocar nos arquivos de instalador sensíveis ainda
        r = get(f"{target}/wp-content/plugins/duplicator/readme.txt")
        if r and r.status_code == 200 and "duplicator" in r.text.lower():
            facts = [fact("tech.duplicator.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.duplicator.version", "duplicator", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.aio_migration.present", durable=True),
        Produces("tech.aio_migration.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de All-in-One WP Migration",
    summary="Confirma a presença do plugin All-in-One WP Migration via readme.txt, extraindo também a versão.",
)
class DetectAllInOneMigration:
    name = "detect_aio_migration"

    def run(self, target):
        r = get(f"{target}/wp-content/plugins/all-in-one-wp-migration/readme.txt")
        if r and r.status_code == 200 and "all-in-one wp migration" in r.text.lower():
            facts = [fact("tech.aio_migration.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.aio_migration.version", "all-in-one-wp-migration", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.wp_statistics.present", durable=True),
        Produces("tech.wp_statistics.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de WP Statistics",
    summary="Confirma a presença do plugin WP Statistics via readme.txt, extraindo também a versão.",
)
class DetectWPStatistics:
    name = "detect_wp_statistics"

    def run(self, target):
        r = get(f"{target}/wp-content/plugins/wp-statistics/readme.txt")
        if r and r.status_code == 200 and "wp statistics" in r.text.lower():
            facts = [fact("tech.wp_statistics.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.wp_statistics.version", "wp-statistics", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.cache_plugin.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Plugin de Cache",
)
class DetectCachePlugin:
    """Detector genérico: cobre os plugins de cache mais comuns (WP Super
    Cache, W3 Total Cache, WP Rocket) com um único fato agregado, porque
    o módulo de folha (wp_cache_exposure) testa caminhos de filesystem
    genéricos e não diferencia qual plugin de cache está instalado."""
    name = "detect_cache_plugin"

    CACHE_SIGNATURES = ["wp-super-cache", "w3-total-cache", "wp-rocket", "litespeed-cache"]

    def run(self, target):
        home = get(target)
        if not home:
            return None
        lowered = home.text.lower()
        for sig in self.CACHE_SIGNATURES:
            if sig in lowered:
                return ModuleResult(facts=[fact(
                    "tech.cache_plugin.present", True, 0.7, self.name, target,
                )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.wpgraphql.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de WPGraphQL",
    summary="Confirma a presença do WPGraphQL enviando uma query mínima ao endpoint /graphql, com fallback para keyword no HTML.",
)
class DetectWPGraphQL:
    """
    WPGraphQL é o plugin GraphQL dominante no ecossistema WordPress -- usado
    sobretudo em sites headless (Next.js, Gatsby, Astro consumindo WP como
    backend). Diferente dos outros detectores de plugin, aqui o endpoint
    /graphql em si já é o sinal mais forte: ele responde a uma query GraphQL
    válida mesmo sem nenhum dado de autenticação.
    """
    name = "detect_wpgraphql"

    def run(self, target):
        # query minimalista, válida em qualquer schema GraphQL: pede só o
        # nome do tipo raiz. Não tenta introspection ainda -- isso é
        # responsabilidade do módulo de folha wp_graphql_introspection.
        probe_query = '{"query": "{ __typename }"}'
        r = post(f"{target}/graphql", probe_query)

        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and "data" in data and data["data"].get("__typename"):
                    return ModuleResult(facts=[fact(
                        "tech.wpgraphql.present", True, 0.95, self.name, target,
                    )])
            except Exception:
                pass

        home = get(target)
        if home and ("wp-graphql" in home.text.lower() or "/graphql" in home.text.lower()):
            return ModuleResult(facts=[fact(
                "tech.wpgraphql.present", True, 0.5, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[
        Produces("tech.wpforms.present", durable=True),
        Produces("tech.wpforms.version", durable=True),
    ],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de WPForms",
    summary="Confirma a presença do WPForms via readme.txt do plugin (extraindo também a versão), com fallback para keyword no HTML.",
)
class DetectWPForms:
    name = "detect_wpforms"

    def run(self, target):
        r = get(f"{target}/wp-content/plugins/wpforms-lite/readme.txt")
        if r and r.status_code == 200 and "wpforms" in r.text.lower():
            facts = [fact("tech.wpforms.present", True, 0.9, self.name, target)]
            version = _extract_version(r.text)
            if version:
                facts.append(_version_fact(
                    "tech.wpforms.version", "wpforms-lite", version, 0.9, self.name, target,
                ))
            return ModuleResult(facts=facts)

        home = get(target)
        if home and ("wpforms" in home.text.lower()):
            return ModuleResult(facts=[fact(
                "tech.wpforms.present", True, 0.6, self.name, target,
            )])
        return None


@discovery_module(
    requires=_REQUIRES_WORDPRESS,
    produces=[Produces("tech.gravityforms.present", durable=True)],
    cost=1,
    category="plugin_detection",
    display_name="Detecção de Gravity Forms",
    summary="Confirma a presença do Gravity Forms via a AJAX action nativa gform_get_config, distinguindo resposta de plugin ausente vs. presente mas exigindo nonce.",
)
class DetectGravityForms:
    name = "detect_gravityforms"

    def run(self, target):
        # gform_get_config é uma AJAX action nativa do Gravity Forms --
        # responde mesmo sem auth (precisa de um nonce, mas a ROTA existir
        # já confirma a presença do plugin, que é tudo que este detector
        # precisa saber; explorar o nonce é responsabilidade de um módulo
        # de folha, não deste detector raiz).
        r = get(f"{target}/wp-admin/admin-ajax.php?action=gform_get_config")
        if r and r.status_code == 200 and ("gform" in r.text.lower() or r.text.strip() == "0"):
            # action=gform_get_config sem nonce válido tipicamente devolve "0"
            # (resposta padrão do WP para AJAX action existente mas rejeitada)
            # em vez de 400/404 -- isso já distingue "plugin não instalado" de
            # "plugin instalado, mas chamada precisa de nonce".
            if r.text.strip() == "0":
                return ModuleResult(facts=[fact(
                    "tech.gravityforms.present", True, 0.6, self.name, target,
                )])
            return ModuleResult(facts=[fact(
                "tech.gravityforms.present", True, 0.9, self.name, target,
            )])

        home = get(target)
        if home and "gravityforms" in home.text.lower():
            return ModuleResult(facts=[fact(
                "tech.gravityforms.present", True, 0.6, self.name, target,
            )])
        return None
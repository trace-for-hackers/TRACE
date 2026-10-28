"""
modules/site_type_profiler.py

Classifica o TIPO de site (ecommerce, blog, institucional...) gastando o
mínimo possível de requisições -- normalmente 1, no máximo 2. Isso é
DELIBERADAMENTE distinto de `core/classifier.py` (`SiteClassifier`):

    - `SiteClassifier` roda ANTES de existir um `KnowledgeStore` (é chamado
      por `knowledge/bootstrap.py` para alimentar `ModuleSpec.site_types`,
      um filtro separado, fora do sistema de fatos) e faz ~30 requisições,
      uma por caminho candidato de cada tipo (`_path_exists` probando
      `/cart`, `/checkout`, `/blog`, etc. um por um). É caro, mas roda uma
      vez só por alvo e fica em cache 7 dias.
    - Este módulo roda DENTRO do motor de fatos, como qualquer outro
      módulo de descoberta, e produz um `Fact` de verdade
      (`profile.site_type`) que qualquer módulo futuro pode declarar como
      `Requirement`. Ele NUNCA probe caminho nenhum -- extrai todo sinal
      de dados que já estariam na mesma resposta que qualquer módulo raiz
      já buscaria de qualquer forma (a homepage).

Os dois classificadores podem, em teoria, discordar (heurísticas
diferentes, fontes de sinal diferentes) -- isso é esperado e aceitável,
não é um bug: um é filtro de elegibilidade fora do grafo de fatos, o outro
é conhecimento explicável dentro dele.

## Estratégia de economia de requisição

Passo 1 (sempre, exatamente 1 requisição): busca a homepage e minera SETE
sinais dessa ÚNICA resposta, sem nenhum custo adicional:

  1. JSON-LD (`<script type="application/ld+json">`) -- sinal mais forte,
     porque é o site se autodeclarando de propósito para SEO/rich
     snippets. `@type: Product` praticamente garante ecommerce.
  2. `<meta property="og:type">` -- sinal de força média, Open Graph
     também é autodeclarado, mas o vocabulário é mais genérico.
  3. `<meta name="generator">` -- reconhece plataforma conhecida (Shopify,
     Ghost, Docusaurus, Discourse...) por substring.
  4. Âncoras (`<a href>`) -- em vez de PROVAR se `/cart` existe (como o
     `SiteClassifier` faz), lê os links que o PRÓPRIO SITE já publicou na
     homepage. Mesma ideia, custo zero: se o menu tem um link pra
     "/checkout", isso já é evidência, não precisamos confirmar que
     `/checkout` resolve.
  5. Texto visível / título / meta description -- varredura de keyword,
     igual em espírito ao `PROFILE_INDICATORS` do `SiteClassifier`, mas
     com peso pequeno por palavra em vez de soma até um limiar fixo.
  6. TLD (`.gov`, `.edu`, `.org`) -- custo zero, só `urlparse`.
  7. Estrutura da página (proporção de âncora-âncora que é fragmento `#`
     vs. link real, e quantos links internos distintos existem) -- tell
     estrutural barato pra distinguir landing page de site com várias
     páginas.
  8. Content-Type da própria resposta -- se não for HTML, não tem o que
     minerar dos sinais acima; classifica direto como `api_headless`.

Passo 2 (no máximo +1 requisição, só se ambíguo): se o placar do passo 1
não tiver um vencedor claro (nota máxima abaixo de ~0.5 OU a diferença
pro segundo lugar for menor que ~0.15), busca `{target}/sitemap.xml` UMA
vez (sem seguir `sitemap_index.xml`, sem retry) e roda a MESMA tabela de
palavra-chave de caminho do passo 4 contra cada URL declarada -- com peso
maior, porque são URLs que o site afirma existir de verdade, não links
que podem levar a qualquer lugar.

Cada sinal documenta, no próprio código, o que causaria uma classificação
errada -- mesmo espírito de `_SQL_ERROR_SIGNATURES` em
`injection_heuristics.py` e do raciocínio multi-sinal de `wp_detect.py`:
nenhum sinal isolado decide sozinho, e o motivo de cada peso está anotado
onde o peso é usado.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse
from xml.etree import ElementTree

from bs4 import BeautifulSoup

from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult


# ── tabelas de sinal (constantes puras, sem I/O) ────────────────────────────

_JSONLD_TYPE_MAP: dict[str, tuple[str, float]] = {
    "Product": ("ecommerce", 0.8),
    "Store": ("ecommerce", 0.8),
    "OnlineStore": ("ecommerce", 0.8),
    "BlogPosting": ("blog", 0.8),
    "Blog": ("blog", 0.8),
    "NewsArticle": ("news_media", 0.8),
    "NewsMediaOrganization": ("news_media", 0.8),
    "GovernmentOrganization": ("government", 0.9),
    "EducationalOrganization": ("education", 0.8),
    "Course": ("education", 0.8),
    "NGO": ("nonprofit_ngo", 0.8),
    "SoftwareApplication": ("saas_webapp", 0.7),
    "WebApplication": ("saas_webapp", 0.7),
    "DiscussionForumPosting": ("forum_community", 0.8),
    "Organization": ("institutional", 0.5),
    "LocalBusiness": ("institutional", 0.5),
    "Corporation": ("institutional", 0.5),
}

_OG_TYPE_MAP: dict[str, tuple[str, float]] = {
    "product": ("ecommerce", 0.4),
    "article": ("blog", 0.35),
    "business.business": ("institutional", 0.35),
    "profile": ("institutional", 0.25),
}

_GENERATOR_MAP: dict[str, tuple[str, float]] = {
    "shopify": ("ecommerce", 0.3),
    "woocommerce": ("ecommerce", 0.3),
    "magento": ("ecommerce", 0.3),
    "prestashop": ("ecommerce", 0.3),
    "bigcommerce": ("ecommerce", 0.3),
    "ghost": ("blog", 0.3),
    "hexo": ("blog", 0.3),
    "jekyll": ("blog", 0.3),
    "docusaurus": ("documentation", 0.3),
    "mkdocs": ("documentation", 0.3),
    "sphinx": ("documentation", 0.3),
    "readthedocs": ("documentation", 0.3),
    "gitbook": ("documentation", 0.3),
    "discourse": ("forum_community", 0.3),
    "vanilla": ("forum_community", 0.3),
    "phpbb": ("forum_community", 0.3),
    "vbulletin": ("forum_community", 0.3),
    "nodebb": ("forum_community", 0.3),
}

_PATH_KEYWORDS: dict[str, list[str]] = {
    "ecommerce": ["/cart", "/checkout", "/shop", "/store", "/product", "/carrinho", "/loja", "/produto", "comprar", "add to cart"],
    "blog": ["/blog", "/article", "/post", "/category/", "/tag/", "/author/", "leia mais", "read more"],
    "portfolio": ["/portfolio", "/projects", "/work", "/case-studies", "/projetos", "/trabalhos"],
    "institutional": ["/about", "/contact", "/services", "/team", "/sobre", "/contato", "/servicos", "/equipe", "/careers", "/vagas"],
    "news_media": ["/news", "/noticias", "/press", "/imprensa"],
    "forum_community": ["/forum", "/thread", "/topic", "/community", "/comunidade"],
    "saas_webapp": ["/login", "/signup", "/register", "/dashboard", "/pricing", "/planos", "free trial", "teste grátis"],
    "documentation": ["/docs", "/documentation", "/api-reference", "/guide", "/getting-started"],
    "education": ["/course", "/curso", "/lesson", "/aula", "/enroll", "/matricule-se"],
    "nonprofit_ngo": ["/donate", "/doacao", "/volunteer", "/voluntario"],
    "marketplace": ["/vendors", "/sellers", "/marketplace", "become a seller", "torne-se um vendedor"],
}

_ANCHOR_HIT_WEIGHT = 0.05
_ANCHOR_CAP = 0.35

_SITEMAP_HIT_WEIGHT = 0.15
_SITEMAP_CAP = 0.6

_TEXT_KEYWORDS: dict[str, list[str]] = {
    "ecommerce": ["woocommerce", "add-to-cart", "wc-ajax", "carrinho", "comprar agora", "frete grátis"],
    "blog": ["wp-block-post-date", "entry-date", "posted-on", "publicado em"],
    "portfolio": ["portfolio-item", "case study", "estudo de caso"],
    "institutional": ["quem somos", "who we are", "nossa missão", "our mission"],
    "news_media": ["breaking news", "últimas notícias", "editoria"],
    "forum_community": ["reply to thread", "responder ao tópico", "members online"],
    "saas_webapp": ["start free trial", "teste grátis", "start your trial", "upgrade plan", "cancel anytime"],
    "documentation": ["api reference", "getting started", "quickstart", "documentação técnica"],
    "education": ["matricule-se", "enroll now", "syllabus", "ementa", "carga horária"],
    "nonprofit_ngo": ["faça uma doação", "make a donation", "voluntariado", "organização sem fins lucrativos", "non-profit"],
    "marketplace": ["torne-se um vendedor", "become a seller", "multi-vendor"],
    "government": ["prefeitura", "secretaria de estado", "diário oficial", "portal da transparência"],
}

_TEXT_HIT_WEIGHT = 0.12
_TEXT_CAP = 0.5

_UNKNOWN_FLOOR = 0.25


# ── extração pura (testável sem rede) ───────────────────────────────────────

def _collect_jsonld_types(data) -> list[str]:
    types: list[str] = []
    if isinstance(data, list):
        for item in data:
            types.extend(_collect_jsonld_types(item))
        return types
    if isinstance(data, dict):
        graph = data.get("@graph")
        if isinstance(graph, list):
            for item in graph:
                types.extend(_collect_jsonld_types(item))
        t = data.get("@type")
        if isinstance(t, str):
            types.append(t)
        elif isinstance(t, list):
            types.extend(x for x in t if isinstance(x, str))
    return types


def _bump(scores: dict, hits: dict, site_type: str, weight: float, reason: str) -> None:
    scores[site_type] = scores.get(site_type, 0.0) + weight
    hits.setdefault(site_type, []).append(reason)


def score_jsonld(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = tag.string or tag.get_text() or ""
        try:
            data = json.loads(raw)
        except Exception:
            continue
        for t in _collect_jsonld_types(data):
            mapped = _JSONLD_TYPE_MAP.get(t)
            if mapped:
                site_type, weight = mapped
                _bump(scores, hits, site_type, weight, f"JSON-LD @type={t}")


def score_og_type(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    tag = soup.find("meta", attrs={"property": "og:type"})
    if tag is None or not tag.get("content"):
        return
    value = tag["content"].strip().lower()
    mapped = _OG_TYPE_MAP.get(value)
    if mapped:
        site_type, weight = mapped
        _bump(scores, hits, site_type, weight, f"og:type={value}")


def score_generator(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    tag = soup.find("meta", attrs={"name": "generator"})
    if tag is None or not tag.get("content"):
        return
    value = tag["content"].strip().lower()
    for needle, (site_type, weight) in _GENERATOR_MAP.items():
        if needle in value:
            _bump(scores, hits, site_type, weight, f"meta generator contém '{needle}'")


def score_anchors(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    contrib: dict[str, float] = {}
    matched_reason: dict[str, set] = {}

    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").lower()
        text = a.get_text(" ", strip=True).lower()
        haystack = f"{href} {text}"
        for site_type, keywords in _PATH_KEYWORDS.items():
            for kw in keywords:
                if kw in haystack:
                    contrib[site_type] = contrib.get(site_type, 0.0) + _ANCHOR_HIT_WEIGHT
                    matched_reason.setdefault(site_type, set()).add(kw)

    for site_type, total in contrib.items():
        capped = min(total, _ANCHOR_CAP)
        kws = ", ".join(sorted(matched_reason[site_type]))
        _bump(scores, hits, site_type, capped, f"âncoras internas mencionam [{kws}] (capado em {_ANCHOR_CAP})")


def score_text_keywords(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_desc = (meta_desc_tag.get("content") or "").lower() if meta_desc_tag else ""
    body_text = soup.get_text(" ", strip=True).lower()
    haystack = f"{title} {meta_desc} {body_text}"

    contrib: dict[str, float] = {}
    matched_reason: dict[str, set] = {}
    for site_type, keywords in _TEXT_KEYWORDS.items():
        for kw in keywords:
            if kw in haystack:
                contrib[site_type] = contrib.get(site_type, 0.0) + _TEXT_HIT_WEIGHT
                matched_reason.setdefault(site_type, set()).add(kw)

    for site_type, total in contrib.items():
        capped = min(total, _TEXT_CAP)
        kws = ", ".join(sorted(matched_reason[site_type]))
        _bump(scores, hits, site_type, capped, f"texto/título/meta menciona [{kws}] (capado em {_TEXT_CAP})")


def score_tld(target: str, scores: dict, hits: dict) -> None:
    host = urlparse(target).netloc.lower()
    if host.endswith(".gov") or host.endswith(".gov.br"):
        _bump(scores, hits, "government", 0.3, f"TLD governamental ({host})")
    elif host.endswith(".edu") or host.endswith(".edu.br"):
        _bump(scores, hits, "education", 0.3, f"TLD educacional ({host})")
    elif host.endswith(".org"):
        _bump(scores, hits, "nonprofit_ngo", 0.15, f"TLD .org ({host})")


def score_landing_structure(soup: BeautifulSoup, scores: dict, hits: dict) -> None:
    anchors = soup.find_all("a", href=True)
    if not anchors:
        return

    fragment_count = 0
    distinct_internal: set[str] = set()
    for a in anchors:
        href = (a.get("href") or "").strip()
        if href == "" or href.startswith("#"):
            fragment_count += 1
        elif not href.lower().startswith(("http://", "https://", "mailto:", "tel:", "javascript:")):
            distinct_internal.add(href.split("#")[0])
        else:
            distinct_internal.add(href.split("#")[0])

    total = len(anchors)
    fragment_ratio = fragment_count / total if total else 0.0

    if fragment_ratio > 0.5 and len(distinct_internal) < 8:
        _bump(
            scores, hits, "landing_page", 0.4,
            f"{fragment_ratio:.0%} das âncoras são fragmentos de página única, "
            f"só {len(distinct_internal)} links internos distintos",
        )


def is_html_response(content_type: str) -> bool:
    if not content_type:
        return True
    return "html" in content_type.lower()


def score_homepage(html_text: str, content_type: str, target: str) -> tuple[dict, dict]:
    scores: dict[str, float] = {}
    hits: dict[str, list[str]] = {}

    if not is_html_response(content_type):
        _bump(scores, hits, "api_headless", 0.6, f"Content-Type não-HTML ({content_type or 'ausente'})")
        return scores, hits

    soup = BeautifulSoup(html_text or "", "html.parser")

    score_jsonld(soup, scores, hits)
    score_og_type(soup, scores, hits)
    score_generator(soup, scores, hits)
    score_anchors(soup, scores, hits)
    score_text_keywords(soup, scores, hits)
    score_tld(target, scores, hits)
    score_landing_structure(soup, scores, hits)

    return scores, hits


def score_sitemap_urls(urls: list[str]) -> tuple[dict, dict]:
    scores: dict[str, float] = {}
    hits: dict[str, list[str]] = {}

    contrib: dict[str, float] = {}
    matched_reason: dict[str, set] = {}
    for u in urls:
        path = urlparse(u).path.lower()
        for site_type, keywords in _PATH_KEYWORDS.items():
            for kw in keywords:
                if kw.startswith("/") and kw in path:
                    contrib[site_type] = contrib.get(site_type, 0.0) + _SITEMAP_HIT_WEIGHT
                    matched_reason.setdefault(site_type, set()).add(kw)

    for site_type, total in contrib.items():
        capped = min(total, _SITEMAP_CAP)
        kws = ", ".join(sorted(matched_reason[site_type]))
        _bump(scores, hits, site_type, capped, f"sitemap.xml declara URLs com [{kws}] (capado em {_SITEMAP_CAP})")

    return scores, hits


def parse_sitemap_locs(xml_text: str) -> list[str]:
    try:
        root = ElementTree.fromstring(xml_text)
    except Exception:
        return []

    locs = []
    for elem in root.iter():
        if elem.tag.endswith("loc") and elem.text:
            locs.append(elem.text.strip())
    return locs


def is_ambiguous(scores: dict) -> bool:
    if not scores:
        return True
    ordered = sorted(scores.values(), reverse=True)
    top = ordered[0]
    second = ordered[1] if len(ordered) > 1 else 0.0
    return top < 0.5 or (top - second) < 0.15


def merge_scores(base: dict, extra: dict) -> None:
    for k, v in extra.items():
        base[k] = base.get(k, 0.0) + v


def merge_hits(base: dict, extra: dict) -> None:
    for k, v in extra.items():
        base.setdefault(k, []).extend(v)


def pick_winner(scores: dict) -> tuple[str, float]:
    if not scores:
        return "unknown", 0.0
    best_type = max(scores, key=lambda t: scores[t])
    return best_type, scores[best_type]


@discovery_module(
    requires=[],
    produces=[
        Produces("profile.site_type", durable=True),
        Produces("profile.site_type_signals", durable=False),
    ],
    cost=2,
    max_reentries=1,
    category="site_profiling",
    display_name="Perfil de Tipo de Site",
    summary="Classifica o tipo de site (ecommerce, blog, institucional, etc.) a partir de sinais extraídos de UM único fetch de homepage, com no máximo 1 requisição adicional (sitemap) só quando o resultado ficar ambíguo.",
)
class SiteTypeProfiler:
    """
    Ver docstring do módulo (topo do arquivo) para a relação com
    core/classifier.py e o algoritmo completo de economia de requisição.
    """

    name = "site_type_profiler"

    def run(self, target):
        r_home = get(target)
        if r_home is None:
            return None

        content_type = r_home.headers.get("Content-Type", "") if hasattr(r_home, "headers") else ""
        scores, hits = score_homepage(r_home.text, content_type, target)

        requests_spent = 1
        sitemap_used = False

        if is_ambiguous(scores):
            r_sitemap = get(f"{target.rstrip('/')}/sitemap.xml")
            requests_spent += 1
            if r_sitemap is not None and r_sitemap.status_code == 200:
                locs = parse_sitemap_locs(r_sitemap.text)
                if locs:
                    sitemap_used = True
                    sitemap_scores, sitemap_hits = score_sitemap_urls(locs)
                    merge_scores(scores, sitemap_scores)
                    merge_hits(hits, sitemap_hits)

        best_type, best_score = pick_winner(scores)
        if best_score < _UNKNOWN_FLOOR:
            best_type = "unknown"

        confidence = min(best_score, 1.0) if best_score > 0 else 0.0

        signals_value = {
            "scores": scores,
            "hits": hits,
            "requests_spent": requests_spent,
            "sitemap_used": sitemap_used,
            "winner": best_type,
        }

        return ModuleResult(
            findings=[],
            facts=[
                fact(
                    key="profile.site_type",
                    value=best_type,
                    confidence=confidence,
                    produced_by=self.name,
                    target=target,
                    evidence_ref=None,
                ),
                fact(
                    key="profile.site_type_signals",
                    value=signals_value,
                    confidence=confidence,
                    produced_by=self.name,
                    target=target,
                    evidence_ref=None,
                ),
            ],
        )

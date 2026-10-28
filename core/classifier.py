import requests

PROFILE_INDICATORS: dict[str, list[tuple[str, int]]] = {
    "ecommerce": [
        ("/cart",              3),
        ("/checkout",          3),
        ("/shop",              2),
        ("/loja",              2),
        ("/produto",           2),
        ("/produtos",          2),
        ("woocommerce",        3),  # keyword na homepage
        ("add-to-cart",        3),
        ("wc-ajax",            3),
        ("/minha-conta",       1),
        ("/my-account",        1),
        ("carrinho",           1),
    ],
    "blog": [
        ("/blog",              3),
        ("/posts",             2),
        ("/artigos",           2),
        ("/category/",         3),
        ("/tag/",              2),
        ("/author/",           2),
        ("wp-block-post-date", 2),  # classe do Gutenberg
        ("entry-date",         1),
        ("posted-on",          1),
        ("/feed/",             1),
    ],
    "portfolio": [
        ("/portfolio",         3),
        ("/projetos",          2),
        ("/trabalhos",         2),
        ("/cases",             2),
        ("/work",              2),
        ("/projects",          2),
        ("portfolio-item",     2),  # classe comum de temas
        ("case study",         1),
    ],
    "institutional": [
        ("/sobre",             2),
        ("/about",             2),
        ("/contato",           2),
        ("/contact",           2),
        ("/servicos",          2),
        ("/services",          2),
        ("/equipe",            1),
        ("/team",              1),
        ("/missao",            1),
        ("/mission",           1),
        ("quem somos",         1),
        ("who we are",         1),
    ],
}
 
THRESHOLD = 4  # pontuação mínima para considerar um tipo detectado
 
 
class SiteClassifier:
    """
    Classifica o tipo de site via probes HTTP leves.
 
    Uso:
        classifier = SiteClassifier(timeout=6)
        site_type, indicators = classifier.classify("https://example.com")
    """
 
    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "W.R.A.I.T.H Scanner"
        )
        self.session.headers["Accept"] = "*/*"

    def classify(self, target: str) -> tuple[str, dict]:
        """
        Retorna (site_type, indicators_found).
 
        indicators_found é um dict {tipo: [indicadores que acertaram]}
        útil para debug e para salvar no Postgres.
        """
        target = target.rstrip("/")
        homepage_content = self._fetch_body(target)
 
        scores: dict[str, int]        = {t: 0 for t in PROFILE_INDICATORS}
        found:  dict[str, list[str]]  = {t: [] for t in PROFILE_INDICATORS}
 
        for site_type, indicators in PROFILE_INDICATORS.items():
            for indicator, weight in indicators:
                hit = False
 
                if indicator.startswith("/"):
                    # Probe de path — verifica se retorna 200
                    hit = self._path_exists(target, indicator)
                else:
                    # Keyword — verifica na homepage
                    if homepage_content and indicator.lower() in homepage_content:
                        hit = True
 
                if hit:
                    scores[site_type] += weight
                    found[site_type].append(indicator)
 
        best_type  = max(scores, key=lambda t: scores[t])
        best_score = scores[best_type]
 
        if best_score < THRESHOLD:
            return "unknown", {"scores": scores, "found": found}
 
        # Empate: prioriza pela ordem do dict (ecommerce > blog > portfolio > institutional)
        winners = [t for t, s in scores.items() if s == best_score]
        for preferred in PROFILE_INDICATORS:
            if preferred in winners:
                site_type = preferred
                break
        else:
            site_type = best_type
 
        return site_type, {"scores": scores, "found": found}
 
    # ── helpers ───────────────────────────────────────────────────────────────
 
    def _fetch_body(self, target: str) -> str | None:
        try:
            r = self.session.get(target, timeout=self.timeout, allow_redirects=True)
            return r.text.lower() if r and r.status_code == 200 else None
        except Exception:
            return None
 
    def _path_exists(self, target: str, path: str) -> bool:
        try:
            r = self.session.get(target + path, timeout=self.timeout, allow_redirects=True)
            return r is not None and r.status_code == 200
        except Exception:
            return False

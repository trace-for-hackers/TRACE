"""
modules/js_rendering_crawler.py

Crawler baseado em navegador real (Playwright/Chromium headless) --
diferente de crawler.py (que só parseia HTML ESTÁTICO devolvido pelo
servidor), este executa o JavaScript da página de verdade, esperando o
front-end (Angular/React/Vue/etc.) renderizar antes de extrair link e
formulário -- E intercepta toda requisição de rede (fetch/XHR) que a
própria aplicação faz durante o carregamento, capturando endpoint de
API que NUNCA aparece como link estático no HTML.

Motivado por teste real (09/2026): contra uma SPA (Angular, ex.: OWASP
Juice Shop), crawler.py nunca sai da casca vazia que o servidor
devolve -- todo link/formulário só existe depois do JS rodar. Isso
fazia os heurísticos de injeção (SQLi/XSS/SSTI/LDAP/command injection)
nunca terem parâmetro nenhum pra testar contra esse tipo de app, mesmo
com vulnerabilidade real por trás -- não era "não achou", era "nunca
viu a página".

LIMITAÇÃO HONESTA, deliberada: só produz `surface.param.*` (o MESMO
formato que crawler.py já produz) pra requisição GET com querystring --
por isso funciona com TODO heurístico de injeção existente sem precisar
mudar nada neles. Requisição POST com corpo JSON (comum em API REST
tipo /rest/user/login) também é capturada, mas vira fato numa categoria
separada (`surface.json_param.*`) que NENHUM heurístico ainda consome
-- os heurísticos hoje mandam corpo form-encoded (utils/requester.py
post()), não JSON. Estender isso é o próximo passo natural, não feito
aqui de propósito (misturaria "descobrir parâmetro de SPA" com "testar
corpo JSON" na mesma mudança -- dois problemas, duas mudanças).

DEPENDÊNCIA OPCIONAL: precisa de `playwright` instalado E do binário do
Chromium baixado (`python3 -m playwright install chromium`) -- os dois
são pesados (só o navegador passa de 100MB) e propositalmente NÃO são
dependência obrigatória do TRACE. Sem eles, este módulo imprime aviso
claro e não roda -- o resto do TRACE funciona normal (mesmo padrão de
degradação graciosa de pyarrow/opentelemetry, ver requirements.txt).
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse, parse_qs

from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

_PAGE_LOAD_TIMEOUT_MS = 15_000
_NETWORK_IDLE_TIMEOUT_MS = 5_000


def _hash10(raw: str) -> str:
    """Mesmo padrão de crawler.py -- SHA1 truncado, estável entre
    execuções (diferente de hash() nativo do Python, que varia por
    processo)."""
    return hashlib.sha1(raw.encode()).hexdigest()[:10]


def extract_get_params_from_url(url: str) -> list[tuple[str, str]]:
    """(url_base, param) pra cada parâmetro de querystring -- função
    pura, usada tanto pra link do DOM renderizado quanto pra requisição
    de rede capturada. Testável sem navegador nenhum."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    base_url = url.split("?")[0]
    return [(base_url, param) for param in qs]


def classify_captured_request(method: str, url: str, has_json_body: bool) -> str:
    """Decide em que FORMATO DE FATO uma requisição capturada deveria
    virar -- 'get_query' (compatível com todo heurístico existente),
    'json_body' (capturado, mas sem consumidor ainda), ou 'ignore'
    (sem parâmetro nenhum pra testar, ex.: GET sem querystring)."""
    parsed = urlparse(url)
    if method.upper() == "GET" and parsed.query:
        return "get_query"
    if method.upper() in ("POST", "PUT", "PATCH") and has_json_body:
        return "json_body"
    return "ignore"


def _same_origin(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


@discovery_module(
    requires=(),
    produces=[
        Produces("surface.param.*", durable=False),
        Produces("surface.json_param.*", durable=False),
    ],
    cost=15,  # caro de propósito -- sobe navegador real, renderiza, espera rede
    category="discovery_injection",
    display_name="Crawler com Renderização de JavaScript",
    summary="Renderiza a página com Chromium headless real (via Playwright) e intercepta requisição de rede feita pela própria SPA -- descobre parâmetro que crawler.py nunca veria em app React/Angular/Vue, onde todo link/formulário só existe depois do JS rodar.",
)
class JSRenderingCrawler:
    name = "js_rendering_crawler"

    def run(self, target: str):
        if not PLAYWRIGHT_AVAILABLE:
            print("[js_rendering_crawler] playwright não instalado -- módulo não roda "
                  "(pip install playwright && python3 -m playwright install chromium).")
            return None

        captured_requests = []

        try:
            with sync_playwright() as p:
                try:
                    browser = p.chromium.launch(headless=True)
                except Exception as e:
                    print(f"[js_rendering_crawler] não consegui iniciar o Chromium: {e} "
                          f"-- rode 'python3 -m playwright install chromium'.")
                    return None

                page = browser.new_page()

                def on_request(request):
                    content_type = (request.headers.get("content-type") or "").lower()
                    is_json = bool(request.post_data) and "json" in content_type
                    parsed_body = None
                    if is_json:
                        try:
                            import json as _json
                            parsed_body = _json.loads(request.post_data)
                        except Exception:
                            is_json = False  # corpo alegava ser JSON mas não parseou -- trata como sem corpo utilizável
                    captured_requests.append({
                        "method": request.method,
                        "url": request.url,
                        "has_json_body": is_json,
                        "json_body": parsed_body,
                    })

                page.on("request", on_request)

                try:
                    page.goto(target, timeout=_PAGE_LOAD_TIMEOUT_MS, wait_until="domcontentloaded")
                    page.wait_for_load_state("networkidle", timeout=_NETWORK_IDLE_TIMEOUT_MS)
                except Exception:
                    pass  # timeout de rede ociosa não é erro fatal -- já capturou o que rolou até aqui

                try:
                    dom_links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    dom_links = []

                browser.close()
        except Exception as e:
            print(f"[js_rendering_crawler] erro inesperado: {type(e).__name__}: {e}")
            return None

        facts_out = []
        seen_get = set()
        seen_json = set()

        all_candidates = [(r["method"], r["url"], r["has_json_body"], r.get("json_body")) for r in captured_requests]
        all_candidates += [("GET", link, False, None) for link in dom_links]

        for method, url, has_json_body, json_body in all_candidates:
            if not _same_origin(target, url):
                continue

            kind = classify_captured_request(method, url, has_json_body)

            if kind == "get_query":
                for base_url, param in extract_get_params_from_url(url):
                    dedup_key = f"{base_url}|{param}"
                    if dedup_key in seen_get:
                        continue
                    seen_get.add(dedup_key)
                    facts_out.append(fact(
                        f"surface.param.{_hash10(dedup_key)}",
                        {"url": base_url, "method": "GET", "param": param},
                        0.9, self.name, target,
                    ))

            elif kind == "json_body":
                # só objeto de nível superior tem campo pra injetar --
                # lista ("[1,2,3]") ou valor primitivo na raiz não dá pra
                # testar campo por campo do mesmo jeito.
                if not isinstance(json_body, dict) or not json_body:
                    continue
                dedup_key = f"{method}|{url}"
                if dedup_key in seen_json:
                    continue
                seen_json.add(dedup_key)
                facts_out.append(fact(
                    f"surface.json_param.{_hash10(dedup_key)}",
                    {"url": url, "method": method, "body_template": json_body,
                     "fields": list(json_body.keys())},
                    0.7, self.name, target,
                ))

        if not facts_out:
            return None
        return ModuleResult(facts=facts_out)

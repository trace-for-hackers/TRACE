from utils.requester import get
from knowledge.contracts import discovery_module, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult


@discovery_module(
    requires=[],  # raiz: sempre elegível, é a porta de entrada da cadeia de descoberta
    produces=[Produces("cms.wordpress.detected", durable=True)],
    cost=3,  # 3 requisições (home, /wp-json, /wp-login.php) -- ainda barato
    category="cms_detection",
    display_name="Detecção Multi-Sinal de WordPress",
)
class WPDetect:
    """
    Detector raiz de WordPress, com múltiplos sinais independentes.

    Por quê: wp_version.py (o detector raiz original) depende só da meta tag
    <meta name="generator">, que muitos sites removem por segurança (plugins
    como o "WP Hide" ou simples theme override fazem isso). Sem essa tag,
    cms.wordpress.detected nunca era produzido e a cadeia inteira de
    descoberta ficava travada na onda 0 -- mesmo em sites que claramente são
    WordPress.

    Este módulo soma confiança a partir de 5 sinais, sem exigir todos:

        /wp-json responde com JSON contendo "name"/"description"  -> +0.5 (forte:
            é a REST API nativa do core, dificilmente removida ou falsificada)
        /wp-login.php existe (200 ou redirect para wp-login)        -> +0.3
        cookie de sessão "wordpress_" ou "wp-settings-" presente     -> +0.3
        meta generator content contém "wordpress"                   -> +0.4
        HTML contém "/wp-content/" ou "/wp-includes/"                -> +0.2

    A soma é "capada" em 1.0. min_confidence default exigido pelos módulos
    dependentes é 0.5 -- ou seja, BASTA UM sinal forte (/wp-json OU meta tag)
    para liberar a onda 1, mesmo que todos os outros sinais falhem.

    Se nenhum sinal bater, retorna None (não produz fato nenhum) -- e nesse
    caso a cadeia simplesmente não avança, o que é o comportamento correto
    para um alvo que de fato não é WordPress.
    """

    name = "wp_detect"

    def run(self, target):
        signals = []     # lista de (nome_do_sinal, peso) que bateram, para evidência
        confidence = 0.0

        # ── sinal 1: REST API nativa (/wp-json) ────────────────────────────
        r_json = get(f"{target}/wp-json")
        if r_json and r_json.status_code == 200:
            try:
                data = r_json.json()
                if isinstance(data, dict) and ("name" in data or "description" in data or "routes" in data):
                    signals.append(("wp-json reachable", 0.5))
                    confidence += 0.5
            except Exception:
                pass

        # ── sinal 2: /wp-login.php existe ──────────────────────────────────
        r_login = get(f"{target}/wp-login.php")
        if r_login and r_login.status_code in (200, 302, 403):
            body = (r_login.text or "").lower()
            if "wordpress" in body or "wp-login" in body or r_login.status_code in (200, 302):
                signals.append(("wp-login.php presente", 0.3))
                confidence += 0.3

        # ── sinal 3, 4 e 5: cookies de sessão, meta generator, paths de asset
        # (todos a partir de UMA única requisição na home, para economizar)
        r_home = get(target)
        if r_home:
            cookie_names = " ".join(c for c in r_home.cookies.keys()) if hasattr(r_home, "cookies") else ""
            set_cookie_header = r_home.headers.get("Set-Cookie", "") if hasattr(r_home, "headers") else ""
            cookie_blob = (cookie_names + " " + set_cookie_header).lower()
            if "wordpress_" in cookie_blob or "wp-settings-" in cookie_blob:
                signals.append(("cookie de sessão WordPress", 0.3))
                confidence += 0.3

            body = (r_home.text or "").lower()

            if "name=\"generator\" content=\"wordpress" in body or 'name="generator" content="wordpress' in body:
                signals.append(("meta generator tag", 0.4))
                confidence += 0.4

            if "/wp-content/" in body or "/wp-includes/" in body:
                signals.append(("paths /wp-content/ ou /wp-includes/ no HTML", 0.2))
                confidence += 0.2

        if not signals:
            return None

        confidence = min(confidence, 1.0)

        return ModuleResult(
            findings=[],  # detecção de WordPress em si não é um achado de segurança,
                          # é conhecimento estrutural -- não gera linha no relatório,
                          # só alimenta o Knowledge Store
            facts=[fact(
                key="cms.wordpress.detected",
                value=True,
                confidence=confidence,
                produced_by=self.name,
                target=target,
                evidence_ref=None,
            )],
        )
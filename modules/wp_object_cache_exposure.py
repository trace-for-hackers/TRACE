import re
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


# Padrões que indicam uma string de conexão Redis/Memcached real, não só a
# palavra "redis" aparecendo em texto solto (que daria falso positivo
# constante em qualquer site que mencione a tecnologia em um post de blog).
CONNECTION_STRING_PATTERNS = [
    r"redis://[^\s\"'<>]+",
    r"tcp://[\d.]+:\d{2,5}",                  # memcached/redis via tcp://host:port
    r"['\"]?password['\"]?\s*[:=]\s*['\"][^'\"\s]{4,}['\"]",
    r"['\"]?auth['\"]?\s*[:=]\s*['\"][^'\"\s]{4,}['\"]",
]

# Paths onde configuração de cache costuma ser deixada acessível por engano
# -- diferente de wp_cache_exposure.py (que testa paths genéricos de plugins
# de cache de página como WP Super Cache/W3TC/WP Rocket), este módulo foca
# especificamente no DROP-IN de object cache (object-cache.php), que é um
# arquivo de configuração de baixo nível, não um plugin de página.
OBJECT_CACHE_PATHS = [
    "wp-content/object-cache.php",
    "wp-content/object-cache.php.bak",
    "wp-content/cache/object-cache.php",
]


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=len(OBJECT_CACHE_PATHS),
    category="object_cache",
)
class WPObjectCacheExposure:
    """
    Testa se o drop-in wp-content/object-cache.php (usado para integrar
    WordPress com Redis ou Memcached como cache de objetos, complementar ao
    cache de página) está acessível publicamente e, se sim, se o seu
    conteúdo vaza uma string de conexão com credenciais.

    Diferente de wp_cache_exposure.py (cache de página -- WP Super Cache,
    W3TC, WP Rocket, detectado via tech.cache_plugin.present), object-cache.php
    é um arquivo PHP de baixo nível que normalmente NUNCA deveria ser servido
    como texto puro pelo servidor (PHP deveria ser executado, não exibido)
    -- se ele responde com conteúdo legível, isso já indica um problema de
    configuração do servidor mais amplo (PHP não sendo processado naquele
    diretório), não só uma falha específica de cache.
    """
    name = "wp_object_cache_exposure"

    def run(self, target):
        exposed = []

        for path in OBJECT_CACHE_PATHS:
            r = get(f"{target}/{path}")
            if not r or r.status_code != 200:
                continue

            body = r.text or ""
            if len(body) < 30:
                continue

            # se o PHP foi executado normalmente pelo servidor, a resposta
            # não deveria conter a tag <?php nem credenciais em texto puro --
            # a presença disso confirma que o servidor está servindo o
            # arquivo como texto, não interpretando como código.
            if "<?php" not in body and "redis" not in body.lower() and "memcache" not in body.lower():
                continue

            matches = []
            for pattern in CONNECTION_STRING_PATTERNS:
                found = re.findall(pattern, body, re.IGNORECASE)
                matches.extend(found)

            exposed.append({
                "path": f"/{path}",
                "contains_php_tag": "<?php" in body,
                "connection_strings_found": len(matches),
            })

        if not exposed:
            return None

        f = Finding(
            module=self.name,
            title="Object Cache Configuration Exposed",
            severity="critical",
            description=(
                "The wp-content/object-cache.php drop-in is being served as plain text "
                "instead of being executed by the PHP interpreter, potentially exposing "
                "Redis/Memcached connection details, including credentials."
            ),
            endpoint="/wp-content/",
            evidence=exposed,
        )

        f.business_impact = (
            "If the object cache backend (Redis/Memcached) is reachable from outside "
            "and lacks its own authentication, an attacker with the leaked connection "
            "string can read or write cached objects directly -- which, depending on "
            "what WordPress caches (session tokens, transients, sometimes serialized "
            "user data), can lead to session hijacking or further compromise. The fact "
            "that this PHP file is served as plain text also indicates a broader "
            "server misconfiguration (PHP not being processed in that directory), which "
            "may affect other files beyond this one."
        )

        f.remediation = (
            "Investigate why PHP files in wp-content/ are being served as plain text "
            "instead of executed -- this is a server/webserver configuration issue, not "
            "just a WordPress one. Rotate any exposed cache credentials immediately and "
            "ensure the cache backend is not reachable from outside the application "
            "server's network."
        )

        f.exploitability = "Easy"

        return [f.to_dict()]
from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.fact import fact
from knowledge.result import ModuleResult

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5),
              Requirement("surface.rest_api.present", min_confidence=0.5)],
    produces=[Produces("auth.users_enumerated", durable=False)],
    cost=4,
    display_name="Enumeração de Usuários WordPress",
    summary="Combina REST API (/wp-json/wp/v2/users) e redirect de author archive (?author=N) para listar usuários válidos sem autenticação.",
)
class WPUserEnumeration:
    """
    Combina dois vetores clássicos de enumeração de usuários WordPress no
    mesmo módulo, porque ambos produzem o mesmo fato e um é o fallback
    natural do outro:
 
    1. REST API (/wp-json/wp/v2/users) -- vetor moderno, lista todos os
       usuários com slug, nome de exibição e ID de uma vez só, sem
       autenticação, quando a API não está restrita.
 
    2. Author archive enumeration (?author=1, ?author=2...) -- vetor clássico,
       funciona mesmo quando a REST API de usuários está bloqueada (plugin de
       segurança, ou WP antigo), porque o redirect de ?author=N para
       /author/slug-do-usuario/ revela o slug do usuário pelo Location header,
       mesmo que a página de destino dê 404.
 
    Diferente de wp_login_enumeration.py (que testa o formulário de
    recuperação de senha, um vetor de timing/mensagem diferente), este módulo
    foca em descobrir QUAIS usuários existem, não se um username específico
    é válido.
    """
    name = "wp_user_enumeration"
 
    MAX_AUTHOR_IDS_TO_PROBE = 5
 
    def run(self, target):
        users_found = {}  # slug -> {"source": ..., "id": ..., "name": ...}
 
        # ── vetor 1: REST API ──────────────────────────────────────────────
        r = get(f"{target}/wp-json/wp/v2/users")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list):
                    for u in data:
                        slug = u.get("slug")
                        if slug:
                            users_found[slug] = {
                                "source": "rest_api",
                                "id": u.get("id"),
                                "name": u.get("name"),
                            }
            except Exception:
                pass
 
        # ── vetor 2: author archive (fallback, roda mesmo se a REST API
        # já achou algo, porque o redirect pode revelar IDs adicionais
        # que a REST API paginada não devolveu na primeira página) ────────
        for author_id in range(1, self.MAX_AUTHOR_IDS_TO_PROBE + 1):
            r = get(f"{target}/?author={author_id}")
            if not r:
                continue
 
            location = r.headers.get("Location", "") if hasattr(r, "headers") else ""
            slug_from_redirect = None
            if "/author/" in location:
                try:
                    slug_from_redirect = location.split("/author/")[1].strip("/").split("/")[0]
                except IndexError:
                    pass
 
            if slug_from_redirect and slug_from_redirect not in users_found:
                users_found[slug_from_redirect] = {
                    "source": "author_archive_redirect",
                    "id": author_id,
                    "name": None,
                }
 
        if not users_found:
            return None
 
        f = Finding(
            module=self.name,
            title="WordPress Users Enumerated",
            severity="medium",
            description=(
                "WordPress usernames were enumerated via the REST API and/or author "
                "archive redirects, without authentication."
            ),
            endpoint="/wp-json/wp/v2/users",
            evidence={"users": users_found, "total": len(users_found)},
        )
 
        f.business_impact = (
            "Enumerated usernames are the first input needed for targeted brute-force, "
            "credential stuffing, or social engineering attacks. Combined with a weak "
            "password policy, this significantly lowers the cost of account takeover."
        )
 
        f.remediation = (
            "Restrict the /wp-json/wp/v2/users endpoint to authenticated requests, "
            "and disable author archive redirects that leak usernames via the "
            "Location header (e.g., via a security plugin or custom rewrite rule)."
        )
 
        f.exploitability = "Easy"
 
        return ModuleResult(
            findings=[f.to_dict()],
            facts=[fact(
                "auth.users_enumerated", list(users_found.keys()), 0.9, self.name, target,
            )],
        )
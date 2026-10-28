from utils.requester import get, post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement


@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=2,
    category="trackback",
    display_name="Trackback de Comentário Aberto",
    summary="Verifica se o trackback nativo (wp-trackback.php) aceita submissões sem CAPTCHA ou rate limiting, vetor clássico de spam de comentário.",
)
class WPCommentTrackbackOpen:
    """
    Testa se o trackback nativo do sistema de comentários (wp-trackback.php)
    está habilitado e aceita requisições sem CAPTCHA/rate limiting.

    Distinto do vetor de pingback via XML-RPC já coberto por xmlrpc.py /
    xmlrpc_ssrf.py (que usa o método pingback.ping via POST em /xmlrpc.php,
    um endpoint único e global): wp-trackback.php é POR POST -- cada post
    individual tem seu próprio endpoint de trackback
    (target/?p=123 ou target/post-slug/trackback/), e aceita um payload
    diferente (form-encoded simples, não XML-RPC). Um WAF ou plugin de
    segurança que bloqueia /xmlrpc.php especificamente pode deixar
    wp-trackback.php completamente aberto sem perceber, porque são
    superfícies de código distintas dentro do core do WordPress.

    O achado em si não é SSRF direto (trackback não faz uma requisição HTTP
    de volta automaticamente como pingback faz) -- é primariamente um vetor
    de spam de comentário e, em instalações antigas sem mitigação,
    historicamente também alvo de abuso para flood/DoS de baixo volume
    (cada trackback aceito grava no banco e dispara notificação por e-mail
    ao autor do post).
    """
    name = "wp_comment_trackback_open"

    def run(self, target):
        # encontra um post real para testar -- sem um post_id válido, o
        # trackback sempre falha por "post not found", o que mascararia se
        # o mecanismo em si está habilitado ou desabilitado.
        post_url = self._find_a_post(target)
        if not post_url:
            return None

        trackback_url = post_url.rstrip("/") + "/trackback/"
        probe_payload = {
            "title": "wraith-trackback-probe",
            "url": "https://wraith-probe.invalid/",
            "blog_name": "WRAITH Probe",
            "excerpt": "probe",
        }

        r = post(trackback_url, probe_payload)
        if not r:
            return None

        body = (r.text or "").lower()
        # resposta de sucesso do trackback é XML com <error>0</error>;
        # rejeição (trackback desabilitado para o post, ou globalmente)
        # tipicamente devolve <error>1</error> com uma mensagem.
        if "<error>0</error>" in body:
            f = Finding(
                module=self.name,
                title="WordPress Comment Trackback Enabled Without Protection",
                severity="low",
                description=(
                    "The native WordPress trackback mechanism (wp-trackback.php) accepted "
                    "a probe submission without any CAPTCHA or rate-limiting challenge."
                ),
                endpoint=trackback_url,
                evidence={"response_snippet": body[:200]},
            )
            f.business_impact = (
                "Open trackbacks are a well-known low-effort vector for automated comment "
                "spam at scale, and can be used to flood the post author's notification "
                "email or pad the comments table with junk entries."
            )
            f.remediation = (
                "Disable trackbacks and pingbacks globally in Settings > Discussion, or "
                "install a plugin that rate-limits and CAPTCHA-protects trackback/pingback "
                "submissions."
            )
            f.exploitability = "Easy"
            return [f.to_dict()]

        return None

    def _find_a_post(self, target):
        """Usa a REST API (se disponível) para achar a URL de um post real --
        muito mais confiável do que tentar adivinhar slugs. Se a REST API
        estiver bloqueada, retorna None e o módulo simplesmente não roda
        (sem post real para testar, o resultado seria inconclusivo de
        qualquer forma)."""
        r = get(f"{target}/wp-json/wp/v2/posts?per_page=1")
        if not r or r.status_code != 200:
            return None
        try:
            data = r.json()
        except Exception:
            return None
        if isinstance(data, list) and data:
            return data[0].get("link")
        return None
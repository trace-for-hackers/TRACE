from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement, RequirementMode


@discovery_module(
    requires=[
        Requirement("tech.wpforms.present", min_confidence=0.5),
        Requirement("tech.gravityforms.present", min_confidence=0.5),
    ],
    requirement_mode=RequirementMode.ANY,  # testa qualquer um dos dois plugins,
                                            # não exige os dois presentes ao mesmo tempo
    cost=4,
    category="form_entries",
    display_name="Exposição de Entries de Formulário",
    summary="Testa páginas públicas com shortcode de listagem de entries (WPForms) e o endpoint de export sem capability check (Gravity Forms), que vazariam dados pessoais submetidos por visitantes.",
)
class WPFormEntriesExposure:
    """
    Testa vetores conhecidos de má configuração que expõem entries (respostas
    de formulário) de WPForms/Gravity Forms sem autenticação:

    1. WPForms: a página de "entries" em si vive sob /wp-admin/ (autenticada
       por padrão), mas alguns sites usam o shortcode [wpforms_entries_table]
       numa página pública para listagem customizada -- se essa página
       pública existir e não estiver protegida por outro mecanismo (membership
       plugin, .htaccess), as entries ficam visíveis no HTML renderizado.

    2. Gravity Forms: AJAX action gform_get_config (a mesma que o detector
       usa) confirma presença, mas o action rg_update_feed_active e outros
       endpoints de admin-ajax exigem nonce válido -- este módulo testa
       especificamente se o endpoint de exportação de entries em CSV
       (admin-ajax.php?action=gf_entry_list_export ou rota equivalente)
       responde com dados reais em vez de erro de permissão, o que indica
       checagem de capability ausente ou mal implementada.

    Diferente de tentar explorar os CVEs de XSS armazenado documentados para
    Gravity Forms (que exigem injetar payload e esperar um admin visualizar
    a entry depois -- não é algo que um scan de reconhecimento confirma na
    hora), este módulo foca em DETECTAR EXPOSIÇÃO DE DADOS JÁ EXISTENTES,
    que é verificável imediatamente e sem ambiguidade.
    """
    name = "wp_form_entries_exposure"

    # nomes de página comuns onde sites publicam shortcodes de listagem de
    # entries por engano (geralmente para "dashboards" internos que foram
    # esquecidos sem proteção de acesso)
    WPFORMS_COMMON_PAGES = ["entries", "form-entries", "submissions", "form-submissions"]

    def run(self, target):
        findings = []

        # ── vetor 1: WPForms shortcode de entries em página pública ────────
        for slug in self.WPFORMS_COMMON_PAGES:
            r = get(f"{target}/{slug}/")
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if "wpforms-entries-table" in body.lower() or (
                "wpforms" in body.lower() and "entry-id" in body.lower()
            ):
                findings.append({
                    "vector": "wpforms_public_entries_page",
                    "url": f"{target}/{slug}/",
                })

        # ── vetor 2: Gravity Forms export de entries sem capability check ───
        r = get(f"{target}/wp-admin/admin-ajax.php?action=gf_entry_list_export")
        if r and r.status_code == 200:
            body = r.text or ""
            # heurística: um export real de entries devolve CSV/conteúdo
            # estruturado; uma rejeição por permissão devolve "0", -1, ou
            # uma mensagem de erro JSON curta. Corpo "grande demais para ser
            # um erro" é o melhor sinal disponível sem autenticação válida
            # para comparar lado a lado.
            if len(body) > 200 and ("," in body or "entry" in body.lower()):
                findings.append({
                    "vector": "gravityforms_export_endpoint_unprotected",
                    "url": f"{target}/wp-admin/admin-ajax.php?action=gf_entry_list_export",
                    "response_length": len(body),
                })

        if not findings:
            return None

        f = Finding(
            module=self.name,
            title="Form Entries Exposed Without Authentication",
            severity="high",
            description=(
                "Form submission entries (WPForms and/or Gravity Forms) appear to be "
                "accessible without authentication, either via a public page using an "
                "entries-listing shortcode or via an unprotected export endpoint."
            ),
            endpoint="/",
            evidence=findings,
        )

        f.business_impact = (
            "Form entries frequently contain personal data submitted by site visitors "
            "(names, emails, phone numbers, and in some cases payment-adjacent fields). "
            "Exposure without authentication is a direct data breach and, depending on "
            "jurisdiction and data category, may carry regulatory notification obligations."
        )

        f.remediation = (
            "Remove or password-protect any public page using an entries-listing "
            "shortcode. For Gravity Forms, verify that export/list AJAX actions enforce "
            "current_user_can() capability checks server-side, not just client-side "
            "nonce validation."
        )

        f.exploitability = "Easy"

        return [f.to_dict()]
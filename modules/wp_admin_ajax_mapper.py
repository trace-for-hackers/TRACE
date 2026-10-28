from utils.requester import post
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=1,
    display_name="Mapeamento de Ações do admin-ajax.php",
    summary="Testa uma lista de actions comuns (upload, backup, restore, instalação de plugin) contra admin-ajax.php para descobrir quais respondem sem autenticação.",
)
class WPAdminAjaxMapper:
    name = "wp_admin_ajax_mapper"

    COMMON_ACTIONS = [
        "revslider_show_image",
        "upload_image",
        "upload_file",
        "import_data",
        "export_data",
        "backup",
        "restore",
        "download_backup",
        "get_image",
        "fetch_image",
        "process_form",
        "submit_form",
        "save_settings",
        "update_settings",
        "install_plugin",
        "install_theme",
        "update_plugin",
    ]

    def run(self, target):
        url = f"{target}/wp-admin/admin-ajax.php"
        interesting = []

        for action in self.COMMON_ACTIONS:
            r = post(url, data={"action": action})

            if not r:
                continue

            body = r.text.strip().lower()

            if body == "0":
                continue

            interesting.append({
                "action": action,
                "status": r.status_code,
                "response_sample": body[:120]
            })

        if not interesting:
            return None

        findings = []

        if interesting:
            f = Finding(
                module=self.name,
                title="WordPress admin-ajax.php Actions Exposed",
                severity="medium",
                description="Exposed WordPress admin-ajax.php actions discovered.",
                endpoint="/wp-admin/admin-ajax.php",
                evidence=interesting
            )

            f.business_impact = (
                "An attacker can explore exposed admin-ajax.php actions to gather sensitive information or exploit vulnerabilities."
            )

            f.remediation = (
                "Restrict access to the admin-ajax.php endpoint or disable unnecessary actions via server configuration."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
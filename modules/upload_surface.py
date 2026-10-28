from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module, Requirement

@discovery_module(
    requires=[Requirement("cms.wordpress.detected", min_confidence=0.5)],
    cost=8,  # testa 1 diretório + 8 arquivos comuns + 4 paths de PHP -- caro, vale gatear
    category="upload_surface",
    display_name="Superfície de Uploads Exposta",
    summary="Testa listagem de diretório e arquivos sensíveis comuns (logs, backups, configs) dentro de wp-content/uploads/. Módulo caro (8 requisições), por isso só roda após confirmar WordPress.",
)
class WPUploadSurface:
    name = "wp_upload_surface"

    COMMON_FILES = [
        "debug.log",
        "backup.zip",
        "db.sql",
        "database.sql",
        "site.bak",
        "wp-config.php.bak",
        "error_log",
        "log.txt"
    ]

    def run(self, target):
        base = f"{target}/wp-content/uploads/"
        interesting = []

        r = get(base)
        if r and "Index of" in r.text:
            interesting.append({
                "type": "directory_listing",
                "path": base
            })

        for file in self.COMMON_FILES:
            url = base + file
            r = get(url)
            if r and r.status_code == 200 and len(r.text) > 20:
                interesting.append({
                    "type": "exposed_file",
                    "path": url
                })

        php_test_paths = [
            "shell.php",
            "cmd.php",
            "test.php",
            "upload.php"
        ]

        for file in php_test_paths:
            url = base + file
            r = get(url)
            if r and r.status_code == 200 and "<?php" in r.text:
                interesting.append({
                    "type": "php_file_in_uploads",
                    "path": url
                })

        if not interesting:
            return None

        findings = []

        if interesting:
            f = Finding(
                module=self.name,
                title="WordPress Uploads Directory Exposed",
                severity="medium",
                description="Sensitive files or directory listing found in uploads directory.",
                endpoint="/wp-content/uploads/",
                evidence=interesting
            )

            f.business_impact = (
                "An attacker can explore exposed uploads directory to gather sensitive information or exploit vulnerabilities."
            )

            f.remediation = (
                "Restrict access to the uploads directory or disable directory listing via server configuration."
            )

            f.exploitability = "Easy"

            findings.append(f.to_dict())

            return findings
        return None
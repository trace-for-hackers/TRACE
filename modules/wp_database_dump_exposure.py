from utils.requester import get
from core.finding import Finding
from knowledge.contracts import discovery_module


# Padrões de nome de arquivo de backup de banco mais comuns em erro humano:
# script de deploy/backup manual deixado no webroot, nome do site + extensão
# óbvia, ou nome genérico que ferramentas de backup usam por padrão.
COMMON_DB_DUMP_PATHS = [
    "database.sql", "db.sql", "backup.sql", "dump.sql",
    "database.sql.gz", "db.sql.gz", "backup.sql.gz", "dump.sql.gz",
    "database.zip", "backup.zip", "site-backup.zip",
    "wp-content/backup.sql", "wp-content/backups/backup.sql",
    "backup-db.sql", "sql.sql", "data.sql",
]

# Strings que, se presentes no corpo, confirmam que é de fato um dump SQL
# (e não uma página de erro 200 ou um arquivo vazio com nome coincidente).
SQL_DUMP_SIGNATURES = [
    "CREATE TABLE", "INSERT INTO", "-- MySQL dump", "-- phpMyAdmin SQL Dump",
    "wp_users", "wp_options", "wp_posts",
]


@discovery_module(
    requires=[],  # raiz: erro de deixar dump no webroot independe de framework/plugin --
                  # vale testar mesmo antes de confirmar WordPress
    cost=len(COMMON_DB_DUMP_PATHS),
    category="exposed_backup",
    display_name="Dump de Banco de Dados Exposto",
    summary="Testa nomes comuns de arquivo de backup/dump SQL deixados no webroot por erro humano, que exporiam toda a base de dados se acessíveis.",
)
class WPDatabaseDumpExposure:
    """
    Testa nomes de arquivo comuns de dump/backup de banco de dados deixados
    no webroot por engano -- erro humano clássico durante deploy manual ou
    backup feito via script sem cuidado de remover o arquivo depois.

    Diferente de wp_duplicator_leak.py e wp_migration_leak.py (que testam
    caminhos ESPECÍFICOS de plugins de migração/backup, e por isso exigem o
    fato de presença do plugin correspondente), este módulo testa nomes
    genéricos que não dependem de nenhum plugin -- por isso é raiz.
    """
    name = "wp_database_dump_exposure"

    def run(self, target):
        found = []

        for path in COMMON_DB_DUMP_PATHS:
            r = get(f"{target}/{path}")
            if not r or r.status_code != 200:
                continue

            body = r.text or ""
            if len(body) < 50:
                continue  # corpo curto demais para ser um dump real

            if any(sig in body for sig in SQL_DUMP_SIGNATURES):
                found.append({"path": f"/{path}", "size_bytes": len(body)})

        if not found:
            return None

        f = Finding(
            module=self.name,
            title="Database Backup/Dump File Exposed",
            severity="critical",
            description=(
                "A publicly accessible database dump or backup file was found in the "
                "web root, exposing raw SQL content."
            ),
            endpoint="/",
            evidence=found,
        )

        f.business_impact = (
            "A raw database dump typically contains every table in the WordPress "
            "installation, including wp_users (password hashes), wp_options (secret "
            "keys, API credentials), and any custom table with business or customer "
            "data. This is equivalent to a full database compromise without needing "
            "any further exploitation."
        )

        f.remediation = (
            "Remove the exposed backup file immediately. Never store database backups "
            "inside the web-accessible root directory; use a location outside the "
            "webroot or a dedicated backup storage service, and block common backup "
            "file extensions (.sql, .sql.gz, .zip) at the web server level."
        )

        f.exploitability = "Easy"

        return [f.to_dict()]
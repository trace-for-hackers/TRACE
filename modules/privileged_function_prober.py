"""
modules/privileged_function_prober.py

Escalação VERTICAL de privilégio: identidade sem privilégio chamando
função que deveria ser exclusiva de admin -- diferente de IDOR
(horizontal, "identidade B no recurso de A"), aqui é "identidade
qualquer numa AÇÃO que deveria exigir papel elevado".

SINAL USADO: status HTTP, não corpo da resposta. Isso é diferente (e
mais confiável) do que a primeira tentativa de mass_assignment_prober.py
usava -- lá, "aceitar campo sem reclamar" é o comportamento PADRÃO de
qualquer parser JSON permissivo, então virou ruído. Aqui é o oposto:
401/403 É a convenção padrão da indústria pra "essa ação não é sua",
então usar status como sinal principal é muito mais confiável.

LIMITAÇÃO HONESTA E EXPLÍCITA: o módulo não sabe, a priori, qual
identidade registrada É legitimamente privilegiada. Se você registrar
uma conta admin de verdade como identidade, ela também vai ser testada
contra as ações candidatas -- e se ela tiver sucesso (porque É admin
mesmo), isso NÃO é uma vulnerabilidade, é o esperado. O achado sempre
inclui essa ressalva explícita, porque o módulo não tem como distinguir
sozinho "identidade escalou privilégio" de "identidade já era admin".
"""

from __future__ import annotations

from utils.requester import get_as, post_as, request_as, registered_identities
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

# palavra no path/operationId que sugere ação exclusiva de admin --
# lista curta e específica, igual em espírito à de mass_assignment_prober
_ADMIN_KEYWORDS = ("admin", "manage", "moderate", "staff", "superuser", "internal")

_HARMLESS_ID_VALUE = "surfacer_privtest_nonexistent"


def find_privileged_operations(spec: dict) -> list[dict]:
    """
    Candidato a "ação exclusiva de admin": todo DELETE (convenção comum
    de ação destrutiva ser admin-gated) + qualquer operação cujo path ou
    operationId contenha palavra da lista _ADMIN_KEYWORDS, em QUALQUER
    método HTTP.
    """
    paths = spec.get("paths", {})
    results = []

    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        param_name = None
        if path.endswith("}"):
            param_name = path.rsplit("/", 1)[-1].strip("{}")

        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            method_lower = method.lower()
            if method_lower not in ("get", "post", "put", "patch", "delete"):
                continue

            operation_id = str(op.get("operationId", ""))
            is_delete = method_lower == "delete"
            mentions_admin_keyword = any(
                kw in path.lower() or kw in operation_id.lower() for kw in _ADMIN_KEYWORDS
            )

            if is_delete or mentions_admin_keyword:
                results.append({
                    "path": path, "method": method.upper(),
                    "param_name": param_name, "operation_id": operation_id,
                })

    return results


def is_clearly_denied(status_code: int) -> bool:
    return status_code in (401, 403)


@discovery_module(
    requires=[
        Requirement("config.identity_available", min_confidence=0.5),
        Requirement("config.openapi_spec_available", min_confidence=0.5),
    ],
    produces=[],
    cost=5,
    category="privilege_escalation",
    display_name="Sondagem de Função Privilegiada",
    summary="Testa cada identidade registrada contra operação DELETE ou com nome sugerindo ação de admin -- 401/403 é o esperado; qualquer outra coisa vira candidato a escalação vertical, com ressalva explícita sobre identidade legitimamente privilegiada.",
)
class PrivilegedFunctionProber:
    name = "privileged_function_prober"

    def run(self, target: str):
        identities = registered_identities()
        if not identities:
            return None

        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[privileged_function_prober] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[privileged_function_prober] não consegui carregar o spec: {e}")
            return None

        candidates = find_privileged_operations(spec)
        if not candidates:
            return None

        findings = []

        for op in candidates:
            url = target.rstrip("/") + op["path"]
            if op["param_name"]:
                url = url.replace("{" + op["param_name"] + "}", _HARMLESS_ID_VALUE)

            for identity in identities:
                if op["method"] == "GET":
                    resp = get_as(identity, url)
                elif op["method"] == "POST":
                    resp = post_as(identity, url, json_body={})
                else:
                    resp = request_as(identity, op["method"], url, json_body={})

                if resp is None:
                    continue
                if is_clearly_denied(resp.status_code):
                    continue  # comportamento esperado, não é achado

                findings.append({
                    "title": f"Candidato a escalação de privilégio: '{identity}' não foi negado em {op['method']} {op['path']}",
                    "severity": "high",
                    "module": self.name,
                    "category": "privilege_escalation",
                    "endpoint": url,
                    "description": (
                        f"A identidade '{identity}' chamou {op['method']} {op['path']} (candidato "
                        f"a ação exclusiva de admin) e recebeu status {resp.status_code} -- não é "
                        f"o 401/403 esperado pra uma identidade sem privilégio elevado. "
                        f"IMPORTANTE: se '{identity}' É legitimamente uma conta admin, isso NÃO é "
                        f"uma vulnerabilidade -- confirme manualmente o nível de privilégio real "
                        f"dessa identidade antes de reportar."
                    ),
                    "business_impact": (
                        "Se a identidade testada não deveria ter esse privilégio, isso é "
                        "escalação vertical -- usuário comum executando ação exclusiva de admin."
                    ),
                    "remediation": "Confirmar checagem de papel/privilégio no backend antes de executar a ação, independente do que o cliente envia.",
                    "evidence": {"identity": identity, "method": op["method"], "path": op["path"], "status": resp.status_code},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)

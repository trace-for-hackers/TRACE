"""
modules/unauthenticated_endpoint_scanner.py

Terceira categoria de BAC, distinta das outras duas: um endpoint FIXO
(sem parâmetro de ID, sem conceito de "dono") cujo próprio spec OpenAPI
declara que devolve campo sensível (senha, email, flag de admin...), e
que responde de verdade a uma requisição sem credencial nenhuma.

Achado real que motivou este módulo: GET /users/v1/_debug no VAmPI --
"Excessive Data Exposure through debug endpoint", item documentado
oficialmente. Esse endpoint não tem ID, não pertence a ninguém
especificamente -- é global e sempre existiu, então nem o
auth_crawler.py nem o idor_correlator.py (os dois pensados em torno de
"recurso com dono") conseguem enxergar esse tipo de problema.

Diferença de abordagem: em vez de comparar contra baseline de "negado"
(não existe uma versão "errada" de um path fixo pra comparar), a
detecção aqui é por CONTEÚDO -- o schema declarado no próprio spec
já diz quais campos a resposta deveria conter; se um desses campos
parecer sensível E a resposta anônima realmente trouxer ele preenchido,
isso é sinal direto, sem precisar de baseline nenhum.
"""

from __future__ import annotations

import requests

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.api_resource_provisioner import load_spec

_SENSITIVE_FIELD_NAMES = {
    "password", "senha", "secret", "token", "auth_token", "api_key",
    "apikey", "ssn", "cpf", "credit_card", "card_number", "admin",
    "is_admin", "role", "private_key",
}

_anonymous_session = requests.Session()
_anonymous_session.headers.update({"User-Agent": "surfacer/0.1", "Accept": "*/*"})


def _get_anonymous(url: str):
    try:
        return _anonymous_session.request("GET", url, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[unauthenticated_endpoint_scanner] erro em GET {url} (anônimo): {type(e).__name__}: {e}")
        return None


def find_sensitive_fields_in_schema(schema: dict) -> set[str]:
    """Percorre o schema (incluindo array/objeto aninhado, que é como o
    VAmPI declara 'users: [ {admin, email, password, username} ]')
    procurando nome de campo que bate com a lista de palavras sensíveis.
    Não é exaustivo de propósito -- poucos nomes, específicos, baixa
    chance de falso positivo por coincidência de nome."""
    found = set()

    def _walk(node):
        if not isinstance(node, dict):
            return
        for prop_name, prop_schema in node.get("properties", {}).items():
            if prop_name.lower() in _SENSITIVE_FIELD_NAMES:
                found.add(prop_name)
            _walk(prop_schema)
        if "items" in node:
            _walk(node["items"])

    _walk(schema)
    return found


def find_unparameterized_get_paths(spec: dict) -> list[dict]:
    """Todo path GET sem {parametro} -- não precisa de ID nenhum pra
    chamar, então dá pra testar direto, sem depender de descoberta
    prévia de recurso (diferente de auth_crawler/idor_correlator)."""
    results = []
    for path, ops in spec.get("paths", {}).items():
        if "{" in path:
            continue
        get_op = ops.get("get") if isinstance(ops, dict) else None
        if not get_op:
            continue
        schema = (
            get_op.get("responses", {}).get("200", {})
            .get("content", {}).get("application/json", {}).get("schema", {})
        )
        sensitive = find_sensitive_fields_in_schema(schema)
        if sensitive:
            results.append({"path": path, "sensitive_fields": sensitive})
    return results


def _response_mentions_field(body: dict | list, field_names: set[str]) -> set[str]:
    """Confirma que o campo sensível realmente aparece PREENCHIDO na
    resposta de verdade -- o schema é o que o spec PROMETE, isso aqui é
    o que o servidor de fato devolveu. Só reporta achado quando os dois
    batem, não só quando o spec menciona o campo."""
    found = set()

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in field_names and v not in (None, "", False):
                    found.add(k)
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(body)
    return found


_spec_path: str | None = None


def configure_openapi_spec_for_scanner(path_or_url: str) -> None:
    global _spec_path
    _spec_path = path_or_url


@discovery_module(
    requires=[Requirement("config.openapi_spec_available", min_confidence=0.5)],
    produces=[Produces("finding.unauthenticated_exposure.*", durable=False)],
    cost=10,
    category="access_control",
    display_name="Varredura de Endpoint Sem Autenticação",
    summary="Lê o spec OpenAPI do alvo, acha endpoint fixo (sem parâmetro) cujo schema declara campo sensível, e confirma se responde mesmo sem nenhuma credencial.",
)
class UnauthenticatedEndpointScanner:
    name = "unauthenticated_endpoint_scanner"

    def run(self, target: str):
        # reaproveita a MESMA configuração global de spec do
        # api_resource_provisioner -- um --openapi-spec só, usado pelos
        # dois módulos, sem o operador precisar configurar duas vezes.
        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path or _spec_path
        if not spec_path:
            print("[unauthenticated_endpoint_scanner] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[unauthenticated_endpoint_scanner] não consegui carregar o spec: {e}")
            return None

        candidates = find_unparameterized_get_paths(spec)
        if not candidates:
            return None

        findings = []
        for candidate in candidates:
            url = target.rstrip("/") + candidate["path"]
            resp = _get_anonymous(url)
            if resp is None or resp.status_code != 200:
                continue

            try:
                body = resp.json()
            except ValueError:
                continue

            confirmed = _response_mentions_field(body, candidate["sensitive_fields"])
            if not confirmed:
                continue

            findings.append({
                "title": f"Exposição sem autenticação em {candidate['path']}",
                "severity": "critical" if "password" in confirmed or "senha" in confirmed else "high",
                "module": self.name,
                "category": "broken_authentication",
                "endpoint": url,
                "description": (
                    f"O endpoint {candidate['path']} respondeu com status 200 a uma "
                    f"requisição SEM NENHUMA credencial, e a resposta de fato contém "
                    f"o(s) campo(s) sensível(is) preenchido(s): {sorted(confirmed)}."
                ),
                "business_impact": (
                    "Dado sensível (possivelmente credencial de outros usuários) exposto "
                    "publicamente, sem exigir autenticação."
                ),
                "remediation": "Adicionar checagem de autenticação obrigatória neste endpoint, ou removê-lo se for de debug/desenvolvimento.",
                "evidence": {
                    "path": candidate["path"], "sensitive_fields_declared_in_spec": sorted(candidate["sensitive_fields"]),
                    "sensitive_fields_confirmed_in_response": sorted(confirmed),
                    "status": resp.status_code,
                },
            })

        if not findings:
            return None
        return ModuleResult(findings=findings)

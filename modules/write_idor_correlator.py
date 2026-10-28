"""
modules/write_idor_correlator.py

IDOR em operação de ESCRITA -- diferente do idor_correlator.py (leitura),
aqui a checagem certa não é "a resposta parece diferente do negado", é
"o efeito realmente aconteceu". Caso real que motivou isso:
PUT /users/v1/{username}/password no VAmPI -- em modo vulnerável, o
username da URL decide de quem a senha muda; em modo corrigido, SEMPRE
muda a senha do dono do token, ignorando a URL. As DUAS respostas são
IDÊNTICAS (mesmo status 204, mesmo corpo) -- só comparar resposta nunca
distinguiria os dois casos. A única forma de confirmar é logar como a
VÍTIMA com a senha nova que o ATACANTE setou -- se o login funcionar, a
escrita cross-user aconteceu de verdade.

DESCOBERTA EM 3 PARTES, cada uma reaproveitando uma peça que já existe:
  1. Par criação -> leitura por nome de campo (mass_assignment_prober.py,
     find_verifiable_post_endpoints) -- acha o endpoint de registro e o
     {username} correspondente.
  2. A partir do MESMO id_field, acha endpoint de ESCRITA (PUT/PATCH)
     cujo path contém esse parâmetro, mesmo com segmento extra
     (/password) -- generalização nova, não existia em nenhum módulo
     anterior.
  3. Acha o endpoint de LOGIN (POST com o mesmo id_field + um campo de
     senha, path/operationId sugerindo autenticação) -- usado só pra
     VERIFICAR o efeito, nunca pra criar/escrever nada.

LIMITAÇÃO HONESTA: só cobre o caso "trocar senha de outro usuário",
porque é o único onde dá pra verificar efeito de forma barata e
genérica (tentando logar). IDOR de escrita em campo que não seja
credencial de login exigiria um mecanismo de verificação diferente por
domínio -- não generalizado aqui.
"""

from __future__ import annotations

from utils.requester import post_as, request_as, registered_identities, register_test_artifact
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.api_resource_provisioner import build_request_body, _random_suffix
from modules.mass_assignment_prober import find_verifiable_post_endpoints

_PASSWORD_FIELD_NAMES = {"password", "pass", "pwd", "senha"}
_LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "logon")

_SENTINEL_PASSWORD = "Surfacer_WriteIdorTest_2026!"

# nomes comuns de campo que carregam o token de sessão numa resposta de
# login bem-sucedido -- usado como sinal POSITIVO de sucesso.
_TOKEN_FIELD_NAMES = {"auth_token", "token", "access_token", "jwt", "authtoken"}
_FAILURE_STATUS_VALUES = {"fail", "failed", "error", "failure"}


def _login_response_indicates_success(resp) -> bool:
    """BUG REAL encontrado testando contra o VAmPI (07/09/2026): o
    endpoint de login dele devolve status HTTP 200 tanto pra login
    bem-sucedido quanto pra senha errada -- só o CORPO da resposta
    (campo 'status': 'fail' vs presença de 'auth_token') distingue os
    dois casos. Confiar só no status code gerava falso positivo: o
    teste passava mesmo na versão CORRIGIDA do VAmPI, porque a resposta
    de "senha incorreta" também vem com 200.

    Exige sinal POSITIVO (campo de token presente) pra confirmar sucesso
    -- não apenas "ausência de status de falha reconhecido". Isso é
    deliberado: se a resposta vem num formato que o módulo não reconhece,
    o padrão é NÃO confirmar, nunca assumir sucesso por exclusão."""
    if resp is None or resp.status_code not in (200, 201):
        return False
    try:
        body = resp.json()
    except ValueError:
        return False
    if not isinstance(body, dict):
        return False

    status_value = str(body.get("status", "")).lower()
    if status_value in _FAILURE_STATUS_VALUES:
        return False

    return any(body.get(field) for field in _TOKEN_FIELD_NAMES)


def find_password_field(schema: dict) -> str | None:
    for prop in schema.get("properties", {}):
        if prop.lower() in _PASSWORD_FIELD_NAMES:
            return prop
    return None


def find_write_endpoints(spec: dict, id_field: str) -> list[dict]:
    """PUT/PATCH cujo path contém o MESMO {id_field} do par
    criação->leitura, mesmo com segmento extra no path
    (/users/v1/{username}/password tem segmento a mais que
    /users/v1/{username}, e isso é esperado, não filtrado)."""
    results = []
    marker = "{" + id_field + "}"
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict) or marker not in path:
            continue
        for method in ("put", "patch"):
            op = ops.get(method)
            if not op:
                continue
            schema = (
                op.get("requestBody", {}).get("content", {})
                .get("application/json", {}).get("schema", {})
            )
            pwd_field = find_password_field(schema)
            if pwd_field:
                results.append({"path": path, "method": method.upper(), "password_field": pwd_field, "request_schema": schema})
    return results


def find_login_endpoint(spec: dict, id_field: str) -> dict | None:
    """POST cujo path/operationId sugere login E cujo schema tem o
    id_field junto com um campo de senha -- usado só pra CONFIRMAR
    efeito, nunca pra escrever nada."""
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        post_op = ops.get("post")
        if not post_op:
            continue
        operation_id = str(post_op.get("operationId", "")).lower()
        if not any(kw in path.lower() or kw in operation_id for kw in _LOGIN_KEYWORDS):
            continue
        schema = (
            post_op.get("requestBody", {}).get("content", {})
            .get("application/json", {}).get("schema", {})
        )
        props = {p.lower() for p in schema.get("properties", {})}
        pwd_field = find_password_field(schema)
        if id_field.lower() in props and pwd_field:
            return {"path": path, "password_field": pwd_field, "request_schema": schema}
    return None


@discovery_module(
    requires=[
        Requirement("config.identity_available", min_confidence=0.5),
        Requirement("config.openapi_spec_available", min_confidence=0.5),
    ],
    produces=[],
    cost=15,
    category="access_control",
    display_name="Correlação de IDOR em Escrita",
    summary="Cria dois usuários, um ataca a senha do outro via endpoint de escrita, e CONFIRMA o efeito tentando logar como a vítima com a senha que o atacante setou -- comparar só a resposta da escrita não distingue vulnerável de corrigido nesse caso.",
)
class WriteIdorCorrelator:
    name = "write_idor_correlator"

    def run(self, target: str):
        identities = registered_identities()
        if not identities:
            return None

        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[write_idor_correlator] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[write_idor_correlator] não consegui carregar o spec: {e}")
            return None

        register_pairs = find_verifiable_post_endpoints(spec)
        findings = []

        for pair in register_pairs:
            id_field = pair["id_field"]
            write_endpoints = find_write_endpoints(spec, id_field)
            if not write_endpoints:
                continue
            login_endpoint = find_login_endpoint(spec, id_field)
            if not login_endpoint:
                continue  # sem forma barata de confirmar efeito -- não arrisca falso positivo

            attacker_identity = identities[0]

            victim_id = f"surfacer_wi_victim_{_random_suffix()}"
            victim_password = f"OriginalPass_{_random_suffix()}!"
            victim_body = build_request_body(pair["request_schema"], id_field, victim_id)
            # garante que a senha original da vítima é conhecida (pra não
            # confundir com sucesso de login por acaso) -- sobrescreve
            # qualquer valor dummy que build_request_body tenha colocado
            pwd_field_register = find_password_field(pair["request_schema"])
            if pwd_field_register:
                victim_body[pwd_field_register] = victim_password

            resp_victim = post_as(attacker_identity, target.rstrip("/") + pair["post_path"], json_body=victim_body)
            if resp_victim is None or resp_victim.status_code not in (200, 201):
                continue
            register_test_artifact("usuário vítima (write_idor_correlator)",
                                    target.rstrip("/") + pair["item_path"].replace("{" + id_field + "}", victim_id),
                                    identity=attacker_identity)

            for write_ep in write_endpoints:
                write_url = target.rstrip("/") + write_ep["path"].replace("{" + id_field + "}", victim_id)
                poison_body = {write_ep["password_field"]: _SENTINEL_PASSWORD}

                resp_write = request_as(attacker_identity, write_ep["method"], write_url, json_body=poison_body)
                if resp_write is None or resp_write.status_code not in (200, 201, 204):
                    continue  # escrita nem foi aceita -- nada a confirmar

                login_body = {id_field: victim_id, login_endpoint["password_field"]: _SENTINEL_PASSWORD}
                resp_login = post_as(
                    attacker_identity, target.rstrip("/") + login_endpoint["path"], json_body=login_body,
                )
                login_succeeded = _login_response_indicates_success(resp_login)

                if login_succeeded:
                    findings.append({
                        "title": f"IDOR em escrita CONFIRMADO: '{attacker_identity}' trocou a senha de outro usuário via {write_ep['method']} {write_ep['path']}",
                        "severity": "critical",
                        "module": self.name,
                        "category": "broken_access_control",
                        "endpoint": write_url,
                        "description": (
                            f"A identidade '{attacker_identity}' chamou {write_ep['method']} "
                            f"{write_ep['path']} contra o usuário '{victim_id}' (criado só pra "
                            f"este teste) e definiu uma senha nova. CONFIRMADO tentando logar "
                            f"como '{victim_id}' com essa senha -- login teve sucesso, provando "
                            f"que a escrita afetou a vítima de verdade, não o próprio atacante."
                        ),
                        "business_impact": (
                            "Qualquer usuário autenticado pode trocar a senha de QUALQUER outro "
                            "usuário -- controle de conta completo, não precisa nem saber a senha "
                            "atual da vítima."
                        ),
                        "remediation": (
                            "Validar que o dono do token de autenticação é o MESMO usuário "
                            "referenciado no path, antes de aplicar qualquer alteração."
                        ),
                        "evidence": {
                            "attacker_identity": attacker_identity, "victim_id": victim_id,
                            "write_endpoint": write_ep["path"], "login_endpoint": login_endpoint["path"],
                        },
                    })

        if not findings:
            return None
        return ModuleResult(findings=findings)

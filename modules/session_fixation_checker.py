"""
modules/session_fixation_checker.py

Session fixation: se o identificador de sessao (cookie) continua o
MESMO antes e depois do login, um atacante que force a vitima a usar um
session ID conhecido de antemao (fixado via link, ou porque o app so
emite cookie na primeira visita) pode sequestrar a sessao autenticada
depois -- nao precisa nem roubar credencial nenhuma.

Descoberta de registro/login reaproveita o MESMO padrao de
write_idor_correlator.py (find_verifiable_post_endpoints do
mass_assignment_prober.py pra achar o registro, find_login_endpoint pra
achar o login) -- os tres modulos front-end de autenticacao (write-IDOR,
session fixation, e o de baixo) compartilham a mesma descoberta de
"onde fica o registro e o login" no spec.

LIMITACAO HONESTA: só detecta fixation baseada em COOKIE de sessão
tradicional. Alvo que usa só token Bearer/JWT (sem cookie nenhum, como
o VAmPI) não tem "sessão" nesse sentido -- o módulo simplesmente não
encontra cookie nenhum pra comparar e não roda.
"""

from __future__ import annotations

import requests

from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.api_resource_provisioner import build_request_body, _random_suffix
from modules.write_idor_correlator import find_password_field
from modules.predictable_token_analyzer import find_session_like_cookie

_REGISTER_KEYWORDS = ("register", "signup", "sign-up", "create-account")
_LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "logon")


def find_registration_endpoint(spec: dict) -> dict | None:
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        post_op = ops.get("post")
        if not post_op:
            continue
        operation_id = str(post_op.get("operationId", "")).lower()
        if not any(kw in path.lower() or kw in operation_id for kw in _REGISTER_KEYWORDS):
            continue
        schema = post_op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
        if find_password_field(schema):
            return {"path": path, "request_schema": schema}
    return None


def find_login_endpoint_generic(spec: dict) -> dict | None:
    """Mesma lógica de find_login_endpoint em write_idor_correlator.py,
    mas sem exigir um id_field específico -- aqui só precisamos achar
    ONDE é o login, não correlacionar com um par criação/leitura."""
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        post_op = ops.get("post")
        if not post_op:
            continue
        operation_id = str(post_op.get("operationId", "")).lower()
        if not any(kw in path.lower() or kw in operation_id for kw in _LOGIN_KEYWORDS):
            continue
        schema = post_op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
        if find_password_field(schema):
            return {"path": path, "request_schema": schema}
    return None


def is_session_fixed(pre_login_value: str | None, post_login_value: str | None) -> bool:
    """True só se os dois valores existem E são idênticos -- ausência de
    um dos dois (ex.: app não usa cookie antes do login) não é achado,
    é limitação de observação."""
    if not pre_login_value or not post_login_value:
        return False
    return pre_login_value == post_login_value


@discovery_module(
    requires=[Requirement("config.openapi_spec_available", min_confidence=0.5)],
    produces=[],
    cost=3,
    category="authentication_generic",
    display_name="Checador de Session Fixation",
    summary="Compara o cookie de sessão antes e depois do login -- se for idêntico, um atacante que fixar o session ID de antemão pode sequestrar a sessão autenticada da vítima.",
)
class SessionFixationChecker:
    name = "session_fixation_checker"

    def run(self, target: str):
        import modules.api_resource_provisioner as provisioner
        spec_path = provisioner._spec_path
        if not spec_path:
            print("[session_fixation_checker] nenhum --openapi-spec fornecido -- módulo não roda.")
            return None

        from modules.api_resource_provisioner import load_spec
        try:
            spec = load_spec(spec_path)
        except Exception as e:
            print(f"[session_fixation_checker] não consegui carregar o spec: {e}")
            return None

        register_ep = find_registration_endpoint(spec)
        login_ep = find_login_endpoint_generic(spec)
        if not register_ep or not login_ep:
            return None

        session = requests.Session()
        session.headers.update({"User-Agent": "surfacer/0.1"})

        try:
            r_anonymous = session.get(target, timeout=10, verify=False)
        except requests.exceptions.RequestException:
            return None

        cookie_name = find_session_like_cookie(r_anonymous.cookies.get_dict())
        if not cookie_name:
            return None  # alvo não usa cookie de sessão detectável -- não é achado, é limitação

        pre_login_value = r_anonymous.cookies.get_dict().get(cookie_name)

        test_username = f"surfacer_sf_{_random_suffix()}"
        test_password = f"SenhaTeste_{_random_suffix()}!"
        register_body = build_request_body(register_ep["request_schema"], "username", test_username)
        pwd_field = find_password_field(register_ep["request_schema"])
        if pwd_field:
            register_body[pwd_field] = test_password

        try:
            session.post(target.rstrip("/") + register_ep["path"], json=register_body, timeout=10, verify=False)
        except requests.exceptions.RequestException:
            return None
        from utils.requester import register_test_artifact
        register_test_artifact("usuário de teste (session_fixation_checker)",
                                target.rstrip("/") + register_ep["path"].rstrip("/") + "/" + test_username)

        login_body = {"username": test_username}
        login_pwd_field = find_password_field(login_ep["request_schema"])
        if login_pwd_field:
            login_body[login_pwd_field] = test_password
        for prop in login_ep["request_schema"].get("properties", {}):
            if prop.lower() in ("username", "email") and prop not in login_body:
                login_body[prop] = test_username

        try:
            session.post(target.rstrip("/") + login_ep["path"], json=login_body, timeout=10, verify=False)
        except requests.exceptions.RequestException:
            return None

        post_login_value = session.cookies.get_dict().get(cookie_name)

        if not is_session_fixed(pre_login_value, post_login_value):
            return None

        return ModuleResult(findings=[{
            "title": "Session Fixation confirmado: cookie de sessão não muda após login",
            "severity": "high",
            "module": self.name,
            "category": "session_fixation",
            "endpoint": target.rstrip("/") + login_ep["path"],
            "description": (
                f"O cookie '{cookie_name}' teve o MESMO valor antes e depois do login -- "
                f"'{pre_login_value}'. Um atacante que fixar esse valor na vítima antes dela "
                f"logar (via link, ou explorando ausência de proteção) herda a sessão "
                f"autenticada dela sem precisar da senha."
            ),
            "business_impact": "Sequestro de sessão autenticada sem precisar de credencial nenhuma, apenas fixar o identificador de sessão antes do login da vítima.",
            "remediation": "Gerar um NOVO identificador de sessão sempre que o nível de privilégio mudar (login, elevação de permissão), invalidando o anterior.",
            "evidence": {"cookie_name": cookie_name, "value_unchanged": pre_login_value},
        }])

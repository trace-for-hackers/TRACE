"""
utils/requester.py

Camada HTTP do TRACE. Diferente do utils/requester.py original do
WRAITH (que eu mesmo sinalizei como ponto fraco: `except: return None`
sem log nenhum do motivo), aqui cada falha é logada com o tipo real do
erro -- timeout, DNS, conexão recusada, SSL -- porque isso importa mais
ainda aqui: os módulos de heurística de injeção enviam payload de verdade
(mesmo que inofensivo) e comparam respostas; se uma request falha
silenciosamente, o módulo pode interpretar a ausência de resposta como
"payload não gerou diferença" e simplesmente errar a heurística sem
ninguém perceber por quê.
"""

from __future__ import annotations

import time
import requests
import urllib3
import time
from urllib.parse import urlsplit

from observability import span, target_identity, record_exception, init_metrics

urllib3.disable_warnings()

session = requests.Session()
_OTEL_METRICS = init_metrics()
session.headers.update({
    "User-Agent": "surfacer/0.1",
    "Accept": "*/*",
})


def set_session_cookies(cookies: dict) -> None:
    """Define cookie na sessão ANÔNIMA compartilhada -- diferente de
    register_identity() (que cria sessão NOMEADA, usada só pelos módulos
    de BAC/IDOR via get_as/post_as). Isso aqui afeta get()/post(), que é
    o que crawler.py e TODOS os heurísticos de injeção (SQLi, XSS, SSTI,
    LDAP, command injection) usam pra descobrir e testar parâmetro.

    Necessário pra qualquer alvo que exija login pra ver a própria
    superfície de ataque (ex.: DVWA -- toda página vulnerável fica atrás
    de sessão autenticada, e sem isso o crawler nunca sai da página de
    login, então os módulos de injeção nunca têm parâmetro nenhum pra
    testar -- não é "não achou vulnerabilidade", é "nunca viu a página")."""
    session.cookies.update(cookies)


def _safe_request(method: str, url: str, **kwargs):
    timeout = kwargs.pop("timeout", 10)
    parsed = urlsplit(str(url))
    attrs = {
        "http.request.method": method.upper(),
        "server.address": parsed.hostname or "unknown",
        "url.scheme": parsed.scheme or "unknown",
    }
    started = time.perf_counter()
    with span("trace.http.client", attrs) as current:
        try:
            response = session.request(method, url, timeout=timeout, verify=False, **kwargs)
            elapsed = time.perf_counter() - started
            if current is not None:
                current.set_attribute("http.response.status_code", response.status_code)
            if _OTEL_METRICS:
                labels = {"http.request.method": method.upper(), "server.address": parsed.hostname or "unknown"}
                _OTEL_METRICS["http_requests"].add(1, labels)
                _OTEL_METRICS["http_latency"].record(elapsed, labels)
            return response
        except requests.exceptions.Timeout as exc:
            record_exception(current, exc)
            print(f"[requester] timeout em {method} {url}")
        except requests.exceptions.ConnectionError as exc:
            record_exception(current, exc)
            print(f"[requester] conexão recusada/DNS falhou em {method} {url}: {exc}")
        except requests.exceptions.SSLError as exc:
            record_exception(current, exc)
            print(f"[requester] erro de SSL em {method} {url}: {exc}")
        except requests.exceptions.RequestException as exc:
            record_exception(current, exc)
            print(f"[requester] erro em {method} {url}: {type(exc).__name__}: {exc}")
        return None


def get(url: str, params: dict | None = None):
    return _safe_request("GET", url, params=params)


def get_with_headers(url: str, headers: dict):
    """Variante de get() que aceita headers extras por requisição, sem
    afetar os headers default da sessão compartilhada (User-Agent,
    Accept). Usado por módulos que precisam controlar um header
    específico da requisição, como Origin para testes de CORS -- não dá
    pra simular isso só lendo a resposta de um get() comum. Portado do
    utils/requester.py original do WRAITH ao unificar os dois projetos."""
    merged = {**session.headers, **headers}
    return _safe_request("GET", url, headers=merged)


def post(url: str, data: dict | None = None):
    return _safe_request("POST", url, data=data)


def post_json(url: str, json_body: dict | None = None):
    """Como post(), mas manda o corpo como JSON de verdade
    (Content-Type: application/json), não form-encoded -- necessário
    pra testar API REST moderna (ex.: /rest/user/login de SPA tipo
    Angular/React), que rejeita ou ignora corpo form-encoded. Usado
    pelos heurísticos de injeção quando o fato descoberto é
    surface.json_param.* (ver modules/js_rendering_crawler.py), nunca
    quando é surface.param.* (esse continua indo form-encoded via
    post() acima, sem mudança nenhuma no caminho já testado)."""
    return _safe_request("POST", url, json=json_body)


def request_raw(method: str, url: str, timeout: int = 8):
    """Requisição crua, sem passar pela sessão compartilhada -- usado
    quando um módulo precisa de controle total (ex.: sem seguir
    redirect). Portado do WRAITH original."""
    try:
        return requests.request(method=method, url=url, timeout=timeout, allow_redirects=False, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[requester] erro em {method} {url} (request_raw): {type(e).__name__}: {e}")
        return None


# ── sessões por identidade ───────────────────────────────────────────────
# Pra BAC/IDOR, precisamos de mais de uma sessão autenticada simultânea --
# uma por identidade fornecida pelo operador (usuário A, usuário B, etc.).
# Isso é literalmente o que separa esse domínio do resto: todo módulo até
# aqui (crawler, heurísticas de injeção) usava UMA sessão anônima só.

_identity_sessions: dict[str, requests.Session] = {}


def register_identity(name: str, cookies: dict | None = None, headers: dict | None = None) -> None:
    """Configura uma sessão nomeada -- chamado uma vez no início do scan,
    com credencial que o OPERADOR forneceu (nunca descoberta/adivinhada
    pela ferramenta). Ver main.py --identity / --identity-header.

    BUG REAL encontrado testando contra o VAmPI (29/08/2026): cada
    chamada criava uma requests.Session() NOVA, então registrar cookie e
    header pra MESMA identidade em duas chamadas separadas (--identity
    pra cookie, --identity-header pra header Bearer) fazia a segunda
    chamada apagar silenciosamente o que a primeira tinha configurado --
    a identidade terminava só com uma das duas credenciais, dependendo
    da ordem dos argumentos. Agora reaproveita a sessão existente se já
    houver uma para esse nome, e só ACRESCENTA cookie/header novo."""
    s = _identity_sessions.get(name)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": "surfacer/0.1", "Accept": "*/*"})
        _identity_sessions[name] = s
    if cookies:
        s.cookies.update(cookies)
    if headers:
        s.headers.update(headers)


def get_as(identity: str, url: str, params: dict | None = None):
    """Como get(), mas usando a sessão da identidade nomeada. Falha alto e
    claro (KeyError) se a identidade não foi registrada -- silenciosamente
    cair pra sessão anônima aqui seria pior que travar: um teste de IDOR
    "bem sucedido" contra a sessão errada não vale nada, e pior, mentiria
    no relatório.

    1 retry em erro de conexão -- achado real contra o VAmPI (29/08/2026):
    servidor de desenvolvimento Flask (single-threaded, sem threaded=True)
    engasgou numa request e devolveu RemoteDisconnected. Sem retry, isso
    silenciosamente vira "sem sinal" em vez de investigar -- e o
    _significantly_different() corretamente NUNCA transforma ausência de
    dado em falso positivo, o que é certo, mas significa que um achado
    real pode se perder por uma falha de rede transitória, não por o
    alvo ser seguro. 1 retry cobre a flakiness comum de servidor de dev
    sem mascarar falha persistente (essa ainda vira None depois da 2ª tentativa)."""
    if identity not in _identity_sessions:
        raise KeyError(f"identidade '{identity}' não registrada -- chame register_identity() antes do scan")
    session = _identity_sessions[identity]
    for attempt in (1, 2):
        try:
            return session.request("GET", url, params=params, timeout=10, verify=False)
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                print(f"[requester] erro em GET {url} como '{identity}' (após retry): {type(e).__name__}: {e}")
                return None
            time.sleep(0.3)


def post_as(identity: str, url: str, json_body: dict | None = None):
    """Como get_as(), mas POST com corpo JSON -- usado por
    api_resource_provisioner.py para criar recurso de teste como uma
    identidade específica (APIs modernas quase sempre esperam
    application/json, não form-encoded). Mesmo retry de get_as."""
    if identity not in _identity_sessions:
        raise KeyError(f"identidade '{identity}' não registrada -- chame register_identity() antes do scan")
    session = _identity_sessions[identity]
    for attempt in (1, 2):
        try:
            return session.request("POST", url, json=json_body, timeout=10, verify=False)
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                print(f"[requester] erro em POST {url} como '{identity}' (após retry): {type(e).__name__}: {e}")
                return None
            time.sleep(0.3)


def request_as(identity: str, method: str, url: str, json_body: dict | None = None):
    """Requisição HTTP arbitrária usando a sessão de uma identidade.

    Mantém as mesmas garantias de get_as()/post_as(): exige uma identidade
    previamente registrada, não cai silenciosamente na sessão anônima e faz
    um retry simples para falhas transitórias de conexão. É usada pelos
    módulos que precisam de PUT/PATCH/DELETE para validar controles de acesso.
    """
    if identity not in _identity_sessions:
        raise KeyError(f"identidade '{identity}' não registrada -- chame register_identity() antes do scan")
    session = _identity_sessions[identity]
    method = method.upper()
    for attempt in (1, 2):
        try:
            return session.request(method, url, json=json_body, timeout=10, verify=False)
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                print(
                    f"[requester] erro em {method} {url} como '{identity}' "
                    f"(após retry): {type(e).__name__}: {e}"
                )
                return None
            time.sleep(0.3)


def registered_identities() -> list[str]:
    return list(_identity_sessions.keys())


# ── gate de confirmação pra módulo intrusivo (SQLi/XSS/SSTI/LDAP/command
# injection -- manda payload de verdade) -- mesmo padrão de fato de config
# já usado pra identity/openapi-spec/callback-host.
_intrusive_confirmed = False


def set_intrusive_confirmed(value: bool = True) -> None:
    global _intrusive_confirmed
    _intrusive_confirmed = value


def is_intrusive_confirmed() -> bool:
    return _intrusive_confirmed


# ── registro de artefato de teste criado durante o scan (usuário/recurso
# criado por api_resource_provisioner.py, write_idor_correlator.py, etc.)
# -- permite limpeza best-effort no fim do scan, em vez de deixar lixo de
# teste espalhado no banco do cliente.
_test_artifacts: list[dict] = []


def register_test_artifact(kind: str, url: str, identity: str | None = None) -> None:
    """kind = descrição curta ('usuário vítima', 'recurso via spec', etc.),
    url = endpoint que representa o recurso criado (usado na tentativa de
    DELETE, quando o método existir nesse mesmo caminho)."""
    _test_artifacts.append({"kind": kind, "url": url, "identity": identity})


def get_test_artifacts() -> list[dict]:
    return list(_test_artifacts)


def cleanup_test_artifacts() -> dict:
    """Tenta DELETE no próprio caminho de cada artefato registrado --
    best-effort: API que não suporta DELETE ali (404/405/etc.) so cai no
    relatorio de "nao removido", nunca levanta excecao pro chamador. Chamado
    uma vez, no fim do scan (ver main.py)."""
    removed, failed = [], []
    for artifact in _test_artifacts:
        try:
            identity = artifact.get("identity")
            if identity:
                resp = request_as(identity, "DELETE", artifact["url"])
            else:
                resp = _safe_request("DELETE", artifact["url"])
            if resp is not None and resp.status_code in (200, 202, 204):
                removed.append(artifact)
            else:
                failed.append(artifact)
        except Exception:
            failed.append(artifact)
    return {"removed": removed, "failed": failed}

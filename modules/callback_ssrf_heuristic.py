"""
modules/callback_ssrf_heuristic.py

Generaliza modules/wp_ssrf_detection.py (hoje só dentro do pacote
WordPress) -- manda um parametro com URL apontando pra um COLETOR
controlado pelo proprio TRACE, com um TOKEN unico por teste, e confirma
SSRF de forma out-of-band: se o coletor recebeu uma requisicao com
aquele token, o servidor-alvo fez uma requisicao de saida de verdade --
confirmacao muito mais forte que analisar a resposta (funciona ate em
SSRF "cego", onde o alvo nunca devolve o conteudo buscado).

O COLETOR roda como um servidor HTTP local, numa thread separada,
durante o scan -- pensado pra teste em rede onde o scanner e o alvo se
enxergam (rede interna, ambiente de laboratorio). Pra alvo na internet
publica, o operador precisa apontar pra um coletor de verdade acessível
publicamente (configuravel via configure_callback_host) -- sem isso,
o modulo nao roda (nao adianta um coletor que o alvo nunca vai
conseguir alcançar).
"""

from __future__ import annotations

import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from utils.requester import get, post
from knowledge.contracts import discovery_module, Requirement, Produces
from knowledge.result import ModuleResult

_CALLBACK_WAIT_SECONDS = 3.0

# estado global de configuracao -- mesmo padrao de configure_openapi_spec
# em api_resource_provisioner.py (o motor sempre instancia o modulo sem
# argumento, ver knowledge/scheduler.py)
_callback_host: str | None = None
_callback_port: int = 0


def configure_callback_host(host: str, port: int = 0) -> None:
    """host = endereco que o ALVO consegue alcancar de volta (nao
    necessariamente 127.0.0.1 -- em teste de rede interna, o IP da
    maquina que roda o TRACE; num alvo de internet publica, precisaria
    ser um coletor publicamente acessivel). port=0 deixa o SO escolher
    uma porta livre."""
    global _callback_host, _callback_port
    _callback_host = host
    _callback_port = port


class _CallbackCollector:
    """Servidor HTTP minimo que só registra QUANDO e COM QUE TOKEN foi
    chamado -- não processa nada além disso. Uma instância por scan
    inteiro (não por parâmetro), reaproveitada entre todos os testes."""

    def __init__(self, host: str, port: int):
        self.hits: dict[str, float] = {}  # token -> timestamp do hit
        self._lock = threading.Lock()
        handler = self._make_handler()
        self._server = HTTPServer((host, port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _make_handler(self):
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                token = self.path.strip("/").split("/")[-1]
                with collector._lock:
                    collector.hits[token] = time.time()
                self.send_response(200)
                self.end_headers()

        return Handler

    def was_hit(self, token: str) -> bool:
        with self._lock:
            return token in self.hits

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
    display_name="Heurística de SSRF via Callback",
    summary="Envia URL de callback com token único por parâmetro e confirma SSRF de forma out-of-band -- funciona até em SSRF cego, onde a resposta nunca expõe o conteúdo buscado.",
)
class CallbackSSRFHeuristic:
    name = "callback_ssrf_heuristic"
    _collector: _CallbackCollector | None = None

    @classmethod
    def _get_collector(cls) -> _CallbackCollector | None:
        if _callback_host is None:
            return None
        if cls._collector is None:
            cls._collector = _CallbackCollector(_callback_host, _callback_port)
        return cls._collector

    def run(self, target, facts_in):
        collector = self._get_collector()
        if collector is None:
            print("[callback_ssrf_heuristic] nenhum callback host configurado -- módulo não roda "
                  "(ver configure_callback_host()).")
            return None

        params = facts_in.get("surface.param.*", [])
        findings = []

        for f in params:
            info = f.value
            url, method, param = info["url"], info["method"], info["param"]

            token = uuid.uuid4().hex[:16]
            callback_url = f"http://{_callback_host}:{collector.port}/{token}"

            _send(url, method, {param: callback_url})
            time.sleep(_CALLBACK_WAIT_SECONDS)

            if collector.was_hit(token):
                findings.append({
                    "title": f"SSRF confirmado via callback: parâmetro '{param}' em {url}",
                    "severity": "critical",
                    "module": self.name,
                    "category": "ssrf",
                    "endpoint": url,
                    "description": (
                        f"O parâmetro '{param}' (via {method}), recebendo uma URL de callback "
                        f"controlada com token único, resultou numa requisição REAL de volta "
                        f"pro coletor -- confirmação out-of-band, o servidor fez a requisição "
                        f"de saída de verdade, mesmo sem expor o conteúdo na resposta."
                    ),
                    "business_impact": (
                        "SSRF confirmado pode ser usado pra acessar serviço interno não exposto "
                        "publicamente, endpoint de metadado de cloud, ou escanear a rede interna "
                        "a partir do próprio servidor."
                    ),
                    "remediation": "Validar e restringir destino de requisição de saída via allowlist explícita, nunca aceitar URL arbitrária do usuário sem checagem.",
                    "evidence": {"url": url, "method": method, "param": param, "callback_token": token},
                })

        if not findings:
            return None
        return ModuleResult(findings=findings)
